use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyLocation, DependencyType};
use crate::utils::file_utils::make_instance_id;

#[derive(Clone, Default)]
pub struct GoProducer {}

#[derive(Clone, Debug)]
struct GoRequire {
    module: String,
    version: String,
}

#[derive(Clone, Debug)]
struct GoReplace {
    old_module: String,
    new_module: String,
    /// 若为 None，表示替换为本地相对/绝对文件目录（如 ./local/pkg）
    new_version: Option<String>,
}

#[derive(Clone, Debug, Default)]
struct ParsedGoMod {
    module_name: Option<String>,
    requires: Vec<GoRequire>,
    replaces: Vec<GoReplace>,
    excludes: HashSet<(String, String)>,
}

impl SbomProducer for GoProducer {
    fn use_file(&self, path: &Path, _config: &SbomProducerConfiguration) -> bool {
        path.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("go.mod"))
    }

    fn find_dependencies(
        &self,
        paths: &[PathBuf],
        _config: &SbomProducerConfiguration,
    ) -> anyhow::Result<Vec<Dependency>> {
        // Syft catalogs each go.mod independently. go.sum contains checksums, not selected dependencies.
        let mut manifests: Vec<_> = paths
            .iter()
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.eq_ignore_ascii_case("go.mod"))
            })
            .collect();
        manifests.sort();
        manifests.dedup();
        let mut dependencies = Vec::new();
        for path in manifests {
            dependencies.extend(Self::analyze_go_mod(&fs::read_to_string(path)?, path)?);
        }
        Ok(dependencies)
    }
}

impl GoProducer {
    fn analyze_go_mod(content: &str, path: &Path) -> anyhow::Result<Vec<Dependency>> {
        let parsed = Self::parse_go_mod(content);
        let file_salt = path.to_string_lossy().replace('\\', "/");
        let location = Some(DependencyLocation::from_file(path));
        let root_name = parsed.module_name.unwrap_or_else(|| "go-app".to_string());
        let root_purl = Dependency::auto_fix_and_validate_purl(&format!("pkg:golang/{root_name}"));
        let root_id = make_instance_id(&root_purl, &file_salt);
        // Match Syft: require entries, replacement identities, then excludes.
        let mut modules: HashMap<String, Option<String>> = parsed
            .requires
            .into_iter()
            .map(|r| (r.module, Some(r.version)))
            .collect();
        for replacement in parsed.replaces {
            let final_name = if replacement.new_version.is_some() {
                modules.remove(&replacement.old_module);
                replacement.new_module
            } else {
                // A local replacement keeps the original module name without a registry version.
                replacement.old_module
            };
            modules.insert(final_name, replacement.new_version);
        }
        for (module, _) in parsed.excludes {
            modules.remove(&module);
        }
        let mut modules: Vec<_> = modules.into_iter().collect();
        modules.sort_by(|a, b| a.0.cmp(&b.0));
        let mut dependencies = Vec::new();
        let mut children = Vec::new();
        for (name, version) in modules {
            let raw_purl = match &version {
                Some(v) => format!("pkg:golang/{name}@{v}"),
                None => format!("pkg:golang/{name}"),
            };
            let purl = Dependency::auto_fix_and_validate_purl(&raw_purl);
            let id = make_instance_id(&purl, &file_salt);
            children.push(id.clone());
            dependencies.push(
                DependencyBuilder::default()
                    .group(Self::extract_go_namespace(&name))
                    .name(name)
                    .version(version)
                    .purl(purl)
                    .instance_id(id)
                    .location(location.clone())
                    .build()
                    .map_err(|e| anyhow::anyhow!(e))?,
            );
        }
        dependencies.insert(
            0,
            DependencyBuilder::default()
                .group(Self::extract_go_namespace(&root_name))
                .name(root_name)
                .version(None)
                .r#type(DependencyType::Application)
                .purl(root_purl)
                .instance_id(root_id)
                .dependencies(children)
                .location(location)
                .build()
                .map_err(|e| anyhow::anyhow!(e))?,
        );
        Ok(dependencies)
    }

    pub fn extract_go_namespace(module_path: &str) -> Option<String> {
        module_path.rsplit_once('/').map(|(ns, _)| ns.to_string())
    }

    fn parse_go_mod(content: &str) -> ParsedGoMod {
        let mut parsed = ParsedGoMod::default();

        #[derive(Clone, Copy, PartialEq, Eq)]
        enum BlockState {
            None,
            Require,
            Replace,
            Exclude,
            Other,
        }

        let mut state = BlockState::None;

        for raw_line in content.lines() {
            let (code_part, comment_part) = match raw_line.split_once("//") {
                Some((code, comm)) => (code.trim(), Some(comm.trim())),
                None => (raw_line.trim(), None),
            };

            if code_part.is_empty() {
                continue;
            }

            let is_indirect = comment_part
                .map(|c| c.contains("indirect"))
                .unwrap_or(false);

            if code_part == ")" || code_part.starts_with(')') {
                state = BlockState::None;
                continue;
            }

            match state {
                BlockState::None => {
                    if let Some(rest) = code_part.strip_prefix("module ") {
                        let mod_name = rest.trim().trim_matches('"');
                        if !mod_name.is_empty() {
                            parsed.module_name = Some(mod_name.to_string());
                        }
                    } else if let Some(rest) = code_part.strip_prefix("require") {
                        let rest = rest.trim();
                        if rest.starts_with('(') {
                            let inner = rest.trim_start_matches('(').trim();
                            if !inner.is_empty() && !inner.starts_with(')') {
                                Self::parse_require_line(inner, is_indirect, &mut parsed.requires);
                            }
                            if !rest.ends_with(')') {
                                state = BlockState::Require;
                            }
                        } else {
                            Self::parse_require_line(rest, is_indirect, &mut parsed.requires);
                        }
                    } else if let Some(rest) = code_part.strip_prefix("replace") {
                        let rest = rest.trim();
                        if rest.starts_with('(') {
                            let inner = rest.trim_start_matches('(').trim();
                            if !inner.is_empty() && !inner.starts_with(')') {
                                Self::parse_replace_line(inner, &mut parsed.replaces);
                            }
                            if !rest.ends_with(')') {
                                state = BlockState::Replace;
                            }
                        } else {
                            Self::parse_replace_line(rest, &mut parsed.replaces);
                        }
                    } else if let Some(rest) = code_part.strip_prefix("exclude") {
                        let rest = rest.trim();
                        if rest.starts_with('(') {
                            let inner = rest.trim_start_matches('(').trim();
                            if !inner.is_empty() && !inner.starts_with(')') {
                                Self::parse_exclude_line(inner, &mut parsed.excludes);
                            }
                            if !rest.ends_with(')') {
                                state = BlockState::Exclude;
                            }
                        } else {
                            Self::parse_exclude_line(rest, &mut parsed.excludes);
                        }
                    } else if code_part.ends_with('(') {
                        state = BlockState::Other;
                    }
                }
                BlockState::Require => {
                    Self::parse_require_line(code_part, is_indirect, &mut parsed.requires);
                }
                BlockState::Replace => {
                    Self::parse_replace_line(code_part, &mut parsed.replaces);
                }
                BlockState::Exclude => {
                    Self::parse_exclude_line(code_part, &mut parsed.excludes);
                }
                BlockState::Other => {}
            }
        }

        parsed
    }

    fn parse_require_line(line: &str, _is_indirect: bool, out: &mut Vec<GoRequire>) {
        let mut tokens = line.split_whitespace();
        if let (Some(module), Some(version)) = (tokens.next(), tokens.next()) {
            let clean_mod = module.trim_matches('"').to_string();
            let clean_ver = version.trim_matches('"').to_string();
            if !clean_mod.is_empty() && !clean_ver.is_empty() {
                out.push(GoRequire {
                    module: clean_mod,
                    version: clean_ver,
                });
            }
        }
    }

    fn parse_replace_line(line: &str, out: &mut Vec<GoReplace>) {
        let Some((left, right)) = line.split_once("=>") else {
            return;
        };
        let mut left_tokens = left.split_whitespace();
        let Some(old_mod) = left_tokens.next() else {
            return;
        };

        let mut right_tokens = right.split_whitespace();
        let Some(new_mod) = right_tokens.next() else {
            return;
        };
        let new_ver = right_tokens.next().map(|s| s.trim_matches('"').to_string());

        let is_local_path = new_ver.is_none()
            || new_mod.starts_with("./")
            || new_mod.starts_with("../")
            || new_mod.starts_with('/')
            || new_mod.contains('\\');

        out.push(GoReplace {
            old_module: old_mod.trim_matches('"').to_string(),
            new_module: new_mod.trim_matches('"').to_string(),
            new_version: if is_local_path { None } else { new_ver },
        });
    }

    fn parse_exclude_line(line: &str, out: &mut HashSet<(String, String)>) {
        let mut tokens = line.split_whitespace();
        if let (Some(module), Some(version)) = (tokens.next(), tokens.next()) {
            out.insert((
                module.trim_matches('"').to_string(),
                version.trim_matches('"').to_string(),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_go_mod_with_replace_and_exclude() {
        let go_mod_content = r#"
module github.com/bnbu/demo-service

go 1.22

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/pkg/errors v0.9.1
    github.com/old/library v1.0.0
    github.com/local/sdk v0.1.0
    github.com/bad/vuln v1.2.3
)

require (
    github.com/bytedance/sonic v1.9.1 // indirect
    golang.org/x/sys v0.8.0 // indirect
)

replace (
    github.com/old/library v1.0.0 => github.com/new/library v1.0.2
    github.com/local/sdk => ./internal/sdk
)

exclude github.com/bad/vuln v1.2.3
"#;

        let parsed = GoProducer::parse_go_mod(go_mod_content);
        assert_eq!(
            parsed.module_name.as_deref(),
            Some("github.com/bnbu/demo-service")
        );
        assert_eq!(parsed.requires.len(), 7);
        assert_eq!(parsed.replaces.len(), 2);
        assert!(parsed
            .excludes
            .contains(&("github.com/bad/vuln".to_string(), "v1.2.3".to_string())));

        let deps = GoProducer::analyze_go_mod(go_mod_content, Path::new("go.mod")).unwrap();
        assert!(deps
            .iter()
            .any(|d| d.name == "github.com/new/library" && d.version.as_deref() == Some("v1.0.2")));
        assert!(deps
            .iter()
            .any(|d| d.name == "github.com/local/sdk" && d.version.is_none()));
        assert!(!deps
            .iter()
            .any(|d| d.name == "github.com/bad/vuln" || d.name == "github.com/old/library"));
    }

    #[test]
    fn checksum_and_workspace_files_do_not_catalog_packages() {
        let producer = GoProducer::default();
        let config = SbomProducerConfiguration {
            use_debug: false,
            base_path: PathBuf::from("."),
        };
        for name in ["go.sum", "go.work"] {
            assert!(!producer.use_file(Path::new(name), &config));
        }
        let deps =
            GoProducer::analyze_go_mod("module example.com/app\n", Path::new("go.mod")).unwrap();
        assert_eq!(deps.len(), 1);
        assert!(deps[0].version.is_none());
    }

    #[test]
    fn replacement_entries_are_cataloged_and_excludes_apply_by_name() {
        let deps = GoProducer::analyze_go_mod(
            "module example.com/app\nrequire example.com/excluded v1.0.0\nexclude example.com/excluded v0.9.0\nreplace example.com/unused => example.com/fork v2.0.0\n",
            Path::new("go.mod"),
        ).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[1].name, "example.com/fork");
        assert_eq!(deps[1].version.as_deref(), Some("v2.0.0"));
    }
}
