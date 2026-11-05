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
    indirect: bool,
}

#[derive(Clone, Debug)]
struct GoReplace {
    old_module: String,
    old_version: Option<String>,
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
            .map(|name| {
                name.eq_ignore_ascii_case("go.mod")
                    || name.eq_ignore_ascii_case("go.sum")
                    || name.eq_ignore_ascii_case("go.work")
            })
            .unwrap_or(false)
    }

    fn find_dependencies(
        &self,
        paths: &[PathBuf],
        config: &SbomProducerConfiguration,
    ) -> anyhow::Result<Vec<Dependency>> {
        let mut all_dependencies = Vec::new();

        // 第一趟（推广自 Maven 父级上下文穿透）：收集工作区根 go.work 中的全局 replace 规则
        let mut workspace_replaces = Vec::new();
        let root_go_work = config.base_path.join("go.work");
        if root_go_work.exists() {
            if let Ok(content) = fs::read_to_string(&root_go_work) {
                let parsed_work = Self::parse_go_mod(&content);
                workspace_replaces.extend(parsed_work.replaces);
            }
        }
        for p in paths {
            if p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.eq_ignore_ascii_case("go.work"))
            {
                if let Ok(content) = fs::read_to_string(p) {
                    let parsed_work = Self::parse_go_mod(&content);
                    workspace_replaces.extend(parsed_work.replaces);
                }
            }
        }

        // 按父目录聚类，使同一目录下的 go.mod 与 go.sum 协同解析
        let mut dir_groups: HashMap<PathBuf, Vec<PathBuf>> = HashMap::new();
        for p in paths {
            if p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.eq_ignore_ascii_case("go.work"))
            {
                continue;
            }
            let parent = p.parent().unwrap_or_else(|| Path::new("")).to_path_buf();
            dir_groups.entry(parent).or_default().push(p.clone());
        }

        let mut sorted_dirs: Vec<PathBuf> = dir_groups.keys().cloned().collect();
        sorted_dirs.sort();

        for dir in sorted_dirs {
            let files = &dir_groups[&dir];
            let go_mod_path = files
                .iter()
                .find(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.eq_ignore_ascii_case("go.mod"))
                })
                .cloned()
                .or_else(|| {
                    let candidate = dir.join("go.mod");
                    candidate.exists().then_some(candidate)
                });

            let go_sum_path = files
                .iter()
                .find(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.eq_ignore_ascii_case("go.sum"))
                })
                .cloned()
                .or_else(|| {
                    let candidate = dir.join("go.sum");
                    candidate.exists().then_some(candidate)
                });

            let deps = Self::analyze_go_project(
                go_mod_path.as_deref(),
                go_sum_path.as_deref(),
                &workspace_replaces,
            )?;
            all_dependencies.extend(deps);
        }

        Ok(all_dependencies)
    }
}

impl GoProducer {
    /// 协同分析单个 Go 模块目录下的 `go.mod` 与 `go.sum`，并融合工作区级 `go.work` 的 `replace` 规则
    fn analyze_go_project(
        go_mod_path: Option<&Path>,
        go_sum_path: Option<&Path>,
        workspace_replaces: &[GoReplace],
    ) -> anyhow::Result<Vec<Dependency>> {
        let primary_path = match (go_mod_path, go_sum_path) {
            (Some(m), _) => m,
            (None, Some(s)) => s,
            (None, None) => return Ok(vec![]),
        };

        let file_salt = primary_path.to_string_lossy().replace('\\', "/");
        let location = Some(DependencyLocation::from_file(primary_path));

        let parsed_mod = if let Some(mod_path) = go_mod_path {
            let content = fs::read_to_string(mod_path)?;
            Some(Self::parse_go_mod(&content))
        } else {
            None
        };

        let sum_entries = if let Some(sum_path) = go_sum_path {
            if let Ok(content) = fs::read_to_string(sum_path) {
                Self::parse_go_sum(&content)
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        let root_module_name = parsed_mod
            .as_ref()
            .and_then(|m| m.module_name.clone())
            .unwrap_or_else(|| {
                primary_path
                    .parent()
                    .and_then(|d| d.file_name())
                    .and_then(|n| n.to_str())
                    .unwrap_or("go-app")
                    .to_string()
            });

        // Go 模块自身的版本默认标记为 0.0.0（go.mod 中的 `go 1.2x` 为编译器语言版本而非包版本）
        let root_version = "0.0.0".to_string();

        let root_purl_raw = format!("pkg:golang/{}@{}", root_module_name, root_version);
        let root_purl = Dependency::auto_fix_and_validate_purl(&root_purl_raw);
        let root_instance_id = make_instance_id(&root_purl, &file_salt);

        // 融合 go.work 级 replace 与当前 go.mod 级 replace
        let mut combined_replaces: Vec<GoReplace> = workspace_replaces.to_vec();
        if let Some(ref m) = parsed_mod {
            combined_replaces.extend(m.replaces.clone());
        }

        let empty_excludes = HashSet::new();
        let excludes = parsed_mod
            .as_ref()
            .map(|m| &m.excludes)
            .unwrap_or(&empty_excludes);

        let mut resolved_modules: Vec<(String, String, bool)> = Vec::new();
        let mut seen_module_names: HashSet<String> = HashSet::new();
        let mut seen_mod_ver: HashSet<(String, String)> = HashSet::new();

        if let Some(ref mod_data) = parsed_mod {
            for req in &mod_data.requires {
                if excludes.contains(&(req.module.clone(), req.version.clone())) {
                    continue;
                }
                if let Some((final_mod, final_ver)) =
                    Self::apply_replace(&req.module, &req.version, &combined_replaces)
                {
                    seen_module_names.insert(req.module.clone());
                    seen_module_names.insert(final_mod.clone());
                    if seen_mod_ver.insert((final_mod.clone(), final_ver.clone())) {
                        resolved_modules.push((final_mod, final_ver, req.indirect));
                    }
                } else {
                    seen_module_names.insert(req.module.clone());
                }
            }
        }

        // 仅当 go.mod 缺失或未包含有效 require 时，才回退使用 go.sum 补全（避免引入 go.sum 中不参与构建的历史/测试校验项）
        if parsed_mod.is_none() || resolved_modules.is_empty() {
            for (sum_mod, sum_ver) in sum_entries {
                if seen_module_names.contains(&sum_mod) {
                    continue;
                }
                if excludes.contains(&(sum_mod.clone(), sum_ver.clone())) {
                    continue;
                }
                if let Some((final_mod, final_ver)) =
                    Self::apply_replace(&sum_mod, &sum_ver, &combined_replaces)
                {
                    seen_module_names.insert(sum_mod);
                    seen_module_names.insert(final_mod.clone());
                    if seen_mod_ver.insert((final_mod.clone(), final_ver.clone())) {
                        resolved_modules.push((final_mod, final_ver, true));
                    }
                }
            }
        }

        if resolved_modules.is_empty() && parsed_mod.is_none() {
            return Ok(vec![]);
        }

        let mut leaf_deps = Vec::with_capacity(resolved_modules.len());
        let mut root_children = Vec::new();

        for (mod_path, ver, _indirect) in resolved_modules {
            let raw_purl = format!("pkg:golang/{}@{}", mod_path, ver);
            let valid_purl = Dependency::auto_fix_and_validate_purl(&raw_purl);
            let child_id = make_instance_id(&valid_purl, &file_salt);

            if !root_children.contains(&child_id) {
                root_children.push(child_id.clone());
            }

            let group = Self::extract_go_namespace(&mod_path);

            let dep = DependencyBuilder::default()
                .group(group)
                .name(mod_path)
                .version(Some(ver))
                .r#type(DependencyType::Library)
                .purl(valid_purl)
                .instance_id(child_id)
                .dependencies(vec![])
                .location(location.clone())
                .build()
                .map_err(|e| anyhow::anyhow!(e))?;

            leaf_deps.push(dep);
        }

        let root_group = Self::extract_go_namespace(&root_module_name);
        let root_dep = DependencyBuilder::default()
            .group(root_group)
            .name(root_module_name)
            .version(Some(root_version))
            .r#type(DependencyType::Application)
            .purl(root_purl)
            .instance_id(root_instance_id)
            .dependencies(root_children)
            .location(location)
            .build()
            .map_err(|e| anyhow::anyhow!(e))?;

        let mut all_deps = Vec::with_capacity(leaf_deps.len() + 1);
        all_deps.push(root_dep);
        all_deps.extend(leaf_deps);

        Ok(all_deps)
    }

    pub fn extract_go_namespace(module_path: &str) -> Option<String> {
        module_path.rsplit_once('/').map(|(ns, _)| ns.to_string())
    }

    fn apply_replace(
        module: &str,
        version: &str,
        replaces: &[GoReplace],
    ) -> Option<(String, String)> {
        for rep in replaces {
            if rep.old_module == module && rep.old_version.as_deref() == Some(version) {
                return rep
                    .new_version
                    .as_ref()
                    .map(|new_ver| (rep.new_module.clone(), new_ver.clone()));
            }
        }
        for rep in replaces {
            if rep.old_module == module && rep.old_version.is_none() {
                return rep
                    .new_version
                    .as_ref()
                    .map(|new_ver| (rep.new_module.clone(), new_ver.clone()));
            }
        }
        Some((module.to_string(), version.to_string()))
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

    fn parse_require_line(line: &str, is_indirect: bool, out: &mut Vec<GoRequire>) {
        let mut tokens = line.split_whitespace();
        if let (Some(module), Some(version)) = (tokens.next(), tokens.next()) {
            let clean_mod = module.trim_matches('"').to_string();
            let clean_ver = version.trim_matches('"').to_string();
            if !clean_mod.is_empty() && !clean_ver.is_empty() {
                out.push(GoRequire {
                    module: clean_mod,
                    version: clean_ver,
                    indirect: is_indirect,
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
        let old_ver = left_tokens.next().map(|s| s.trim_matches('"').to_string());

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
            old_version: old_ver,
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

    fn parse_go_sum(content: &str) -> Vec<(String, String)> {
        let mut result = Vec::new();
        let mut seen = HashSet::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("//") {
                continue;
            }
            let mut parts = line.split_whitespace();
            if let (Some(module), Some(raw_ver)) = (parts.next(), parts.next()) {
                let clean_ver = raw_ver.strip_suffix("/go.mod").unwrap_or(raw_ver);
                let key = (module.to_string(), clean_ver.to_string());
                if seen.insert(key.clone()) {
                    result.push(key);
                }
            }
        }

        result
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

        let rep = GoProducer::apply_replace("github.com/old/library", "v1.0.0", &parsed.replaces);
        assert_eq!(
            rep,
            Some(("github.com/new/library".to_string(), "v1.0.2".to_string()))
        );

        let local_rep =
            GoProducer::apply_replace("github.com/local/sdk", "0.1.0", &parsed.replaces);
        assert_eq!(local_rep, None);
    }

    #[test]
    fn test_parse_go_sum_dedup() {
        let go_sum_content = r#"
github.com/gin-gonic/gin v1.9.1 h1:4idEAncQnU5cB7BeOkPtxjfCSye0AAm1R0RVIqJ+Jmg=
github.com/gin-gonic/gin v1.9.1/go.mod h1:hPrL7YrpYKXt5YId3A/Tnip5kqbEAP+KLuI3SUcPTeU=
golang.org/x/sys v0.8.0 h1:EBmGv8NaZBZTWvrbjNoL6HVt+IVy3QDQpJs7VRIw3tU=
golang.org/x/sys v0.8.0/go.mod h1:oPkhp1MJrh7nUepCBck5+mAzfO9JrbApNNgaTdGDITg=
"#;

        let entries = GoProducer::parse_go_sum(go_sum_content);
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0],
            ("github.com/gin-gonic/gin".to_string(), "v1.9.1".to_string())
        );
        assert_eq!(
            entries[1],
            ("golang.org/x/sys".to_string(), "v0.8.0".to_string())
        );
    }
}
