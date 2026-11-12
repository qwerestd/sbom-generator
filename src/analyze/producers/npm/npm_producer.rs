use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyLocation, DependencyType};
use crate::utils::context_resolver::HierarchicalContext;
use crate::utils::file_utils::make_instance_id;
use crate::utils::tree_sitter::language::get_tree_sitter_json;
use crate::utils::tree_sitter::tree::{build_location_from_offsets, get_tree};

#[derive(Clone, Default)]
pub struct NpmProducer {}

/// Keep the complete declaration; constraints must never be reduced to their lower bound.
fn sanitize_semver_range(raw: &str) -> &str {
    raw.trim()
}

impl SbomProducer for NpmProducer {
    fn use_file(&self, path: &Path, _config: &SbomProducerConfiguration) -> bool {
        path.file_name()
            .is_some_and(|n| n.eq_ignore_ascii_case("package.json"))
    }

    fn find_dependencies(
        &self,
        paths: &[PathBuf],
        config: &SbomProducerConfiguration,
    ) -> anyhow::Result<Vec<Dependency>> {
        let mut result = vec![];

        // 推广自 Maven 的双趟上下文收集：从根 package.json 提取 workspaces catalog 与受管版本
        let mut root_ctx = HierarchicalContext::new();
        let root_pkg_json = config.base_path.join("package.json");
        if root_pkg_json.exists() {
            if let Ok(c) = fs::read_to_string(&root_pkg_json) {
                Self::collect_workspace_catalog_context(&c, &mut root_ctx);
            }
        }

        for p in paths {
            {
                let content = fs::read_to_string(p)?;
                let clean_content = content.trim_start_matches('\u{FEFF}').trim();
                let file_salt = p.to_string_lossy().replace('\\', "/");

                match serde_json::from_str::<serde_json::Value>(clean_content) {
                    Ok(json) => {
                        let file_deps = Self::parse_single_package_json(
                            &json,
                            clean_content,
                            &file_salt,
                            p,
                            &root_ctx,
                        )?;
                        result.extend(file_deps);
                    }
                    Err(e) => {
                        anyhow::bail!("invalid package.json {}: {e}", p.display());
                    }
                }
            }
        }
        Ok(result)
    }
}

impl NpmProducer {
    /// Resolve local declarations against already scanned application directories.
    /// Names are deliberately not an index: independent directories may use the
    /// same package name and version, and lockfile roots have different IDs.
    pub fn link_local_dependencies(
        paths: &[PathBuf],
        dependencies: &mut Vec<Dependency>,
        base_path: &Path,
    ) -> anyhow::Result<()> {
        let scan_root = fs::canonicalize(base_path)?;
        let mut roots: HashMap<PathBuf, Vec<String>> = HashMap::new();
        for dep in dependencies.iter() {
            if dep.r#type != DependencyType::Application || !dep.purl.starts_with("pkg:npm/") {
                continue;
            }
            let Some(dir) = dep
                .location
                .as_ref()
                .and_then(|l| Path::new(&l.block.file).parent())
                .and_then(|p| fs::canonicalize(p).ok())
            else {
                continue;
            };
            if dir.starts_with(&scan_root) {
                let ids = roots.entry(dir).or_default();
                if !ids.contains(&dep.instance_id) {
                    ids.push(dep.instance_id.clone());
                }
            }
        }
        let mut links: HashMap<String, Vec<String>> = HashMap::new();
        let mut aliases = HashMap::<String, String>::new();
        for path in paths
            .iter()
            .filter(|p| p.file_name().is_some_and(|n| n == "package.json"))
        {
            let Some(source_dir) = path.parent().and_then(|p| fs::canonicalize(p).ok()) else {
                continue;
            };
            let Some(source_ids) = roots.get(&source_dir) else {
                continue;
            };
            let [source_id] = source_ids.as_slice() else {
                continue;
            };
            let content = fs::read_to_string(path)?;
            // A valid lockfile may have been chosen over an invalid manifest.
            let Ok(json) =
                serde_json::from_str::<serde_json::Value>(content.trim_start_matches('\u{FEFF}'))
            else {
                continue;
            };
            for category in [
                "dependencies",
                "devDependencies",
                "optionalDependencies",
                "peerDependencies",
            ] {
                for (name, spec) in json
                    .get(category)
                    .and_then(|v| v.as_object())
                    .into_iter()
                    .flatten()
                {
                    let Some(raw) = spec.as_str().map(str::trim) else {
                        continue;
                    };
                    let target_dir = if let Some(relative) = raw
                        .strip_prefix("file:")
                        .or_else(|| raw.strip_prefix("link:"))
                    {
                        fs::canonicalize(source_dir.join(relative)).ok()
                    } else if raw.starts_with("workspace:") {
                        let matching: Vec<_> = dependencies
                            .iter()
                            .filter(|d| d.r#type == DependencyType::Application && &d.name == name)
                            .filter_map(|d| {
                                d.location
                                    .as_ref()
                                    .and_then(|l| Path::new(&l.block.file).parent())
                                    .and_then(|p| fs::canonicalize(p).ok())
                            })
                            .collect();
                        if matching.len() == 1 {
                            matching.into_iter().next()
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    let Some(target_dir) = target_dir else {
                        continue;
                    };
                    if !target_dir.starts_with(&scan_root) || target_dir == source_dir {
                        continue;
                    }
                    if let Some(ids) = roots.get(&target_dir) {
                        if let [target_id] = ids.as_slice() {
                            for d in dependencies.iter().filter(|d| {
                                &d.name == name
                                    && d.r#type == DependencyType::Library
                                    && d.properties
                                        .get("sbom:dependency:declaration")
                                        .is_some_and(|v| v == raw)
                            }) {
                                if d.location
                                    .as_ref()
                                    .and_then(|l| Path::new(&l.block.file).parent())
                                    .and_then(|p| fs::canonicalize(p).ok())
                                    .as_ref()
                                    == Some(&source_dir)
                                {
                                    aliases.insert(d.instance_id.clone(), target_id.clone());
                                }
                            }
                            links
                                .entry(source_id.clone())
                                .or_default()
                                .push(target_id.clone());
                        }
                    }
                }
            }
        }
        dependencies.retain(|d| !aliases.contains_key(&d.instance_id));
        for dep in dependencies {
            for child in &mut dep.dependencies {
                if let Some(id) = aliases.get(child) {
                    *child = id.clone();
                }
            }
            if let Some(children) = links.get(&dep.instance_id) {
                for child in children {
                    if !dep.dependencies.contains(child) {
                        dep.dependencies.push(child.clone());
                    }
                }
            }
        }
        Ok(())
    }

    /// 收集 Monorepo 根 `package.json` 中的 `catalog` 或公共受管版本
    pub fn collect_workspace_catalog_context(content: &str, ctx: &mut HierarchicalContext) {
        let Ok(json) =
            serde_json::from_str::<serde_json::Value>(content.trim_start_matches('\u{FEFF}'))
        else {
            return;
        };

        // 1. 兼容 pnpm / Bun / Yarn 现代 workspaces.catalog 或顶层 catalog
        let catalog_opts = [
            json.get("catalog").and_then(|c| c.as_object()),
            json.get("workspaces")
                .and_then(|w| w.get("catalog"))
                .and_then(|c| c.as_object()),
        ];

        for cat in catalog_opts.into_iter().flatten() {
            for (pkg_name, ver_val) in cat {
                if let Some(v_str) = ver_val.as_str() {
                    let clean = sanitize_semver_range(v_str);
                    if !clean.is_empty() {
                        ctx.insert_managed_version(pkg_name.clone(), clean.to_string());
                    }
                }
            }
        }
    }

    /// 推广自 Maven 的 Tree-sitter AST 源码行列定位：基于 `tree-sitter-json` 提取每个依赖键值的精确位置
    fn extract_json_ast_locations(
        content: &str,
        file_path: &Path,
    ) -> HashMap<String, DependencyLocation> {
        let mut loc_map = HashMap::new();
        let json_lang = get_tree_sitter_json();
        let Some(tree) = get_tree(content, &json_lang) else {
            return loc_map;
        };

        let query_str = r#"
            (pair
                key: (string (string_content) @dep_name)
                value: (string (string_content) @dep_ver)
            ) @pair_block
        "#;

        let Ok(query) = tree_sitter::Query::new(&json_lang, query_str) else {
            return loc_map;
        };

        let mut cursor = tree_sitter::QueryCursor::new();
        let matches = cursor.matches(&query, tree.root_node(), content.as_bytes());

        for m in matches {
            if m.captures.len() >= 3 {
                let block_node = m.captures[0].node;
                let name_node = m.captures[1].node;
                let ver_node = m.captures[2].node;

                let name_str = &content[name_node.start_byte()..name_node.end_byte()];
                let loc = build_location_from_offsets(
                    file_path,
                    content,
                    (block_node.start_byte(), block_node.end_byte()),
                    Some((name_node.start_byte(), name_node.end_byte())),
                    Some((ver_node.start_byte(), ver_node.end_byte())),
                );
                loc_map.insert(name_str.to_string(), loc);
            }
        }

        loc_map
    }

    fn parse_single_package_json(
        json: &serde_json::Value,
        raw_content: &str,
        file_salt: &str,
        file_path: &Path,
        workspace_ctx: &HierarchicalContext,
    ) -> anyhow::Result<Vec<Dependency>> {
        let fallback_location = Some(DependencyLocation::from_file(file_path));
        let ast_locations = Self::extract_json_ast_locations(raw_content, file_path);

        let app_name = json
            .get("name")
            .and_then(|n| n.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                file_path
                    .parent()
                    .and_then(|dir| dir.file_name())
                    .and_then(|n| n.to_str())
                    .unwrap_or("unnamed-js-app")
                    .to_string()
            });

        let app_ver = json
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0");
        let app_purl = format!("pkg:npm/{}@{}", app_name, app_ver);
        let app_instance_id = make_instance_id(&app_purl, file_salt);

        let dep_categories = [
            "dependencies",
            "devDependencies",
            "peerDependencies",
            "optionalDependencies",
        ];

        let mut child_ids = Vec::new();
        let mut leaf_deps = Vec::new();

        for category in dep_categories {
            if let Some(deps) = json.get(category).and_then(|d| d.as_object()) {
                for (name, version) in deps {
                    let raw_ver_str = version.as_str().unwrap_or("").trim();

                    let clean_ver = sanitize_semver_range(raw_ver_str);
                    // 若子包使用 "catalog:" 或 "workspace:*"，自动回退查询 workspace_ctx 受管版本表
                    let resolved_ver_opt = if clean_ver.is_empty() {
                        workspace_ctx.resolve_version(name, None)
                    } else {
                        workspace_ctx
                            .resolve_version(name, Some(clean_ver))
                            .or_else(|| Some(clean_ver.to_string()))
                    };

                    let (resolved_ver_opt, requirement) =
                        crate::utils::version_spec::manifest_version(
                            resolved_ver_opt.as_deref(),
                            "npm",
                        );
                    let purl_str = match &resolved_ver_opt {
                        Some(v) if !v.is_empty() => format!("pkg:npm/{}@{}", name, v),
                        _ => format!("pkg:npm/{}", name),
                    };

                    let valid_purl = Dependency::auto_fix_and_validate_purl(&purl_str);
                    let child_id = make_instance_id(&valid_purl, file_salt);
                    child_ids.push(child_id.clone());

                    let item_loc = ast_locations
                        .get(name)
                        .cloned()
                        .or_else(|| fallback_location.clone());

                    let mut leaf = DependencyBuilder::default()
                        .name(name.clone())
                        .version(resolved_ver_opt)
                        .version_requirement(requirement)
                        .r#type(DependencyType::Library)
                        .purl(valid_purl)
                        .instance_id(child_id)
                        .dependencies(vec![])
                        .location(item_loc)
                        .build()
                        .unwrap();

                    leaf.properties
                        .insert(format!("sbom:scope:{category}"), "true".into());
                    leaf.properties
                        .insert("sbom:dependency:declaration".into(), raw_ver_str.into());
                    if raw_ver_str.starts_with("file:")
                        || raw_ver_str.starts_with("link:")
                        || raw_ver_str.starts_with("workspace:")
                    {
                        leaf.properties
                            .insert("sbom:source:kind".into(), "local-reference".into());
                    } else if raw_ver_str.starts_with("git") || raw_ver_str.contains("://") {
                        leaf.properties
                            .insert("sbom:source:kind".into(), "vcs-or-url".into());
                    }
                    leaf_deps.push(leaf);
                }
            }
        }

        let root_dep = DependencyBuilder::default()
            .name(app_name)
            .version(Some(app_ver.to_string()))
            .r#type(DependencyType::Application)
            .purl(app_purl)
            .instance_id(app_instance_id)
            .dependencies(child_ids)
            .location(fallback_location)
            .build()
            .unwrap();

        let mut all_deps = Vec::with_capacity(leaf_deps.len() + 1);
        all_deps.push(root_dep);
        all_deps.extend(leaf_deps);

        Ok(all_deps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_npm_producer_find_dependencies_extended() {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("resources/npm/package.json");

        let producer = NpmProducer::default();
        let config = SbomProducerConfiguration {
            use_debug: false,
            base_path: d.parent().unwrap().to_path_buf(),
        };

        let deps = producer
            .find_dependencies(&[d], &config)
            .expect("Failed to parse package.json");

        assert!(deps.iter().any(|d| d.name == "react"
            && d.version.is_none()
            && d.version_requirement.as_deref() == Some("^18.0.0")));

        assert!(deps.iter().any(|d| d.name == "fsevents"
            && d.version.is_none()
            && d.version_requirement.as_deref() == Some("~2.3.2")));

        assert!(deps
            .iter()
            .any(|d| d.name == "git-dep" && d.version.is_none()));

        assert_eq!(
            deps.len(),
            8,
            "Expected 8 declarations including local and Git dependencies, found {}",
            deps.len()
        );
    }
}
