use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyLocation, DependencyType};
use crate::utils::file_utils::make_instance_id;

#[derive(Clone, Default)]
pub struct NpmLockProducer {}

impl SbomProducer for NpmLockProducer {
    fn use_file(&self, path: &Path, _config: &SbomProducerConfiguration) -> bool {
        path.file_name()
            .is_some_and(|n| n.eq_ignore_ascii_case("package-lock.json"))
    }

    fn find_dependencies(
        &self,
        paths: &[PathBuf],
        _config: &SbomProducerConfiguration,
    ) -> anyhow::Result<Vec<Dependency>> {
        let mut result = Vec::new();

        for p in paths {
            let Ok(content) = std::fs::read_to_string(p) else {
                continue;
            };
            let clean_content = content.trim_start_matches('\u{FEFF}').trim();
            let file_salt = p.to_string_lossy().replace('\\', "/");
            let location = Some(DependencyLocation::from_file(p));

            match serde_json::from_str::<serde_json::Value>(clean_content) {
                Ok(json) => {
                    result.extend(Self::parse_npm_lock(&json, &file_salt, location)?);
                }
                Err(e) => {
                    eprintln!(
                        "❌ [Debug] 无法解析 package-lock.json {:?}，错误原因: {}",
                        p, e
                    );
                }
            }
        }
        Ok(result)
    }
}

impl NpmLockProducer {
    fn parse_npm_lock(
        json: &serde_json::Value,
        file_salt: &str,
        location: Option<DependencyLocation>,
    ) -> anyhow::Result<Vec<Dependency>> {
        let Some(packages) = json.get("packages").and_then(|p| p.as_object()) else {
            return Ok(vec![]);
        };

        struct RawNode {
            pkg_path: String,
            name: String,
            version: String,
            purl: String,
            instance_id: String,
            dep_names: Vec<String>,
        }

        let mut nodes = Vec::with_capacity(packages.len());
        let mut path_to_id: HashMap<String, String> = HashMap::with_capacity(packages.len());

        for (pkg_path, pkg_data) in packages {
            if pkg_path.is_empty() {
                continue;
            }

            let name = match pkg_data.get("name").and_then(|n| n.as_str()) {
                Some(n) => n.to_string(),
                None => {
                    if let Some(idx) = pkg_path.rfind("node_modules/") {
                        pkg_path[idx + 13..].to_string()
                    } else {
                        pkg_path.rsplit('/').next().unwrap_or(pkg_path).to_string()
                    }
                }
            };

            let Some(version) = pkg_data.get("version").and_then(|v| v.as_str()) else {
                continue;
            };

            let purl = format!("pkg:npm/{}@{}", name, version);
            let valid_purl = Dependency::auto_fix_and_validate_purl(&purl);

            let combined_salt = format!("{}:{}", file_salt, pkg_path);
            let instance_id = make_instance_id(&valid_purl, &combined_salt);

            path_to_id.insert(pkg_path.clone(), instance_id.clone());

            let mut dep_names = Vec::new();
            if let Some(deps) = pkg_data.get("dependencies").and_then(|d| d.as_object()) {
                dep_names.extend(deps.keys().cloned());
            }

            nodes.push(RawNode {
                pkg_path: pkg_path.clone(),
                name,
                version: version.to_string(),
                purl: valid_purl,
                instance_id,
                dep_names,
            });
        }

        let mut final_deps = Vec::with_capacity(nodes.len());

        for node in nodes {
            let mut child_ids = Vec::with_capacity(node.dep_names.len());

            for d_name in &node.dep_names {
                if let Some(target_id) = Self::resolve_npm_dep(&node.pkg_path, d_name, &path_to_id)
                {
                    child_ids.push(target_id.clone());
                }
            }

            if let Ok(dep) = DependencyBuilder::default()
                .name(node.name)
                .version(Some(node.version))
                .r#type(DependencyType::Library)
                .purl(node.purl)
                .instance_id(node.instance_id)
                .dependencies(child_ids)
                .location(location.clone())
                .build()
            {
                final_deps.push(dep);
            }
        }

        Ok(final_deps)
    }

    fn resolve_npm_dep<'a>(
        caller_pkg_path: &str,
        dep_name: &str,
        path_to_id: &'a HashMap<String, String>,
    ) -> Option<&'a String> {
        let mut curr = caller_pkg_path;

        loop {
            let candidate = if curr.is_empty() {
                format!("node_modules/{}", dep_name)
            } else {
                format!("{}/node_modules/{}", curr, dep_name)
            };

            if let Some(id) = path_to_id.get(&candidate) {
                return Some(id);
            }

            if curr.is_empty() {
                break;
            }

            if let Some(idx) = curr.rfind("/node_modules/") {
                curr = &curr[..idx];
            } else {
                curr = "";
            }
        }

        None
    }
}
