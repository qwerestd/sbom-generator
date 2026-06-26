// src/analyze/producers/npm_lock_producer.rs

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyType};

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

            match serde_json::from_str::<serde_json::Value>(clean_content) {
                Ok(json) => {
                    result.extend(Self::parse_npm_lock(&json)?);
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
    fn parse_npm_lock(json: &serde_json::Value) -> anyhow::Result<Vec<Dependency>> {
        // 兼容 npm lockfileVersion 2 和 3 的 "packages" 扁平结构
        let Some(packages) = json.get("packages").and_then(|p| p.as_object()) else {
            return Ok(vec![]);
        };

        struct RawNode {
            name: String,
            version: String,
            purl: String,
            dep_names: Vec<String>,
        }

        let mut nodes = Vec::with_capacity(packages.len());
        let mut name_to_purl = HashMap::new();

        for (pkg_path, pkg_data) in packages {
            // pkg_path 为 "" 代表根项目自己，必须跳过
            if pkg_path.is_empty() {
                continue;
            }

            // 从路径还原真正的包名，处理如 "node_modules/@babel/core" -> "@babel/core"
            let name = match pkg_data.get("name").and_then(|n| n.as_str()) {
                Some(n) => n.to_string(),
                None => pkg_path
                    .rsplit("node_modules/")
                    .next()
                    .unwrap_or(pkg_path)
                    .to_string(),
            };

            let Some(version) = pkg_data.get("version").and_then(|v| v.as_str()) else {
                continue;
            };

            let purl = format!("pkg:npm/{}@{}", name, version);
            name_to_purl.insert(name.clone(), purl.clone());

            let mut dep_names = Vec::new();
            if let Some(deps) = pkg_data.get("dependencies").and_then(|d| d.as_object()) {
                dep_names.extend(deps.keys().cloned());
            }

            nodes.push(RawNode {
                name,
                version: version.to_string(),
                purl,
                dep_names,
            });
        }

        let mut final_deps = Vec::with_capacity(nodes.len());
        for node in nodes {
            let child_purls: Vec<String> = node
                .dep_names
                .iter()
                .filter_map(|d_name| name_to_purl.get(d_name).cloned())
                .collect();

            if let Ok(dep) = DependencyBuilder::default()
                .name(node.name)
                .version(Some(node.version))
                .r#type(DependencyType::Library)
                .purl(node.purl)
                .dependencies(child_purls) // 👈 自动构建完整的传递依赖关系链路！
                .location(None)
                .build()
            {
                final_deps.push(dep);
            }
        }

        Ok(final_deps)
    }
}
