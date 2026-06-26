// src/analyze/producers/dynamic/cargo_dynamic.rs

use crate::analyze::producers::dynamic_producer::DynamicProducer;
use crate::model::configuration::Configuration;
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyType};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

#[derive(Default)]
pub struct CargoDynamicProducer {}

// 【核心：必须显式为 CargoDynamicProducer 实现 DynamicProducer】
impl DynamicProducer for CargoDynamicProducer {
    fn is_applicable(&self, configuration: &Configuration) -> bool {
        let mut path = PathBuf::from(&configuration.directory);
        path.push("Cargo.toml");
        path.exists()
    }

    // 检查此处的任何类型（如 anyhow::Result 是否带了泛型，Configuration 是否加了引用）
    fn detect_dependencies(
        &self,
        configuration: &Configuration,
    ) -> anyhow::Result<Vec<Dependency>> {
        let output = Command::new("cargo")
            .args(["metadata", "--format-version=1", "--all-features"])
            .current_dir(&configuration.directory)
            .output()?;

        if !output.status.success() {
            let stderr_str = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("Cargo metadata 执行失败: {}", stderr_str));
        }

        let stdout_str = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value = serde_json::from_str(&stdout_str)?;

        struct PkgMeta {
            name: String,
            version: String,
            purl: String,
        }

        let mut id_to_meta: HashMap<&str, PkgMeta> = HashMap::new();

        if let Some(packages) = json.get("packages").and_then(|p| p.as_array()) {
            for pkg in packages {
                if let (Some(id), Some(name), Some(version)) = (
                    pkg.get("id").and_then(|i| i.as_str()),
                    pkg.get("name").and_then(|n| n.as_str()),
                    pkg.get("version").and_then(|v| v.as_str()),
                ) {
                    id_to_meta.insert(
                        id,
                        PkgMeta {
                            name: name.to_string(),
                            version: version.to_string(),
                            purl: format!("pkg:cargo/{}@{}", name, version),
                        },
                    );
                }
            }
        }

        let mut id_to_child_purls: HashMap<&str, Vec<String>> = HashMap::new();

        if let Some(nodes) = json
            .get("resolve")
            .and_then(|r| r.get("nodes"))
            .and_then(|n| n.as_array())
        {
            for node in nodes {
                if let Some(parent_id) = node.get("id").and_then(|i| i.as_str()) {
                    let mut child_purls = vec![];

                    if let Some(child_ids) = node.get("dependencies").and_then(|d| d.as_array()) {
                        for cid_val in child_ids {
                            if let Some(cid) = cid_val.as_str() {
                                if let Some(child_meta) = id_to_meta.get(cid) {
                                    child_purls.push(child_meta.purl.clone());
                                }
                            }
                        }
                    }
                    id_to_child_purls.insert(parent_id, child_purls);
                }
            }
        }

        let mut final_deps = vec![];

        for (id, meta) in id_to_meta {
            let edges = id_to_child_purls.remove(id).unwrap_or_default();

            if let Ok(dep) = DependencyBuilder::default()
                .name(meta.name)
                .version(Some(meta.version))
                .r#type(DependencyType::Library)
                .purl(Dependency::auto_fix_and_validate_purl(&meta.purl))
                .dependencies(edges)
                .location(None)
                .build()
            {
                final_deps.push(dep);
            }
        }

        Ok(final_deps)
    }
}
