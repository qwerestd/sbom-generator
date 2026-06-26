use crate::analyze::producers::dynamic_producer::DynamicProducer;
use crate::model::configuration::Configuration;
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyType};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

#[derive(Default)]
pub struct NpmDynamicProducer {}

impl DynamicProducer for NpmDynamicProducer {
    fn is_applicable(&self, config: &Configuration) -> bool {
        let mut path = PathBuf::from(&config.directory);
        path.push("package.json");
        let mut node_modules = PathBuf::from(&config.directory);
        node_modules.push("node_modules");

        path.exists() && node_modules.exists()
    }

    fn detect_dependencies(&self, config: &Configuration) -> anyhow::Result<Vec<Dependency>> {
        let npm_cmd = if cfg!(target_os = "windows") {
            "npm.cmd"
        } else {
            "npm"
        };

        let output = Command::new(npm_cmd)
            .args(["ls", "--json", "--all"])
            .current_dir(&config.directory)
            .output()?;

        let stdout_str = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value = serde_json::from_str(&stdout_str)?;

        // 使用全局 Map 承载，天然去重 + 拓扑边融合
        let mut graph_map: HashMap<String, Dependency> = HashMap::new();

        if let Some(root_deps) = json.get("dependencies").and_then(|d| d.as_object()) {
            for (name, info) in root_deps {
                Self::extract_graph_node(name, info, &mut graph_map);
            }
        }

        Ok(graph_map.into_values().collect())
    }
}

impl NpmDynamicProducer {
    /// 独立递归提取器：还原上下级 DAG 连接关系
    fn extract_graph_node(
        name: &str,
        info: &serde_json::Value,
        graph_map: &mut HashMap<String, Dependency>,
    ) {
        let Some(version) = info.get("version").and_then(|v| v.as_str()) else {
            return;
        };
        let purl = format!("pkg:npm/{}@{}", name, version);

        // 1. 深度搜寻当前节点“亲生的”直接子依赖 PURL
        let mut child_purls = vec![];
        if let Some(sub_deps) = info.get("dependencies").and_then(|d| d.as_object()) {
            for (sub_name, sub_info) in sub_deps {
                if let Some(sub_ver) = sub_info.get("version").and_then(|v| v.as_str()) {
                    child_purls.push(format!("pkg:npm/{}@{}", sub_name, sub_ver));
                }
                // 递归向下挖掘
                Self::extract_graph_node(sub_name, sub_info, graph_map);
            }
        }

        // 2. 注册进全局图谱（若存在多路共同依赖，边集合求并集）
        graph_map
            .entry(purl.clone())
            .and_modify(|existing_dep| {
                for cp in &child_purls {
                    if !existing_dep.dependencies.contains(cp) {
                        existing_dep.dependencies.push(cp.clone());
                    }
                }
            })
            .or_insert_with(|| {
                DependencyBuilder::default()
                    .name(name.to_string())
                    .version(Some(version.to_string()))
                    .r#type(DependencyType::Library)
                    .purl(Dependency::auto_fix_and_validate_purl(purl.as_str()))
                    .dependencies(child_purls) // 【核心修复：拓扑边血脉注入】
                    .location(None)
                    .build()
                    .unwrap()
            });
    }
}
