use crate::analyze::producers::dynamic_producer::DynamicProducer;
use crate::model::configuration::Configuration;
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyType};
use crate::utils::file_utils::make_instance_id;
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

        // 1. 推导 Monorepo 根工程的初始作用域盐
        let root_name = json
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("npm-workspace-root");
        let root_ver = json
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0");
        let root_scope = format!("pkg:npm/{}@{}", root_name, root_ver);

        let mut graph_map: HashMap<String, Dependency> = HashMap::new();

        if let Some(root_deps) = json.get("dependencies").and_then(|d| d.as_object()) {
            for (name, info) in root_deps {
                // 将 root_scope 作为初始盐向下传递
                Self::extract_graph_node(name, info, &root_scope, &mut graph_map);
            }
        }

        Ok(graph_map.into_values().collect())
    }
}

impl NpmDynamicProducer {
    /// 独立递归提取器：支持 Workspaces 领地切变与 Hoisting 自动融合
    fn extract_graph_node(
        name: &str,
        info: &serde_json::Value,
        current_scope: &str,
        graph_map: &mut HashMap<String, Dependency>,
    ) {
        let Some(version) = info.get("version").and_then(|v| v.as_str()) else {
            return;
        };
        let raw_purl = format!("pkg:npm/{}@{}", name, version);
        let valid_purl = Dependency::auto_fix_and_validate_purl(&raw_purl);

        // 1. 为当前包派生带“领地上下文”的身份证
        let instance_id = make_instance_id(&valid_purl, current_scope);

        // -------------------------------------------------------------
        // 🚀 【核心边界侦测】：判断当前节点是否为 Monorepo 内本地 Workspace 子工程
        // NPM v7+ 中，本地软链包带有 "link": true 或 "resolved": "file:..."
        // -------------------------------------------------------------
        let is_workspace_pkg = info.get("link").and_then(|l| l.as_bool()).unwrap_or(false)
            || info
                .get("resolved")
                .and_then(|r| r.as_str())
                .is_some_and(|r| r.starts_with("file:"));

        // 如果跨入了本地子工程，子工程内部第三方库的“领地盐”，切变为该子工程的 PURL
        let next_scope = if is_workspace_pkg {
            &valid_purl
        } else {
            current_scope
        };

        // 2. 深度解析直接子依赖的【instance_id】
        let mut child_instance_ids = vec![];
        if let Some(sub_deps) = info.get("dependencies").and_then(|d| d.as_object()) {
            for (sub_name, sub_info) in sub_deps {
                if let Some(sub_ver) = sub_info.get("version").and_then(|v| v.as_str()) {
                    let sub_raw_purl = format!("pkg:npm/{}@{}", sub_name, sub_ver);
                    let sub_valid_purl = Dependency::auto_fix_and_validate_purl(&sub_raw_purl);

                    // 【精髓】：子依赖严格使用切变后的 next_scope 派生 ID！
                    let child_id = make_instance_id(&sub_valid_purl, next_scope);
                    child_instance_ids.push(child_id);
                }
                // 带着 next_scope 继续往下递归
                Self::extract_graph_node(sub_name, sub_info, next_scope, graph_map);
            }
        }

        // 3. 注册进全局图谱（Key 与边严格设为 instance_id）
        graph_map
            .entry(instance_id.clone())
            .and_modify(|existing_dep| {
                // 应对 npm 的 "deduped": true 机制：
                // 若该包被 Hoisting 机制多处复用，优雅并入新发现的子依赖边
                for cid in &child_instance_ids {
                    if !existing_dep.dependencies.contains(cid) {
                        existing_dep.dependencies.push(cid.clone());
                    }
                }
            })
            .or_insert_with(|| {
                DependencyBuilder::default()
                    .name(name.to_string())
                    .version(Some(version.to_string()))
                    .r#type(DependencyType::Library)
                    .purl(valid_purl)
                    .instance_id(instance_id) // 👈 稳稳落盘
                    .dependencies(child_instance_ids) // 👈 注入的是 ID 列表
                    .location(None)
                    .build()
                    .unwrap()
            });
    }
}
