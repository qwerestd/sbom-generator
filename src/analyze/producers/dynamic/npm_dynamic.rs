use crate::analyze::producers::dynamic_producer::DynamicProducer;
use crate::model::configuration::Configuration;
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyType};
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

        // 仅当存在 package.json 且已经安装了 node_modules 时才执行动态检测
        path.exists() && node_modules.exists()
    }

    fn detect_dependencies(&self, config: &Configuration) -> anyhow::Result<Vec<Dependency>> {
        // 为了兼容 Windows 和 Unix，选择正确的 npm 命令名
        let npm_cmd = if cfg!(target_os = "windows") {
            "npm.cmd"
        } else {
            "npm"
        };

        let output = Command::new(npm_cmd)
            .arg("ls")
            .arg("--json")
            .arg("--all")
            .current_dir(&config.directory)
            .output()?;

        let mut deps = vec![];
        let stdout_str = String::from_utf8_lossy(&output.stdout);

        // 解析 npm ls --json 的输出
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout_str) {
            // 递归提取嵌套依赖树
            fn extract_deps(node: &serde_json::Value, deps: &mut Vec<Dependency>) {
                if let Some(dependencies) = node.get("dependencies").and_then(|d| d.as_object()) {
                    for (name, info) in dependencies {
                        if let Some(version) = info.get("version").and_then(|v| v.as_str()) {
                            if let Ok(dep) = DependencyBuilder::default()
                                .name(name.clone())
                                .version(Some(version.to_string()))
                                .r#type(DependencyType::Library)
                                .purl(format!("pkg:npm/{}@{}", name, version))
                                .location(None)
                                .build()
                            {
                                deps.push(dep);
                            }
                        }
                        // 递归解析子依赖
                        extract_deps(info, deps);
                    }
                }
            }
            extract_deps(&json, &mut deps);
        }

        Ok(deps)
    }
}
