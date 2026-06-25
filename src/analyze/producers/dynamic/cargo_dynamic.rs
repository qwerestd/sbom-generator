use crate::analyze::producers::dynamic_producer::DynamicProducer;
use crate::model::configuration::Configuration;
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyType};
use std::path::PathBuf;
use std::process::Command;
#[derive(Default)]
pub struct CargoDynamicProducer {}
impl DynamicProducer for CargoDynamicProducer {
    fn is_applicable(&self, configuration: &Configuration) -> bool {
        let mut path = PathBuf::from(&configuration.directory);
        path.push("Cargo.toml");
        path.exists()
    }

    fn detect_dependencies(
        &self,
        configuration: &Configuration,
    ) -> anyhow::Result<Vec<Dependency>> {
        // 调用 cargo metadata 获取精确的解析后依赖树
        let output = Command::new("cargo")
            .arg("metadata")
            .arg("--format-version=1")
            .arg("--all-features")
            .current_dir(&configuration.directory)
            .output()?;

        let mut deps = vec![];

        if output.status.success() {
            let stdout_str = String::from_utf8_lossy(&output.stdout);

            // 解析 cargo metadata 输出的 JSON
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout_str) {
                // metadata.packages 包含了所有被解析到的依赖包（包含自身和传递依赖）
                if let Some(packages) = json.get("packages").and_then(|p| p.as_array()) {
                    for pkg in packages {
                        if let (Some(name), Some(version)) = (
                            pkg.get("name").and_then(|n| n.as_str()),
                            pkg.get("version").and_then(|v| v.as_str()),
                        ) {
                            if let Ok(dep) = DependencyBuilder::default()
                                .name(name.to_string())
                                .version(Some(version.to_string()))
                                .r#type(DependencyType::Library)
                                .purl(format!("pkg:cargo/{}@{}", name, version))
                                .location(None) // 动态获取的通常不绑定具体代码行
                                .build()
                            {
                                deps.push(dep);
                            }
                        }
                    }
                }
            }
        } else {
            let stderr_str = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("Cargo 命令执行失败: {}", stderr_str));
        }

        Ok(deps)
    }
}
