use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyType};
use std::path::{Path, PathBuf};

#[derive(Clone, Default)]
pub struct CargoProducer {}

impl SbomProducer for CargoProducer {
    fn use_file(&self, path: &Path, _config: &SbomProducerConfiguration) -> bool {
        path.file_name()
            .is_some_and(|n| n.eq_ignore_ascii_case("Cargo.toml"))
    }

    fn find_dependencies(
        &self,
        paths: &[PathBuf],
        _config: &SbomProducerConfiguration,
    ) -> anyhow::Result<Vec<Dependency>> {
        let mut result = vec![];
        let categories = ["dependencies", "dev-dependencies", "build-dependencies"];

        for p in paths {
            if let Ok(content) = std::fs::read_to_string(p) {
                if let Ok(toml_value) = content.parse::<toml::Value>() {
                    for category in categories {
                        if let Some(deps) = toml_value.get(category).and_then(|v| v.as_table()) {
                            for (name, val) in deps {
                                let version = if let Some(v_str) = val.as_str() {
                                    // 格式: package = "1.0"
                                    Some(v_str.to_string())
                                } else if let Some(v_obj) = val.as_table() {
                                    // 格式: package = { version = "1.0" }
                                    v_obj
                                        .get("version")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string())
                                } else {
                                    None
                                };

                                if let Some(ver) = version {
                                    result.push(
                                        DependencyBuilder::default()
                                            .name(name.clone())
                                            .version(Some(ver.clone()))
                                            .r#type(DependencyType::Library)
                                            .purl(format!("pkg:cargo/{}@{}", name, ver))
                                            .location(None)
                                            .build()
                                            .unwrap(),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(result)
    }
}
#[test]
fn test_cargo_producer_find_dependencies_extended() {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("resources/cargo/Cargo.toml");

    let producer = CargoProducer::default();
    let config = SbomProducerConfiguration {
        use_debug: false,
        base_path: d.parent().unwrap().to_path_buf(),
    };

    let deps = producer
        .find_dependencies(&[d], &config)
        .expect("Failed to parse Cargo.toml");

    // 验证构建依赖 (build-dependencies) 是否被正确解析
    assert!(deps
        .iter()
        .any(|d| d.name == "cc" && d.version.as_deref() == Some("1.0.79")));
    assert!(deps
        .iter()
        .any(|d| d.name == "pkg-config" && d.version.as_deref() == Some("0.3.27")));

    // 验证缺少 version 字段的依赖（例如 workspace = true）被安全忽略
    assert!(!deps.iter().any(|d| d.name == "my-workspace-lib"));

    // 确保总数符合预期（原有的 5 个 + 新增的 2 个有效的 = 7）
    assert_eq!(
        deps.len(),
        7,
        "Expected 7 dependencies, found {}",
        deps.len()
    );
}
