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
#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::producers::producer::SbomProducerConfiguration;
    use std::path::PathBuf;

    #[test]
    fn test_cargo_producer_find_dependencies() {
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

        // resources/cargo/Cargo.toml 中的 dependencies 和 dev-dependencies 包含：
        // regex, rand, serde, tokio, criterion
        // (注：libc 在 [target.'cfg(unix)'.dependencies] 中，你的代码目前跳过它，这是符合预期的)
        assert_eq!(
            deps.len(),
            5,
            "Expected 5 dependencies, found {}",
            deps.len()
        );

        // 验证普通格式
        assert!(deps
            .iter()
            .any(|d| d.name == "regex" && d.version.as_deref() == Some("1.10.0")));
        assert!(deps
            .iter()
            .any(|d| d.name == "rand" && d.version.as_deref() == Some("0.8.5")));

        // 验证内联表/对象格式 (带有 features 的)
        assert!(deps
            .iter()
            .any(|d| d.name == "serde" && d.version.as_deref() == Some("1.0.190")));
        assert!(deps
            .iter()
            .any(|d| d.name == "tokio" && d.version.as_deref() == Some("1.33.0")));

        // 验证 dev-dependencies 能被正确提取
        assert!(deps
            .iter()
            .any(|d| d.name == "criterion" && d.version.as_deref() == Some("0.5.1")));
    }
}
