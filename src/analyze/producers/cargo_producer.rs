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
