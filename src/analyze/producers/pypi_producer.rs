use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyType};
use lazy_static::lazy_static;
use regex::Regex;
use std::path::{Path, PathBuf};

lazy_static! {
    // 匹配如 "requests[security] == 2.25.1" 或 "urllib3>=1.21.1"
    // 忽略大小写，分组1为包名，分组2为操作符，分组3为版本号
    static ref PYPI_REGEX: Regex = Regex::new(r"(?i)^([A-Z0-9_\-\.]+)(?:\[.*\])?\s*(==|>=|<=|~=|!=)\s*([A-Z0-9\.\-\*]+)").unwrap();
}

#[derive(Clone, Default)]
pub struct PypiProducer {}

impl SbomProducer for PypiProducer {
    fn use_file(&self, path: &Path, _config: &SbomProducerConfiguration) -> bool {
        path.file_name()
            .is_some_and(|n| n.eq_ignore_ascii_case("requirements.txt"))
    }

    fn find_dependencies(
        &self,
        paths: &[PathBuf],
        _config: &SbomProducerConfiguration,
    ) -> anyhow::Result<Vec<Dependency>> {
        let mut result = vec![];
        for p in paths {
            if let Ok(content) = std::fs::read_to_string(p) {
                for line in content.lines() {
                    // 1. 去除尾部的行内环境标记 (分号后面部分) 和 注释 (井号后面部分)
                    let clean_line = line
                        .split('#')
                        .next()
                        .unwrap_or("")
                        .split(';')
                        .next()
                        .unwrap_or("")
                        .trim();

                    if clean_line.is_empty() {
                        continue;
                    }

                    // 2. 正则匹配并提取
                    if let Some(caps) = PYPI_REGEX.captures(clean_line) {
                        let name = caps.get(1).unwrap().as_str().to_string();
                        let version = caps.get(3).unwrap().as_str().to_string();

                        result.push(
                            DependencyBuilder::default()
                                .name(name.clone())
                                .version(Some(version.clone()))
                                .r#type(DependencyType::Library)
                                .purl(format!("pkg:pypi/{}@{}", name, version))
                                .location(None)
                                .build()
                                .unwrap(),
                        );
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
    fn test_pypi_producer_find_dependencies() {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("resources/py/requirements.txt");

        let producer = PypiProducer::default();
        let config = SbomProducerConfiguration {
            use_debug: false,
            base_path: d.parent().unwrap().to_path_buf(),
        };

        let deps = producer
            .find_dependencies(&[d], &config)
            .expect("Failed to parse requirements.txt");

        // resources/py/requirements.txt 中一共包含 7 个有效的包：
        // requests, urllib3, Flask, fastapi, colorama, aiohttp, pytest
        assert_eq!(
            deps.len(),
            7,
            "Expected 7 dependencies, found {}",
            deps.len()
        );

        // 测试简单包
        assert!(deps
            .iter()
            .any(|d| d.name == "requests" && d.version.as_deref() == Some("2.31.0")));
        assert!(deps
            .iter()
            .any(|d| d.name == "urllib3" && d.version.as_deref() == Some("1.26.16")));

        // 测试带 Extras 的包 (Flask[async] 和 fastapi[all])
        assert!(deps
            .iter()
            .any(|d| d.name == "Flask" && d.version.as_deref() == Some("2.3.2")));
        assert!(deps
            .iter()
            .any(|d| d.name == "fastapi" && d.version.as_deref() == Some("0.100.0")));

        // 测试带有环境标记的复杂行 (colorama 和 aiohttp)
        assert!(deps
            .iter()
            .any(|d| d.name == "colorama" && d.version.as_deref() == Some("0.4.6")));
        assert!(deps
            .iter()
            .any(|d| d.name == "aiohttp" && d.version.as_deref() == Some("3.8.4")));

        // 测试带有行内注释的包 (pytest)
        assert!(deps
            .iter()
            .any(|d| d.name == "pytest" && d.version.as_deref() == Some("7.4.0")));
    }
}
