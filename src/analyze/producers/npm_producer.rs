use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyType};
use std::path::{Path, PathBuf};

#[derive(Clone, Default)]
pub struct NpmProducer {}

impl SbomProducer for NpmProducer {
    fn use_file(&self, path: &Path, _config: &SbomProducerConfiguration) -> bool {
        path.file_name()
            .is_some_and(|n| n.eq_ignore_ascii_case("package.json"))
    }

    fn find_dependencies(
        &self,
        paths: &[PathBuf],
        _config: &SbomProducerConfiguration,
    ) -> anyhow::Result<Vec<Dependency>> {
        let mut result = vec![];
        let dep_categories = [
            "dependencies",
            "devDependencies",
            "peerDependencies",
            "optionalDependencies",
        ];

        for p in paths {
            if let Ok(content) = std::fs::read_to_string(p) {
                // 【核心修复】去除 Windows PowerShell 生成的不可见 BOM 头 (`\u{FEFF}`)
                let clean_content = content.trim_start_matches('\u{FEFF}').trim();

                // 将 if let Ok 换成 match，暴露出具体的错误原因
                match serde_json::from_str::<serde_json::Value>(clean_content) {
                    Ok(json) => {
                        for category in dep_categories {
                            if let Some(deps) = json.get(category).and_then(|d| d.as_object()) {
                                for (name, version) in deps {
                                    let version_str = version.as_str().unwrap_or("").trim();
                                    if version_str.starts_with("file:")
                                        || version_str.starts_with("git+")
                                    {
                                        continue;
                                    }
                                    result.push(
                                        DependencyBuilder::default()
                                            .name(name.clone())
                                            .version(Some(version_str.to_string()))
                                            .r#type(DependencyType::Library)
                                            .purl(format!("pkg:npm/{}@{}", name, version_str))
                                            .location(None)
                                            .build()
                                            .unwrap(),
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        // 如果再次遇到格式问题，终端会明确告诉你第几行第几列出错了
                        println!("❌ [Debug] 无法解析 JSON 文件 {:?}，错误原因: {}", p, e);
                    }
                }
            }
        }
        Ok(result)
    }
}
#[test]
fn test_npm_producer_find_dependencies_extended() {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("resources/npm/package.json");

    let producer = NpmProducer::default();
    let config = SbomProducerConfiguration {
        use_debug: false,
        base_path: d.parent().unwrap().to_path_buf(),
    };

    let deps = producer
        .find_dependencies(&[d], &config)
        .expect("Failed to parse package.json");

    // 验证 peerDependencies 被提取
    assert!(deps
        .iter()
        .any(|d| d.name == "react" && d.version.as_deref() == Some("^18.0.0")));

    // 验证 optionalDependencies 被提取
    assert!(deps
        .iter()
        .any(|d| d.name == "fsevents" && d.version.as_deref() == Some("~2.3.2")));

    // 验证 git+ 协议前缀的依赖被正确跳过（类似于 file: 协议）
    assert!(!deps.iter().any(|d| d.name == "git-dep"));

    // 期望总数: 3(原有) + 2(新增 react, fsevents) = 5
    assert_eq!(
        deps.len(),
        5,
        "Expected 5 dependencies, found {}",
        deps.len()
    );
}
