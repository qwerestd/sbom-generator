// src/analyze/producers/npm_producer.rs

use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyType};
use std::path::{Path, PathBuf};

#[derive(Clone, Default)]
pub struct NpmProducer {}

/// NPM SemVer 范围清洗器
/// 将 "^18.0.0" -> "18.0.0", "~2.3.2" -> "2.3.2"
/// 严格遵守《Package URL (PURL) Specification v1.0》铁律
fn sanitize_semver_range(raw: &str) -> &str {
    let s = raw.trim();
    // 剥离 JS 生态常见的范围前缀符号
    let cleaned = s.trim_start_matches(['^', '~', '>', '<', '=', ' ']);

    // 如果用户写的是 "*" 或 "x"，清洗后交由无版本逻辑处理
    if cleaned == "*" || cleaned.eq_ignore_ascii_case("x") {
        ""
    } else {
        cleaned
    }
}

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
                // 去除 Windows PowerShell 生成的不可见 BOM 头 (`\u{FEFF}`)
                let clean_content = content.trim_start_matches('\u{FEFF}').trim();

                match serde_json::from_str::<serde_json::Value>(clean_content) {
                    Ok(json) => {
                        for category in dep_categories {
                            if let Some(deps) = json.get(category).and_then(|d| d.as_object()) {
                                for (name, version) in deps {
                                    let raw_ver_str = version.as_str().unwrap_or("").trim();
                                    if raw_ver_str.starts_with("file:")
                                        || raw_ver_str.starts_with("git+")
                                    {
                                        continue;
                                    }

                                    // 【核心合规动作】：清洗掉非法前缀范围符号
                                    let clean_ver = sanitize_semver_range(raw_ver_str);

                                    let (ver_opt, purl_str) = if clean_ver.is_empty() {
                                        (None, format!("pkg:npm/{}", name))
                                    } else {
                                        (
                                            Some(clean_ver.to_string()),
                                            format!("pkg:npm/{}@{}", name, clean_ver),
                                        )
                                    };

                                    result.push(
                                        DependencyBuilder::default()
                                            .name(name.clone())
                                            .version(ver_opt)
                                            .r#type(DependencyType::Library)
                                            .purl(Dependency::auto_fix_and_validate_purl(
                                                purl_str.as_str(),
                                            ))
                                            .location(None)
                                            .build()
                                            .unwrap(),
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        // 标准规范：CLI日志打印用 eprintln! 避免污染标准输出管道
                        eprintln!("❌ [Debug] 无法解析 JSON 文件 {:?}，错误原因: {}", p, e);
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

    // 验证 peerDependencies 被合规清洗并提取 ( ^18.0.0 -> 18.0.0 )
    assert!(deps
        .iter()
        .any(|d| d.name == "react" && d.version.as_deref() == Some("18.0.0")));

    // 验证 optionalDependencies 被合规清洗并提取 ( ~2.3.2 -> 2.3.2 )
    assert!(deps
        .iter()
        .any(|d| d.name == "fsevents" && d.version.as_deref() == Some("2.3.2")));

    // 验证 git+ 协议前缀的依赖被正确跳过
    assert!(!deps.iter().any(|d| d.name == "git-dep"));

    // 期望总数: 3(原有) + 2(新增 react, fsevents) = 5
    assert_eq!(
        deps.len(),
        5,
        "Expected 5 dependencies, found {}",
        deps.len()
    );
}
