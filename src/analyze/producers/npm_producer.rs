// src/analyze/producers/npm_producer.rs

use std::path::{Path, PathBuf};

use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyType};
use crate::utils::file_utils::make_instance_id;

#[derive(Clone, Default)]
pub struct NpmProducer {}

/// NPM SemVer 范围清洗器
fn sanitize_semver_range(raw: &str) -> &str {
    let s = raw.trim();
    let cleaned = s.trim_start_matches(['^', '~', '>', '<', '=', ' ']);

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

        for p in paths {
            if let Ok(content) = std::fs::read_to_string(p) {
                let clean_content = content.trim_start_matches('\u{FEFF}').trim();

                // 【核心修复 1】：获取当前 package.json 的物理路径作为作用域盐
                let file_salt = p.to_string_lossy().replace('\\', "/");

                match serde_json::from_str::<serde_json::Value>(clean_content) {
                    Ok(json) => {
                        if let Ok(file_deps) = Self::parse_single_package_json(&json, &file_salt, p)
                        {
                            result.extend(file_deps);
                        }
                    }
                    Err(e) => {
                        eprintln!("❌ [Debug] 无法解析 JSON 文件 {:?}，错误原因: {}", p, e);
                    }
                }
            }
        }
        Ok(result)
    }
}

impl NpmProducer {
    /// 独立接管单个 package.json 的 DAG 编织
    fn parse_single_package_json(
        json: &serde_json::Value,
        file_salt: &str,
        file_path: &Path,
    ) -> anyhow::Result<Vec<Dependency>> {
        // 1. 提取当前前端工程的主体元数据（亲生父母 Node）
        let app_name = json
            .get("name")
            .and_then(|n| n.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                // 如果用户没写 name，保底使用它所在的文件夹名称
                file_path
                    .parent()
                    .and_then(|dir| dir.file_name())
                    .and_then(|n| n.to_str())
                    .unwrap_or("unnamed-js-app")
                    .to_string()
            });

        let app_ver = json
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0");
        let app_purl = format!("pkg:npm/{}@{}", app_name, app_ver);
        let app_instance_id = make_instance_id(&app_purl, file_salt);

        let dep_categories = [
            "dependencies",
            "devDependencies",
            "peerDependencies",
            "optionalDependencies",
        ];

        let mut child_ids = Vec::new();
        let mut leaf_deps = Vec::new();

        for category in dep_categories {
            if let Some(deps) = json.get(category).and_then(|d| d.as_object()) {
                for (name, version) in deps {
                    let raw_ver_str = version.as_str().unwrap_or("").trim();
                    if raw_ver_str.starts_with("file:") || raw_ver_str.starts_with("git+") {
                        continue;
                    }

                    let clean_ver = sanitize_semver_range(raw_ver_str);
                    let (ver_opt, purl_str) = if clean_ver.is_empty() {
                        (None, format!("pkg:npm/{}", name))
                    } else {
                        (
                            Some(clean_ver.to_string()),
                            format!("pkg:npm/{}@{}", name, clean_ver),
                        )
                    };

                    let valid_purl = Dependency::auto_fix_and_validate_purl(&purl_str);

                    // 【精髓 A】：子依赖严格使用该 package.json 的路径派生身份证！
                    let child_id = make_instance_id(&valid_purl, file_salt);
                    child_ids.push(child_id.clone());

                    // 【精髓 B】：接生叶子节点实体（CycloneDX1.6要求被牵引的子边自身也必须注册为空边）
                    let leaf = DependencyBuilder::default()
                        .name(name.clone())
                        .version(ver_opt)
                        .r#type(DependencyType::Library)
                        .purl(valid_purl)
                        .instance_id(child_id) // 👈 自身ID显式入库
                        .dependencies(vec![]) // 👈 叶子节点没有后代
                        .location(None)
                        .build()
                        .unwrap();

                    leaf_deps.push(leaf);
                }
            }
        }

        // 2. 构建工程主体 Node（把亲生父母和孩子连上血脉线）
        let root_dep = DependencyBuilder::default()
            .name(app_name)
            .version(Some(app_ver.to_string()))
            .r#type(DependencyType::Library) // 后续方向四可优化为 Application
            .purl(app_purl)
            .instance_id(app_instance_id)
            .dependencies(child_ids) // 👈 亲生父母的 dependsOn 指向所有叶子节点ID
            .location(None)
            .build()
            .unwrap();

        let mut all_deps = Vec::with_capacity(leaf_deps.len() + 1);
        all_deps.push(root_dep); // 根节点排头
        all_deps.extend(leaf_deps);

        Ok(all_deps)
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
        6,
        "Expected 6 dependencies, found {}",
        deps.len()
    );
}
