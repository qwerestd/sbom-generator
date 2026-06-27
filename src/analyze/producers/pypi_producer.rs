use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyType};
use crate::utils::file_utils::make_instance_id;
use lazy_static::lazy_static;
use regex::Regex;
use std::path::{Path, PathBuf};

lazy_static! {
    static ref PYPI_LINE_RE: Regex = Regex::new(
        r"(?i)^([A-Z0-9][A-Z0-9_\-\.]*)(?:\[[^\]]+\])?(?:\s*(==|>=|<=|~=|!=|>|<)\s*([A-Z0-9\.\-\*]+))?"
    ).unwrap();

    static ref PEP503_NORM_RE: Regex = Regex::new(r"[-_.]+").unwrap();
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
                // 【核心修复 1】：获取当前 requirements.txt 的物理路径作为作用域盐
                let file_salt = p.to_string_lossy().replace('\\', "/");

                if let Ok(file_deps) = Self::parse_single_requirements(&content, &file_salt, p) {
                    result.extend(file_deps);
                }
            }
        }
        Ok(result)
    }
}

impl PypiProducer {
    /// 独立接管单个 requirements.txt 的 DAG 编织
    fn parse_single_requirements(
        content: &str,
        file_salt: &str,
        file_path: &Path,
    ) -> anyhow::Result<Vec<Dependency>> {
        // 1. 推导当前 Python 工程自身的根节点名字
        // requirements.txt 没有 JSON 那种 name 字段，保底使用它所在的文件夹名称
        let app_name = file_path
            .parent()
            .and_then(|dir| dir.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("python-app")
            .to_string();

        let norm_app_name = PEP503_NORM_RE
            .replace_all(&app_name.to_lowercase(), "-")
            .to_string();

        // 虚拟出项目自身的根 PURL (例如: pkg:pypi/my-py-app@0.0.0)
        let root_purl = format!("pkg:pypi/{}@0.0.0", norm_app_name);
        let root_instance_id = make_instance_id(&root_purl, file_salt);

        let mut leaf_deps = vec![];
        let mut child_ids = vec![];

        for line in content.lines() {
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

            if clean_line.starts_with('-')
                || clean_line.starts_with('.')
                || clean_line.starts_with('/')
                || clean_line.contains("://")
            {
                continue;
            }

            if let Some(caps) = PYPI_LINE_RE.captures(clean_line) {
                let raw_name = caps.get(1).unwrap().as_str();
                let raw_ver = caps.get(3).map(|m| m.as_str());

                let normalized_name = PEP503_NORM_RE
                    .replace_all(&raw_name.to_lowercase(), "-")
                    .to_string();

                let ver_opt = raw_ver.map(|v| v.to_string());

                let purl_str = match ver_opt {
                    Some(ref v) if !v.contains('*') => {
                        format!("pkg:pypi/{}@{}", normalized_name, v)
                    }
                    _ => format!("pkg:pypi/{}", normalized_name),
                };

                let valid_purl = Dependency::auto_fix_and_validate_purl(&purl_str);

                // 【精髓 A】：叶子包拿自身PURL + 当前requirements路径派生ID
                let child_id = make_instance_id(&valid_purl, file_salt);
                child_ids.push(child_id.clone());

                // 【精髓 B】：接生叶子实体
                leaf_deps.push(
                    DependencyBuilder::default()
                        .name(raw_name.to_string())
                        .version(ver_opt)
                        .r#type(DependencyType::Library)
                        .purl(valid_purl)
                        .instance_id(child_id) // 👈 自身ID显式入库
                        .dependencies(vec![]) // 👈 叶子没有后代
                        .location(None)
                        .build()
                        .unwrap(),
                );
            }
        }

        // 防御动作：如果这个 txt 文件里一行第三方包都没有，直接返回空
        if leaf_deps.is_empty() {
            return Ok(vec![]);
        }

        // 2. 接生工程根节点自身（把清单和10个包连上血脉）
        let root_dep = DependencyBuilder::default()
            .name(app_name)
            .version(Some("0.0.0".to_string()))
            .r#type(DependencyType::Library) // 后续方向四可优化为 Application
            .purl(root_purl)
            .instance_id(root_instance_id)
            .dependencies(child_ids) // 👈 根节点的 dependsOn 指向下方所有叶子包
            .location(None)
            .build()
            .unwrap();

        let mut all_deps = Vec::with_capacity(leaf_deps.len() + 1);
        all_deps.push(root_dep); // 根排头
        all_deps.extend(leaf_deps);

        Ok(all_deps)
    }
}

#[test]
fn test_pypi_producer_find_dependencies_extended() {
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

    assert!(deps
        .iter()
        .any(|d| d.name == "Django" && d.version.as_deref() == Some("4.2.1")));

    assert!(deps
        .iter()
        .any(|d| d.name == "numpy" && d.version.as_deref() == Some("1.24.0")));

    assert!(deps
        .iter()
        .any(|d| d.name == "my_custom-pkg.ext" && d.version.as_deref() == Some("1.0.0-alpha1")));

    // 🚨 【核心修改】：总数由 10 变更为 11！
    // 10(原有解析出的第三方包) + 1(本txt文件代表的项目根节点本身) = 11
    assert_eq!(
        deps.len(),
        11,
        "Expected 11 dependencies, found {}",
        deps.len()
    );
}
