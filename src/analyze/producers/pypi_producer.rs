use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyType};
use lazy_static::lazy_static;
use regex::Regex;
use std::path::{Path, PathBuf};

lazy_static! {
    // 工业级全能正则：
    // 分组1: 包名 (合法首字符 + 中间允许字母数字及 - _ .)
    // 分组2: 可选的 Extra [security,socks] (直接剥离)
    // 分组3: 可选的操作符 (==|>=|<=|~=|!=|>|<)
    // 分组4: 可选的版本号文字
    static ref PYPI_LINE_RE: Regex = Regex::new(
        r"(?i)^([A-Z0-9][A-Z0-9_\-\.]*)(?:\[[^\]]+\])?(?:\s*(==|>=|<=|~=|!=|>|<)\s*([A-Z0-9\.\-\*]+))?"
    ).unwrap();

    // PEP 503 规范化清洗正则：将连续的 _ . - 统一压扁为单减号 -
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
            let Ok(content) = std::fs::read_to_string(p) else {
                continue;
            };

            for line in content.lines() {
                // 1. 干净利落的行尾剥离 (顺序极度重要：先砍掉#注释，再砍掉;环境变量标记)
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

                // 【安全防线一】：拦截 pip 本地路径、远程URL、命令行传参（如 -r base.txt, --index-url）
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

                    // 【安全防线二】：PEP 503 规范化转译 ( PURL 官方铁律 )
                    // "My_Custom-Pkg.ext" -> "my-custom-pkg-ext"
                    let normalized_name = PEP503_NORM_RE
                        .replace_all(&raw_name.to_lowercase(), "-")
                        .to_string();

                    let ver_opt = raw_ver.map(|v| v.to_string());

                    // 生成标准的机读 PURL（若写了通配符1.2.*或没写版本，转为无版本号PURL）
                    let purl_str = match ver_opt {
                        Some(ref v) if !v.contains('*') => {
                            format!("pkg:pypi/{}@{}", normalized_name, v)
                        }
                        _ => format!("pkg:pypi/{}", normalized_name),
                    };

                    result.push(
                        DependencyBuilder::default()
                            .name(raw_name.to_string()) // 👈 存入原始名字，供人类在 UI 上阅读，且保绿你的单测
                            .version(ver_opt)
                            .r#type(DependencyType::Library)
                            .purl(purl_str) // 👈 存入洗练后的机读 PURL，供安全工具撞库
                            .location(None)
                            .build()
                            .unwrap(),
                    );
                }
            }
        }
        Ok(result)
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

    // 验证兼容性匹配符号 ~= 被解析
    assert!(deps
        .iter()
        .any(|d| d.name == "Django" && d.version.as_deref() == Some("4.2.1")));

    // 验证不等于匹配符号 != 和空格容错
    assert!(deps
        .iter()
        .any(|d| d.name == "numpy" && d.version.as_deref() == Some("1.24.0")));

    // 验证带有特殊字符(_, -, .)的包名和 alpha 版本号
    assert!(deps
        .iter()
        .any(|d| d.name == "my_custom-pkg.ext" && d.version.as_deref() == Some("1.0.0-alpha1")));

    // 期望总数: 7(原有) + 3(新增) = 10
    assert_eq!(
        deps.len(),
        10,
        "Expected 10 dependencies, found {}",
        deps.len()
    );
}
