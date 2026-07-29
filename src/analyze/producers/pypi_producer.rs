use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::analyze::producers::python::discovery::discover_python_projects;
use crate::analyze::producers::python::merge::{resolve_python_project, to_existing_dependencies};
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyType};
use crate::utils::file_utils::{get_manifest_rel_path, make_instance_id};
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
        let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
            return false;
        };

        matches!(
            file_name,
            "uv.lock"
                | "pyproject.toml"
                | "requirements.txt"
                | "poetry.lock"
                | "Pipfile.lock"
                | "setup.py"
                | "setup.cfg"
                | "conda-lock.yml"
                | "conda-lock.yaml"
        ) || (file_name.starts_with("requirements-") && file_name.ends_with(".txt"))
            || path
                .parent()
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str())
                .is_some_and(|dir| dir == "requirements" && file_name.ends_with(".txt"))
    }

    fn find_dependencies(
        &self,
        paths: &[PathBuf],
        config: &SbomProducerConfiguration,
    ) -> anyhow::Result<Vec<Dependency>> {
        let projects = discover_python_projects(paths);
        if !projects.is_empty() {
            let mut result = Vec::new();
            for project in projects {
                let resolved = resolve_python_project(&project);
                for warning in &resolved.warnings {
                    eprintln!("[Python] {}", warning);
                }
                result.extend(to_existing_dependencies(&resolved, &config.base_path));
            }
            return Ok(result);
        }

        let mut result = vec![];

        for p in paths {
            if let Ok(content) = std::fs::read_to_string(p) {
                // 【核心修复 1】：获取当前 requirements.txt 的物理路径作为作用域盐
                let file_salt = get_manifest_rel_path(&config.base_path, p);

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
                let raw_op = caps.get(2).map(|m| m.as_str());
                let raw_ver = caps.get(3).map(|m| m.as_str());

                let normalized_name = PEP503_NORM_RE
                    .replace_all(&raw_name.to_lowercase(), "-")
                    .to_string();

                let declared_version = raw_ver.map(|v| match raw_op {
                    Some(op) => format!("{}{}", op, v),
                    None => v.to_string(),
                });
                let ver_opt = match (raw_op, raw_ver) {
                    (Some("=="), Some(v)) if !v.contains('*') => Some(v.to_string()),
                    (None, Some(v)) if !v.contains('*') => Some(v.to_string()),
                    _ => None,
                };

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
                if let Ok(dep) = DependencyBuilder::default()
                    .name(raw_name.to_string())
                    .version(ver_opt)
                    .declared_version(declared_version)
                    .r#type(DependencyType::Library)
                    .purl(valid_purl)
                    .instance_id(child_id) // 👈 自身ID显式入库
                    .dependencies(vec![]) // 👈 叶子没有后代
                    .location(None)
                    .build()
                {
                    leaf_deps.push(dep);
                }
            }
        }

        // 防御动作：如果这个 txt 文件里一行第三方包都没有，直接返回空
        if leaf_deps.is_empty() {
            return Ok(vec![]);
        }

        // 2. 接生工程根节点自身（把清单和10个包连上血脉）
        let Ok(root_dep) = DependencyBuilder::default()
            .name(app_name)
            .version(Some("0.0.0".to_string()))
            .declared_version(Some("0.0.0".to_string()))
            .r#type(DependencyType::Library) // 后续方向四可优化为 Application
            .purl(root_purl)
            .instance_id(root_instance_id)
            .dependencies(child_ids) // 👈 根节点的 dependsOn 指向下方所有叶子包
            .location(None)
            .build()
        else {
            return Ok(leaf_deps);
        };

        let mut all_deps = Vec::with_capacity(leaf_deps.len() + 1);
        all_deps.push(root_dep); // 根排头
        all_deps.extend(leaf_deps);

        Ok(all_deps)
    }
}

#[test]
fn test_pypi_producer_find_dependencies_extended() {
    use crate::model::configuration::RustScopeFilter;

    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("resources/py/requirements.txt");

    let producer = PypiProducer::default();
    let config = SbomProducerConfiguration {
        use_debug: false,
        base_path: d.parent().unwrap().to_path_buf(),
        rust_scope: RustScopeFilter::Prod,
        dynamic: false,
    };

    let deps = producer
        .find_dependencies(&[d], &config)
        .expect("Failed to parse requirements.txt");

    assert!(deps.iter().any(|d| {
        d.name == "Django"
            && d.version.is_none()
            && d.declared_version.as_deref() == Some("~=4.2.1")
    }));

    assert!(deps.iter().any(|d| {
        d.name == "numpy"
            && d.version.is_none()
            && d.declared_version.as_deref() == Some("!=1.24.0")
    }));

    assert!(deps.iter().any(|d| {
        d.name == "my_custom-pkg.ext"
            && d.version.is_none()
            && d.declared_version.as_deref() == Some(">=1.0.0-alpha1")
    }));

    // 新 Python pipeline 不再为 requirements.txt 虚构项目根组件，只输出真实声明依赖。
    assert_eq!(
        deps.len(),
        10,
        "Expected 10 dependencies, found {}",
        deps.len()
    );
}
