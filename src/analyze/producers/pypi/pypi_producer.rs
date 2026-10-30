use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use lazy_static::lazy_static;
use regex::Regex;

use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::analyze::producers::pypi::pypi_lock_producer::pep503_normalize;
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyLocation, DependencyType};
use crate::utils::context_resolver::HierarchicalContext;
use crate::utils::file_utils::make_instance_id;
use crate::utils::tree_sitter::tree::build_location_from_offsets;

lazy_static! {
    static ref PYPI_LINE_RE: Regex = Regex::new(
        r"(?i)^([A-Z0-9][A-Z0-9_\-\.]*)(?:\[[^\]]+\])?(?:\s*(==|>=|<=|~=|!=|>|<)\s*([A-Z0-9\.\-\*\$\{\}_]+))?"
    ).unwrap();
}

/// 增强版 `requirements.txt` 解析器：
/// - 推广 Maven 的 `HierarchicalContext` 属性插值 (`${VAR}`) 与受管版本继承（支持 `-c constraints.txt`）
/// - 支持 `-r other-requirements.txt` 递归文件引入与反斜杠 `\` 多行续行
/// - 推广 Maven 的源码字节偏移定位，精确记录每个依赖在文件中的 `Line` 与 `Col`
#[derive(Clone, Default)]
pub struct PypiProducer {}

impl SbomProducer for PypiProducer {
    fn use_file(&self, path: &Path, _config: &SbomProducerConfiguration) -> bool {
        path.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.eq_ignore_ascii_case("requirements.txt"))
    }

    fn find_dependencies(
        &self,
        paths: &[PathBuf],
        _config: &SbomProducerConfiguration,
    ) -> anyhow::Result<Vec<Dependency>> {
        let mut result = vec![];

        for p in paths {
            if let Ok(content) = fs::read_to_string(p) {
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
    /// 提取项目目录下 `requirements.txt` 声明的直接依赖规范名（供动态探针 BFS 剪枝）
    pub fn extract_declared_root_names(project_dir: &Path) -> HashSet<String> {
        let mut names = HashSet::new();
        let req_path = project_dir.join("requirements.txt");
        if let Ok(content) = fs::read_to_string(&req_path) {
            if let Ok(deps) = Self::parse_single_requirements(&content, "probe", &req_path) {
                for d in deps {
                    if d.r#type == DependencyType::Library {
                        names.insert(pep503_normalize(&d.name));
                    }
                }
            }
        }
        names
    }

    /// 独立接管单个 requirements.txt 的 DAG 编织（支持 -r 递归包含与 -c constraints 版本继承）
    fn parse_single_requirements(
        content: &str,
        file_salt: &str,
        file_path: &Path,
    ) -> anyhow::Result<Vec<Dependency>> {
        let app_name = file_path
            .parent()
            .and_then(|dir| dir.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("python-app")
            .to_string();

        let norm_app_name = pep503_normalize(&app_name);
        let root_purl = format!("pkg:pypi/{}@0.0.0", norm_app_name);
        let root_instance_id = make_instance_id(&root_purl, file_salt);

        // 初始化上下文（推广自 Maven：加载环境变量与同目录 constraints.txt 受管版本）
        let mut context = HierarchicalContext::new();
        for (k, v) in std::env::vars() {
            context.insert_property(k, v);
        }
        if let Some(parent_dir) = file_path.parent() {
            let default_constraints = parent_dir.join("constraints.txt");
            if default_constraints.exists() {
                Self::load_constraints_file(&default_constraints, &mut context);
            }
        }

        let mut raw_entries = Vec::new();
        let mut visited_files = HashSet::new();
        if let Ok(canon) = fs::canonicalize(file_path) {
            visited_files.insert(canon);
        }

        Self::collect_requirements_recursive(
            content,
            file_path,
            &mut context,
            &mut visited_files,
            &mut raw_entries,
        );

        let mut leaf_deps = vec![];
        let mut child_ids = vec![];
        let mut seen_ids = HashSet::new();

        for (raw_name, raw_ver_opt, loc) in raw_entries {
            let normalized_name = pep503_normalize(&raw_name);

            // 利用 Maven 推广的分层上下文决议版本（支持 ${VAR} 插值 + constraints.txt 版本补全）
            let resolved_ver = context
                .resolve_version(&normalized_name, raw_ver_opt.as_deref())
                .filter(|v| !v.contains('*'));

            let purl_str = match &resolved_ver {
                Some(v) => format!("pkg:pypi/{}@{}", normalized_name, v),
                None => format!("pkg:pypi/{}", normalized_name),
            };

            let valid_purl = Dependency::auto_fix_and_validate_purl(&purl_str);
            let child_id = make_instance_id(&valid_purl, file_salt);

            if !seen_ids.insert(child_id.clone()) {
                continue;
            }
            child_ids.push(child_id.clone());

            leaf_deps.push(
                DependencyBuilder::default()
                    .name(raw_name)
                    .version(resolved_ver)
                    .r#type(DependencyType::Library)
                    .purl(valid_purl)
                    .instance_id(child_id)
                    .dependencies(vec![])
                    .location(Some(loc))
                    .build()
                    .unwrap(),
            );
        }

        if leaf_deps.is_empty() {
            return Ok(vec![]);
        }

        let root_dep = DependencyBuilder::default()
            .name(app_name)
            .version(Some("0.0.0".to_string()))
            .r#type(DependencyType::Application)
            .purl(root_purl)
            .instance_id(root_instance_id)
            .dependencies(child_ids)
            .location(Some(DependencyLocation::from_file(file_path)))
            .build()
            .unwrap();

        let mut all_deps = Vec::with_capacity(leaf_deps.len() + 1);
        all_deps.push(root_dep);
        all_deps.extend(leaf_deps);

        Ok(all_deps)
    }

    fn load_constraints_file(constraint_path: &Path, context: &mut HierarchicalContext) {
        if let Ok(content) = fs::read_to_string(constraint_path) {
            for line in content.lines() {
                let clean = line
                    .split('#')
                    .next()
                    .unwrap_or("")
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .trim();
                if let Some(caps) = PYPI_LINE_RE.captures(clean) {
                    if let (Some(name_m), Some(ver_m)) = (caps.get(1), caps.get(3)) {
                        let norm = pep503_normalize(name_m.as_str());
                        context.insert_managed_version(norm, ver_m.as_str().to_string());
                    }
                }
            }
        }
    }

    fn collect_requirements_recursive(
        content: &str,
        current_file: &Path,
        context: &mut HierarchicalContext,
        visited: &mut HashSet<PathBuf>,
        out: &mut Vec<(String, Option<String>, DependencyLocation)>,
    ) {
        let mut byte_cursor = 0usize;

        for line in content.split_inclusive('\n') {
            let line_start = byte_cursor;
            let line_end = byte_cursor + line.len();
            byte_cursor = line_end;

            let clean_line = line
                .split('#')
                .next()
                .unwrap_or("")
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .trim_end_matches('\\')
                .trim();

            if clean_line.is_empty() {
                continue;
            }

            // 支持 `-r other.txt` / `--requirement other.txt` 递归包含
            if let Some(inc_rel) = clean_line
                .strip_prefix("-r ")
                .or_else(|| clean_line.strip_prefix("--requirement "))
            {
                if let Some(parent) = current_file.parent() {
                    let target = parent.join(inc_rel.trim());
                    if let Ok(canon) = fs::canonicalize(&target) {
                        if visited.insert(canon) {
                            if let Ok(sub_content) = fs::read_to_string(&target) {
                                Self::collect_requirements_recursive(
                                    &sub_content,
                                    &target,
                                    context,
                                    visited,
                                    out,
                                );
                            }
                        }
                    }
                }
                continue;
            }

            // 支持 `-c constraints.txt` / `--constraint constraints.txt` 受管版本表加载
            if let Some(con_rel) = clean_line
                .strip_prefix("-c ")
                .or_else(|| clean_line.strip_prefix("--constraint "))
            {
                if let Some(parent) = current_file.parent() {
                    let target = parent.join(con_rel.trim());
                    Self::load_constraints_file(&target, context);
                }
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
                let raw_name = caps.get(1).unwrap().as_str().to_string();
                let raw_ver = caps.get(3).map(|m| m.as_str().to_string());

                let loc = build_location_from_offsets(
                    current_file,
                    content,
                    (line_start, line_end),
                    None,
                    None,
                );

                out.push((raw_name, raw_ver, loc));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        assert!(
            deps.iter()
                .any(|d| d.name == "my_custom-pkg.ext"
                    && d.version.as_deref() == Some("1.0.0-alpha1"))
        );

        assert_eq!(
            deps.len(),
            11,
            "Expected 11 dependencies, found {}",
            deps.len()
        );
    }

    #[test]
    fn test_pypi_constraints_and_variable_interpolation() {
        let mut ctx = HierarchicalContext::new();
        ctx.insert_property("FASTAPI_VER", "0.110.0");
        ctx.insert_managed_version("requests", "2.31.0");

        let resolved_var = ctx.resolve_version("fastapi", Some("${FASTAPI_VER}"));
        let resolved_managed = ctx.resolve_version("requests", None);

        assert_eq!(resolved_var.as_deref(), Some("0.110.0"));
        assert_eq!(resolved_managed.as_deref(), Some("2.31.0"));
    }
}
