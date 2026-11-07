use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use lazy_static::lazy_static;
use regex::Regex;

use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::analyze::producers::pypi::pypi_lock_producer::pep503_normalize;
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyLocation, DependencyType};
use crate::utils::file_utils::make_instance_id;

lazy_static! {
    static ref PEP508_SPEC_RE: Regex = Regex::new(
        r"(?i)^\s*([A-Z0-9][A-Z0-9_\-\.]*)(?:\[[^\]]*\])?\s*(?:\(?\s*(==|>=|<=|~=|!=|>|<|\^|~)\s*([A-Z0-9\.\-\*]+))?"
    ).unwrap();
}

/// 现代 Python 清单解析器：支持 `pyproject.toml` (PEP 621 标准 & Poetry) 与 `Pipfile`
#[derive(Clone, Default)]
pub struct PyprojectProducer {}

impl SbomProducer for PyprojectProducer {
    fn use_file(&self, path: &Path, _config: &SbomProducerConfiguration) -> bool {
        path.file_name()
            .and_then(|n| n.to_str())
            .map(|name| {
                name.eq_ignore_ascii_case("pyproject.toml") || name.eq_ignore_ascii_case("Pipfile")
            })
            .unwrap_or(false)
    }

    fn find_dependencies(
        &self,
        paths: &[PathBuf],
        _config: &SbomProducerConfiguration,
    ) -> anyhow::Result<Vec<Dependency>> {
        let mut all_deps = Vec::new();

        for path in paths {
            let content = fs::read_to_string(path)?;
            let file_salt = path.to_string_lossy().replace('\\', "/");
            all_deps.extend(Self::parse_manifest_toml(&content, &file_salt, path)?);
        }

        Ok(all_deps)
    }
}

impl PyprojectProducer {
    /// 提取 `pyproject.toml` 或 `Pipfile` 中声明的直接依赖名称集合（供动态探针作为可达性起点）
    pub fn extract_declared_root_names(project_dir: &Path) -> HashSet<String> {
        let mut names = HashSet::new();
        for fname in ["pyproject.toml", "Pipfile"] {
            let p = project_dir.join(fname);
            if let Ok(content) = fs::read_to_string(&p) {
                if let Ok(deps) = Self::parse_manifest_toml(&content, "probe", &p) {
                    for d in deps {
                        if d.r#type == DependencyType::Library {
                            names.insert(pep503_normalize(&d.name));
                        }
                    }
                }
            }
        }
        names
    }

    pub fn parse_manifest_toml(
        content: &str,
        file_salt: &str,
        file_path: &Path,
    ) -> anyhow::Result<Vec<Dependency>> {
        let toml_val: toml::Value = toml::from_str(content)?;
        let location = Some(DependencyLocation::from_file(file_path));

        // 1. 提取工程名称与版本（优先 [project]，其次 [tool.poetry]，最后取文件夹名）
        let project_table = toml_val.get("project").and_then(|p| p.as_table());
        let poetry_table = toml_val
            .get("tool")
            .and_then(|t| t.get("poetry"))
            .and_then(|p| p.as_table());

        let app_name = project_table
            .and_then(|t| t.get("name"))
            .and_then(|n| n.as_str())
            .or_else(|| {
                poetry_table
                    .and_then(|t| t.get("name"))
                    .and_then(|n| n.as_str())
            })
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                file_path
                    .parent()
                    .and_then(|d| d.file_name())
                    .and_then(|n| n.to_str())
                    .unwrap_or("python-app")
                    .to_string()
            });

        let app_version = project_table
            .and_then(|t| t.get("version"))
            .and_then(|v| v.as_str())
            .or_else(|| {
                poetry_table
                    .and_then(|t| t.get("version"))
                    .and_then(|v| v.as_str())
            })
            .unwrap_or("0.0.0")
            .to_string();

        let norm_app = pep503_normalize(&app_name);
        let root_purl = format!("pkg:pypi/{}@{}", norm_app, app_version);
        let root_id = make_instance_id(&root_purl, file_salt);

        let mut extracted_specs: Vec<(String, Option<String>)> = Vec::new();

        // A. 解析 PEP 621 [project.dependencies] 与 [project.optional-dependencies]
        if let Some(proj) = project_table {
            if let Some(deps_arr) = proj.get("dependencies").and_then(|d| d.as_array()) {
                for item in deps_arr {
                    if let Some(spec_str) = item.as_str() {
                        if let Some(parsed) = Self::parse_pep508_spec(spec_str) {
                            extracted_specs.push(parsed);
                        }
                    }
                }
            }
            if let Some(opt_deps) = proj.get("optional-dependencies").and_then(|o| o.as_table()) {
                for group_arr in opt_deps.values().filter_map(|v| v.as_array()) {
                    for item in group_arr {
                        if let Some(spec_str) = item.as_str() {
                            if let Some(parsed) = Self::parse_pep508_spec(spec_str) {
                                extracted_specs.push(parsed);
                            }
                        }
                    }
                }
            }
        }

        // B. 解析 Poetry [tool.poetry.dependencies], [tool.poetry.dev-dependencies], [tool.poetry.group.*.dependencies]
        if let Some(poetry) = poetry_table {
            for sec in ["dependencies", "dev-dependencies"] {
                if let Some(table) = poetry.get(sec).and_then(|d| d.as_table()) {
                    Self::collect_table_deps(table, &mut extracted_specs);
                }
            }
            if let Some(groups) = poetry.get("group").and_then(|g| g.as_table()) {
                for grp_val in groups.values() {
                    if let Some(deps_table) = grp_val.get("dependencies").and_then(|d| d.as_table())
                    {
                        Self::collect_table_deps(deps_table, &mut extracted_specs);
                    }
                }
            }
        }

        // C. 解析 Pipfile [packages] 与 [dev-packages]
        for pipfile_sec in ["packages", "dev-packages"] {
            if let Some(table) = toml_val.get(pipfile_sec).and_then(|p| p.as_table()) {
                Self::collect_table_deps(table, &mut extracted_specs);
            }
        }

        if extracted_specs.is_empty() {
            return Ok(vec![]);
        }

        let mut leaf_deps = Vec::new();
        let mut child_ids = Vec::new();
        let mut seen = HashSet::new();

        for (raw_name, ver_opt) in extracted_specs {
            let norm_name = pep503_normalize(&raw_name);
            if norm_name == "python" {
                continue;
            }

            let clean_ver = ver_opt
                .map(|v| {
                    v.trim_start_matches(['^', '~', '=', '>', '<', ' '])
                        .to_string()
                })
                .filter(|v| !v.is_empty() && !v.contains('*'));

            let purl_str = match &clean_ver {
                Some(v) => format!("pkg:pypi/{}@{}", norm_name, v),
                None => format!("pkg:pypi/{}", norm_name),
            };

            let valid_purl = Dependency::auto_fix_and_validate_purl(&purl_str);
            let child_id = make_instance_id(&valid_purl, file_salt);

            if !seen.insert(child_id.clone()) {
                continue;
            }
            child_ids.push(child_id.clone());

            if let Ok(dep) = DependencyBuilder::default()
                .name(raw_name)
                .version(clean_ver)
                .r#type(DependencyType::Library)
                .purl(valid_purl)
                .instance_id(child_id)
                .dependencies(vec![])
                .location(location.clone())
                .build()
            {
                leaf_deps.push(dep);
            }
        }

        if leaf_deps.is_empty() {
            return Ok(vec![]);
        }

        let root_dep = DependencyBuilder::default()
            .name(app_name)
            .version(Some(app_version))
            .r#type(DependencyType::Application)
            .purl(root_purl)
            .instance_id(root_id)
            .dependencies(child_ids)
            .location(location)
            .build()
            .map_err(|e| anyhow::anyhow!(e))?;

        let mut all = Vec::with_capacity(leaf_deps.len() + 1);
        all.push(root_dep);
        all.extend(leaf_deps);
        Ok(all)
    }

    fn collect_table_deps(table: &toml::Table, out: &mut Vec<(String, Option<String>)>) {
        for (name, val) in table {
            if name.eq_ignore_ascii_case("python") {
                continue;
            }
            if let Some(ver_str) = val.as_str() {
                out.push((name.clone(), Some(ver_str.to_string())));
            } else if let Some(sub_table) = val.as_table() {
                // 跳过 path / git 指向的本地或非注册表包
                if sub_table.contains_key("path") || sub_table.contains_key("git") {
                    continue;
                }
                let ver = sub_table
                    .get("version")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                out.push((name.clone(), ver));
            }
        }
    }

    pub fn parse_pep508_spec(spec: &str) -> Option<(String, Option<String>)> {
        let clean = spec.split(';').next().unwrap_or("").trim();
        let caps = PEP508_SPEC_RE.captures(clean)?;
        let name = caps.get(1)?.as_str().to_string();
        let ver = caps.get(3).map(|m| m.as_str().to_string());
        Some((name, ver))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pyproject_pep621_and_poetry() {
        let content = r#"
[project]
name = "ai-agent-service"
version = "1.2.0"
dependencies = [
    "fastapi>=0.110.0",
    "uvicorn[standard]==0.29.0",
]

[tool.poetry.group.dev.dependencies]
pytest = "^8.1.1"
python = "^3.11"
"#;
        let deps = PyprojectProducer::parse_manifest_toml(
            content,
            "test/pyproject.toml",
            Path::new("test/pyproject.toml"),
        )
        .unwrap();

        // 1 root + 3 deps (fastapi, uvicorn, pytest; python 被过滤)
        assert_eq!(deps.len(), 4);
        assert!(deps
            .iter()
            .any(|d| d.name == "uvicorn" && d.version.as_deref() == Some("0.29.0")));
        assert!(deps
            .iter()
            .any(|d| d.name == "pytest" && d.version.as_deref() == Some("8.1.1")));
    }
}
