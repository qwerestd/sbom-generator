use std::fs;
use std::path::{Path, PathBuf};

use lazy_static::lazy_static;
use regex::Regex;

use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyLocation, DependencyType};
use crate::utils::file_utils::make_instance_id;
use crate::utils::graph_utils::{build_reachable_dag, RawGraphNode};

lazy_static! {
    static ref PEP503_NORM_RE: Regex = Regex::new(r"[-_.]+").unwrap();
}

pub fn pep503_normalize(raw: &str) -> String {
    PEP503_NORM_RE
        .replace_all(&raw.to_lowercase(), "-")
        .to_string()
}

/// Python 锁文件解析器：支持 `poetry.lock`、`uv.lock`（还原完整多层 DAG 拓扑图）与 `Pipfile.lock`
#[derive(Clone, Default)]
pub struct PypiLockProducer {}

impl SbomProducer for PypiLockProducer {
    fn use_file(&self, path: &Path, _config: &SbomProducerConfiguration) -> bool {
        path.file_name()
            .and_then(|n| n.to_str())
            .map(|name| {
                name.eq_ignore_ascii_case("poetry.lock")
                    || name.eq_ignore_ascii_case("uv.lock")
                    || name.eq_ignore_ascii_case("Pipfile.lock")
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
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let file_salt = path.to_string_lossy().replace('\\', "/");

            let parsed = if file_name.eq_ignore_ascii_case("poetry.lock")
                || file_name.eq_ignore_ascii_case("uv.lock")
            {
                Self::parse_toml_lock(&content, &file_salt, path)?
            } else if file_name.eq_ignore_ascii_case("Pipfile.lock") {
                Self::parse_pipfile_lock(&content, &file_salt, path)?
            } else {
                vec![]
            };

            all_deps.extend(parsed);
        }

        Ok(all_deps)
    }
}

impl PypiLockProducer {
    /// 解析 `poetry.lock` 或 `uv.lock` 并通过通用 4-Pass 图算法构建完整传递依赖 DAG
    pub fn parse_toml_lock(
        content: &str,
        file_salt: &str,
        lock_path: &Path,
    ) -> anyhow::Result<Vec<Dependency>> {
        let lock_toml: toml::Value = toml::from_str(content)?;
        let Some(packages) = lock_toml.get("package").and_then(|p| p.as_array()) else {
            return Ok(vec![]);
        };

        let location = Some(DependencyLocation::from_file(lock_path));
        let mut raw_nodes = Vec::with_capacity(packages.len());

        for pkg in packages {
            let Some(name) = pkg.get("name").and_then(|n| n.as_str()) else {
                continue;
            };
            let Some(version) = pkg.get("version").and_then(|v| v.as_str()) else {
                continue;
            };

            let norm_name = pep503_normalize(name);
            let raw_purl = format!("pkg:pypi/{}@{}", norm_name, version);
            let valid_purl = Dependency::auto_fix_and_validate_purl(&raw_purl);
            let instance_id = make_instance_id(&valid_purl, file_salt);

            let mut raw_deps = Vec::new();

            if let Some(deps_val) = pkg.get("dependencies") {
                // 兼容 poetry.lock 的 [package.dependencies] 字典格式
                if let Some(deps_table) = deps_val.as_table() {
                    for dep_key in deps_table.keys() {
                        raw_deps.push((pep503_normalize(dep_key), None));
                    }
                }
                // 兼容 uv.lock 的 dependencies = [{ name = "..." }, ...] 数组格式
                else if let Some(deps_arr) = deps_val.as_array() {
                    for item in deps_arr {
                        if let Some(dep_name) = item.get("name").and_then(|n| n.as_str()) {
                            let dep_ver = item
                                .get("version")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());
                            raw_deps.push((pep503_normalize(dep_name), dep_ver));
                        } else if let Some(dep_str) = item.as_str() {
                            raw_deps.push((pep503_normalize(dep_str), None));
                        }
                    }
                }
            }

            raw_nodes.push(RawGraphNode {
                group: None,
                name: name.to_string(),
                version: Some(version.to_string()),
                purl: valid_purl,
                instance_id,
                raw_deps,
                lookup_key: norm_name,
                force_root: false,
                location: location.clone(),
            });
        }

        Ok(build_reachable_dag(raw_nodes))
    }

    /// 解析 `Pipfile.lock` (JSON)
    pub fn parse_pipfile_lock(
        content: &str,
        file_salt: &str,
        lock_path: &Path,
    ) -> anyhow::Result<Vec<Dependency>> {
        let json: serde_json::Value = serde_json::from_str(content)?;
        let location = Some(DependencyLocation::from_file(lock_path));

        let app_name = lock_path
            .parent()
            .and_then(|d| d.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("pipenv-app")
            .to_string();
        let norm_app = pep503_normalize(&app_name);
        let root_purl = format!("pkg:pypi/{}@0.0.0", norm_app);
        let root_id = make_instance_id(&root_purl, file_salt);

        let mut leaf_deps = Vec::new();
        let mut child_ids = Vec::new();

        for section in ["default", "develop"] {
            if let Some(pkgs) = json.get(section).and_then(|s| s.as_object()) {
                for (pkg_name, pkg_info) in pkgs {
                    let raw_ver = pkg_info
                        .get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .trim_start_matches('=');

                    let norm_name = pep503_normalize(pkg_name);
                    let (ver_opt, purl_str) = if raw_ver.is_empty() {
                        (None, format!("pkg:pypi/{}", norm_name))
                    } else {
                        (
                            Some(raw_ver.to_string()),
                            format!("pkg:pypi/{}@{}", norm_name, raw_ver),
                        )
                    };

                    let valid_purl = Dependency::auto_fix_and_validate_purl(&purl_str);
                    let child_id = make_instance_id(&valid_purl, file_salt);
                    if !child_ids.contains(&child_id) {
                        child_ids.push(child_id.clone());
                        if let Ok(dep) = DependencyBuilder::default()
                            .name(pkg_name.clone())
                            .version(ver_opt)
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
                }
            }
        }

        if leaf_deps.is_empty() {
            return Ok(vec![]);
        }

        let root_dep = DependencyBuilder::default()
            .name(app_name)
            .version(Some("0.0.0".to_string()))
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_poetry_lock_dag() {
        let poetry_lock = r#"
[[package]]
name = "fastapi"
version = "0.110.0"

[package.dependencies]
pydantic = ">=1.7.4"
starlette = ">=0.36.3,<0.37.0"

[[package]]
name = "pydantic"
version = "2.6.4"

[[package]]
name = "starlette"
version = "0.36.3"
"#;
        let deps = PypiLockProducer::parse_toml_lock(
            poetry_lock,
            "test/poetry.lock",
            Path::new("test/poetry.lock"),
        )
        .unwrap();

        assert_eq!(deps.len(), 3);
        let fastapi = deps.iter().find(|d| d.name == "fastapi").unwrap();
        assert_eq!(fastapi.dependencies.len(), 2);
        assert_eq!(fastapi.r#type, DependencyType::Application);
    }

    #[test]
    fn test_parse_uv_lock() {
        let uv_lock = r#"
version = 1
revision = 1

[[package]]
name = "flask"
version = "3.0.0"
dependencies = [
    { name = "werkzeug" },
    { name = "click" }
]

[[package]]
name = "werkzeug"
version = "3.0.1"

[[package]]
name = "click"
version = "8.1.7"
"#;
        let deps =
            PypiLockProducer::parse_toml_lock(uv_lock, "test/uv.lock", Path::new("test/uv.lock"))
                .unwrap();

        assert_eq!(deps.len(), 3);
        let flask = deps.iter().find(|d| d.name == "flask").unwrap();
        assert_eq!(flask.dependencies.len(), 2);
    }

    #[test]
    fn test_parse_pipfile_lock() {
        let pipfile_lock = r#"{
            "_meta": { "hash": { "sha256": "abc" } },
            "default": {
                "requests": {
                    "version": "==2.31.0"
                },
                "urllib3": {
                    "version": "==2.0.7"
                }
            },
            "develop": {
                "pytest": {
                    "version": "==8.0.0"
                }
            }
        }"#;

        let deps = PypiLockProducer::parse_pipfile_lock(
            pipfile_lock,
            "test/Pipfile.lock",
            Path::new("my-service/Pipfile.lock"),
        )
        .unwrap();

        assert_eq!(deps.len(), 4, "1 root application + 3 leaf dependencies");
        let root = deps
            .iter()
            .find(|d| d.r#type == DependencyType::Application)
            .unwrap();
        assert_eq!(root.name, "my-service");
        assert_eq!(root.dependencies.len(), 3);
    }
}
