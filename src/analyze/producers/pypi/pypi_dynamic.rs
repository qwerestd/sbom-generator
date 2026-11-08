use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Command;

use lazy_static::lazy_static;
use regex::Regex;

use crate::analyze::producers::dynamic_producer::DynamicProducer;
use crate::analyze::producers::pypi::pypi_lock_producer::pep503_normalize;
use crate::analyze::producers::pypi::pypi_producer::PypiProducer;
use crate::analyze::producers::pypi::pyproject_producer::PyprojectProducer;
use crate::model::configuration::Configuration;
use crate::model::dependency::Dependency;
use crate::utils::cli_driver::CliLocator;
use crate::utils::file_utils::make_instance_id;
use crate::utils::graph_utils::{build_reachable_dag, RawGraphNode};

lazy_static! {
    static ref REQ_NAME_RE: Regex = Regex::new(r"(?i)^\s*([A-Z0-9][A-Z0-9_\-\.]*)").unwrap();
}

/// 增强版 Python 动态探针：
/// 1. 优先通过 `CliLocator::resolve_python_for_dir` 定位项目本地虚拟环境 (`.venv` / `venv` / `VIRTUAL_ENV`)
/// 2. 结合项目清单声明的根依赖启动 4-Pass BFS 可达性剪枝，彻底消除全局 Python 环境无关包污染
#[derive(Default)]
pub struct PypiDynamicProducer {}

impl DynamicProducer for PypiDynamicProducer {
    fn is_applicable(&self, config: &Configuration) -> bool {
        let dir = PathBuf::from(&config.directory);
        let has_manifest = dir.join("requirements.txt").exists()
            || dir.join("pyproject.toml").exists()
            || dir.join("setup.py").exists()
            || dir.join("Pipfile").exists();

        has_manifest && CliLocator::resolve_python_for_dir(&dir).is_some()
    }

    fn detect_dependencies(&self, config: &Configuration) -> anyhow::Result<Vec<Dependency>> {
        let work_dir = PathBuf::from(&config.directory);
        let py_bin = CliLocator::resolve_python_for_dir(&work_dir)
            .ok_or_else(|| anyhow::anyhow!("当前宿主机未找到 python / python3 解释器"))?;

        let mut cmd = Command::new(py_bin);
        cmd.args(["-m", "pip", "inspect"]).current_dir(&work_dir);

        let output = CliLocator::run_with_timeout(cmd, std::time::Duration::from_secs(15))?;

        if !output.status.success() {
            let err_msg = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!(
                "pip inspect 执行失败 (可能宿主机 pip 版本低于 22.2): {}",
                err_msg
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value = serde_json::from_str(&stdout)?;

        // 提取项目显式声明的直接依赖集合，用于从根执行可达性剪枝
        let mut root_declared = PypiProducer::extract_declared_root_names(&work_dir);
        root_declared.extend(PyprojectProducer::extract_declared_root_names(&work_dir));

        let app_name = work_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("python-app");

        let salt = work_dir.to_string_lossy().replace('\\', "/");
        Self::parse_pip_inspect_graph(&json, app_name, &root_declared, &salt)
    }
}

impl PypiDynamicProducer {
    pub fn parse_pip_inspect_graph(
        json: &serde_json::Value,
        app_name: &str,
        declared_roots: &HashSet<String>,
        file_salt: &str,
    ) -> anyhow::Result<Vec<Dependency>> {
        let Some(installed_list) = json.get("installed").and_then(|i| i.as_array()) else {
            return Ok(vec![]);
        };

        let mut raw_nodes = Vec::with_capacity(installed_list.len() + 1);
        let mut installed_norm_names = HashSet::new();

        for item in installed_list {
            let Some(meta) = item.get("metadata") else {
                continue;
            };
            let Some(name) = meta.get("name").and_then(|n| n.as_str()) else {
                continue;
            };
            let Some(version) = meta.get("version").and_then(|v| v.as_str()) else {
                continue;
            };

            let norm_name = pep503_normalize(name);
            installed_norm_names.insert(norm_name.clone());

            let raw_purl = format!("pkg:pypi/{}@{}", norm_name, version);
            let valid_purl = Dependency::auto_fix_and_validate_purl(&raw_purl);
            let instance_id = make_instance_id(&valid_purl, file_salt);

            let mut raw_deps = Vec::new();
            if let Some(r_arr) = meta.get("requires_dist").and_then(|r| r.as_array()) {
                for r_val in r_arr {
                    if let Some(r_str) = r_val.as_str() {
                        // 过滤需要特定 extra 才会激活的可选依赖边，防止无关噪声膨胀
                        if let Some((_, marker)) = r_str.split_once(';') {
                            if marker.contains("extra ==") || marker.contains("extra==") {
                                continue;
                            }
                        }
                        if let Some(caps) = REQ_NAME_RE.captures(r_str) {
                            let child_norm = pep503_normalize(&caps[1]);
                            raw_deps.push((child_norm, None));
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
                location: None,
            });
        }

        if raw_nodes.is_empty() {
            return Ok(vec![]);
        }

        // 严禁接受“部分匹配”：
        // 假设项目声明了 A 和 B，当前环境只装了 A，绝不能只返回 A 的依赖图（否则 B 会从整份 SBOM 中蒸发，CLI 仍虚假显示动态成功）。
        // 必须要求 declared_roots 全部在当前环境中已安装；若有任何缺失，必须报错回退到静态责任链！
        if !declared_roots.is_empty() {
            let missing_roots: Vec<String> = declared_roots
                .iter()
                .filter(|r| !installed_norm_names.contains(*r))
                .cloned()
                .collect();

            if !missing_roots.is_empty() {
                anyhow::bail!(
                    "Python 动态环境不完整：项目声明了 {} 个依赖，但环境中缺少 {} 个依赖 ({:?})。拒绝部分匹配，正在触发静态责任链降级以确保完整覆盖！",
                    declared_roots.len(),
                    missing_roots.len(),
                    missing_roots
                );
            }

            let matched_roots: Vec<(String, Option<String>)> =
                declared_roots.iter().map(|r| (r.clone(), None)).collect();

            let norm_app = pep503_normalize(app_name);
            let root_purl = format!("pkg:pypi/{}@0.0.0", norm_app);
            let root_id = make_instance_id(&root_purl, file_salt);

            raw_nodes.push(RawGraphNode {
                group: None,
                name: app_name.to_string(),
                version: Some("0.0.0".to_string()),
                purl: root_purl,
                instance_id: root_id,
                raw_deps: matched_roots,
                lookup_key: norm_app,
                force_root: true,
                location: None,
            });
        }

        Ok(build_reachable_dag(raw_nodes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pip_inspect_reachability_pruning() {
        let mock_inspect = serde_json::json!({
            "installed": [
                {
                    "metadata": {
                        "name": "requests",
                        "version": "2.31.0",
                        "requires_dist": [
                            "urllib3 (<3,>=1.21.1)",
                            "PySocks (!=1.5.7,>=1.5.6) ; extra == 'socks'"
                        ]
                    }
                },
                {
                    "metadata": {
                        "name": "urllib3",
                        "version": "2.0.7"
                    }
                },
                {
                    "metadata": {
                        "name": "PySocks",
                        "version": "1.7.1"
                    }
                },
                {
                    "metadata": {
                        "name": "unrelated-global-pkg",
                        "version": "9.9.9"
                    }
                }
            ]
        });

        let mut declared = HashSet::new();
        declared.insert("requests".to_string());

        let deps = PypiDynamicProducer::parse_pip_inspect_graph(
            &mock_inspect,
            "my-py-service",
            &declared,
            "test/py",
        )
        .unwrap();

        // 应仅保留: my-py-service (root) -> requests -> urllib3 (共3个)
        // unrelated-global-pkg 与未激活的 extra PySocks 均被精准剪枝剔除！
        assert_eq!(deps.len(), 3);
        assert!(deps.iter().any(|d| d.name == "requests"));
        assert!(deps.iter().any(|d| d.name == "urllib3"));
        assert!(!deps.iter().any(|d| d.name == "unrelated-global-pkg"));
        assert!(!deps.iter().any(|d| d.name == "PySocks"));
    }

    #[test]
    fn test_pip_inspect_rejects_partial_match() {
        let mock_inspect = serde_json::json!({
            "installed": [
                {
                    "metadata": {
                        "name": "package-a",
                        "version": "1.0.0"
                    }
                }
            ]
        });

        let mut declared = HashSet::new();
        declared.insert("package-a".to_string());
        declared.insert("package-b".to_string()); // package-b 缺失

        let res = PypiDynamicProducer::parse_pip_inspect_graph(
            &mock_inspect,
            "my-py-service",
            &declared,
            "test/py",
        );

        assert!(
            res.is_err(),
            "must reject partial match when package-b is missing"
        );
        let err_str = res.unwrap_err().to_string();
        assert!(err_str.contains("拒绝部分匹配"));
        assert!(err_str.contains("package-b"));
    }
}
