use crate::analyze::producers::dynamic_producer::DynamicProducer;
use crate::model::configuration::Configuration;
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyType};
use crate::utils::file_utils::make_instance_id;
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::process::Command;

lazy_static! {
    static ref REQ_NAME_RE: Regex = Regex::new(r"(?i)^\s*([A-Z0-9][A-Z0-9_\-\.]*)").unwrap();
    static ref PEP503_RE: Regex = Regex::new(r"[-_.]+").unwrap();
}

#[derive(Default)]
pub struct PypiDynamicProducer {}

impl PypiDynamicProducer {
    fn pep503_normalize(raw: &str) -> String {
        PEP503_RE.replace_all(&raw.to_lowercase(), "-").to_string()
    }

    fn probe_python_binary() -> Option<&'static str> {
        for bin in ["python3", "python"] {
            if let Ok(out) = Command::new(bin).arg("--version").output() {
                if out.status.success() {
                    return Some(bin);
                }
            }
        }
        None
    }
}

impl DynamicProducer for PypiDynamicProducer {
    fn is_applicable(&self, config: &Configuration) -> bool {
        let dir = PathBuf::from(&config.directory);
        let has_manifest = dir.join("requirements.txt").exists()
            || dir.join("pyproject.toml").exists()
            || dir.join("setup.py").exists()
            || dir.join("Pipfile").exists();

        has_manifest && Self::probe_python_binary().is_some()
    }

    fn detect_dependencies(&self, config: &Configuration) -> anyhow::Result<Vec<Dependency>> {
        let py_bin = Self::probe_python_binary()
            .ok_or_else(|| anyhow::anyhow!("当前宿主机未找到 python / python3 解释器"))?;

        let output = Command::new(py_bin)
            .args(["-m", "pip", "inspect"])
            .current_dir(&config.directory)
            .output()?;

        if !output.status.success() {
            let err_msg = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!(
                "pip inspect 执行失败 (可能宿主机 pip 版本低于 22.2): {}",
                err_msg
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value = serde_json::from_str(&stdout)?;

        let Some(installed_list) = json.get("installed").and_then(|i| i.as_array()) else {
            return Ok(vec![]);
        };

        // =================================================================
        // 第一趟：构建 [ PEP503标准名 -> instance_id ] 的绝对寻址字典
        // =================================================================
        struct RawDist {
            orig_name: String,
            version: String,
            purl: String,
            instance_id: String, // 【核心新增字段】
            requires_dist: Vec<String>,
        }

        // 🚨 认知升级：字典里存的 Value 从 purl 变为了 instance_id！
        let mut norm_to_id: HashMap<String, String> = HashMap::with_capacity(installed_list.len());
        let mut dists: Vec<RawDist> = Vec::with_capacity(installed_list.len());

        // Python 虚拟环境内严格全局单例，盐写死常量即可
        let py_global_salt = "pypi-site-packages";

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

            let norm_name = Self::pep503_normalize(name);
            let purl = format!("pkg:pypi/{}@{}", norm_name, version);

            // 1. 为当前 Python 包生成带 Salt 的标准主键
            let instance_id = make_instance_id(&purl, py_global_salt);

            let mut reqs = vec![];
            if let Some(r_arr) = meta.get("requires_dist").and_then(|r| r.as_array()) {
                for r_val in r_arr {
                    if let Some(r_str) = r_val.as_str() {
                        reqs.push(r_str.to_string());
                    }
                }
            }

            norm_to_id.insert(norm_name, instance_id.clone());

            dists.push(RawDist {
                orig_name: name.to_string(),
                version: version.to_string(),
                purl,
                instance_id,
                requires_dist: reqs,
            });
        }

        // =================================================================
        // 第二趟：转译 DAG 关系边
        // =================================================================
        let mut final_deps = Vec::with_capacity(dists.len());

        for dist in dists {
            let mut child_ids = Vec::new(); // 👈 里面塞的必须是 ID
            let mut seen_edges = HashSet::new();

            for req_str in &dist.requires_dist {
                if let Some(caps) = REQ_NAME_RE.captures(req_str) {
                    let raw_child = &caps[1];
                    let norm_child = Self::pep503_normalize(raw_child);

                    // 去字典里捞！捞出来的直接就是对方的 instance_id
                    if let Some(target_id) = norm_to_id.get(&norm_child) {
                        if seen_edges.insert(target_id) {
                            child_ids.push(target_id.clone());
                        }
                    }
                }
            }

            if let Ok(dep) = DependencyBuilder::default()
                .name(dist.orig_name)
                .version(Some(dist.version))
                .r#type(DependencyType::Library)
                .purl(dist.purl)
                .instance_id(dist.instance_id) // 👈 稳稳注入自身ID
                .dependencies(child_ids) // 👈 稳稳连线子ID列表
                .location(None)
                .build()
            {
                final_deps.push(dep);
            }
        }

        Ok(final_deps)
    }
}
