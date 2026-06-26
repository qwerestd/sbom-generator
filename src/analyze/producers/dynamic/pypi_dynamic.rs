use crate::analyze::producers::dynamic_producer::DynamicProducer;
use crate::model::configuration::Configuration;
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyType};
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::process::Command;

lazy_static! {
    // PEP 508 依赖头部纯包名提取正则：
    // "urllib3 (<3,>=1.21.1); extra == 'socks'" -> 提取出 "urllib3"
    // "google-api-core[grpc] >= 1.34.0"         -> 提取出 "google-api-core"
    static ref REQ_NAME_RE: Regex = Regex::new(r"(?i)^\s*([A-Z0-9][A-Z0-9_\-\.]*)").unwrap();

    // PEP 503 标准化替换正则 (官方规范：压扁所有连续的 - _ .)
    static ref PEP503_RE: Regex = Regex::new(r"[-_.]+").unwrap();
}

#[derive(Default)]
pub struct PypiDynamicProducer {}

impl PypiDynamicProducer {
    /// PEP 503 规范化清洗： "My_Custom-Pkg.ext" -> "my-custom-pkg-ext"
    fn pep503_normalize(raw: &str) -> String {
        PEP503_RE.replace_all(&raw.to_lowercase(), "-").to_string()
    }

    /// 跨平台智能探测 Python 解释器二进制名称
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

        // 发起官方原生内建检查
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
        // 第一趟：构建 [ PEP503标准名 -> PURL ] 的快速寻址字典
        // =================================================================
        struct RawDist {
            orig_name: String,
            version: String,
            purl: String,
            requires_dist: Vec<String>,
        }

        let mut norm_to_purl: HashMap<String, String> =
            HashMap::with_capacity(installed_list.len());
        let mut dists: Vec<RawDist> = Vec::with_capacity(installed_list.len());

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

            let mut reqs = vec![];
            if let Some(r_arr) = meta.get("requires_dist").and_then(|r| r.as_array()) {
                for r_val in r_arr {
                    if let Some(r_str) = r_val.as_str() {
                        reqs.push(r_str.to_string());
                    }
                }
            }

            norm_to_purl.insert(norm_name, purl.clone());

            dists.push(RawDist {
                orig_name: name.to_string(),
                version: version.to_string(),
                purl,
                requires_dist: reqs,
            });
        }

        // =================================================================
        // 第二趟：转译 DAG 关系边，利用字典天然过滤环境未激活的分支
        // =================================================================
        let mut final_deps = Vec::with_capacity(dists.len());

        for dist in dists {
            let mut child_purls = Vec::new();
            let mut seen_edges = HashSet::new(); // 防止多路条件导致边重复

            for req_str in &dist.requires_dist {
                if let Some(caps) = REQ_NAME_RE.captures(req_str) {
                    let raw_child = &caps[1];
                    let norm_child = Self::pep503_normalize(raw_child);

                    // 【核心神技】：去第一趟的字典里找！
                    // 如果找到了，说明 pip 在宿主机环境里真的安装了它（条件成立）；
                    // 如果没找到（如 sys_platform == 'win32' 而本机是 Linux），字典查不到，天然静默过滤！
                    if let Some(target_purl) = norm_to_purl.get(&norm_child) {
                        if seen_edges.insert(target_purl) {
                            child_purls.push(target_purl.clone());
                        }
                    }
                }
            }

            if let Ok(dep) = DependencyBuilder::default()
                .name(dist.orig_name) // 保留屏幕前人类爱看的原名 (Flask)
                .version(Some(dist.version))
                .r#type(DependencyType::Library)
                .purl(dist.purl) // 注入机读撞库的规范 PURL (pkg:pypi/flask@3.0.0)
                .dependencies(child_purls) // 👈 完整的 DAG 树血脉边！
                .location(None)
                .build()
            {
                final_deps.push(dep);
            }
        }

        Ok(final_deps)
    }
}
