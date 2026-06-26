// src/analyze/producers/cargo_producer.rs

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyType};

#[derive(Clone, Default)]
pub struct CargoProducer {}

impl SbomProducer for CargoProducer {
    fn use_file(&self, path: &Path, _config: &SbomProducerConfiguration) -> bool {
        // 【核心工程理念】：静态轨只认 Cargo.lock！
        // 绝对不扫 Cargo.toml，更不准在静态轨里 fork 子进程去执行 cargo 二进制命令
        path.file_name()
            .map(|name| name == "Cargo.lock")
            .unwrap_or(false)
    }

    fn find_dependencies(
        &self,
        paths: &[PathBuf],
        _config: &SbomProducerConfiguration,
    ) -> anyhow::Result<Vec<Dependency>> {
        let mut all_dependencies = Vec::new();

        for lock_path in paths {
            let content = fs::read_to_string(lock_path)?;
            let file_deps = Self::parse_cargo_lock(&content)?;
            all_dependencies.extend(file_deps);
        }

        Ok(all_dependencies)
    }
}

impl CargoProducer {
    /// 内存解析 Cargo.lock 文本，还原全量组件及 DAG 拓扑连接边
    fn parse_cargo_lock(content: &str) -> anyhow::Result<Vec<Dependency>> {
        let lock_toml: toml::Value = toml::from_str(content)?;

        let Some(packages) = lock_toml.get("package").and_then(|p| p.as_array()) else {
            return Ok(vec![]);
        };

        struct RawNode {
            name: String,
            version: String,
            purl: String,
            raw_deps: Vec<String>,
            #[allow(dead_code)]
            is_local: bool,
        }

        let mut nodes = Vec::with_capacity(packages.len());

        // =================================================================
        // 第一趟：双索引映射表构建
        // exact_map : ("serde", "1.0.197") -> "pkg:cargo/serde@1.0.197"
        // single_map: "serde" -> "pkg:cargo/serde@1.0.197"
        // (注：Cargo规范保证，只有全局唯一的包，其依赖字符串才会省略版本号)
        // =================================================================
        let mut exact_map: HashMap<(&str, &str), String> = HashMap::new();
        let mut single_map: HashMap<&str, String> = HashMap::new();

        for pkg in packages {
            let Some(name) = pkg.get("name").and_then(|n| n.as_str()) else {
                continue;
            };
            let Some(version) = pkg.get("version").and_then(|v| v.as_str()) else {
                continue;
            };

            // 本地 Workspace 成员在 Lock 里没有 "source" 字段
            let is_local = pkg.get("source").is_none();
            let purl = format!("pkg:cargo/{}@{}", name, version);

            let mut raw_deps = vec![];
            if let Some(deps) = pkg.get("dependencies").and_then(|d| d.as_array()) {
                for d_val in deps {
                    if let Some(d_str) = d_val.as_str() {
                        raw_deps.push(d_str.to_string());
                    }
                }
            }

            exact_map.insert((name, version), purl.clone());
            single_map.insert(name, purl.clone());

            nodes.push(RawNode {
                name: name.to_string(),
                version: version.to_string(),
                purl,
                raw_deps,
                is_local,
            });
        }

        // =================================================================
        // 第二趟：转译依赖边，组装标准的 CycloneDX Dependency 模型
        // =================================================================
        let mut final_deps = Vec::with_capacity(nodes.len());

        for node in nodes {
            // 【可定制点】：如果你的业务严格要求“不把本地私有模块算作第三方组件”，
            // 请把下面这行解开注释：
            // if node.is_local { continue; }

            let mut child_purls = Vec::with_capacity(node.raw_deps.len());

            for dep_expr in &node.raw_deps {
                // Cargo.lock 里的依赖字符串规范分为三种：
                // A. "bitflags"
                // B. "bitflags 1.3.2"
                // C. "bitflags 1.3.2 (registry+https://...)"
                let mut iter = dep_expr.split_whitespace();
                let d_name = iter.next().unwrap_or("");
                let d_ver = iter.next(); // 可能是版本号，也可能是 None

                let target_purl = match d_ver {
                    Some(ver) => exact_map.get(&(d_name, ver)).cloned(),
                    None => single_map.get(d_name).cloned(),
                };

                if let Some(p) = target_purl {
                    child_purls.push(p);
                }
            }

            if let Ok(dep) = DependencyBuilder::default()
                .name(node.name)
                .version(Some(node.version))
                .r#type(DependencyType::Library)
                .purl(Dependency::auto_fix_and_validate_purl(node.purl.as_str()))
                .dependencies(child_purls) // 【核心点：注入 DAG 子节点边】
                .location(None) // 离线静态 Lock 无法推导代码物理行号
                .build()
            {
                final_deps.push(dep);
            }
        }

        Ok(final_deps)
    }
}
