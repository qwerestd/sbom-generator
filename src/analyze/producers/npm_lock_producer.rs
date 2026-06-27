// src/analyze/producers/npm_lock_producer.rs
// src/analyze/producers/npm_lock_producer.rs

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyType};
use crate::utils::file_utils::make_instance_id;
// 【新增引入】统一派生算法

#[derive(Clone, Default)]
pub struct NpmLockProducer {}

impl SbomProducer for NpmLockProducer {
    fn use_file(&self, path: &Path, _config: &SbomProducerConfiguration) -> bool {
        path.file_name()
            .is_some_and(|n| n.eq_ignore_ascii_case("package-lock.json"))
    }

    fn find_dependencies(
        &self,
        paths: &[PathBuf],
        _config: &SbomProducerConfiguration,
    ) -> anyhow::Result<Vec<Dependency>> {
        let mut result = Vec::new();

        for p in paths {
            let Ok(content) = std::fs::read_to_string(p) else {
                continue;
            };
            let clean_content = content.trim_start_matches('\u{FEFF}').trim();

            // 【核心修复 1】：提取当前 lock 文件的物理相对路径作为盐
            let file_salt = p.to_string_lossy().replace('\\', "/");

            match serde_json::from_str::<serde_json::Value>(clean_content) {
                Ok(json) => {
                    result.extend(Self::parse_npm_lock(&json, &file_salt)?);
                }
                Err(e) => {
                    eprintln!(
                        "❌ [Debug] 无法解析 package-lock.json {:?}，错误原因: {}",
                        p, e
                    );
                }
            }
        }
        Ok(result)
    }
}

impl NpmLockProducer {
    fn parse_npm_lock(
        json: &serde_json::Value,
        file_salt: &str,
    ) -> anyhow::Result<Vec<Dependency>> {
        let Some(packages) = json.get("packages").and_then(|p| p.as_object()) else {
            return Ok(vec![]);
        };

        struct RawNode {
            pkg_path: String,
            name: String,
            version: String,
            purl: String,
            instance_id: String, // 【新增】自身唯一身份证
            dep_names: Vec<String>,
        }

        let mut nodes = Vec::with_capacity(packages.len());

        // 🚨 认知升级：字典寻址升级为 [ 物理挂载路径 -> instance_id ]
        // 例如: "packages/app-a/node_modules/axios" -> "pkg:npm/axios@1.6?package-id=xxx"
        let mut path_to_id: HashMap<String, String> = HashMap::with_capacity(packages.len());

        for (pkg_path, pkg_data) in packages {
            if pkg_path.is_empty() {
                continue; // "" 代表根项目自身，跳过
            }

            // 智能提取包名：兼容普通包、Scope包(@babel/core)以及Workspace本地工程
            let name = match pkg_data.get("name").and_then(|n| n.as_str()) {
                Some(n) => n.to_string(),
                None => {
                    if let Some(idx) = pkg_path.rfind("node_modules/") {
                        pkg_path[idx + 13..].to_string()
                    } else {
                        pkg_path.rsplit('/').next().unwrap_or(pkg_path).to_string()
                    }
                }
            };

            let Some(version) = pkg_data.get("version").and_then(|v| v.as_str()) else {
                continue;
            };

            let purl = format!("pkg:npm/{}@{}", name, version);
            let valid_purl = Dependency::auto_fix_and_validate_purl(&purl);

            // 【核心修复 2】：拿 (纯PURL + lock物理路径 + 内部node_modules挂载点) 派生绝对ID
            let combined_salt = format!("{}:{}", file_salt, pkg_path);
            let instance_id = make_instance_id(&valid_purl, &combined_salt);

            path_to_id.insert(pkg_path.clone(), instance_id.clone());

            let mut dep_names = Vec::new();
            if let Some(deps) = pkg_data.get("dependencies").and_then(|d| d.as_object()) {
                dep_names.extend(deps.keys().cloned());
            }

            nodes.push(RawNode {
                pkg_path: pkg_path.clone(),
                name,
                version: version.to_string(),
                purl: valid_purl,
                instance_id,
                dep_names,
            });
        }

        // =================================================================
        // 第二趟：转译 DAG 边（复现 Node.js 原生寻址规范）
        // =================================================================
        let mut final_deps = Vec::with_capacity(nodes.len());

        for node in nodes {
            let mut child_ids = Vec::with_capacity(node.dep_names.len());

            for d_name in &node.dep_names {
                // 调用官方模块寻址模拟器
                if let Some(target_id) = Self::resolve_npm_dep(&node.pkg_path, d_name, &path_to_id)
                {
                    child_ids.push(target_id.clone());
                } else {
                    eprintln!(
                        "⚠️ [NPM连线悬空] 在 {} 下未找到子依赖 {} 的物理节点",
                        node.pkg_path, d_name
                    );
                }
            }

            if let Ok(dep) = DependencyBuilder::default()
                .name(node.name)
                .version(Some(node.version))
                .r#type(DependencyType::Library)
                .purl(node.purl)
                .instance_id(node.instance_id) // 👈 自身ID稳稳落盘
                .dependencies(child_ids) // 👈 连线的是寻址到的子ID
                .location(None)
                .build()
            {
                final_deps.push(dep);
            }
        }

        Ok(final_deps)
    }

    /// 🚀 【神技】：纯内存模拟 Node.js 原生 `node_modules` 向上递归寻址规范
    fn resolve_npm_dep<'a>(
        caller_pkg_path: &str,
        dep_name: &str,
        path_to_id: &'a HashMap<String, String>,
    ) -> Option<&'a String> {
        let mut curr = caller_pkg_path;

        loop {
            // 拼装当前层级的候选挂载路径
            let candidate = if curr.is_empty() {
                format!("node_modules/{}", dep_name)
            } else {
                format!("{}/node_modules/{}", curr, dep_name)
            };

            // 1. 如果在当前领地摸到了，立刻命中返回！
            if let Some(id) = path_to_id.get(&candidate) {
                return Some(id);
            }

            if curr.is_empty() {
                break; // 已经溯源到了根目录 node_modules 依然没找到，彻底宣告悬空
            }

            // 2. 剥离当前领地，往上一级 node_modules 作用域回溯
            if let Some(idx) = curr.rfind("/node_modules/") {
                curr = &curr[..idx];
            } else {
                curr = ""; // 比如从 "packages/sub-a" 直接一步跳回根目录 ""
            }
        }

        None
    }
}
