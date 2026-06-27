use crate::analyze::producers::dynamic_producer::DynamicProducer;
use crate::model::configuration::Configuration;
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyType};
use crate::utils::file_utils::make_instance_id;
use std::collections::{HashMap, HashSet, VecDeque}; // 👈 新增 HashSet 和 VecDeque 用于图遍历
use std::path::PathBuf;
use std::process::Command;

#[derive(Default)]
pub struct CargoDynamicProducer {}

impl DynamicProducer for CargoDynamicProducer {
    fn is_applicable(&self, configuration: &Configuration) -> bool {
        let mut path = PathBuf::from(&configuration.directory);
        path.push("Cargo.toml");
        path.exists()
    }

    fn detect_dependencies(
        &self,
        configuration: &Configuration,
    ) -> anyhow::Result<Vec<Dependency>> {
        let mut cmd = Command::new("cargo");
        cmd.args(["metadata", "--format-version=1", "--all-features"])
            .current_dir(&configuration.directory);

        let output = cmd.output()?;

        if !output.status.success() {
            let stderr_str = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("Cargo metadata 执行失败: {}", stderr_str));
        }

        let stdout_str = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value = serde_json::from_str(&stdout_str)?;

        struct PkgMeta {
            name: String,
            version: String,
            purl: String,
            instance_id: String,
        }

        let mut id_to_meta: HashMap<String, PkgMeta> = HashMap::new();

        // 1. 获取所有项目实体信息
        if let Some(packages) = json.get("packages").and_then(|p| p.as_array()) {
            for pkg in packages {
                if let (Some(id), Some(name), Some(version)) = (
                    pkg.get("id").and_then(|i| i.as_str()),
                    pkg.get("name").and_then(|n| n.as_str()),
                    pkg.get("version").and_then(|v| v.as_str()),
                ) {
                    let raw_purl = format!("pkg:cargo/{}@{}", name, version);
                    let valid_purl = Dependency::auto_fix_and_validate_purl(&raw_purl);
                    let instance_id = make_instance_id(&valid_purl, id);

                    id_to_meta.insert(
                        id.to_string(),
                        PkgMeta {
                            name: name.to_string(),
                            version: version.to_string(),
                            purl: valid_purl,
                            instance_id,
                        },
                    );
                }
            }
        }

        // 2. 提取工作区根节点 (Workspace Members) —— 这是溯源的起点
        let mut workspace_members: Vec<String> = vec![];
        if let Some(members) = json.get("workspace_members").and_then(|m| m.as_array()) {
            workspace_members = members
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
        }

        // 3. 构建“核心运行时”的边关系 (过滤掉 dev 和 build 依赖)
        let mut id_to_child_ids: HashMap<String, Vec<String>> = HashMap::new();

        if let Some(nodes) = json
            .get("resolve")
            .and_then(|r| r.get("nodes"))
            .and_then(|n| n.as_array())
        {
            for node in nodes {
                if let Some(parent_id) = node.get("id").and_then(|i| i.as_str()) {
                    let mut child_ids = vec![];

                    if let Some(deps) = node.get("deps").and_then(|d| d.as_array()) {
                        for dep_obj in deps {
                            // 👈 【核心过滤】判断是否为普通运行时依赖
                            // Cargo 规定: kind == null 为运行时 normal 依赖
                            let is_runtime = dep_obj
                                .get("dep_kinds")
                                .and_then(|k| k.as_array())
                                .map(|kinds| {
                                    kinds.iter().any(|k| {
                                        let kind = k.get("kind");
                                        kind.is_none()
                                            || kind.unwrap().is_null()
                                            || kind.unwrap().as_str() == Some("normal")
                                    })
                                })
                                .unwrap_or(true); // 如果没有 dep_kinds，保守判定为 runtime

                            if !is_runtime {
                                continue; // 坚决丢弃宏依赖、构建辅助依赖、测试依赖
                            }

                            if let Some(cid) = dep_obj.get("pkg").and_then(|p| p.as_str()) {
                                child_ids.push(cid.to_string());
                            }
                        }
                    }
                    id_to_child_ids.insert(parent_id.to_string(), child_ids);
                }
            }
        }

        // 4. 【精髓升级】可达性分析 (BFS)
        // 从根节点出发，只顺着 Runtime 的路径往下找，找到的才算是真正的组件
        let mut reachable_ids: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<String> = VecDeque::new();

        for member_id in workspace_members {
            reachable_ids.insert(member_id.clone());
            queue.push_back(member_id);
        }

        while let Some(current_id) = queue.pop_front() {
            if let Some(children) = id_to_child_ids.get(&current_id) {
                for child_id in children {
                    if !reachable_ids.contains(child_id) {
                        reachable_ids.insert(child_id.clone());
                        queue.push_back(child_id.clone());
                    }
                }
            }
        }

        // 5. 组装最终结果
        let mut final_deps = vec![];

        // 💡 保持与静态解析器完全一致的强力噪音特征黑名单
        let is_trivy_ignored_noise = |name: &str| -> bool {
            if name.starts_with("windows_") || name.starts_with("windows-") || name == "winapi" {
                return true;
            }
            let macro_tools = [
                "syn",
                "quote",
                "proc-macro2",
                "synstructure",
                "unicode-ident",
                "heck",
                "autocfg",
                "version_check",
                "cc",
                "pkg-config",
            ];
            if macro_tools.contains(&name) || name.contains("-macro") || name.contains("macro-") {
                return true;
            }
            let test_tools = [
                "pretty_assertions",
                "tempfile",
                "trybuild",
                "assert_cmd",
                "assert_fs",
                "criterion",
                "criterion-plot",
                "env_logger",
                "tracing-subscriber",
            ];
            if test_tools.contains(&name) {
                return true;
            }
            false
        };

        for id in &reachable_ids {
            if let Some(meta) = id_to_meta.get(id) {
                // 🚀 1. 如果自身命中了 Trivy 黑名单（噪音节点），直接丢弃
                if is_trivy_ignored_noise(&meta.name) {
                    continue;
                }

                let mut edge_instance_ids = vec![];

                if let Some(children) = id_to_child_ids.get(id) {
                    for child_id in children {
                        if reachable_ids.contains(child_id) {
                            if let Some(child_meta) = id_to_meta.get(child_id) {
                                // 🚀 2. 在子依赖连线中，同步切断指向噪音节点的边
                                if !is_trivy_ignored_noise(&child_meta.name) {
                                    edge_instance_ids.push(child_meta.instance_id.clone());
                                }
                            }
                        }
                    }
                }

                if let Ok(dep) = DependencyBuilder::default()
                    .name(meta.name.clone())
                    .version(Some(meta.version.clone()))
                    .r#type(DependencyType::Library)
                    .purl(meta.purl.clone())
                    .instance_id(meta.instance_id.clone())
                    .dependencies(edge_instance_ids) // 👈 纯净的子边
                    .location(None)
                    .build()
                {
                    final_deps.push(dep);
                }
            }
        }

        Ok(final_deps)
    }
}
