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

        // 3. 构建依赖的边关系（收集所有依赖，不再过滤 dev 和 build）
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
                            // 直接提取所有的子依赖 ID，不论其属于 normal、dev 还是 build
                            if let Some(cid) = dep_obj.get("pkg").and_then(|p| p.as_str()) {
                                child_ids.push(cid.to_string());
                            }
                        }
                    }
                    id_to_child_ids.insert(parent_id.to_string(), child_ids);
                }
            }
        }

        // 4. 可达性分析 (BFS)
        // 从根节点出发，顺着所有的依赖路径往下找
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

        for id in &reachable_ids {
            if let Some(meta) = id_to_meta.get(id) {
                let mut edge_instance_ids = vec![];

                if let Some(children) = id_to_child_ids.get(id) {
                    for child_id in children {
                        if reachable_ids.contains(child_id) {
                            if let Some(child_meta) = id_to_meta.get(child_id) {
                                // 收集所有相连的子节点
                                edge_instance_ids.push(child_meta.instance_id.clone());
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
                    .dependencies(edge_instance_ids)
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
