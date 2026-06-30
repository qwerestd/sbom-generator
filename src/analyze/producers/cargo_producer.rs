use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyType};
use crate::utils::file_utils::make_instance_id;

#[derive(Clone, Default)]
pub struct CargoProducer {}

impl SbomProducer for CargoProducer {
    fn use_file(&self, path: &Path, _config: &SbomProducerConfiguration) -> bool {
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

            // 1. 将当前锁文件的物理路径标准 POSIX 化作为绝对隔离盐
            let file_salt = lock_path.to_string_lossy().replace('\\', "/");

            let file_deps = Self::parse_cargo_lock(&content, &file_salt)?;
            all_dependencies.extend(file_deps);
        }

        Ok(all_dependencies)
    }
}

impl CargoProducer {
    fn parse_cargo_lock(content: &str, file_salt: &str) -> anyhow::Result<Vec<Dependency>> {
        let lock_toml: toml::Value = toml::from_str(content)?;

        let Some(packages) = lock_toml.get("package").and_then(|p| p.as_array()) else {
            return Ok(vec![]);
        };

        struct RawNode {
            name: String,
            version: String,
            purl: String,
            instance_id: String,
            raw_deps: Vec<String>,
        }

        let mut nodes = Vec::with_capacity(packages.len());

        let mut exact_map: HashMap<(&str, &str), String> = HashMap::new();
        let mut single_map: HashMap<&str, String> = HashMap::new();
        let mut id_to_name: HashMap<String, String> = HashMap::new();

        // =================================================================
        // 第一趟：双索引映射表构建，分配物理隔离 ID
        // =================================================================
        for pkg in packages {
            let Some(name) = pkg.get("name").and_then(|n| n.as_str()) else {
                continue;
            };
            let Some(version) = pkg.get("version").and_then(|v| v.as_str()) else {
                continue;
            };

            let raw_purl = format!("pkg:cargo/{}@{}", name, version);
            let valid_purl = Dependency::auto_fix_and_validate_purl(&raw_purl);
            let instance_id = make_instance_id(&valid_purl, file_salt);

            let mut raw_deps = vec![];
            if let Some(deps) = pkg.get("dependencies").and_then(|d| d.as_array()) {
                for d_val in deps {
                    if let Some(d_str) = d_val.as_str() {
                        raw_deps.push(d_str.to_string());
                    }
                }
            }

            exact_map.insert((name, version), instance_id.clone());
            single_map.insert(name, instance_id.clone());
            id_to_name.insert(instance_id.clone(), name.to_string());

            nodes.push(RawNode {
                name: name.to_string(),
                version: version.to_string(),
                purl: valid_purl,
                instance_id,
                raw_deps,
            });
        }

        // =================================================================
        // 第二趟：连线并计算“入度(In-Degree)”以自动发现根节点
        // =================================================================
        let mut id_to_children: HashMap<String, Vec<String>> = HashMap::new();
        let mut in_degree: HashMap<String, usize> = HashMap::new();

        for node in &nodes {
            in_degree.insert(node.instance_id.clone(), 0); // 初始化
        }

        for node in &nodes {
            let mut child_ids = Vec::with_capacity(node.raw_deps.len());

            for dep_expr in &node.raw_deps {
                let mut iter = dep_expr.split_whitespace();
                let d_name = iter.next().unwrap_or("");
                let second_token = iter.next();

                let target_id = match second_token {
                    Some(ver) if !ver.starts_with('(') => exact_map.get(&(d_name, ver)).cloned(),
                    _ => single_map.get(d_name).cloned(),
                };

                if let Some(id) = target_id {
                    child_ids.push(id.clone());
                    *in_degree.entry(id).or_insert(0) += 1; // 目标节点被依赖，入度 +1
                }
            }
            id_to_children.insert(node.instance_id.clone(), child_ids);
        }

        // =================================================================
        // 第三趟：自动提取根节点并执行 BFS 可达性分析
        // =================================================================
        let mut queue: VecDeque<String> = VecDeque::new();
        let mut reachable_ids: HashSet<String> = HashSet::new();

        // 将所有入度为 0 的节点（即工作区根项目）送入队列
        for (id, deg) in &in_degree {
            if *deg == 0 {
                reachable_ids.insert(id.clone());
                queue.push_back(id.clone());
            }
        }

        while let Some(current) = queue.pop_front() {
            if let Some(children) = id_to_children.get(&current) {
                for child in children {
                    if !reachable_ids.contains(child) {
                        reachable_ids.insert(child.clone());
                        queue.push_back(child.clone());
                    }
                }
            }
        }

        // =================================================================
        // 第四趟：生成最终的纯净依赖（移除黑名单过滤，保留所有组件）
        // =================================================================
        let mut final_deps = Vec::with_capacity(nodes.len());

        for node in nodes {
            // 1. 如果不可达（孤岛节点），直接丢弃
            if !reachable_ids.contains(&node.instance_id) {
                continue;
            }

            // 2. 收集所有可达子节点的连接（移除了根据名字过滤逻辑，保留所有边）
            let valid_child_ids: Vec<String> = id_to_children
                .get(&node.instance_id)
                .unwrap_or(&vec![])
                .iter()
                .filter(|cid| reachable_ids.contains(*cid)) // 必须可达
                .cloned()
                .collect();

            if let Ok(dep) = DependencyBuilder::default()
                .name(node.name)
                .version(Some(node.version))
                .r#type(DependencyType::Library)
                .purl(node.purl)
                .instance_id(node.instance_id)
                .dependencies(valid_child_ids) // 👈 包含所有的子边
                .location(None)
                .build()
            {
                final_deps.push(dep);
            }
        }

        Ok(final_deps)
    }
}
