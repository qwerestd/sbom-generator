use std::collections::{HashMap, HashSet, VecDeque};

use crate::model::dependency::{Dependency, DependencyBuilder, DependencyLocation, DependencyType};
use crate::utils::file_utils::make_instance_id;

/// 通用 4-Pass 图算法输入节点
#[derive(Clone, Debug)]
pub struct RawGraphNode {
    pub group: Option<String>,
    pub name: String,
    pub version: Option<String>,
    pub purl: String,
    pub instance_id: String,
    /// 声明的依赖项表达式：支持 `(dep_key, Option<dep_version>)` 双索引匹配
    pub raw_deps: Vec<(String, Option<String>)>,
    /// 在索引表中注册的键名（如 Cargo 的 `serde`、Maven/Gradle 的 `group:artifact`、Python 的 PEP503 规范名）
    pub lookup_key: String,
    /// 是否强制标记为工程根节点（Application）
    pub force_root: bool,
    pub location: Option<DependencyLocation>,
}

/// 通用四趟图处理引擎（推广自 Cargo / Gradle / Go 的 4-Pass 架构）：
/// - 第一趟：构建 `(lookup_key, version)` 精确索引与 `lookup_key` 单键索引
/// - 第二趟：连线有向边并统计每个节点的入度 (`In-Degree`)
/// - 第三趟：从所有根节点（`force_root` 或 `in_degree == 0`）出发执行 BFS 可达性剪枝
/// - 第四趟：组装隔离的 `Dependency` 实体，自动区分 `Application` 与 `Library`
pub fn build_reachable_dag(nodes: Vec<RawGraphNode>) -> Vec<Dependency> {
    if nodes.is_empty() {
        return vec![];
    }

    let mut exact_map: HashMap<(String, String), String> = HashMap::with_capacity(nodes.len());
    let mut single_map: HashMap<String, String> = HashMap::with_capacity(nodes.len());

    // 第一趟：构建双索引表
    for node in &nodes {
        if let Some(ref ver) = node.version {
            exact_map.insert(
                (node.lookup_key.clone(), ver.clone()),
                node.instance_id.clone(),
            );
        }
        single_map.insert(node.lookup_key.clone(), node.instance_id.clone());
    }

    // 第二趟：连线并计算入度
    let mut id_to_children: HashMap<String, Vec<String>> = HashMap::with_capacity(nodes.len());
    let mut in_degree: HashMap<String, usize> = HashMap::with_capacity(nodes.len());

    for node in &nodes {
        in_degree.insert(node.instance_id.clone(), 0);
    }

    for node in &nodes {
        let mut child_ids = Vec::with_capacity(node.raw_deps.len());
        let mut seen_edges = HashSet::new();

        for (dep_key, dep_ver_opt) in &node.raw_deps {
            let target_id = match dep_ver_opt {
                Some(ver) if !ver.is_empty() => exact_map
                    .get(&(dep_key.clone(), ver.clone()))
                    .or_else(|| single_map.get(dep_key))
                    .cloned(),
                _ => single_map.get(dep_key).cloned(),
            };

            if let Some(cid) = target_id {
                if cid != node.instance_id && seen_edges.insert(cid.clone()) {
                    child_ids.push(cid.clone());
                    *in_degree.entry(cid).or_insert(0) += 1;
                }
            }
        }

        id_to_children.insert(node.instance_id.clone(), child_ids);
    }

    // 第三趟：BFS 可达性分析
    let mut queue: VecDeque<String> = VecDeque::new();
    let mut reachable_ids: HashSet<String> = HashSet::new();

    // 若存在显式指定的 force_root 节点，优先仅从 force_root 出发剪枝孤岛包（例如 pip inspect 环境中的无关包）；
    // 否则从所有入度为 0 的节点出发。
    let has_explicit_roots = nodes.iter().any(|n| n.force_root);
    for node in &nodes {
        let is_start = if has_explicit_roots {
            node.force_root
        } else {
            in_degree.get(&node.instance_id).copied().unwrap_or(0) == 0
        };

        if is_start && reachable_ids.insert(node.instance_id.clone()) {
            queue.push_back(node.instance_id.clone());
        }
    }

    while let Some(current) = queue.pop_front() {
        if let Some(children) = id_to_children.get(&current) {
            for child in children {
                if reachable_ids.insert(child.clone()) {
                    queue.push_back(child.clone());
                }
            }
        }
    }

    // 第四趟：组装最终依赖列表
    let mut final_deps = Vec::with_capacity(reachable_ids.len());
    for node in nodes {
        if !reachable_ids.contains(&node.instance_id) {
            continue;
        }

        let valid_children: Vec<String> = id_to_children
            .get(&node.instance_id)
            .map(|children| {
                children
                    .iter()
                    .filter(|cid| reachable_ids.contains(*cid))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();

        let is_root =
            node.force_root || in_degree.get(&node.instance_id).copied().unwrap_or(0) == 0;
        let dep_type = if is_root {
            DependencyType::Application
        } else {
            DependencyType::Library
        };

        if let Ok(dep) = DependencyBuilder::default()
            .group(node.group)
            .name(node.name)
            .version(node.version)
            .r#type(dep_type)
            .purl(node.purl)
            .instance_id(node.instance_id)
            .dependencies(valid_children)
            .location(node.location)
            .build()
        {
            final_deps.push(dep);
        }
    }

    final_deps
}

/// 推广自 Maven `parse_ascii_tree` 的通用单调栈树形拓扑构建器。
/// 适用于任意通过缩进层级表达父子依赖树的 CLI 输出（如 `mvn dependency:tree`、`gradle dependencies` 等）。
pub struct AsciiTreeStackBuilder {
    deps_map: HashMap<String, Dependency>,
    parent_stack: Vec<String>,
    current_scope_salt: String,
}

impl AsciiTreeStackBuilder {
    pub fn new(initial_salt: impl Into<String>) -> Self {
        Self {
            deps_map: HashMap::new(),
            parent_stack: Vec::new(),
            current_scope_salt: initial_salt.into(),
        }
    }

    /// 当 `switch_scope_at_root` 为 true 时（如 Maven 多模块树），每次遇到 `depth == 0` 自动切换作用域盐
    pub fn push_node(
        &mut self,
        depth: usize,
        group: Option<String>,
        name: String,
        version: String,
        raw_purl: &str,
        switch_scope_at_root: bool,
    ) -> String {
        let valid_purl = Dependency::auto_fix_and_validate_purl(raw_purl);

        if depth == 0 && switch_scope_at_root {
            self.current_scope_salt = valid_purl.clone();
        }

        let instance_id = make_instance_id(&valid_purl, &self.current_scope_salt);

        self.parent_stack.truncate(depth);
        if let Some(parent_id) = self.parent_stack.last() {
            if let Some(parent_dep) = self.deps_map.get_mut(parent_id) {
                if !parent_dep.dependencies.contains(&instance_id) && parent_id != &instance_id {
                    parent_dep.dependencies.push(instance_id.clone());
                }
            }
        }
        self.parent_stack.push(instance_id.clone());

        let dep_type = if depth == 0 {
            DependencyType::Application
        } else {
            DependencyType::Library
        };

        self.deps_map
            .entry(instance_id.clone())
            .or_insert_with(|| Dependency {
                group,
                r#type: dep_type,
                name,
                version: Some(version),
                purl: valid_purl,
                instance_id: instance_id.clone(),
                dependencies: Vec::new(),
                location: None,
                license: None,
            });

        instance_id
    }

    pub fn into_dependencies(self) -> Vec<Dependency> {
        self.deps_map.into_values().collect()
    }
}
