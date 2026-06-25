use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyType};
use anyhow::Context;
use cargo_metadata::{DependencyKind, MetadataCommand};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Clone, Default)]
pub struct CargoProducer {}

impl SbomProducer for CargoProducer {
    fn use_file(&self, path: &Path, _config: &SbomProducerConfiguration) -> bool {
        path.file_name()
            .map(|name| name == "Cargo.toml")
            .unwrap_or(false)
    }

    fn find_dependencies(
        &self,
        paths: &[PathBuf],
        _config: &SbomProducerConfiguration,
    ) -> anyhow::Result<Vec<Dependency>> {
        let mut all_dependencies = Vec::new();

        for single_path in paths {
            // [1. 元数据提取]
            let metadata = MetadataCommand::new()
                .manifest_path(single_path)
                .exec()
                .with_context(|| {
                    format!("Failed to execute cargo metadata on {:?}", single_path)
                })?;

            let resolve = metadata
                .resolve
                .as_ref()
                .context("No dependency resolve graph found in Cargo metadata")?;

            // [2. 拓扑图剪枝]
            let mut runtime_deps = HashSet::new();
            let mut queue = Vec::new();

            for root in &metadata.workspace_members {
                runtime_deps.insert(root.clone());
                queue.push(root.clone());
            }

            let node_map: HashMap<_, _> = resolve.nodes.iter().map(|n| (&n.id, n)).collect();

            while let Some(node_id) = queue.pop() {
                if let Some(node) = node_map.get(&node_id) {
                    for edge in &node.deps {
                        let is_runtime = edge
                            .dep_kinds
                            .iter()
                            .any(|k| k.kind != DependencyKind::Development);

                        if is_runtime && runtime_deps.insert(edge.pkg.clone()) {
                            queue.push(edge.pkg.clone());
                        }
                    }
                }
            }

            // --- 【新增步骤：建立 PackageId 到 PURL 的映射表】 ---
            // 因为在找子依赖时，我们手里只有 PackageId，但 SBOM 规范需要存 PURL
            let mut id_to_purl = HashMap::new();
            for pkg in &metadata.packages {
                let purl = format!("pkg:cargo/{}@{}", pkg.name, pkg.version);
                id_to_purl.insert(pkg.id.clone(), purl);
            }
            // ------------------------------------------------------

            // [3. 组装组件模型]
            let mut single_file_dependencies = Vec::new();

            for pkg in &metadata.packages {
                if !runtime_deps.contains(&pkg.id) {
                    continue;
                }

                // 注意：由于当前逻辑排除了 workspace_members 本身（只作为根，不作为依赖），
                // 这个行为保持原样。
                if metadata.workspace_members.contains(&pkg.id) {
                    continue;
                }

                let mut builder = DependencyBuilder::default();

                builder.name(pkg.name.to_string());
                builder.version(Some(pkg.version.to_string()));
                builder.r#type(DependencyType::Library);

                let purl = format!("pkg:cargo/{}@{}", pkg.name, pkg.version);
                builder.purl(purl.clone()); // 克隆一下，下面还要用

                // --- 【新增步骤：提取当前组件的依赖关系图】 ---
                let mut child_dependencies = Vec::new();

                // 从拓扑节点中找到当前组件
                if let Some(node) = node_map.get(&pkg.id) {
                    // 遍历它所指向的下级边
                    for edge in &node.deps {
                        // 过滤规则必须与顶层一致：排除开发依赖
                        let is_runtime = edge
                            .dep_kinds
                            .iter()
                            .any(|k| k.kind != DependencyKind::Development);

                        // 如果该子包是运行时依赖，且存在于我们之前筛选好的有效集合中
                        if is_runtime && runtime_deps.contains(&edge.pkg) {
                            // 通过 ID 查出子包的 PURL 并放入数组
                            if let Some(child_purl) = id_to_purl.get(&edge.pkg) {
                                child_dependencies.push(child_purl.clone());
                            }
                        }
                    }
                }

                builder.dependencies(child_dependencies);

                if let Ok(dep) = builder.build() {
                    single_file_dependencies.push(dep);
                }
            }

            all_dependencies.extend(single_file_dependencies);
        }

        Ok(all_dependencies)
    }
}
