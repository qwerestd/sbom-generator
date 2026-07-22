use lazy_static::lazy_static;
use regex::Regex;
use serde::Deserialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use tree_sitter::{Language, Parser, Query, QueryCursor};

use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyType};
use crate::utils::file_utils::make_instance_id;

#[derive(Clone, Default)]
pub struct GradleProducer {}

/// 用于在解析阶段临时存储提取到的依赖信息
struct ExtractedDep {
    group: String,
    name: String,
    version: String,
}

impl SbomProducer for GradleProducer {
    fn use_file(&self, path: &Path, _config: &SbomProducerConfiguration) -> bool {
        path.file_name()
            .and_then(|name| name.to_str())
            .map(|name| {
                name == "build.gradle.kts"
                    || name == "build.gradle"
                    || name == "libs.versions.toml"
                    || name.ends_with("gradle.lockfile")
            })
            .unwrap_or(false)
    }

    fn find_dependencies(
        &self,
        paths: &[PathBuf],
        _config: &SbomProducerConfiguration,
    ) -> anyhow::Result<Vec<Dependency>> {
        let mut all_dependencies = Vec::new();

        for path in paths {
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let content = match fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            // 1. 将当前文件的物理路径标准 POSIX 化作为绝对隔离盐
            let file_salt = path.to_string_lossy().replace('\\', "/");

            // 提取平铺的依赖声明或锁定版本
            let extracted_deps = match file_name {
                name if name.ends_with(".gradle.kts") => {
                    Self::parse_kotlin_dependencies(&content).unwrap_or_default()
                }
                name if name.ends_with(".gradle") => {
                    Self::parse_groovy_dependencies(&content).unwrap_or_default()
                } // 👈 路由到正则解析器
                "libs.versions.toml" => Self::parse_version_catalog(&content).unwrap_or_default(),
                name if name.ends_with("gradle.lockfile") => {
                    Self::parse_gradle_lockfile(&content).unwrap_or_default()
                }
                _ => vec![],
            };

            if extracted_deps.is_empty() {
                continue;
            }

            // 按照标准 4-pass 图处理架构构建依赖
            let file_deps = Self::build_dependency_graph(extracted_deps, &file_salt)?;
            all_dependencies.extend(file_deps);
        }

        Ok(all_dependencies)
    }
}

impl GradleProducer {
    /// 标准四趟图处理架构：分配ID -> 构建边与入度 -> BFS可达性分析 -> 组装实体
    fn build_dependency_graph(
        extracted_deps: Vec<ExtractedDep>,
        file_salt: &str,
    ) -> anyhow::Result<Vec<Dependency>> {
        struct RawNode {
            name: String,
            version: String,
            purl: String,
            instance_id: String,
            raw_deps: Vec<String>,
        }

        let mut nodes = Vec::with_capacity(extracted_deps.len());

        let mut exact_map: HashMap<(String, String), String> = HashMap::new();
        let mut single_map: HashMap<String, String> = HashMap::new();
        let mut id_to_name: HashMap<String, String> = HashMap::new();

        // =================================================================
        // 第一趟：双索引映射表构建，分配物理隔离 ID
        // =================================================================
        for dep in extracted_deps {
            let full_name = format!("{}:{}", dep.group, dep.name);
            let raw_purl = format!("pkg:maven/{}@{}", full_name.replace(':', "/"), dep.version);
            let valid_purl = Dependency::auto_fix_and_validate_purl(&raw_purl);
            let instance_id = make_instance_id(&valid_purl, file_salt);

            let raw_deps: Vec<String> = vec![];

            exact_map.insert(
                (full_name.clone(), dep.version.clone()),
                instance_id.clone(),
            );
            single_map.insert(full_name.clone(), instance_id.clone());
            id_to_name.insert(instance_id.clone(), full_name.clone());

            nodes.push(RawNode {
                name: full_name,
                version: dep.version,
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
            in_degree.insert(node.instance_id.clone(), 0);
        }

        for node in &nodes {
            let mut child_ids = Vec::with_capacity(node.raw_deps.len());

            for d_name in &node.raw_deps {
                let target_id = single_map.get(d_name).cloned();

                if let Some(id) = target_id {
                    child_ids.push(id.clone());
                    *in_degree.entry(id).or_insert(0) += 1;
                }
            }
            id_to_children.insert(node.instance_id.clone(), child_ids);
        }

        // =================================================================
        // 第三趟：自动提取根节点并执行 BFS 可达性分析
        // =================================================================
        let mut queue: VecDeque<String> = VecDeque::new();
        let mut reachable_ids: HashSet<String> = HashSet::new();

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
        // 第四趟：生成最终的纯净依赖
        // =================================================================
        let mut final_deps = Vec::with_capacity(nodes.len());

        for node in nodes {
            if !reachable_ids.contains(&node.instance_id) {
                continue;
            }

            let valid_child_ids: Vec<String> = id_to_children
                .get(&node.instance_id)
                .unwrap_or(&vec![])
                .iter()
                .filter(|cid| reachable_ids.contains(*cid))
                .cloned()
                .collect();

            if let Ok(dep) = DependencyBuilder::default()
                .name(node.name)
                .version(Some(node.version))
                .r#type(DependencyType::Library)
                .purl(node.purl)
                .instance_id(node.instance_id)
                .dependencies(valid_child_ids)
                .location(None)
                .build()
            {
                final_deps.push(dep);
            }
        }

        Ok(final_deps)
    }

    // ----------------------------------------------------------------------------------
    // 以下为特定语法提取器 (Tree-Sitter, TOML, Regex & Lockfile)
    // ----------------------------------------------------------------------------------

    /// 解析 Groovy DSL (`build.gradle`) [已降级为安全正则匹配]
    fn parse_groovy_dependencies(content: &str) -> anyhow::Result<Vec<ExtractedDep>> {
        lazy_static! {
            // 匹配格式如: implementation 'group:name:version' 或 compileOnly("group:name:version")
            static ref GROOVY_DEP_RE: Regex = Regex::new(
                r#"(?x)
                (?:api|implementation|compileOnly|runtimeOnly|testImplementation|testCompile)
                \s*\(?\s*
                ['"]([^'"]+:[^'"]+:[^'"]+)['"]
                \s*\)?
                "#
            ).unwrap();
        }

        let mut deps = Vec::new();

        for cap in GROOVY_DEP_RE.captures_iter(content) {
            if let Some(match_str) = cap.get(1) {
                let parts: Vec<&str> = match_str.as_str().split(':').collect();

                // 确保分为 3 段 (group:name:version)，且剔除含 '$' 的动态变量插值
                if parts.len() == 3 && !parts[2].contains('$') {
                    deps.push(ExtractedDep {
                        group: parts[0].to_string(),
                        name: parts[1].to_string(),
                        version: parts[2].to_string(),
                    });
                }
            }
        }

        Ok(deps)
    }

    /// 使用 Tree-sitter 解析 Kotlin DSL (`build.gradle.kts`)
    fn parse_kotlin_dependencies(content: &str) -> anyhow::Result<Vec<ExtractedDep>> {
        let language = tree_sitter_kotlin::language();
        let query_str = r#"
            (call_expression
                (simple_identifier) @config
                (#match? @config "^(api|implementation|compileOnly|runtimeOnly|testImplementation|testCompile)$")
                (call_suffix
                    (value_arguments
                        (value_argument
                            (line_string_literal
                                (line_string_content) @dep_string
                            )
                        )
                    )
                )
            )
        "#;
        Self::execute_tree_sitter_query(content, language, query_str)
    }

    /// 通用的 Tree-sitter 查询与数据提取引擎
    fn execute_tree_sitter_query(
        content: &str,
        language: Language,
        query_str: &str,
    ) -> anyhow::Result<Vec<ExtractedDep>> {
        let mut deps = Vec::new();
        let mut parser = Parser::new();
        parser.set_language(&language)?;

        let tree = parser
            .parse(content, None)
            .ok_or_else(|| anyhow::anyhow!("Failed to parse AST"))?;
        let root_node = tree.root_node();

        let query = Query::new(&language, query_str)?;
        let mut cursor = QueryCursor::new();
        let matches = cursor.matches(&query, root_node, content.as_bytes());

        for m in matches {
            for cap in m.captures {
                if query.capture_names()[cap.index as usize] == "dep_string" {
                    let node = cap.node;
                    let dep_str = &content[node.start_byte()..node.end_byte()];
                    let parts: Vec<&str> = dep_str.split(':').collect();

                    if parts.len() == 3 && !parts[2].contains('$') {
                        deps.push(ExtractedDep {
                            group: parts[0].to_string(),
                            name: parts[1].to_string(),
                            version: parts[2].to_string(),
                        });
                    }
                }
            }
        }
        Ok(deps)
    }

    /// 解析 Gradle Lockfile 纯文本 (格式: group:name:version=config1,config2)
    fn parse_gradle_lockfile(content: &str) -> anyhow::Result<Vec<ExtractedDep>> {
        let mut deps = Vec::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("empty=") {
                continue;
            }

            if let Some((module_str, _configs)) = line.split_once('=') {
                let parts: Vec<&str> = module_str.split(':').collect();
                if parts.len() == 3 {
                    deps.push(ExtractedDep {
                        group: parts[0].to_string(),
                        name: parts[1].to_string(),
                        version: parts[2].to_string(),
                    });
                }
            }
        }

        Ok(deps)
    }

    /// 解析 libs.versions.toml (纯 TOML 解析)
    fn parse_version_catalog(content: &str) -> anyhow::Result<Vec<ExtractedDep>> {
        #[derive(Deserialize)]
        struct VersionCatalog {
            versions: Option<toml::Table>,
            libraries: Option<toml::Table>,
        }

        let catalog: VersionCatalog = toml::from_str(content)?;
        let mut deps = Vec::new();

        if let Some(libraries) = catalog.libraries {
            for (_key, value) in libraries {
                if let Some(table) = value.as_table() {
                    if let (Some(module), Some(version_ref)) =
                        (table.get("module"), table.get("version.ref"))
                    {
                        if let (Some(module_str), Some(v_ref_str)) =
                            (module.as_str(), version_ref.as_str())
                        {
                            let parts: Vec<&str> = module_str.split(':').collect();
                            if parts.len() == 2 {
                                let resolved_version = catalog
                                    .versions
                                    .as_ref()
                                    .and_then(|v| v.get(v_ref_str))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or(v_ref_str);

                                deps.push(ExtractedDep {
                                    group: parts[0].to_string(),
                                    name: parts[1].to_string(),
                                    version: resolved_version.to_string(),
                                });
                            }
                        }
                    }
                } else if let Some(dep_str) = value.as_str() {
                    let parts: Vec<&str> = dep_str.split(':').collect();
                    if parts.len() == 3 {
                        deps.push(ExtractedDep {
                            group: parts[0].to_string(),
                            name: parts[1].to_string(),
                            version: parts[2].to_string(),
                        });
                    }
                }
            }
        }
        Ok(deps)
    }
}
