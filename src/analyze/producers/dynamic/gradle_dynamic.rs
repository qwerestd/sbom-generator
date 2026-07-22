use lazy_static::lazy_static;
use regex::Regex;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::process::Command;

use crate::analyze::producers::dynamic_producer::DynamicProducer;
use crate::model::configuration::Configuration;
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyType};
use crate::utils::file_utils::make_instance_id;

#[derive(Clone, Default)]
pub struct GradleDynamicProducer {}

/// 用于在解析阶段临时存储提取到的依赖信息
struct ExtractedDep {
    group: String,
    name: String,
    version: String,
}

impl DynamicProducer for GradleDynamicProducer {
    fn is_applicable(&self, configuration: &Configuration) -> bool {
        // 动态探针是基于目录级别的，检查项目根目录是否存在 Gradle 核心文件
        let dir = Path::new(&configuration.directory);
        dir.join("build.gradle").exists() || dir.join("build.gradle.kts").exists()
    }

    fn detect_dependencies(
        &self,
        configuration: &Configuration,
    ) -> anyhow::Result<Vec<Dependency>> {
        let work_dir = Path::new(&configuration.directory);

        // 1. 调用子进程获取真实输出
        let stdout = Self::execute_gradle_dependencies(work_dir)?;

        // 2. 解析 CLI 输出树
        let extracted_deps = Self::parse_gradle_cli_output(&stdout)?;
        if extracted_deps.is_empty() {
            return Ok(vec![]);
        }

        // 为了动态分析生成的统一 file_salt，使用当前工作目录路径
        let file_salt = work_dir.to_string_lossy().replace('\\', "/");

        // 3. 走原有的 4-pass 架构构建依赖图
        Self::build_dependency_graph(extracted_deps, &file_salt)
    }
}

impl GradleDynamicProducer {
    /// 调用子进程执行 `gradle dependencies` 以获取真实解析结果
    fn execute_gradle_dependencies(work_dir: &Path) -> anyhow::Result<String> {
        // 优先尝试项目本地的 Gradle Wrapper
        let gradlew_path = if cfg!(target_os = "windows") {
            work_dir.join("gradlew.bat")
        } else {
            work_dir.join("gradlew")
        };

        let cmd = if gradlew_path.exists() {
            gradlew_path.to_string_lossy().to_string()
        } else {
            "gradle".to_string() // 回退到系统环境变量中的 gradle
        };

        // 执行命令: ./gradlew dependencies --configuration runtimeClasspath
        let output = Command::new(cmd)
            .current_dir(work_dir)
            .arg("dependencies")
            .arg("--configuration")
            .arg("runtimeClasspath")
            .output()?;

        if !output.status.success() {
            let err_msg = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!(
                "Gradle dynamic execution failed: {}",
                err_msg
            ));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// 解析 Gradle 命令行输出的 ASCII 树状文本
    fn parse_gradle_cli_output(content: &str) -> anyhow::Result<Vec<ExtractedDep>> {
        lazy_static! {
            // 匹配 Gradle 输出树，例如：
            // \--- org.springframework.boot:spring-boot-starter-web:2.7.5
            // +--- com.google.code.gson:gson:2.9.0 -> 2.9.1 (动态版本决议)
            static ref GRADLE_TREE_RE: Regex = Regex::new(
                r#"[\\+]--- ([a-zA-Z0-9_.-]+):([a-zA-Z0-9_.-]+):([a-zA-Z0-9_.-]+)"#
            ).unwrap();
        }

        let mut deps = Vec::new();
        // 用于去重，因为动态依赖树可能由于多层嵌套而重复打印同一个组件
        let mut seen = HashSet::new();

        for cap in GRADLE_TREE_RE.captures_iter(content) {
            if let (Some(group_match), Some(name_match), Some(version_match)) =
                (cap.get(1), cap.get(2), cap.get(3))
            {
                let group = group_match.as_str().to_string();
                let name = name_match.as_str().to_string();

                // 处理 Gradle 的冲突解决或标记（例如 "1.0.0 -> 1.0.1" 取后半段，或者 "1.0.0 (*)" 过滤后缀）
                let raw_version = version_match.as_str();
                let version = if raw_version.contains("->") {
                    raw_version
                        .split("->")
                        .last()
                        .unwrap_or("")
                        .trim()
                        .to_string()
                } else {
                    raw_version
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                        .to_string()
                };

                // 过滤由于某些异常解析导致的无效版本号
                if !version.is_empty() && version != "unspecified" {
                    let unique_key = format!("{}:{}:{}", group, name, version);
                    if seen.insert(unique_key) {
                        deps.push(ExtractedDep {
                            group,
                            name,
                            version,
                        });
                    }
                }
            }
        }

        Ok(deps)
    }

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

            // 在命令行树状平铺解析下，暂不还原深度树状关系，因此 raw_deps 置空。
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
        // 第二趟：连线并计算“入度(In-Degree)”
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
}
