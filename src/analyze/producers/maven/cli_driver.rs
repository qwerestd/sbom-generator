use crate::model::dependency::{Dependency, DependencyType};
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

pub struct MavenCliDriver;

#[derive(Debug, Clone)]
struct MavenCoord {
    group_id: String,
    artifact_id: String,
    version: String,
    #[allow(dead_code)]
    scope: Option<String>,
}
impl MavenCoord {
    /// 解析 Maven 标准坐标字符串，例如：
    /// "org.springframework:spring-core:jar:5.3.20:compile"
    fn parse(raw: &str) -> Option<Self> {
        let parts: Vec<&str> = raw.trim().split(':').collect();

        // 典型标准格式分为 4~6 段：
        // 4段: group:name:type:version
        // 5段: group:name:type:version:scope
        // 6段: group:name:type:classifier:version:scope
        let (group_id, artifact_id, version, scope) = match parts.len() {
            4 => (parts[0], parts[1], parts[3], None),
            5 => (parts[0], parts[1], parts[3], Some(parts[4])),
            6 => (parts[0], parts[1], parts[4], Some(parts[5])),
            _ => return None,
        };

        Some(Self {
            group_id: group_id.to_string(),
            artifact_id: artifact_id.to_string(),
            version: version.to_string(),
            scope: scope.map(|s| s.to_string()),
        })
    }

    fn to_purl(&self) -> String {
        format!(
            "pkg:maven/{}/{}@{}",
            self.group_id, self.artifact_id, self.version
        )
    }
}

impl MavenCliDriver {
    /// 检查宿主机环境是否具备 mvn 执行能力
    pub fn is_available() -> bool {
        Command::new("mvn")
            .arg("-v")
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    }

    /// 执行 Maven 依赖树生成并转译为带有连接边的 SBOM 依赖列表
    pub fn generate_dependencies(project_dir: &Path) -> Result<Vec<Dependency>, String> {
        // -B: Batch模式（屏蔽进度条等乱码）
        // -q: 仅输出目标结果，屏蔽 [INFO] 扫描日志
        let output = Command::new("mvn")
            .args(["dependency:tree", "-DoutputType=text", "-B", "-q"])
            .current_dir(project_dir)
            .output()
            .map_err(|e| format!("无法启动 mvn 进程: {}", e))?;

        if !output.status.success() {
            let err_msg = String::from_utf8_lossy(&output.stderr);
            return Err(format!("mvn dependency:tree 执行失败: {}", err_msg));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Self::parse_ascii_tree(&stdout)
    }

    /// 核心算法：用「单调栈」将 ASCII 缩进文本转译为有向无环图 (DAG)
    fn parse_ascii_tree(content: &str) -> Result<Vec<Dependency>, String> {
        let mut deps_map: HashMap<String, Dependency> = HashMap::new();
        let mut stack: Vec<String> = Vec::new(); // 维护当前分支链路上的 purl 栈

        // 预编译正则：清洗掉 Maven 偶发的日志头，如 "[INFO] " 或 "[WARNING] "
        let log_prefix_re = Regex::new(r"^\[[A-Z]+]\s?").unwrap();

        for line in content.lines() {
            let cleaned = log_prefix_re.replace(line, "");
            if cleaned.trim().is_empty() {
                continue;
            }

            // 寻找该行第一个字母数字的位置（剥离前缀树枝符号： "+- ", "|  \- "）
            let Some(coord_idx) = cleaned.find(|c: char| c.is_alphanumeric()) else {
                continue;
            };

            let branch_prefix = &cleaned[..coord_idx];
            let coord_str = &cleaned[coord_idx..].trim();

            // 过滤掉非坐标行（例如 Maven 打印的 Project 描述行）
            if coord_str.matches(':').count() < 3 {
                continue;
            }

            let Some(coord) = MavenCoord::parse(coord_str) else {
                continue;
            };

            // 【核心层级推导规律】：
            // Maven 每一级缩进固定占用 3 个字符（如 "+- " 长度3为第1层；"|  +- " 长度6为第2层）
            let depth = if branch_prefix.is_empty() {
                0
            } else {
                (branch_prefix.chars().count() + 1) / 3
            };

            let current_purl = coord.to_purl();

            // 1. 动态对齐单调栈：当退回上一级依赖时，截断栈顶
            if depth <= stack.len() {
                stack.truncate(depth);
            }

            // 2. 建立图连接：如果深度 > 0，当前栈顶元素必然是我的“亲生父节点”
            if depth > 0 && !stack.is_empty() {
                let parent_purl = stack.last().unwrap();
                if let Some(parent_node) = deps_map.get_mut(parent_purl) {
                    if !parent_node.dependencies.contains(&current_purl) {
                        parent_node.dependencies.push(current_purl.clone());
                    }
                }
            }

            // 3. 当前节点入栈，并在全局 Map 中注册
            stack.push(current_purl.clone());

            deps_map
                .entry(current_purl.clone())
                .or_insert_with(|| Dependency {
                    group: Some(coord.group_id),
                    name: coord.artifact_id,
                    version: Some(coord.version),
                    purl: Dependency::auto_fix_and_validate_purl(current_purl.as_str()),
                    r#type: DependencyType::Library,
                    dependencies: Vec::new(),
                    location: None, // 动态解析没有物理代码行号
                });
        }

        Ok(deps_map.into_values().collect())
    }
}
