use crate::model::dependency::{Dependency, DependencyType};
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::sync::LazyLock;

// 全局静态预编译正则，省去每次调用都在堆内存重复解析状态机的开销
static MAVEN_COORD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[a-zA-Z0-9_.\-]+:[a-zA-Z0-9_.\-]+:[a-zA-Z0-9_.\-]+:[a-zA-Z0-9_.\-]+(?::[a-zA-Z0-9_.\-]+)*").unwrap()
});

pub struct MavenCliDriver;

impl MavenCliDriver {
    /// 构造 Maven 命令：环境变量 -> 你的自定义私有路径 -> 系统全局 PATH
    fn build_mvn_command() -> Command {
        // 🚀 策略一：检查临时环境变量（给评审老师留的后门）
        if let Ok(env_mvn) = std::env::var("MVN_CMD") {
            return Command::new(env_mvn);
        }

        // 🚀 策略二：检查你的本机私有定义路径
        let my_custom_mvn = r"D:\IntelliJ IDEA 2024.3.3\plugins\maven\lib\maven3\bin\mvn.cmd";
        if Path::new(my_custom_mvn).exists() {
            return Command::new(my_custom_mvn);
        }

        // 🚀 策略三：降级为操作系统全局 PATH 寻址
        if cfg!(target_os = "windows") {
            let mut cmd = Command::new("cmd");
            cmd.args(["/C", "mvn"]);
            cmd
        } else {
            Command::new("mvn")
        }
    }

    pub fn is_available() -> bool {
        Self::build_mvn_command()
            .arg("-v")
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    }

    pub fn generate_dependencies(project_dir: &Path) -> Result<Vec<Dependency>, String> {
        let mut cmd = Self::build_mvn_command();
        cmd.args(["dependency:tree", "-DoutputType=text", "-B"])
            .current_dir(project_dir);

        let output = cmd
            .output()
            .map_err(|e| format!("无法启动 mvn 进程: {}", e))?;

        if !output.status.success() {
            return Err(format!(
                "mvn dependency:tree 执行失败: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Self::parse_ascii_tree(&String::from_utf8_lossy(&output.stdout))
    }

    /// 正则白嫖树状文本拓扑算法
    fn parse_ascii_tree(content: &str) -> Result<Vec<Dependency>, String> {
        let mut deps_map: HashMap<String, Dependency> = HashMap::new();
        let mut parent_stack: Vec<String> = Vec::new(); // 记录父节点轨道的单调栈

        for line in content.lines() {
            // 剥离 Maven 的 [INFO] 前缀
            let clean_line = match line.find("] ") {
                Some(idx) => &line[idx + 2..],
                None => line,
            };

            if clean_line.starts_with("Building ") || clean_line.contains("Scanning for") {
                continue;
            }

            if let Some(mat) = MAVEN_COORD_RE.find(clean_line) {
                let parts: Vec<&str> = mat.as_str().split(':').collect();
                let (group_id, artifact_id, version) = match parts.len() {
                    4 | 5 => (parts[0], parts[1], parts[3]),
                    6 => (parts[0], parts[1], parts[4]), // 兼容带 classifier 的包
                    _ => continue,
                };

                let raw_purl = format!("pkg:maven/{}/{}@{}", group_id, artifact_id, version);
                let valid_purl = Dependency::auto_fix_and_validate_purl(&raw_purl);

                // 核心算法：Maven 树前缀缩进严格占 3 个字符宽，除以3即为当前依赖深度
                let depth = mat.start() / 3;

                // 维护单调栈并连线父子 DAG 关系
                parent_stack.truncate(depth);
                if let Some(parent_purl) = parent_stack.last() {
                    if let Some(parent_dep) = deps_map.get_mut(parent_purl) {
                        if !parent_dep.dependencies.contains(&valid_purl) {
                            parent_dep.dependencies.push(valid_purl.clone());
                        }
                    }
                }
                parent_stack.push(valid_purl.clone());

                // 内存优化：只有新包才进行堆内存 String 拷贝
                if !deps_map.contains_key(&valid_purl) {
                    deps_map.insert(
                        valid_purl.clone(),
                        Dependency {
                            group: Some(group_id.to_string()),
                            name: artifact_id.to_string(),
                            version: Some(version.to_string()),
                            purl: valid_purl,
                            r#type: DependencyType::Library,
                            dependencies: Vec::new(),
                            location: None,
                        },
                    );
                }
            }
        }

        let result: Vec<Dependency> = deps_map.into_values().collect();
        eprintln!(
            "🔍 [自检] 动态正则引擎成功提取 {} 个 Java 依赖，并已连线 DAG 拓扑！",
            result.len()
        );
        Ok(result)
    }
}
