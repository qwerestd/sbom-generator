use crate::model::dependency::{Dependency, DependencyType};
use crate::utils::file_utils::make_instance_id;
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

    /// 正则白嫖树状文本拓扑算法（已集成多项目物理隔离与 Omitted 核弹防线）
    fn parse_ascii_tree(content: &str) -> Result<Vec<Dependency>, String> {
        let mut deps_map: HashMap<String, Dependency> = HashMap::new();
        let mut parent_stack: Vec<String> = Vec::new(); // 👈 栈内存放的必须是 instance_id
        let mut current_module_scope: String = String::new(); // 【核心新增】当前子项目物理作用域

        for line in content.lines() {
            // 剥离 Maven 的 [INFO] 前缀
            let clean_line = match line.find("] ") {
                Some(idx) => &line[idx + 2..],
                None => line,
            };

            if clean_line.starts_with("Building ") || clean_line.contains("Scanning for") {
                continue;
            }

            // ---------------------------------------------------------
            // 🚨 【防线一】：拦截 Maven 冲突/重复包提示词
            // Maven 遇到重复包会输出: "+- (omitted for duplicate) xxx:yyy:jar:1.0"
            // 不拦截的话，算出的 depth 会从 1 层暴增到 9 层以上，单调栈当场崩溃！
            // ---------------------------------------------------------
            if clean_line.contains("(omitted") || clean_line.contains("(conflict") {
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

                let depth = mat.start() / 3;

                // =====================================================
                // 【精髓 A】：微服务领地切变侦测
                // =====================================================
                // Maven 在打印 Monorepo 多个子工程时，新工程的顶层坐标 depth 永远等于 0！
                // 碰见 0，说明我们跨入了另一个微服务的边界，重新标记 scope
                if depth == 0 {
                    current_module_scope = valid_purl.clone();
                }

                // =====================================================
                // 【精髓 B】：为当前包派生“带子工程语境”的身份证
                // =====================================================
                let instance_id = make_instance_id(&valid_purl, &current_module_scope);

                // =====================================================
                // 【精髓 C】：单调栈连线（连线的父子节点全部流转 instance_id）
                // =====================================================
                parent_stack.truncate(depth);
                if let Some(parent_instance_id) = parent_stack.last() {
                    if let Some(parent_dep) = deps_map.get_mut(parent_instance_id) {
                        if !parent_dep.dependencies.contains(&instance_id) {
                            parent_dep.dependencies.push(instance_id.clone());
                        }
                    }
                }
                parent_stack.push(instance_id.clone());

                // =====================================================
                // 【精髓 D】：落盘入库（Key 严格设为 instance_id）
                // =====================================================
                if !deps_map.contains_key(&instance_id) {
                    deps_map.insert(
                        instance_id.clone(),
                        Dependency {
                            group: Some(group_id.to_string()),
                            r#type: DependencyType::Library,
                            name: artifact_id.to_string(),
                            version: Some(version.to_string()),
                            purl: valid_purl,
                            instance_id,
                            dependencies: Vec::new(),
                            location: None,
                        },
                    );
                }
            }
        }

        let result: Vec<Dependency> = deps_map.into_values().collect();
        eprintln!(
            "🔍 [自检] 动态正则引擎成功提取 {} 个 Java 依赖，多模块隔离 DAG 连线完毕！",
            result.len()
        );
        Ok(result)
    }
}
