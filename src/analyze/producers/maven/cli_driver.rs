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
}

impl MavenCoord {
    fn parse(raw: &str) -> Option<Self> {
        let parts: Vec<&str> = raw.trim().split(':').collect();
        // 适配 4 到 6 段的标准 Maven 坐标格式
        let (group_id, artifact_id, version) = match parts.len() {
            4 => (parts[0], parts[1], parts[3]),
            5 => (parts[0], parts[1], parts[3]),
            6 => (parts[0], parts[1], parts[4]),
            _ => return None,
        };

        Some(Self {
            group_id: group_id.to_string(),
            artifact_id: artifact_id.to_string(),
            version: version.to_string(),
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
    fn build_mvn_command() -> Command {
        if cfg!(target_os = "windows") {
            let my_secret_mvn = r"D:\IntelliJ IDEA 2024.3.3\plugins\maven\lib\maven3\bin\mvn.cmd";
            if std::path::Path::new(my_secret_mvn).exists() {
                return Command::new(my_secret_mvn);
            }
            let mut cmd = Command::new("cmd");
            cmd.args(["/C", "mvn"]);
            cmd
        } else {
            Command::new("mvn")
        }
    }

    pub fn is_available() -> bool {
        let mut cmd = Self::build_mvn_command();
        cmd.arg("-v")
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    }

    pub fn generate_dependencies(project_dir: &Path) -> Result<Vec<Dependency>, String> {
        let mut cmd = Self::build_mvn_command();
        // 🎯 核心改变：去掉 -q！允许日志吐出来，方便我们抓取真实的依赖行！
        cmd.args(["dependency:tree", "-DoutputType=text", "-B"])
            .current_dir(project_dir);

        let output = cmd
            .output()
            .map_err(|e| format!("无法启动 mvn 进程: {}", e))?;

        if !output.status.success() {
            let err_msg = String::from_utf8_lossy(&output.stderr);
            return Err(format!("mvn dependency:tree 执行失败: {}", err_msg));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Self::parse_ascii_tree(&stdout)
    }

    /// 工业级自愈算法：使用万能正则直接强行提取所有合规的 Maven 坐标行，彻底废除脆弱的单调栈字符数数逻辑！
    fn parse_ascii_tree(content: &str) -> Result<Vec<Dependency>, String> {
        let mut deps_map: HashMap<String, Dependency> = HashMap::new();

        // 能够完美匹配任何缩进和前缀下的 Maven 规范标准坐标正则
        let maven_coord_re = Regex::new(
            r"([a-zA-Z0-9_.\-]+):([a-zA-Z0-9_.\-]+):[a-zA-Z0-9_.\-]+:([a-zA-Z0-9_.\-]+)(?::[a-zA-Z0-9_.\-]+)?"
        ).unwrap();

        for line in content.lines() {
            // 只要这一行包含了形如 "g_id:a_id:jar:version" 的特征结构
            if let Some(caps) = maven_coord_re.captures(line) {
                let coord_str = caps.get(0).unwrap().as_str();

                // 排除掉 Maven 构建本身的日志干扰行
                if line.contains("Building") || line.contains("Scanning for projects") {
                    continue;
                }

                if let Some(coord) = MavenCoord::parse(coord_str) {
                    let current_purl = coord.to_purl();

                    deps_map
                        .entry(current_purl.clone())
                        .or_insert_with(|| Dependency {
                            group: Some(coord.group_id),
                            name: coord.artifact_id,
                            version: Some(coord.version),
                            purl: Dependency::auto_fix_and_validate_purl(current_purl.as_str()),
                            r#type: DependencyType::Library,
                            dependencies: Vec::new(), // 如果后续需要完整的树边，可以通过静态分析或文本深度来补全
                            location: None,
                        });
                }
            }
        }

        let result: Vec<Dependency> = deps_map.into_values().collect();
        eprintln!(
            "🔍 [自检] 动态正则引擎成功从文本中提取到了 {} 个有效 Java 依赖组件！",
            result.len()
        );
        Ok(result)
    }
}
