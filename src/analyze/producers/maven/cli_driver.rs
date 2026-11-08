use std::path::Path;
use std::process::Command;
use std::sync::LazyLock;

use regex::Regex;

use crate::model::dependency::Dependency;
use crate::utils::cli_driver::CliLocator;
use crate::utils::graph_utils::AsciiTreeStackBuilder;

static MAVEN_COORD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[a-zA-Z0-9_.\-]+:[a-zA-Z0-9_.\-]+:[a-zA-Z0-9_.\-]+:[a-zA-Z0-9_.\-]+(?::[a-zA-Z0-9_.\-]+)*").unwrap()
});

static CLEAN_ANNOTATION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\([^\)]+\)\s*").unwrap());

pub struct MavenCliDriver;

impl MavenCliDriver {
    pub fn is_available_for_dir(project_dir: &Path) -> bool {
        CliLocator::resolve_maven_for_dir(project_dir).is_some()
    }

    /// 核心依赖生成模块（失败时优雅返回 Err 以支持降级至静态 AST 解析）
    pub fn generate_dependencies(project_dir: &Path) -> Result<Vec<Dependency>, String> {
        let mvn_bin = CliLocator::resolve_maven_for_dir(project_dir)
            .ok_or_else(|| "未检测到可用的 Maven 可执行文件 (mvn / mvnw)".to_string())?;

        let mut cmd = Command::new(mvn_bin);
        cmd.args([
            "dependency:tree",
            "-DoutputType=text",
            "-Dverbose=true",
            "-B",
        ])
        .current_dir(project_dir);

        let output = CliLocator::run_with_timeout(cmd, std::time::Duration::from_secs(30))
            .map_err(|e| format!("Maven dependency:tree 执行失败或超时: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "Maven dependency:tree 执行返回非零状态: {}",
                stderr.trim()
            ));
        }

        Self::parse_ascii_tree(&String::from_utf8_lossy(&output.stdout))
    }

    /// 使用通用单调栈树构建器 `AsciiTreeStackBuilder` 解析 Maven 树状文本输出
    pub fn parse_ascii_tree(content: &str) -> Result<Vec<Dependency>, String> {
        let mut stack_builder = AsciiTreeStackBuilder::new("maven-root");

        for line in content.lines() {
            let clean_line = match line.find("] ") {
                Some(idx) => &line[idx + 2..],
                None => line,
            };

            if clean_line.starts_with("Building ") || clean_line.contains("Scanning for") {
                continue;
            }

            let normalized_line = CLEAN_ANNOTATION_RE.replace_all(clean_line, "");

            if let Some(mat) = MAVEN_COORD_RE.find(&normalized_line) {
                let parts: Vec<&str> = mat.as_str().split(':').collect();

                let (group_id, artifact_id, version, _scope) = match parts.len() {
                    4 => (parts[0], parts[1], parts[3], "compile"),
                    5 => (parts[0], parts[1], parts[3], parts[4]),
                    6 => (parts[0], parts[1], parts[4], parts[5]),
                    _ => continue,
                };

                let raw_purl = format!("pkg:maven/{}/{}@{}", group_id, artifact_id, version);
                let depth = mat.start() / 3;

                stack_builder.push_node(
                    depth,
                    Some(group_id.to_string()),
                    artifact_id.to_string(),
                    version.to_string(),
                    &raw_purl,
                    true,
                );
            }
        }

        Ok(stack_builder.into_dependencies())
    }
}
