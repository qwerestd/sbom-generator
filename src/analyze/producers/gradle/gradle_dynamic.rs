use lazy_static::lazy_static;
use regex::Regex;
use std::path::Path;
use std::process::Command;

use crate::analyze::producers::dynamic_producer::DynamicProducer;
use crate::model::configuration::Configuration;
use crate::model::dependency::Dependency;
use crate::utils::cli_driver::CliLocator;
use crate::utils::graph_utils::AsciiTreeStackBuilder;

#[derive(Clone, Default)]
pub struct GradleDynamicProducer {}

impl DynamicProducer for GradleDynamicProducer {
    fn is_applicable(&self, configuration: &Configuration) -> bool {
        let dir = Path::new(&configuration.directory);
        (dir.join("build.gradle").exists() || dir.join("build.gradle.kts").exists())
            && CliLocator::resolve_gradle_for_dir(dir).is_some()
    }

    fn detect_dependencies(
        &self,
        configuration: &Configuration,
    ) -> anyhow::Result<Vec<Dependency>> {
        let work_dir = Path::new(&configuration.directory);
        let stdout = Self::execute_gradle_dependencies(work_dir)?;

        let file_salt = work_dir.to_string_lossy().replace('\\', "/");
        let app_name = work_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("gradle-app");

        Self::parse_gradle_cli_tree(&stdout, app_name, &file_salt)
    }
}

impl GradleDynamicProducer {
    fn execute_gradle_dependencies(work_dir: &Path) -> anyhow::Result<String> {
        let cmd = CliLocator::resolve_gradle_for_dir(work_dir)
            .ok_or_else(|| anyhow::anyhow!("未检测到可用的 Gradle / gradlew 可执行文件"))?;

        let mut process_cmd = Command::new(cmd);
        process_cmd
            .current_dir(work_dir)
            .arg("dependencies")
            .arg("--configuration")
            .arg("runtimeClasspath");

        let output = CliLocator::run_with_timeout(process_cmd, std::time::Duration::from_secs(30))?;

        if !output.status.success() {
            let err_msg = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!(
                "Gradle dynamic execution failed: {}",
                err_msg
            ));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// 复用推广自 Maven 的 `AsciiTreeStackBuilder` 单调栈解析器还原多层 DAG 边
    pub fn parse_gradle_cli_tree(
        content: &str,
        app_name: &str,
        file_salt: &str,
    ) -> anyhow::Result<Vec<Dependency>> {
        lazy_static! {
            static ref GRADLE_LINE_RE: Regex = Regex::new(
                r#"^([| ]*)[\\+]---\s+([a-zA-Z0-9_.-]+):([a-zA-Z0-9_.-]+):([^\s(]+)(?:\s+->\s+([^\s(]+))?"#
            ).unwrap();
        }

        let mut stack_builder = AsciiTreeStackBuilder::new(file_salt);
        let root_purl = format!("pkg:maven/{}/{}@0.0.0", app_name, app_name);
        stack_builder.push_node(
            0,
            Some(app_name.to_string()),
            app_name.to_string(),
            "0.0.0".to_string(),
            &root_purl,
            false,
        );

        let mut has_child = false;

        for line in content.lines() {
            let Some(caps) = GRADLE_LINE_RE.captures(line) else {
                continue;
            };

            let prefix = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let group = caps.get(2).unwrap().as_str();
            let name = caps.get(3).unwrap().as_str();
            let declared_ver = caps.get(4).unwrap().as_str();
            let resolved_ver = caps.get(5).map(|m| m.as_str()).unwrap_or(declared_ver);

            if resolved_ver.is_empty() || resolved_ver == "unspecified" {
                continue;
            }

            // 根节点占据 depth 0，因此 CLI 第一层依赖处于 depth = (prefix.len() / 5) + 1
            let depth = (prefix.len() / 5) + 1;
            let raw_purl = format!("pkg:maven/{}/{}@{}", group, name, resolved_ver);

            stack_builder.push_node(
                depth,
                Some(group.to_string()),
                name.to_string(),
                resolved_ver.to_string(),
                &raw_purl,
                false,
            );
            has_child = true;
        }

        if !has_child {
            return Ok(vec![]);
        }

        Ok(stack_builder.into_dependencies())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_gradle_cli_tree_hierarchy() {
        let cli_out = r#"
runtimeClasspath - Runtime classpath of source set 'main'.
+--- org.springframework.boot:spring-boot-starter-web:2.7.5
|    +--- org.springframework.boot:spring-boot-starter:2.7.5
|    \--- com.fasterxml.jackson.core:jackson-databind:2.13.3 -> 2.13.4.2
\--- com.google.code.gson:gson:2.9.0 -> 2.9.1 (*)
"#;

        let deps = GradleDynamicProducer::parse_gradle_cli_tree(
            cli_out,
            "my-gradle-service",
            "test/build.gradle",
        )
        .unwrap();

        assert_eq!(deps.len(), 5);
        let starter_web = deps
            .iter()
            .find(|d| d.name == "spring-boot-starter-web")
            .unwrap();
        assert_eq!(starter_web.dependencies.len(), 2);

        let databind = deps.iter().find(|d| d.name == "jackson-databind").unwrap();
        assert_eq!(databind.version.as_deref(), Some("2.13.4.2"));
    }
}
