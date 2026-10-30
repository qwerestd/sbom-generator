use std::path::{Path, PathBuf};

use crate::analyze::producers::maven::context::MavenProducerContext;
use crate::analyze::producers::maven::maven_file::MavenFile;
use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::model::dependency::Dependency;
use derive_builder::Builder;

#[derive(Clone, Builder, Default)]
pub struct MavenProducer {}

impl MavenProducer {
    /// 静态 AST 双趟扫描：支持多模块 Parent 继承与 dependencyManagement 属性穿透
    fn find_dependencies_via_static(
        &self,
        paths: &[PathBuf],
        base_path: &Path,
    ) -> anyhow::Result<Vec<Dependency>> {
        let mut result = vec![];
        let mut maven_context = MavenProducerContext::new(base_path.to_path_buf());

        // 第一趟：解析所有 pom.xml 构建上下文索引
        for p in paths.iter() {
            if let Ok(maven_file) = MavenFile::new(p, &maven_context) {
                maven_context.add_maven_file(&maven_file);
            }
        }

        // 第二趟：解析属性变量、继承关系并提取各模块依赖
        for maven_file in maven_context.get_all_files() {
            let file_salt = maven_file.path.to_string_lossy().replace('\\', "/");
            let deps: Vec<Dependency> = maven_file
                .get_dependencies_for_sbom(&maven_context)
                .iter()
                .map(|d| d.to_isolated_dependency(&file_salt))
                .collect();

            result.extend(deps);
        }

        Ok(result)
    }
}

impl SbomProducer for MavenProducer {
    fn use_file(&self, path: &Path, _configuration: &SbomProducerConfiguration) -> bool {
        match path.file_name() {
            Some(e) => e.eq_ignore_ascii_case("pom.xml"),
            None => false,
        }
    }

    fn find_dependencies(
        &self,
        paths: &[PathBuf],
        configuration: &SbomProducerConfiguration,
    ) -> anyhow::Result<Vec<Dependency>> {
        if paths.is_empty() {
            return Ok(vec![]);
        }

        tracing::info!("启用 Maven 静态 AST 双趟解析器");
        self.find_dependencies_via_static(paths, &configuration.base_path)
    }
}
