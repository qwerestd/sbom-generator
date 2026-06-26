use std::path::{Path, PathBuf};

use crate::analyze::producers::maven::context::MavenProducerContext;
use crate::analyze::producers::maven::maven_file::MavenFile;
use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::model::dependency::Dependency;
use derive_builder::Builder;

// 【新增1】引入上一轮写好的 CLI 驱动器
use super::cli_driver::MavenCliDriver;

#[derive(Clone, Builder)]
pub struct MavenProducer {}

impl MavenProducer {
    /// 【新增2】把你原本写在接口里的“静态AST双趟扫描”原封不动抽离到这里
    fn find_dependencies_via_static(
        &self,
        paths: &[PathBuf],
        base_path: &Path,
    ) -> anyhow::Result<Vec<Dependency>> {
        let mut result = vec![];
        let mut maven_context = MavenProducerContext::new(base_path.to_path_buf());

        // First pass, we are getting the dependency files
        for p in paths.iter() {
            let maven_file = MavenFile::new(p, &maven_context).expect("maven file is parsed");
            maven_context.add_maven_file(&maven_file);
        }

        // Second pass, we are resolving variables and extracting dependencies
        for maven_file in maven_context.get_all_files() {
            let deps: Vec<Dependency> = maven_file
                .get_dependencies_for_sbom(&maven_context)
                .iter()
                .map(|d| d.into())
                .collect();

            result.extend(deps)
        }

        anyhow::Ok(result)
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
            return anyhow::Ok(vec![]);
        }

        // =================================================================
        // 轨道一：动态探针优先（通吃：多模块传递依赖、Parent继承、BOM注入、私服仲裁）
        // =================================================================
        if MavenCliDriver::is_available() {
            // 【核心工程防线】：智能推导 Maven 真正的 Root Project 目录。
            // 不能盲目使用 configuration.base_path，因为用户可能在 Monorepo 下扫 /repo/backend
            let root_pom_dir = paths
                .iter()
                .min_by_key(|p| p.components().count())
                .and_then(|p| p.parent())
                .unwrap_or(&configuration.base_path);

            tracing::info!(
                "检测到本机具备 mvn 执行能力，正在目录 [{}] 发起动态依赖树探测...",
                root_pom_dir.display()
            );

            match MavenCliDriver::generate_dependencies(root_pom_dir) {
                Ok(dynamic_deps) if !dynamic_deps.is_empty() => {
                    tracing::info!(
                        "Maven 动态探针执行成功，共还原 {} 个组件及完整 DAG 关系边",
                        dynamic_deps.len()
                    );
                    return anyhow::Ok(dynamic_deps);
                }
                Ok(_) => {
                    tracing::warn!("Maven 动态探针未提取到有效组件，准备降级...");
                }
                Err(err) => {
                    tracing::warn!(
                        "Maven 动态探针执行受挫 (原因: {})，正在静默降级至静态 AST 扫描",
                        err
                    );
                }
            }
        } else {
            tracing::debug!("当前宿主机未安装 mvn CLI，跳过动态探测");
        }

        // =================================================================
        // 轨道二：静态 AST 兜底（适用于：离线审计环境、纯源码无JDK环境）
        // =================================================================
        tracing::info!("启用 Maven 静态 AST 双趟解析器");
        self.find_dependencies_via_static(paths, &configuration.base_path)
    }
}
