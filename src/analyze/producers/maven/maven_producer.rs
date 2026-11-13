use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::analyze::producers::maven::context::MavenProducerContext;
use crate::analyze::producers::maven::local_repo::{LocalPomRepo, SeedDep};
use crate::analyze::producers::maven::maven_file::MavenFile;
use crate::analyze::producers::maven::model::MavenDependencyScope;
use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyLocation, DependencyType};
use crate::utils::file_utils::make_instance_id;
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
            let maven_file = MavenFile::new(p, &maven_context)?;
            maven_context.add_maven_file(&maven_file);
        }

        let mut projects: HashMap<String, Vec<Dependency>> = HashMap::new();
        for file in maven_context.get_all_files() {
            if let Some(project) = file.get_project_for_sbom(&maven_context) {
                projects
                    .entry(project.purl.clone())
                    .or_default()
                    .push(project);
            }
        }

        // 第二趟：解析属性变量、继承关系并提取各模块依赖
        let mut local_repo = LocalPomRepo::new();
        for maven_file in maven_context.get_all_files() {
            let file_salt = maven_file.path.to_string_lossy().replace('\\', "/");
            let mut sbom_deps = maven_file.get_dependencies_for_sbom(&maven_context);

            // Offline local .m2 / .gradle .pom resolution for external parent, BOMs, and transitives
            let mut managed_overrides: HashMap<(String, String), String> = HashMap::new();
            if local_repo.is_available() {
                let ext_parent = maven_file.parent.as_ref().and_then(|p| {
                    match (&p.group_id, &p.artifact_id, &p.version) {
                        (Some(g), Some(a), Some(v)) => Some((g.as_str(), a.as_str(), v.as_str())),
                        _ => None,
                    }
                });
                let bom_imports: Vec<(&str, &str, &str)> = maven_file
                    .dependency_management
                    .iter()
                    .filter(|d| matches!(d.scope, Some(MavenDependencyScope::Import)))
                    .filter_map(|d| {
                        d.version
                            .as_deref()
                            .map(|v| (d.group_id.as_str(), d.artifact_id.as_str(), v))
                    })
                    .collect();

                let (ext_props, ext_managed) =
                    local_repo.resolve_parent_and_boms(ext_parent, &bom_imports);
                managed_overrides.extend(ext_managed);

                for d in &mut sbom_deps {
                    if !ext_props.is_empty() {
                        *d = d.enrich(&ext_props);
                    }
                    if d.version
                        .as_deref()
                        .is_none_or(|v| v.is_empty() || v.contains("${"))
                    {
                        if let Some(mv) =
                            managed_overrides.get(&(d.group_id.clone(), d.artifact_id.clone()))
                        {
                            d.version = Some(mv.clone());
                        }
                    }
                }
            }

            let mut deps: Vec<Dependency> = sbom_deps
                .iter()
                .map(|d| d.to_isolated_dependency(&file_salt))
                .collect();

            if local_repo.is_available() {
                let seeds: Vec<SeedDep> = sbom_deps
                    .iter()
                    .filter(|d| !matches!(d.scope, Some(MavenDependencyScope::Import)))
                    .filter_map(|d| {
                        d.version.as_ref().map(|v| SeedDep {
                            group_id: d.group_id.clone(),
                            artifact_id: d.artifact_id.clone(),
                            version: v.clone(),
                            exclusions: HashSet::new(),
                        })
                    })
                    .collect();
                let seen_purls: HashSet<String> = deps.iter().map(|d| d.purl.clone()).collect();
                let location = Some(DependencyLocation::from_file(&maven_file.path));
                for t in local_repo.expand_transitive_deps(&seeds, &managed_overrides) {
                    let purl = Dependency::auto_fix_and_validate_purl(&format!(
                        "pkg:maven/{}/{}@{}",
                        t.group_id, t.artifact_id, t.version
                    ));
                    if seen_purls.contains(&purl) || projects.contains_key(&purl) {
                        continue;
                    }
                    let instance_id = make_instance_id(&purl, &file_salt);
                    if let Ok(built) = DependencyBuilder::default()
                        .group(Some(t.group_id))
                        .name(t.artifact_id)
                        .version(Some(t.version))
                        .r#type(DependencyType::Library)
                        .purl(purl)
                        .instance_id(instance_id)
                        .dependencies(vec![])
                        .location(location.clone())
                        .build()
                    {
                        deps.push(built);
                    }
                }
            }

            let mut children = Vec::new();
            deps.retain(|dep| {
                if let Some([local]) = projects.get(&dep.purl).map(Vec::as_slice) {
                    children.push(local.instance_id.clone());
                    false
                } else {
                    children.push(dep.instance_id.clone());
                    true
                }
            });
            if let Some(mut root) = maven_file.get_project_for_sbom(&maven_context) {
                children.retain(|id| id != &root.instance_id);
                root.dependencies = children;
                result.push(root);
            }

            result.extend(deps);
        }

        for path in paths {
            result.extend(super::supplement::collect(path)?);
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
