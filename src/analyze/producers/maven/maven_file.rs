use crate::analyze::producers::maven::constants::{ARTIFACT_ID, GROUP_ID, SCOPE, TYPE, VERSION};
use crate::analyze::producers::maven::context::MavenProducerContext;
use crate::analyze::producers::maven::model::{MavenDependencyScope, MavenDependencyType};
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyLocation, DependencyType};
use crate::model::location::Location;
use crate::model::position::get_position_in_string;
use crate::utils::file_utils::make_instance_id;
use crate::utils::tree_sitter::tree::get_tree; // 【新增引入】统一派生身份证主键算法
use anyhow::anyhow;
use derive_builder::Builder;
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

lazy_static! {
    static ref REGEX_VARIABLE: Regex = Regex::new(r"\$\{([^}]+)\}").unwrap();
}

fn enrich_string_with_properties(s: &str, properties: &HashMap<String, String>) -> String {
    let mut resolved = s.to_string();

    for _ in 0..5 {
        let mut has_replacement = false;
        let current_text = resolved.clone();

        for cap in REGEX_VARIABLE.captures_iter(&current_text) {
            let full_placeholder = &cap[0];
            let var_key = &cap[1];

            if let Some(target_val) = properties.get(var_key) {
                resolved = resolved.replace(full_placeholder, target_val);
                has_replacement = true;
            }
        }

        if !has_replacement {
            break;
        }
    }

    resolved
}

#[derive(Default, Eq, Hash, Clone, Debug, Builder, PartialEq)]
pub struct MavenProjectInfo {
    pub group_id: Option<String>,
    pub artifact_id: String,
    pub version: Option<String>,
}

#[derive(Clone, Debug, Builder)]
pub struct MavenDependency {
    pub group_id: String,
    pub artifact_id: String,
    #[builder(default = "None")]
    pub version: Option<String>,
    #[builder(default = "None")]
    pub r#type: Option<MavenDependencyType>,
    #[builder(default = "None")]
    pub scope: Option<MavenDependencyScope>,
    #[builder(default = "None")]
    #[allow(dead_code)]
    pub location: Option<DependencyLocation>,
}

impl MavenDependency {
    pub fn enrich(&self, properties: &HashMap<String, String>) -> Self {
        MavenDependency {
            group_id: enrich_string_with_properties(&self.group_id, properties)
                .trim()
                .to_string(),
            artifact_id: enrich_string_with_properties(&self.artifact_id, properties)
                .trim()
                .to_string(),
            version: self.version.as_ref().map(|v| {
                enrich_string_with_properties(v, properties)
                    .trim()
                    .to_string()
            }),
            r#type: self.r#type.clone(),
            scope: self.scope.clone(),
            location: self.location.clone(),
        }
    }

    pub fn is_valid_for_sbom(&self) -> bool {
        !self.group_id.trim().is_empty() && !self.artifact_id.trim().is_empty()
    }

    // =====================================================================
    // 🚀 【新增核心改造方法】：支持传递 file_salt 直接转译为带全局身份证的 Dependency 实体
    // =====================================================================
    pub fn to_isolated_dependency(&self, file_salt: &str) -> Dependency {
        let group_clean = self.group_id.trim();
        let name_clean = self.artifact_id.trim();

        let (version_opt, purl_str) = match &self.version {
            Some(raw_v) => {
                let clean_v = raw_v.trim();
                if clean_v.is_empty() || clean_v.contains('$') {
                    (None, format!("pkg:maven/{}/{}", group_clean, name_clean))
                } else {
                    (
                        Some(clean_v.to_string()),
                        format!("pkg:maven/{}/{}@{}", group_clean, name_clean, clean_v),
                    )
                }
            }
            None => (None, format!("pkg:maven/{}/{}", group_clean, name_clean)),
        };

        let valid_purl = Dependency::auto_fix_and_validate_purl(&purl_str);

        // 【核心心法】：拿 (洗练PURL + pom.xml相对路径) 融合成全局唯一 instance_id
        let instance_id = make_instance_id(&valid_purl, file_salt);

        DependencyBuilder::default()
            .group(Some(group_clean.to_string()))
            .name(name_clean.to_string())
            .version(version_opt)
            .location(self.location.clone())
            .r#type(DependencyType::Library)
            .purl(valid_purl)
            .instance_id(instance_id) // 👈 身份证稳稳注入！
            .build()
            .unwrap()
    }
}

// 保留原有的 From 转换，确保全工程存量测试用例和非多项目调用能向下兼容编译通过
impl From<&MavenDependency> for Dependency {
    fn from(value: &MavenDependency) -> Self {
        // 单项目降级场景下，直接使用默认 location.file（即当前pom物理路径）作为盐保底
        let fallback_salt = value
            .location
            .as_ref()
            .map(|l| l.block.file.as_str())
            .unwrap_or("maven-fallback-pom");
        value.to_isolated_dependency(fallback_salt)
    }
}

#[derive(Clone, Debug, Builder, Default)]
pub struct MavenFileParent {
    pub relative_path: Option<String>,
    pub group_id: Option<String>,
    pub artifact_id: Option<String>,
    pub version: Option<String>,
}

#[derive(Clone, Debug, Builder, Default)]
pub struct MavenFile {
    pub project_info: MavenProjectInfo,
    pub path: PathBuf,
    pub properties: HashMap<String, String>,
    pub dependency_management: Vec<MavenDependency>,
    pub dependencies: Vec<MavenDependency>,
    pub parent: Option<MavenFileParent>,
}

fn get_dependencies_from_dependency_management(
    tree: &tree_sitter::Tree,
    path: &Path,
    content: &str,
    context: &MavenProducerContext,
) -> anyhow::Result<Vec<MavenDependency>> {
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut dependencies: Vec<MavenDependency> = vec![];

    let matches = cursor.matches(
        &context.query_dependency_management,
        tree.root_node(),
        content.as_bytes(),
    );

    let path_string = path.display().to_string();

    for m in matches {
        let mut group_id_opt = None;
        let mut artifact_id_opt = None;
        let mut version_opt = None;
        let mut type_opt = None;
        let mut scope_opt = None;

        let mut name_position_opt: Option<Location> = None;
        let mut version_position_opt: Option<Location> = None;

        if m.captures.len() <= 1 {
            continue;
        }

        let element_block = m.captures[0].node;
        let block_position_opt = Some(Location {
            file: path_string.clone(),
            start: get_position_in_string(content, element_block.start_byte())
                .expect("cannot find start"),
            end: get_position_in_string(content, element_block.end_byte())
                .expect("cannot find end"),
        });

        for i in (5..m.captures.len()).step_by(2) {
            if m.captures[i].index != 4 {
                continue;
            }
            let tag_node = m.captures[i].node;
            let value_node = m.captures[i + 1].node;

            let tag_slice = &content[tag_node.start_byte()..tag_node.end_byte()];
            let value_str = &content[value_node.start_byte()..value_node.end_byte()];

            if tag_slice == ARTIFACT_ID {
                artifact_id_opt = Some(value_str.to_string());
                name_position_opt = Some(Location {
                    file: path_string.clone(),
                    start: get_position_in_string(content, value_node.start_byte())
                        .expect("cannot find start"),
                    end: get_position_in_string(content, value_node.end_byte())
                        .expect("cannot find end"),
                });
            } else if tag_slice == GROUP_ID {
                group_id_opt = Some(value_str.to_string());
            } else if tag_slice == VERSION {
                version_opt = Some(value_str.to_string());
                version_position_opt = Some(Location {
                    file: path_string.clone(),
                    start: get_position_in_string(content, value_node.start_byte())
                        .expect("cannot find start"),
                    end: get_position_in_string(content, value_node.end_byte())
                        .expect("cannot find end"),
                });
            } else if tag_slice == TYPE {
                type_opt = MavenDependencyType::from_str(value_str).ok();
            } else if tag_slice == SCOPE {
                scope_opt = MavenDependencyScope::from_str(value_str).ok();
            }
        }

        if let (Some(group_id), Some(artifact_id)) = (group_id_opt, artifact_id_opt) {
            let location = if let (Some(block_pos), Some(name_pos)) =
                (block_position_opt, name_position_opt)
            {
                Some(DependencyLocation {
                    block: block_pos,
                    name: name_pos,
                    version: version_position_opt,
                })
            } else {
                None
            };

            dependencies.push(
                MavenDependencyBuilder::default()
                    .group_id(group_id)
                    .artifact_id(artifact_id)
                    .version(version_opt)
                    .location(location)
                    .r#type(type_opt)
                    .scope(scope_opt)
                    .build()
                    .unwrap(),
            );
        }
    }

    Ok(dependencies)
}

fn get_dependencies(
    tree: &tree_sitter::Tree,
    path: &Path,
    content: &str,
    context: &MavenProducerContext,
) -> anyhow::Result<Vec<MavenDependency>> {
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut dependencies: Vec<MavenDependency> = vec![];

    let matches = cursor.matches(
        &context.query_dependencies,
        tree.root_node(),
        content.as_bytes(),
    );

    let path_string = path.display().to_string();

    for m in matches {
        let mut group_id_opt = None;
        let mut artifact_id_opt = None;
        let mut version_opt = None;
        let mut scope_opt = None;

        let mut name_position_opt: Option<Location> = None;
        let mut version_position_opt: Option<Location> = None;

        if m.captures.len() <= 1 {
            continue;
        }

        let element_block = m.captures[0].node;
        let block_position_opt = Some(Location {
            file: path_string.clone(),
            start: get_position_in_string(content, element_block.start_byte())
                .expect("cannot find start"),
            end: get_position_in_string(content, element_block.end_byte())
                .expect("cannot find end"),
        });

        for i in (0..m.captures.len()).step_by(2) {
            if m.captures[i].index != 3 {
                continue;
            }
            let tag_node = m.captures[i].node;
            let value_node = m.captures[i + 1].node;

            let tag_slice = &content[tag_node.start_byte()..tag_node.end_byte()];
            let value_str = &content[value_node.start_byte()..value_node.end_byte()];

            if tag_slice == ARTIFACT_ID {
                artifact_id_opt = Some(value_str.to_string());
                name_position_opt = Some(Location {
                    file: path_string.clone(),
                    start: get_position_in_string(content, value_node.start_byte())
                        .expect("cannot find start"),
                    end: get_position_in_string(content, value_node.end_byte())
                        .expect("cannot find end"),
                });
            } else if tag_slice == GROUP_ID {
                group_id_opt = Some(value_str.to_string());
            } else if tag_slice == VERSION {
                version_opt = Some(value_str.to_string());
                version_position_opt = Some(Location {
                    file: path_string.clone(),
                    start: get_position_in_string(content, value_node.start_byte())
                        .expect("cannot find start"),
                    end: get_position_in_string(content, value_node.end_byte())
                        .expect("cannot find end"),
                });
            } else if tag_slice == SCOPE {
                scope_opt = MavenDependencyScope::from_str(value_str).ok();
            }
        }

        if let (Some(group_id), Some(artifact_id)) = (group_id_opt, artifact_id_opt) {
            let location = if let (Some(block_pos), Some(name_pos)) =
                (block_position_opt, name_position_opt)
            {
                Some(DependencyLocation {
                    block: block_pos,
                    name: name_pos,
                    version: version_position_opt,
                })
            } else {
                None
            };

            dependencies.push(
                MavenDependencyBuilder::default()
                    .group_id(group_id)
                    .artifact_id(artifact_id)
                    .version(version_opt)
                    .scope(scope_opt)
                    .location(location)
                    .build()
                    .unwrap(),
            );
        }
    }

    Ok(dependencies)
}

pub fn get_variables(
    tree: &tree_sitter::Tree,
    file_content: &str,
    maven_producer_context: &MavenProducerContext,
) -> HashMap<String, String> {
    let mut variables = HashMap::new();

    let mut cursor = tree_sitter::QueryCursor::new();
    let matches = cursor.matches(
        &maven_producer_context.query_project_metadata,
        tree.root_node(),
        file_content.as_bytes(),
    );

    for m in matches {
        let key_node = m.captures[1].node;
        let value_node = m.captures[2].node;
        let key = &file_content[key_node.start_byte()..key_node.end_byte()];
        let value = &file_content[value_node.start_byte()..value_node.end_byte()];

        if key == "version" {
            variables.insert("project.version".to_string(), value.to_string());
        }
    }

    cursor = tree_sitter::QueryCursor::new();
    let matches = cursor.matches(
        &maven_producer_context.query_project_properties,
        tree.root_node(),
        file_content.as_bytes(),
    );
    for m in matches {
        let key_node = m.captures[2].node;
        let value_node = m.captures[3].node;
        let key = file_content[key_node.start_byte()..key_node.end_byte()].to_string();
        let value = file_content[value_node.start_byte()..value_node.end_byte()].to_string();
        variables.insert(key, value);
    }

    variables
}

pub fn get_project_info(
    tree: &tree_sitter::Tree,
    file_content: &str,
    maven_producer_context: &MavenProducerContext,
) -> Option<MavenProjectInfo> {
    let mut cursor = tree_sitter::QueryCursor::new();
    let matches = cursor.matches(
        &maven_producer_context.query_project_metadata,
        tree.root_node(),
        file_content.as_bytes(),
    );

    let mut version = None;
    let mut artifact_id = None;
    let mut group_id = None;

    for m in matches {
        let key_node = m.captures[1].node;
        let value_node = m.captures[2].node;
        let key = &file_content[key_node.start_byte()..key_node.end_byte()];
        let value = &file_content[value_node.start_byte()..value_node.end_byte()];

        if key == "version" {
            version = Some(value.to_string());
        } else if key == "artifactId" {
            artifact_id = Some(value.to_string());
        } else if key == "groupId" {
            group_id = Some(value.to_string());
        }
    }

    artifact_id.map(|a| MavenProjectInfo {
        version,
        artifact_id: a,
        group_id,
    })
}

fn get_parent_information(
    tree: &tree_sitter::Tree,
    _path: &Path,
    content: &str,
    context: &MavenProducerContext,
) -> Option<MavenFileParent> {
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut relative_path = None;
    let mut group_id = None;
    let mut artifact_id = None;
    let mut version = None;

    let matches = cursor.matches(
        &context.query_parent_information,
        tree.root_node(),
        content.as_bytes(),
    );

    for m in matches {
        let key_node = m.captures[2].node;
        let value_node = m.captures[3].node;
        let key_str = &content[key_node.start_byte()..key_node.end_byte()];
        let val_str = &content[value_node.start_byte()..value_node.end_byte()];

        if key_str == "relativePath" {
            relative_path = Some(val_str.to_string());
        } else if key_str == "artifactId" {
            artifact_id = Some(val_str.to_string());
        } else if key_str == "groupId" {
            group_id = Some(val_str.to_string());
        } else if key_str == "version" {
            version = Some(val_str.to_string());
        }
    }

    match (relative_path, group_id, artifact_id, version) {
        (Some(rp), None, None, None) => Some(MavenFileParent {
            relative_path: Some(rp),
            ..Default::default()
        }),
        (Some(rp), Some(gi), Some(ai), Some(v)) => Some(MavenFileParent {
            relative_path: Some(rp),
            artifact_id: Some(ai),
            group_id: Some(gi),
            version: Some(v),
        }),
        (None, Some(gi), Some(ai), Some(v)) => Some(MavenFileParent {
            relative_path: None,
            artifact_id: Some(ai),
            group_id: Some(gi),
            version: Some(v),
        }),
        _ => None,
    }
}

fn replace_properties(properties: HashMap<String, String>) -> HashMap<String, String> {
    let mut result = HashMap::with_capacity(properties.len());
    for (k, v) in &properties {
        result.insert(k.clone(), enrich_string_with_properties(v, &properties));
    }
    result
}

impl MavenFile {
    pub fn new(path: &PathBuf, context: &MavenProducerContext) -> anyhow::Result<Self> {
        let content = fs::read_to_string(path)?;
        let t =
            get_tree(&content, &context.language).ok_or_else(|| anyhow!("cannot parse tree"))?;

        let project_info = get_project_info(&t, &content, context)
            .ok_or_else(|| anyhow!("cannot get project info"))?;

        let variables = get_variables(&t, &content, context);
        let dependencies = get_dependencies(&t, path, &content, context)?;
        let dependency_management =
            get_dependencies_from_dependency_management(&t, path, &content, context)?;
        let parent_info = get_parent_information(&t, path, &content, context);

        Ok(MavenFile {
            project_info,
            path: path.clone(),
            properties: variables,
            dependency_management,
            dependencies,
            parent: parent_info,
        })
    }

    fn get_parent_file_path(&self, context: &MavenProducerContext) -> Option<PathBuf> {
        let rel_str = self.parent.as_ref()?.relative_path.as_ref()?;

        let mut candidate = self.path.parent()?.to_path_buf();
        candidate.push(rel_str);

        let full_path = fs::canonicalize(&candidate).ok()?;
        let base_path = fs::canonicalize(&context.base_path).ok()?;

        let mut rel_path = full_path.strip_prefix(&base_path).ok()?.to_path_buf();

        if !rel_str.ends_with("pom.xml") {
            rel_path.push("pom.xml");
        }

        Some(rel_path)
    }

    fn get_parent_by_project_info(&self, context: &MavenProducerContext) -> Option<MavenFile> {
        let p = self.parent.as_ref()?;
        let a = p.artifact_id.as_ref()?;

        let lookup_info = MavenProjectInfo {
            artifact_id: a.clone(),
            group_id: p.group_id.clone(),
            version: p.version.clone(),
        };

        context
            .get_maven_file_by_project_info(&lookup_info)
            .cloned()
    }

    fn get_all_properties(&self, context: &MavenProducerContext) -> HashMap<String, String> {
        fn get_all_properties_int(
            maven_file: &MavenFile,
            context: &MavenProducerContext,
        ) -> HashMap<String, String> {
            let mut res = HashMap::new();

            if let Some(parent_path) = maven_file.get_parent_file_path(context) {
                if let Some(parent_file) = context.get_maven_file_by_path(&parent_path) {
                    res.extend(parent_file.get_all_properties(context));
                }
            } else if let Some(p) = &maven_file.parent {
                if let (Some(g), Some(a), Some(v)) = (&p.group_id, &p.artifact_id, &p.version) {
                    let key = MavenProjectInfo {
                        artifact_id: a.clone(),
                        group_id: Some(g.clone()),
                        version: Some(v.clone()),
                    };
                    if let Some(m) = context.get_maven_file_by_project_info(&key) {
                        res.extend(m.get_all_properties(context));
                    }
                }
            }

            res.extend(maven_file.properties.clone());
            res
        }

        replace_properties(get_all_properties_int(self, context))
    }

    fn get_all_dependencies_from_dependency_management(
        &self,
        context: &MavenProducerContext,
    ) -> Vec<MavenDependency> {
        let mut res = vec![];

        if let Some(parent_path) = self.get_parent_file_path(context) {
            if let Some(parent_file) = context.get_maven_file_by_path(&parent_path) {
                res.extend(parent_file.get_all_dependencies_from_dependency_management(context));
            }
        } else if let Some(parent_file) = self.get_parent_by_project_info(context) {
            res.extend(parent_file.get_all_dependencies_from_dependency_management(context));
        }

        res.extend(self.dependency_management.clone());
        res
    }

    pub fn get_dependencies_for_sbom(
        &self,
        context: &MavenProducerContext,
    ) -> Vec<MavenDependency> {
        let mut res = Vec::with_capacity(self.dependencies.len());
        let properties = self.get_all_properties(context);
        let dep_mgmt = self.get_all_dependencies_from_dependency_management(context);

        for dep in &self.dependencies {
            let target_dep = if dep.version.is_none() {
                dep_mgmt
                    .iter()
                    .find(|x| x.artifact_id == dep.artifact_id && x.group_id == dep.group_id)
                    .unwrap_or(dep)
            } else {
                dep
            };

            let enriched = target_dep.enrich(&properties);
            if enriched.is_valid_for_sbom() {
                res.push(enriched);
            }
        }

        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_properties() {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("resources/maven/hierarchy/");
        let mut context = MavenProducerContext::new(d.clone());
        d.push("pom.xml");
        let maven_file = MavenFile::new(&d, &context).expect("maven file is parsed");

        assert_eq!(maven_file.properties.len(), 6);
        assert_eq!(
            maven_file.properties.get("project.version").unwrap(),
            "1.0-SNAPSHOT"
        );
        assert_eq!(
            maven_file.properties.get("slf4j.version").unwrap(),
            "2.0.13"
        );
        assert_eq!(maven_file.properties.get("akka.version").unwrap(), "2.6.21");
        assert_eq!(
            maven_file.properties.get("immutables.version").unwrap(),
            "2.8.8"
        );
        assert_eq!(
            maven_file.properties.get("akka-scala.version").unwrap(),
            "${scala.version}"
        );
        assert_eq!(maven_file.properties.get("scala.version").unwrap(), "2.12");

        context.add_maven_file(&maven_file);

        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("resources/maven/hierarchy/subproject/pom.xml");

        let subfile = MavenFile::new(&d, &context).expect("maven file is parsed");

        let sub_properties = subfile.get_all_properties(&context);
        assert_eq!(sub_properties.len(), 6);
        assert_eq!(
            sub_properties.get("project.version").unwrap(),
            "1.0-SNAPSHOT"
        );
        assert_eq!(sub_properties.get("slf4j.version").unwrap(), "2.0.13");
        assert_eq!(sub_properties.get("akka.version").unwrap(), "2.6.21");
        assert_eq!(sub_properties.get("immutables.version").unwrap(), "2.8.8");
        assert_eq!(sub_properties.get("akka-scala.version").unwrap(), "2.12");
        assert_eq!(sub_properties.get("scala.version").unwrap(), "2.12");
    }

    #[test]
    fn test_parse_simple_pom() {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let context = MavenProducerContext::new(d.clone());
        d.push("resources/maven/simple/pom.xml");
        let maven_file = MavenFile::new(&d, &context).expect("maven file is parsed");

        assert_eq!(maven_file.dependencies.len(), 15);
        assert_eq!(maven_file.properties.len(), 9);
        assert_eq!(
            maven_file
                .properties
                .get("project.build.sourceEncoding")
                .unwrap(),
            "UTF-8"
        );
        assert_eq!(
            maven_file.properties.get("json.version").unwrap(),
            "20090211"
        );
        assert_eq!(
            maven_file.properties.get("project.version").unwrap(),
            "1.2-SNAPSHOT"
        );
    }

    #[test]
    fn test_parse_pom_with_dependency() {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let context = MavenProducerContext::new(d.clone());
        d.push("resources/maven/pom-import/pom.xml");
        let maven_file = MavenFile::new(&d, &context).expect("maven file is parsed");

        assert_eq!(maven_file.dependencies.len(), 7);
        assert_eq!(maven_file.properties.len(), 11);
        assert_eq!(maven_file.dependencies[0].group_id, "io.quarkus");
        assert_eq!(maven_file.dependencies[0].artifact_id, "quarkus-arc");
        assert!(maven_file.dependencies[0].r#type.is_none());
        assert!(maven_file.dependencies[0].scope.is_none());
        assert!(maven_file.dependencies[0].version.is_none());

        assert_eq!(maven_file.dependencies[1].group_id, "io.quarkus");
        assert_eq!(maven_file.dependencies[1].artifact_id, "quarkus-rest");
        assert!(maven_file.dependencies[1].r#type.is_none());
        assert!(maven_file.dependencies[1].scope.is_none());
        assert!(maven_file.dependencies[1].version.is_none());

        assert_eq!(maven_file.dependencies[2].group_id, "io.quarkus");
        assert_eq!(
            maven_file.dependencies[2].artifact_id,
            "quarkus-rest-jackson"
        );
        assert!(maven_file.dependencies[2].r#type.is_none());
        assert!(maven_file.dependencies[2].scope.is_none());
        assert!(maven_file.dependencies[2].version.is_none());

        assert_eq!(maven_file.dependencies[3].group_id, "io.quarkus");
        assert_eq!(
            maven_file.dependencies[3].artifact_id,
            "quarkus-rest-client-jackson"
        );
        assert!(maven_file.dependencies[3].r#type.is_none());
        assert!(maven_file.dependencies[3].scope.is_none());
        assert!(maven_file.dependencies[3].version.is_none());

        assert_eq!(maven_file.dependencies[4].group_id, "io.quarkus");
        assert_eq!(maven_file.dependencies[4].artifact_id, "quarkus-junit5");
        assert!(maven_file.dependencies[4].r#type.is_none());
        assert_eq!(
            maven_file.dependencies[4].scope.clone().unwrap(),
            MavenDependencyScope::Test
        );
        assert!(maven_file.dependencies[4].version.is_none());

        assert_eq!(maven_file.dependencies[5].group_id, "io.rest-assured");
        assert_eq!(maven_file.dependencies[5].artifact_id, "rest-assured");
        assert!(maven_file.dependencies[5].r#type.is_none());
        assert_eq!(
            maven_file.dependencies[5].scope.clone().unwrap(),
            MavenDependencyScope::Test
        );
        assert!(maven_file.dependencies[5].version.is_none());

        assert_eq!(maven_file.dependencies[6].group_id, "org.wiremock");
        assert_eq!(maven_file.dependencies[6].artifact_id, "wiremock");
        assert!(maven_file.dependencies[6].r#type.is_none());
        assert_eq!(
            maven_file.dependencies[6].scope.clone().unwrap(),
            MavenDependencyScope::Test
        );
        assert_eq!(
            maven_file.dependencies[6].version.clone().unwrap(),
            "${wiremock.version}"
        );

        assert_eq!(maven_file.dependency_management.len(), 1);
        assert_eq!(
            maven_file.dependency_management[0].artifact_id,
            "${quarkus.platform.artifact-id}"
        );
        assert_eq!(
            maven_file.dependency_management[0].scope.clone().unwrap(),
            MavenDependencyScope::Import
        );
        assert_eq!(
            maven_file.dependency_management[0].group_id,
            "${quarkus.platform.group-id}"
        );
        assert_eq!(
            maven_file.dependency_management[0]
                .clone()
                .version
                .unwrap()
                .as_str(),
            "${quarkus.platform.version}"
        );
        assert_eq!(
            maven_file.dependency_management[0].clone().r#type.unwrap(),
            MavenDependencyType::Pom
        );
    }

    #[test]
    fn test_parse_pom_with_dependency_management() {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let context = MavenProducerContext::new(d.clone());
        d.push("resources/maven/hierarchy/pom.xml");
        let maven_file = MavenFile::new(&d, &context).expect("maven file is parsed");

        assert_eq!(maven_file.dependencies.len(), 2);
        assert_eq!(maven_file.dependency_management.len(), 11);
        assert_eq!(maven_file.properties.len(), 6);

        assert_eq!(
            maven_file.dependencies[0].group_id,
            "com.google.code.findbugs"
        );
        assert_eq!(maven_file.dependencies[0].artifact_id, "jsr305");
        assert!(maven_file.dependencies[0].r#type.is_none());
        assert!(maven_file.dependencies[0].scope.is_none());
        assert!(maven_file.dependencies[0].version.is_none());

        assert_eq!(maven_file.dependencies[1].group_id, "org.immutables");
        assert_eq!(maven_file.dependencies[1].artifact_id, "value-annotations");
        assert!(maven_file.dependencies[1].r#type.is_none());
        assert_eq!(
            maven_file.dependencies[1].clone().scope.unwrap(),
            MavenDependencyScope::Provided
        );
        assert!(maven_file.dependencies[1].version.is_none());

        assert_eq!(
            maven_file.dependency_management[0].group_id,
            "com.typesafe.akka"
        );
        assert_eq!(
            maven_file.dependency_management[0].artifact_id,
            "akka-actor_${akka-scala.version}"
        );
        assert!(maven_file.dependency_management[0].r#type.is_none());
        assert!(maven_file.dependency_management[0].scope.is_none());
        assert_eq!(
            maven_file.dependency_management[0]
                .version
                .clone()
                .unwrap()
                .as_str(),
            "${akka.version}"
        );

        assert_eq!(
            maven_file.dependency_management[1].group_id,
            "com.typesafe.akka"
        );
        assert_eq!(
            maven_file.dependency_management[1].artifact_id,
            "akka-slf4j_${akka-scala.version}"
        );
        assert!(maven_file.dependency_management[1].r#type.is_none());
        assert!(maven_file.dependency_management[1].scope.is_none());
        assert_eq!(
            maven_file.dependency_management[1]
                .version
                .clone()
                .unwrap()
                .as_str(),
            "${akka.version}"
        );
    }
}
