use lazy_static::lazy_static;
use regex::Regex;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use tree_sitter::{Language, Parser, Query, QueryCursor};

use crate::analyze::producers::maven::local_repo::{LocalPomRepo, SeedDep};
use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyLocation, DependencyType};
use crate::utils::context_resolver::HierarchicalContext;
use crate::utils::file_utils::make_instance_id;
use crate::utils::tree_sitter::tree::build_location_from_offsets;

#[derive(Clone, Default)]
pub struct GradleProducer {}

/// 用于在解析阶段临时存储提取到的依赖信息
#[derive(Clone, Debug)]
pub struct ExtractedDep {
    pub group: String,
    pub name: String,
    pub version: String,
    pub location: Option<DependencyLocation>,
}

lazy_static! {
    /// 匹配 Groovy/Kotlin 脚本中的属性定义，如:
    /// `val kotlinVersion = "1.9.22"` / `def gsonVersion = '2.10.1'` / `ext.bootVersion = "3.2.0"`
    static ref SCRIPT_PROP_RE: Regex = Regex::new(
        r#"(?m)^\s*(?:(?:val|var|def)\s+|ext\.)?([a-zA-Z_][a-zA-Z0-9_.]*)\s*=\s*['"]([^'"]+)['"]"#
    ).unwrap();

    /// 匹配 Groovy DSL 依赖声明（支持 3 段 group:name:ver 与 2 段 BOM 受管 group:name，支持 $var / ${var} 插值）
    static ref GROOVY_DEP_RE: Regex = Regex::new(
        r#"(?x)\b(?:api|implementation|compileOnly|runtimeOnly|testImplementation|testCompile)\s*(?:\(\s*)?(?:platform\s*\(\s*)?['\"][^'\"]+:[^'\"]+['\"]\s*\)?(?:\s*,\s*['\"][^'\"]+:[^'\"]+['\"])*"#
    ).unwrap();
    static ref GROOVY_COORD_RE: Regex = Regex::new(r#"['"]([^'"]+:[^'"]+)['"]"#).unwrap();
}

impl SbomProducer for GradleProducer {
    fn use_file(&self, path: &Path, _config: &SbomProducerConfiguration) -> bool {
        path.file_name()
            .and_then(|name| name.to_str())
            .map(|name| {
                name == "build.gradle.kts"
                    || name == "build.gradle"
                    || name == "libs.versions.toml"
                    || name.ends_with("gradle.lockfile")
            })
            .unwrap_or(false)
    }

    fn find_dependencies(
        &self,
        paths: &[PathBuf],
        config: &SbomProducerConfiguration,
    ) -> anyhow::Result<Vec<Dependency>> {
        let mut all_dependencies = Vec::new();

        // =================================================================
        // 第一趟（推广自 Maven 双趟上下文架构）：
        // 收集工作区根级与模块级 gradle.properties、libs.versions.toml 构建分层属性与受管版本表
        // =================================================================
        let mut root_context = HierarchicalContext::new();
        Self::load_gradle_properties_in_dir(&config.base_path, &mut root_context);
        let root_catalog = config.base_path.join("gradle").join("libs.versions.toml");
        if root_catalog.exists() {
            if let Ok(c) = fs::read_to_string(&root_catalog) {
                let _ = Self::populate_context_from_catalog(&c, &mut root_context);
            }
        }
        for path in paths {
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n == "libs.versions.toml")
            {
                if let Ok(c) = fs::read_to_string(path) {
                    let _ = Self::populate_context_from_catalog(&c, &mut root_context);
                }
            }
        }

        // =================================================================
        // 第二趟：带上下文变量插值 (${var} / $var) 与受管版本补全解析各构建文件
        // =================================================================
        let mut local_repo = LocalPomRepo::new();
        for path in paths {
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let content = match fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let mut local_ctx = HierarchicalContext::new();
            if let Some(parent_dir) = path.parent() {
                Self::load_gradle_properties_in_dir(parent_dir, &mut local_ctx);
            }
            Self::extract_script_properties(&content, &mut local_ctx);
            local_ctx.inherit_from(&root_context);

            let file_salt = path.to_string_lossy().replace('\\', "/");
            let is_lockfile = file_name.ends_with("gradle.lockfile");

            let mut extracted_deps = match file_name {
                name if name.ends_with(".gradle.kts") => {
                    Self::parse_kotlin_dependencies(&content, path, &local_ctx).unwrap_or_default()
                }
                name if name.ends_with(".gradle") => {
                    Self::parse_groovy_dependencies(&content, path, &local_ctx).unwrap_or_default()
                }
                "libs.versions.toml" => Self::parse_version_catalog(&content).unwrap_or_default(),
                _ if is_lockfile => Self::parse_gradle_lockfile(&content).unwrap_or_default(),
                _ => vec![],
            };

            if extracted_deps.is_empty() {
                continue;
            }

            if !is_lockfile && local_repo.is_available() {
                let mut managed_overrides: HashMap<(String, String), String> = HashMap::new();
                for d in &extracted_deps {
                    if !d.version.is_empty() {
                        if let Some(eff) =
                            local_repo.resolve_effective_pom(&d.group, &d.name, &d.version)
                        {
                            for (k, v) in eff.managed_versions {
                                managed_overrides.entry(k).or_insert(v);
                            }
                        }
                    }
                }
                for d in &mut extracted_deps {
                    if d.version.is_empty() {
                        if let Some(mv) = managed_overrides.get(&(d.group.clone(), d.name.clone()))
                        {
                            d.version = mv.clone();
                        }
                    }
                }
                let seeds: Vec<SeedDep> = extracted_deps
                    .iter()
                    .filter(|d| !d.version.is_empty())
                    .map(|d| SeedDep {
                        group_id: d.group.clone(),
                        artifact_id: d.name.clone(),
                        version: d.version.clone(),
                        exclusions: HashSet::new(),
                    })
                    .collect();
                let fallback_loc = Some(DependencyLocation::from_file(path));
                for t in local_repo.expand_transitive_deps(&seeds, &managed_overrides) {
                    extracted_deps.push(ExtractedDep {
                        group: t.group_id,
                        name: t.artifact_id,
                        version: t.version,
                        location: fallback_loc.clone(),
                    });
                }
            }

            let file_deps = Self::build_dependency_graph(extracted_deps, &file_salt, path)?;
            all_dependencies.extend(file_deps);
        }

        Ok(all_dependencies)
    }
}

impl GradleProducer {
    fn load_gradle_properties_in_dir(dir: &Path, ctx: &mut HierarchicalContext) {
        let prop_file = dir.join("gradle.properties");
        if let Ok(content) = fs::read_to_string(prop_file) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
                    continue;
                }
                if let Some((k, v)) = line.split_once('=').or_else(|| line.split_once(':')) {
                    ctx.insert_property(k.trim(), v.trim());
                }
            }
        }
    }

    fn extract_script_properties(content: &str, ctx: &mut HierarchicalContext) {
        for cap in SCRIPT_PROP_RE.captures_iter(content) {
            if let (Some(k), Some(v)) = (cap.get(1), cap.get(2)) {
                ctx.insert_property(k.as_str().trim(), v.as_str().trim());
            }
        }
    }

    fn populate_context_from_catalog(
        content: &str,
        ctx: &mut HierarchicalContext,
    ) -> anyhow::Result<()> {
        #[derive(Deserialize)]
        struct RawCatalog {
            versions: Option<toml::Table>,
        }
        if let Ok(cat) = toml::from_str::<RawCatalog>(content) {
            if let Some(vers) = cat.versions {
                for (k, v) in vers {
                    if let Some(s) = v.as_str() {
                        ctx.insert_property(k, s);
                    }
                }
            }
        }
        if let Ok(deps) = Self::parse_version_catalog(content) {
            for d in deps {
                ctx.insert_managed_version(format!("{}:{}", d.group, d.name), d.version);
            }
        }
        Ok(())
    }

    /// 将坐标字符串（2段 `group:name` 或 3段 `group:name:version`）结合上下文插值与 BOM 继承解析为 `ExtractedDep`
    fn resolve_coord_with_context(
        coord_str: &str,
        ctx: &HierarchicalContext,
        location: Option<DependencyLocation>,
    ) -> Option<ExtractedDep> {
        let interpolated = ctx.interpolate(coord_str);
        let parts: Vec<&str> = interpolated.split(':').collect();
        match parts.len() {
            3 => {
                let group = parts[0].trim();
                let name = parts[1].trim();
                let pkg_key = format!("{}:{}", group, name);
                let version = ctx.resolve_version(&pkg_key, Some(parts[2].trim()))?;
                if group.is_empty() || name.is_empty() || group.contains('$') || name.contains('$')
                {
                    return None;
                }
                Some(ExtractedDep {
                    group: group.to_string(),
                    name: name.to_string(),
                    version,
                    location,
                })
            }
            2 => {
                let group = parts[0].trim();
                let name = parts[1].trim();
                let pkg_key = format!("{}:{}", group, name);
                let version = ctx.resolve_version(&pkg_key, None).unwrap_or_default();
                Some(ExtractedDep {
                    group: group.to_string(),
                    name: name.to_string(),
                    version,
                    location,
                })
            }
            _ => None,
        }
    }

    /// 构建带工程根节点的 Gradle 依赖 DAG 图谱
    fn build_dependency_graph(
        extracted_deps: Vec<ExtractedDep>,
        file_salt: &str,
        file_path: &Path,
    ) -> anyhow::Result<Vec<Dependency>> {
        let fallback_location = Some(DependencyLocation::from_file(file_path));

        let app_name = file_path
            .parent()
            .and_then(|dir| dir.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("gradle-app")
            .to_string();

        let root_purl_raw = format!("pkg:maven/{}/{}@0.0.0", app_name, app_name);
        let root_purl = Dependency::auto_fix_and_validate_purl(&root_purl_raw);
        let root_instance_id = make_instance_id(&root_purl, file_salt);

        let mut leaf_deps = Vec::with_capacity(extracted_deps.len());
        let mut child_ids = Vec::with_capacity(extracted_deps.len());
        let mut seen_ids = HashSet::new();

        for dep in extracted_deps {
            let (version, requirement) =
                crate::utils::version_spec::manifest_version(Some(&dep.version), "gradle");
            let raw_purl = match &version {
                Some(v) => format!("pkg:maven/{}/{}@{}", dep.group, dep.name, v),
                None => format!("pkg:maven/{}/{}", dep.group, dep.name),
            };
            let valid_purl = Dependency::auto_fix_and_validate_purl(&raw_purl);
            let instance_id = make_instance_id(&valid_purl, file_salt);

            if !seen_ids.insert(instance_id.clone()) {
                continue;
            }

            child_ids.push(instance_id.clone());

            if let Ok(built) = DependencyBuilder::default()
                .group(Some(dep.group))
                .name(dep.name)
                .version(version)
                .version_requirement(requirement)
                .r#type(DependencyType::Library)
                .purl(valid_purl)
                .instance_id(instance_id)
                .dependencies(vec![])
                .location(dep.location.or_else(|| fallback_location.clone()))
                .build()
            {
                leaf_deps.push(built);
            }
        }

        if leaf_deps.is_empty() {
            return Ok(vec![]);
        }

        let root_dep = DependencyBuilder::default()
            .group(Some(app_name.clone()))
            .name(app_name)
            .version(Some("0.0.0".to_string()))
            .r#type(DependencyType::Application)
            .purl(root_purl)
            .instance_id(root_instance_id)
            .dependencies(child_ids)
            .location(fallback_location)
            .build()
            .map_err(|e| anyhow::anyhow!(e))?;

        let mut final_deps = Vec::with_capacity(leaf_deps.len() + 1);
        final_deps.push(root_dep);
        final_deps.extend(leaf_deps);

        Ok(final_deps)
    }

    /// 解析 Groovy DSL (`build.gradle`)，支持 `${var}` / `$var` 插值与受管版本继承
    pub fn parse_groovy_dependencies(
        content: &str,
        file_path: &Path,
        ctx: &HierarchicalContext,
    ) -> anyhow::Result<Vec<ExtractedDep>> {
        let mut deps = Vec::new();

        for statement in GROOVY_DEP_RE.find_iter(content) {
            for cap in GROOVY_COORD_RE.captures_iter(statement.as_str()) {
                if let Some(coord) = cap.get(1) {
                    let start = statement.start() + coord.start();
                    let end = statement.start() + coord.end();
                    let loc = build_location_from_offsets(
                        file_path,
                        content,
                        (start, end),
                        Some((start, end)),
                        None,
                    );
                    if let Some(resolved) =
                        Self::resolve_coord_with_context(coord.as_str(), ctx, Some(loc))
                    {
                        deps.push(resolved);
                    }
                }
            }
        }

        Ok(deps)
    }

    /// 使用 Tree-sitter 解析 Kotlin DSL (`build.gradle.kts`)，并结合上下文解析变量插值
    pub fn parse_kotlin_dependencies(
        content: &str,
        file_path: &Path,
        ctx: &HierarchicalContext,
    ) -> anyhow::Result<Vec<ExtractedDep>> {
        let language = tree_sitter_kotlin::language();
        let query_str = r#"
            (call_expression
                (simple_identifier) @config
                (#match? @config "^(api|implementation|compileOnly|runtimeOnly|testImplementation|testCompile)$")
                (call_suffix
                    (value_arguments
                        (value_argument
                            (_) @dep_literal
                        )
                    )
                )
            )
        "#;
        Self::execute_tree_sitter_query(content, file_path, language, query_str, ctx)
    }

    fn execute_tree_sitter_query(
        content: &str,
        file_path: &Path,
        language: Language,
        query_str: &str,
        ctx: &HierarchicalContext,
    ) -> anyhow::Result<Vec<ExtractedDep>> {
        let mut deps = Vec::new();
        let mut parser = Parser::new();
        parser.set_language(&language)?;

        let tree = parser
            .parse(content, None)
            .ok_or_else(|| anyhow::anyhow!("Failed to parse AST"))?;
        let root_node = tree.root_node();

        let query = Query::new(&language, query_str)?;
        let mut cursor = QueryCursor::new();
        let matches = cursor.matches(&query, root_node, content.as_bytes());

        for m in matches {
            for cap in m.captures {
                if query.capture_names()[cap.index as usize] == "dep_literal" {
                    let node = cap.node;
                    let raw_literal = &content[node.start_byte()..node.end_byte()];
                    let dep_str = raw_literal.trim_matches('"');

                    let loc = build_location_from_offsets(
                        file_path,
                        content,
                        (node.start_byte(), node.end_byte()),
                        None,
                        None,
                    );

                    if let Some(resolved) =
                        Self::resolve_coord_with_context(dep_str, ctx, Some(loc))
                    {
                        deps.push(resolved);
                    }
                }
            }
        }
        Ok(deps)
    }

    /// 解析 Gradle Lockfile 纯文本 (格式: group:name:version=config1,config2)
    fn parse_gradle_lockfile(content: &str) -> anyhow::Result<Vec<ExtractedDep>> {
        let mut deps = Vec::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("empty=") {
                continue;
            }

            if let Some((module_str, _configs)) = line.split_once('=') {
                let parts: Vec<&str> = module_str.split(':').collect();
                if parts.len() == 3 {
                    deps.push(ExtractedDep {
                        group: parts[0].to_string(),
                        name: parts[1].to_string(),
                        version: parts[2].to_string(),
                        location: None,
                    });
                }
            }
        }

        Ok(deps)
    }

    /// 解析 libs.versions.toml (支持 module="g:n"、group+name、version="x" 以及 version.ref="k")
    pub fn parse_version_catalog(content: &str) -> anyhow::Result<Vec<ExtractedDep>> {
        #[derive(Deserialize)]
        struct VersionCatalog {
            versions: Option<toml::Table>,
            libraries: Option<toml::Table>,
        }

        let catalog: VersionCatalog = toml::from_str(content)?;
        let mut deps = Vec::new();

        let resolve_ver = |table: &toml::Table| -> Option<String> {
            if let Some(v_str) = table.get("version").and_then(|v| v.as_str()) {
                return Some(v_str.to_string());
            }
            let v_ref = table
                .get("version")
                .and_then(|v| v.as_table())
                .and_then(|vt| vt.get("ref"))
                .and_then(|r| r.as_str())
                .or_else(|| table.get("version.ref").and_then(|r| r.as_str()))?;

            catalog
                .versions
                .as_ref()
                .and_then(|vers| vers.get(v_ref))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .or_else(|| Some(v_ref.to_string()))
        };

        if let Some(libraries) = catalog.libraries {
            for (_key, value) in libraries {
                if let Some(table) = value.as_table() {
                    let Some(version) = resolve_ver(table) else {
                        continue;
                    };

                    if let Some(module_str) = table.get("module").and_then(|m| m.as_str()) {
                        let parts: Vec<&str> = module_str.split(':').collect();
                        if parts.len() == 2 {
                            deps.push(ExtractedDep {
                                group: parts[0].to_string(),
                                name: parts[1].to_string(),
                                version,
                                location: None,
                            });
                        }
                    } else if let (Some(group), Some(name)) = (
                        table.get("group").and_then(|g| g.as_str()),
                        table.get("name").and_then(|n| n.as_str()),
                    ) {
                        deps.push(ExtractedDep {
                            group: group.to_string(),
                            name: name.to_string(),
                            version,
                            location: None,
                        });
                    }
                } else if let Some(dep_str) = value.as_str() {
                    let parts: Vec<&str> = dep_str.split(':').collect();
                    if parts.len() == 3 {
                        deps.push(ExtractedDep {
                            group: parts[0].to_string(),
                            name: parts[1].to_string(),
                            version: parts[2].to_string(),
                            location: None,
                        });
                    }
                }
            }
        }
        Ok(deps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_gradle_version_catalog_variants() {
        let toml_content = r#"
[versions]
kotlin = "1.9.22"
ktor = "2.3.7"

[libraries]
kotlin-stdlib = { module = "org.jetbrains.kotlin:kotlin-stdlib", version.ref = "kotlin" }
ktor-core = { group = "io.ktor", name = "ktor-client-core", version.ref = "ktor" }
gson = { group = "com.google.code.gson", name = "gson", version = "2.10.1" }
guava = "com.google.guava:guava:32.1.3-jre"
"#;
        let deps = GradleProducer::parse_version_catalog(toml_content).unwrap();
        assert_eq!(deps.len(), 4);
        assert!(deps.iter().any(|d| d.group == "org.jetbrains.kotlin"
            && d.name == "kotlin-stdlib"
            && d.version == "1.9.22"));
        assert!(deps
            .iter()
            .any(|d| d.group == "io.ktor" && d.name == "ktor-client-core" && d.version == "2.3.7"));
        assert!(deps.iter().any(|d| d.group == "com.google.code.gson"
            && d.name == "gson"
            && d.version == "2.10.1"));
        assert!(deps.iter().any(|d| d.group == "com.google.guava"
            && d.name == "guava"
            && d.version == "32.1.3-jre"));
    }

    #[test]
    fn test_gradle_variable_interpolation_and_bom_inheritance() {
        let groovy_script = r#"
def springBootVersion = '3.2.2'
dependencies {
    implementation "org.springframework.boot:spring-boot-starter-web:$springBootVersion"
    implementation "com.google.code.gson:gson:${gsonVersion}"
    implementation 'io.ktor:ktor-client-core'
}
"#;
        let mut ctx = HierarchicalContext::new();
        ctx.insert_property("gsonVersion", "2.10.1");
        ctx.insert_managed_version("io.ktor:ktor-client-core", "2.3.7");
        GradleProducer::extract_script_properties(groovy_script, &mut ctx);

        let deps = GradleProducer::parse_groovy_dependencies(
            groovy_script,
            Path::new("build.gradle"),
            &ctx,
        )
        .unwrap();

        assert_eq!(deps.len(), 3);
        assert!(deps
            .iter()
            .any(|d| d.name == "spring-boot-starter-web" && d.version == "3.2.2"));
        assert!(deps
            .iter()
            .any(|d| d.name == "gson" && d.version == "2.10.1"));
        assert!(deps
            .iter()
            .any(|d| d.name == "ktor-client-core" && d.version == "2.3.7"));
    }

    #[test]
    fn test_parse_gradle_lockfile() {
        let lockfile_content = r#"
# This is a gradle lockfile
org.springframework.boot:spring-boot-starter-web:3.2.0=compileClasspath,runtimeClasspath
com.fasterxml.jackson.core:jackson-databind:2.15.2=runtimeClasspath
empty=testCompileClasspath
"#;
        let deps = GradleProducer::parse_gradle_lockfile(lockfile_content).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "spring-boot-starter-web");
        assert_eq!(deps[0].version, "3.2.0");
        assert_eq!(deps[1].name, "jackson-databind");
        assert_eq!(deps[1].version, "2.15.2");
    }

    #[test]
    fn groovy_preserves_unresolved_managed_dependency() {
        let deps = GradleProducer::parse_groovy_dependencies(
            "implementation \"io.example:managed\"",
            Path::new("build.gradle"),
            &HierarchicalContext::new(),
        )
        .unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "managed");
        assert!(deps[0].version.is_empty());
    }

    #[test]
    fn parses_groovy_multiple_arguments_and_platform() {
        let content = "implementation platform(\"io.demo:bill:1.0.0\")\nimplementation \"io.demo:first:1.0.0\",\n  \"io.demo:second:2.0.0\"\nruntimeOnly 'io.demo:third:3.0.0', 'io.demo:fourth:4.0.0'";
        let deps = GradleProducer::parse_groovy_dependencies(
            content,
            Path::new("build.gradle"),
            &HierarchicalContext::new(),
        )
        .unwrap();
        let names: Vec<_> = deps.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["bill", "first", "second", "third", "fourth"]);
    }

    #[test]
    fn test_parse_kotlin_dependencies_and_dag() {
        let kts_content = r#"
dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")
    api("io.ktor:ktor-client-core:2.3.7")
}
"#;
        let ctx = HierarchicalContext::new();
        let extracted = GradleProducer::parse_kotlin_dependencies(
            kts_content,
            Path::new("payment/build.gradle.kts"),
            &ctx,
        )
        .unwrap();
        assert_eq!(extracted.len(), 2);

        let file_salt = "payment/build.gradle.kts";
        let graph = GradleProducer::build_dependency_graph(
            extracted,
            file_salt,
            Path::new("payment/build.gradle.kts"),
        )
        .unwrap();

        assert_eq!(graph.len(), 3, "1 root + 2 leaf deps");
        let root = graph
            .iter()
            .find(|d| d.r#type == DependencyType::Application)
            .unwrap();
        assert_eq!(root.name, "payment");
        assert_eq!(root.dependencies.len(), 2);
    }

    #[test]
    fn test_gradle_producer_use_file() {
        let producer = GradleProducer::default();
        let config = SbomProducerConfiguration {
            base_path: PathBuf::from("."),
            use_debug: false,
        };
        assert!(producer.use_file(Path::new("build.gradle"), &config));
        assert!(producer.use_file(Path::new("build.gradle.kts"), &config));
        assert!(producer.use_file(Path::new("libs.versions.toml"), &config));
        assert!(producer.use_file(Path::new("gradle.lockfile"), &config));
        assert!(!producer.use_file(Path::new("pom.xml"), &config));
    }
}
