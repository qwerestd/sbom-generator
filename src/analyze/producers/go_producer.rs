use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyType};
use crate::utils::command::run_with_timeout;
use crate::utils::file_utils::{get_manifest_rel_path, make_instance_id};
use anyhow::Context;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::Duration;

#[derive(Clone, Default)]
pub struct GoProducer {}

#[derive(Clone, Debug)]
struct GoProjectRoot {
    root_path: PathBuf,
    workspace_root: Option<PathBuf>,
    go_work_path: Option<PathBuf>,
    workspace_replaces: Vec<GoReplace>,
    workspace_toolchain: Option<String>,
}

#[derive(Clone, Debug, Default)]
struct GoManifest {
    module_path: Option<String>,
    go_version: Option<String>,
    toolchain: Option<String>,
    requires: Vec<GoRequire>,
    replaces: Vec<GoReplace>,
    excludes: Vec<GoExclude>,
    retractions: Vec<String>,
}

#[derive(Clone, Debug)]
struct GoRequire {
    path: String,
    version: Option<String>,
    indirect: bool,
}

#[derive(Clone, Debug)]
struct GoReplace {
    old_path: String,
    old_version: Option<String>,
    new_path: String,
    new_version: Option<String>,
    local_path: Option<String>,
    local_base_dir: Option<PathBuf>,
}

#[derive(Clone, Debug, Default)]
struct GoWorkspace {
    uses: Vec<String>,
    replaces: Vec<GoReplace>,
    toolchain: Option<String>,
}

#[derive(Clone, Debug)]
struct GoExclude {
    path: String,
    version: String,
}

#[derive(Clone, Debug, Default)]
struct GoEnv {
    goos: Option<String>,
    goarch: Option<String>,
    goversion: Option<String>,
    cgo_enabled: Option<String>,
}

#[derive(Clone, Debug)]
struct GoComponent {
    module_path: String,
    version: Option<String>,
    requested_version: Option<String>,
    purl: String,
    instance_id: String,
    dependencies: BTreeSet<String>,
    project_root: String,
    manifest_path: String,
    workspace_root: Option<String>,
    go_work_path: Option<String>,
    scope: BTreeSet<String>,
    relationship: String,
    direct: bool,
    indirect: bool,
    main_module: bool,
    local: bool,
    workspace_member: bool,
    replacement_original: Option<String>,
    replacement_path: Option<String>,
    replacement_version: Option<String>,
    replacement_type: Option<String>,
    evidence_source: BTreeSet<String>,
    confidence: String,
    parsing_mode: String,
    go_version: Option<String>,
    toolchain_version: Option<String>,
    goos: Option<String>,
    goarch: Option<String>,
    cgo_enabled: Option<String>,
    host_active: Option<bool>,
    excluded_versions: Option<String>,
    retractions: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GoListModule {
    path: String,
    version: Option<String>,
    main: Option<bool>,
    indirect: Option<bool>,
    #[allow(dead_code)]
    dir: Option<String>,
    #[allow(dead_code)]
    go_mod: Option<String>,
    go_version: Option<String>,
    replace: Option<GoListReplace>,
    error: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GoListReplace {
    path: String,
    version: Option<String>,
    dir: Option<String>,
    go_mod: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GoListPackage {
    standard: Option<bool>,
    for_test: Option<String>,
    module: Option<GoListPackageModule>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GoListPackageModule {
    path: String,
    version: Option<String>,
}

impl SbomProducer for GoProducer {
    fn use_file(&self, path: &Path, _configuration: &SbomProducerConfiguration) -> bool {
        path.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|name| {
                matches!(name, "go.mod" | "go.work" | "go.sum")
                    || (name == "modules.txt"
                        && path
                            .parent()
                            .and_then(|p| p.file_name())
                            .and_then(|n| n.to_str())
                            == Some("vendor"))
            })
    }

    fn find_dependencies(
        &self,
        paths: &[PathBuf],
        configuration: &SbomProducerConfiguration,
    ) -> anyhow::Result<Vec<Dependency>> {
        let projects = discover_go_projects(paths, &configuration.base_path);
        let mut result = Vec::new();

        for project in projects {
            let dynamic_result = if configuration.dynamic && go_is_available() {
                match self.resolve_dynamic_project(&project, configuration) {
                    Ok(deps) if !deps.is_empty() => Some(deps),
                    Ok(_) => None,
                    Err(err) => {
                        eprintln!(
                            "[Go] dynamic parsing failed for {}; static fallback will be used: {}",
                            project.root_path.display(),
                            err
                        );
                        None
                    }
                }
            } else {
                None
            };

            if let Some(deps) = dynamic_result {
                result.extend(deps);
            } else {
                match self.resolve_static_project(&project, configuration) {
                    Ok(deps) => result.extend(deps),
                    Err(err) => eprintln!(
                        "[Go] static parsing failed for {}: {}",
                        project.root_path.display(),
                        err
                    ),
                }
            }
        }

        Ok(result)
    }
}

impl GoProducer {
    fn resolve_dynamic_project(
        &self,
        project: &GoProjectRoot,
        configuration: &SbomProducerConfiguration,
    ) -> anyhow::Result<Vec<Dependency>> {
        let manifest = parse_go_mod(&project.root_path.join("go.mod")).unwrap_or_default();
        let env = go_env(project).unwrap_or_default();
        let modules = go_list_modules(project)?;
        let graph_edges = go_mod_graph(project)?;
        let runtime_modules = go_list_package_modules(project, false).unwrap_or_default();
        let test_modules = go_list_package_modules(project, true).unwrap_or_default();

        let mut components = BTreeMap::new();
        let root_rel = get_manifest_rel_path(&configuration.base_path, &project.root_path);
        let manifest_rel =
            get_manifest_rel_path(&configuration.base_path, &project.root_path.join("go.mod"));
        let workspace_rel = project
            .workspace_root
            .as_ref()
            .map(|p| get_manifest_rel_path(&configuration.base_path, p));
        let go_work_rel = project
            .go_work_path
            .as_ref()
            .map(|p| get_manifest_rel_path(&configuration.base_path, p));
        let excluded_versions = excludes_string(&manifest.excludes);
        let retractions = strings_join(&manifest.retractions);
        let mut id_by_graph_key = HashMap::new();

        for module in modules {
            if module.error.is_some() {
                eprintln!(
                    "[Go] module {} reported an error in go list -m output",
                    module.path
                );
            }
            let replacement = module.replace.as_ref();
            let is_main = module.main.unwrap_or(false);
            let module_path = replacement
                .map(|r| r.path.clone())
                .unwrap_or_else(|| module.path.clone());
            let module_version = replacement
                .and_then(|r| r.version.clone())
                .or_else(|| module.version.clone());
            let key = module_key(&module.path, module.version.as_deref());
            let purl = go_purl(&module_path, module_version.as_deref());
            let instance_id = go_instance_id(
                &purl,
                &root_rel,
                &manifest_rel,
                &module_path,
                module_version.as_deref(),
            );
            id_by_graph_key.insert(key, instance_id.clone());

            let mut evidence = BTreeSet::from(["go-list-m".to_string()]);
            if module.replace.is_some() {
                evidence.insert("replace".to_string());
            }
            let replacement_is_local = replacement
                .and_then(|r| r.dir.as_ref().or(r.go_mod.as_ref()))
                .is_some();
            let local = is_main || replacement_is_local;
            let replacement_type = replacement.map(|r| {
                if r.dir.is_some() || r.go_mod.is_some() {
                    "local".to_string()
                } else {
                    "module".to_string()
                }
            });

            components.insert(
                instance_id.clone(),
                GoComponent {
                    module_path: module_path.clone(),
                    version: module_version.clone(),
                    requested_version: module.version.clone(),
                    purl,
                    instance_id,
                    dependencies: BTreeSet::new(),
                    project_root: root_rel.clone(),
                    manifest_path: manifest_rel.clone(),
                    workspace_root: workspace_rel.clone(),
                    go_work_path: go_work_rel.clone(),
                    scope: BTreeSet::from(["unknown".to_string()]),
                    relationship: if is_main { "direct" } else { "unknown" }.to_string(),
                    direct: is_main,
                    indirect: module.indirect.unwrap_or(false),
                    main_module: is_main,
                    local,
                    workspace_member: is_main && project.workspace_root.is_some(),
                    replacement_original: replacement
                        .map(|_| module_identity(&module.path, module.version.as_deref())),
                    replacement_path: replacement.map(|r| r.path.clone()),
                    replacement_version: replacement.and_then(|r| r.version.clone()),
                    replacement_type,
                    evidence_source: evidence,
                    confidence: "high".to_string(),
                    parsing_mode: "dynamic".to_string(),
                    go_version: module
                        .go_version
                        .clone()
                        .or_else(|| manifest.go_version.clone()),
                    toolchain_version: env
                        .goversion
                        .clone()
                        .or_else(|| manifest.toolchain.clone())
                        .or_else(|| project.workspace_toolchain.clone()),
                    goos: env.goos.clone(),
                    goarch: env.goarch.clone(),
                    cgo_enabled: env.cgo_enabled.clone(),
                    host_active: Some(false),
                    excluded_versions: excluded_versions.clone(),
                    retractions: retractions.clone(),
                },
            );
        }

        for (parent, child) in graph_edges {
            let Some(parent_id) = id_by_graph_key.get(&parent).cloned() else {
                eprintln!(
                    "[Go] unresolved go mod graph parent {} in {}",
                    parent,
                    project.root_path.display()
                );
                continue;
            };
            let Some(child_id) = id_by_graph_key.get(&child).cloned() else {
                eprintln!(
                    "[Go] unresolved go mod graph child {} in {}",
                    child,
                    project.root_path.display()
                );
                continue;
            };
            if let Some(parent_comp) = components.get_mut(&parent_id) {
                parent_comp.dependencies.insert(child_id.clone());
                parent_comp
                    .evidence_source
                    .insert("go-mod-graph".to_string());
            }
            if let Some(child_comp) = components.get_mut(&child_id) {
                if child_comp.relationship == "unknown" {
                    child_comp.relationship = "transitive".to_string();
                }
            }
        }

        apply_require_metadata(&mut components, &id_by_graph_key, &manifest.requires);
        apply_package_scopes(
            &mut components,
            &id_by_graph_key,
            runtime_modules,
            "runtime",
        );
        apply_package_scopes(&mut components, &id_by_graph_key, test_modules, "test");

        let mut deps = components_to_dependencies(components);
        deps.sort_by(|a, b| a.instance_id.cmp(&b.instance_id));
        Ok(deps)
    }

    fn resolve_static_project(
        &self,
        project: &GoProjectRoot,
        configuration: &SbomProducerConfiguration,
    ) -> anyhow::Result<Vec<Dependency>> {
        let manifest_path = project.root_path.join("go.mod");
        let manifest = parse_go_mod(&manifest_path)
            .with_context(|| format!("failed to parse {}", manifest_path.display()))?;
        let Some(main_module_path) = manifest.module_path.clone() else {
            return Ok(Vec::new());
        };

        let root_rel = get_manifest_rel_path(&configuration.base_path, &project.root_path);
        let manifest_rel = get_manifest_rel_path(&configuration.base_path, &manifest_path);
        let workspace_rel = project
            .workspace_root
            .as_ref()
            .map(|p| get_manifest_rel_path(&configuration.base_path, p));
        let go_work_rel = project
            .go_work_path
            .as_ref()
            .map(|p| get_manifest_rel_path(&configuration.base_path, p));
        let excluded_versions = excludes_string(&manifest.excludes);
        let retractions = strings_join(&manifest.retractions);

        let mut components: BTreeMap<String, GoComponent> = BTreeMap::new();
        let mut id_by_key = HashMap::new();

        let main_id = insert_go_component(
            &mut components,
            &mut id_by_key,
            GoComponentInput {
                module_path: main_module_path.clone(),
                version: None,
                requested_version: None,
                root_rel: &root_rel,
                manifest_rel: &manifest_rel,
                workspace_rel: workspace_rel.as_deref(),
                go_work_rel: go_work_rel.as_deref(),
                scope: "runtime",
                relationship: "direct",
                direct: true,
                indirect: false,
                main_module: true,
                local: true,
                workspace_member: project.workspace_root.is_some(),
                replacement_original: None,
                replacement_path: None,
                replacement_version: None,
                replacement_type: None,
                evidence_source: "go.mod",
                confidence: "medium",
                parsing_mode: "static-fallback",
                go_version: manifest.go_version.as_deref(),
                toolchain_version: manifest
                    .toolchain
                    .as_deref()
                    .or(project.workspace_toolchain.as_deref()),
                goos: None,
                goarch: None,
                cgo_enabled: None,
                host_active: None,
                excluded_versions: excluded_versions.as_deref(),
                retractions: retractions.as_deref(),
            },
        );

        let effective_manifest = manifest_with_workspace_replaces(&manifest, project);

        for require in &manifest.requires {
            if is_excluded(require, &manifest.excludes) {
                continue;
            }
            let effective = effective_require(
                require,
                &effective_manifest,
                &project.root_path,
                &configuration.base_path,
                project.workspace_root.as_deref(),
            );
            let child_id = insert_go_component(
                &mut components,
                &mut id_by_key,
                GoComponentInput {
                    module_path: effective.module_path,
                    version: effective.version.as_deref(),
                    requested_version: require.version.as_deref(),
                    root_rel: &root_rel,
                    manifest_rel: &manifest_rel,
                    workspace_rel: workspace_rel.as_deref(),
                    go_work_rel: go_work_rel.as_deref(),
                    scope: "unknown",
                    relationship: "direct",
                    direct: true,
                    indirect: require.indirect,
                    main_module: false,
                    local: effective.local,
                    workspace_member: effective.workspace_member,
                    replacement_original: effective.replacement_original.as_deref(),
                    replacement_path: effective.replacement_path.as_deref(),
                    replacement_version: effective.replacement_version.as_deref(),
                    replacement_type: effective.replacement_type.as_deref(),
                    evidence_source: effective.evidence_source,
                    confidence: effective.confidence,
                    parsing_mode: "static-fallback",
                    go_version: manifest.go_version.as_deref(),
                    toolchain_version: manifest
                        .toolchain
                        .as_deref()
                        .or(project.workspace_toolchain.as_deref()),
                    goos: None,
                    goarch: None,
                    cgo_enabled: None,
                    host_active: None,
                    excluded_versions: excluded_versions.as_deref(),
                    retractions: None,
                },
            );
            if let Some(main) = components.get_mut(&main_id) {
                main.dependencies.insert(child_id);
            }
        }

        add_vendor_modules(
            &mut components,
            &mut id_by_key,
            project,
            &manifest,
            StaticGoContext {
                root_rel: &root_rel,
                manifest_rel: &manifest_rel,
                workspace_rel: workspace_rel.as_deref(),
                go_work_rel: go_work_rel.as_deref(),
            },
        );

        let mut deps = components_to_dependencies(components);
        deps.sort_by(|a, b| a.instance_id.cmp(&b.instance_id));
        Ok(deps)
    }
}

struct GoComponentInput<'a> {
    module_path: String,
    version: Option<&'a str>,
    requested_version: Option<&'a str>,
    root_rel: &'a str,
    manifest_rel: &'a str,
    workspace_rel: Option<&'a str>,
    go_work_rel: Option<&'a str>,
    scope: &'a str,
    relationship: &'a str,
    direct: bool,
    indirect: bool,
    main_module: bool,
    local: bool,
    workspace_member: bool,
    replacement_original: Option<&'a str>,
    replacement_path: Option<&'a str>,
    replacement_version: Option<&'a str>,
    replacement_type: Option<&'a str>,
    evidence_source: &'a str,
    confidence: &'a str,
    parsing_mode: &'a str,
    go_version: Option<&'a str>,
    toolchain_version: Option<&'a str>,
    goos: Option<&'a str>,
    goarch: Option<&'a str>,
    cgo_enabled: Option<&'a str>,
    host_active: Option<bool>,
    excluded_versions: Option<&'a str>,
    retractions: Option<&'a str>,
}

struct EffectiveRequire {
    module_path: String,
    version: Option<String>,
    local: bool,
    workspace_member: bool,
    replacement_original: Option<String>,
    replacement_path: Option<String>,
    replacement_version: Option<String>,
    replacement_type: Option<String>,
    evidence_source: &'static str,
    confidence: &'static str,
}

struct StaticGoContext<'a> {
    root_rel: &'a str,
    manifest_rel: &'a str,
    workspace_rel: Option<&'a str>,
    go_work_rel: Option<&'a str>,
}

fn discover_go_projects(paths: &[PathBuf], base_path: &Path) -> Vec<GoProjectRoot> {
    let mut go_mod_roots: BTreeSet<PathBuf> = BTreeSet::new();
    let mut workspace_members: BTreeMap<PathBuf, (PathBuf, PathBuf, GoWorkspace)> = BTreeMap::new();

    for path in paths {
        match path.file_name().and_then(|n| n.to_str()) {
            Some("go.mod") if !is_polluted_go_path(path) => {
                if let Some(parent) = path.parent() {
                    go_mod_roots
                        .insert(fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf()));
                }
            }
            Some("go.work") => {
                if let Some(work_root) = path.parent() {
                    let workspace = parse_go_work(path);
                    let comparable_work_root =
                        fs::canonicalize(work_root).unwrap_or_else(|_| work_root.to_path_buf());
                    for use_path in &workspace.uses {
                        let member_root = normalize_join(work_root, &use_path);
                        let comparable_member =
                            fs::canonicalize(&member_root).unwrap_or_else(|_| member_root.clone());
                        let comparable_base =
                            fs::canonicalize(base_path).unwrap_or_else(|_| base_path.to_path_buf());
                        if !comparable_member.starts_with(&comparable_base) {
                            eprintln!(
                                "[Go] go.work member {} is outside scan root {}; skipped",
                                member_root.display(),
                                base_path.display()
                            );
                            continue;
                        }
                        if member_root.join("go.mod").exists() {
                            go_mod_roots.insert(member_root.clone());
                            workspace_members.insert(
                                member_root,
                                (
                                    comparable_work_root.clone(),
                                    path.to_path_buf(),
                                    workspace.clone(),
                                ),
                            );
                        } else {
                            eprintln!(
                                "[Go] go.work member {} does not contain go.mod",
                                member_root.display()
                            );
                        }
                    }
                }
            }
            _ => {}
        }
    }

    go_mod_roots
        .into_iter()
        .map(|root| {
            let workspace = workspace_members.get(&root).cloned();
            GoProjectRoot {
                root_path: root,
                workspace_root: workspace.as_ref().map(|(root, _, _)| root.clone()),
                go_work_path: workspace.as_ref().map(|(_, path, _)| path.clone()),
                workspace_replaces: workspace
                    .as_ref()
                    .map(|(_, _, workspace)| workspace.replaces.clone())
                    .unwrap_or_default(),
                workspace_toolchain: workspace.and_then(|(_, _, workspace)| workspace.toolchain),
            }
        })
        .collect()
}

fn is_polluted_go_path(path: &Path) -> bool {
    let parts: Vec<_> = path
        .components()
        .filter_map(component_str)
        .map(|s| s.to_ascii_lowercase())
        .collect();

    parts.windows(3).any(|w| w == ["go", "pkg", "mod"])
        || parts.iter().any(|part| {
            matches!(
                part.as_str(),
                ".git"
                    | "vendor"
                    | "node_modules"
                    | "target"
                    | "dist"
                    | "build"
                    | "gomodcache"
                    | ".gocache"
                    | "tmp"
                    | "temp"
                    | "out"
                    | "coverage"
                    | ".cache"
            )
        })
        || parts.windows(2).any(|w| w == ["examples", "generated"])
}

fn component_str(component: Component<'_>) -> Option<String> {
    match component {
        Component::Normal(value) => value.to_str().map(str::to_string),
        _ => None,
    }
}

fn parse_go_work(path: &Path) -> GoWorkspace {
    let Ok(content) = fs::read_to_string(path) else {
        return GoWorkspace::default();
    };
    let mut workspace = parse_go_work_content(&content);
    if let Some(work_root) = path.parent() {
        for replace in &mut workspace.replaces {
            if replace.local_path.is_some() {
                replace.local_base_dir = Some(work_root.to_path_buf());
            }
        }
    }
    workspace
}

fn parse_go_work_content(content: &str) -> GoWorkspace {
    let mut workspace = GoWorkspace::default();
    let mut block: Option<String> = None;
    let mut pending_replace: Option<String> = None;

    for raw_line in content.lines() {
        let line = strip_go_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(left) = pending_replace.take() {
            parse_go_work_directive("replace", &format!("{} {}", left, line), &mut workspace);
            continue;
        }
        if let Some(block_name) = block.clone() {
            if line == ")" {
                block = None;
            } else if block_name == "replace" && line.ends_with("=>") {
                pending_replace = Some(line.to_string());
            } else {
                parse_go_work_directive(&block_name, line, &mut workspace);
            }
            continue;
        }

        if let Some(name) = line.strip_suffix('(').map(str::trim) {
            if matches!(name, "use" | "replace") {
                block = Some(name.to_string());
                continue;
            }
        }

        let mut parts = line.splitn(2, char::is_whitespace);
        let directive = parts.next().unwrap_or("");
        let rest = parts.next().unwrap_or("").trim();
        if directive == "replace" && rest.ends_with("=>") {
            pending_replace = Some(rest.to_string());
        } else {
            parse_go_work_directive(directive, rest, &mut workspace);
        }
    }

    workspace
}

fn parse_go_work_directive(directive: &str, rest: &str, workspace: &mut GoWorkspace) {
    match directive {
        "use" => {
            if !rest.is_empty() {
                workspace.uses.push(unquote(rest));
            }
        }
        "replace" => {
            if let Some(replace) = parse_replace(rest) {
                workspace.replaces.push(replace);
            }
        }
        "toolchain" => {
            workspace.toolchain = rest.split_whitespace().next().map(str::to_string);
        }
        _ => {}
    }
}

fn parse_go_mod(path: &Path) -> anyhow::Result<GoManifest> {
    let content = fs::read_to_string(path)?;
    Ok(parse_go_mod_content(&content))
}

fn manifest_with_workspace_replaces(manifest: &GoManifest, project: &GoProjectRoot) -> GoManifest {
    let mut effective = manifest.clone();
    effective
        .replaces
        .extend(project.workspace_replaces.clone());
    if effective.toolchain.is_none() {
        effective.toolchain = project.workspace_toolchain.clone();
    }
    effective
}

fn parse_go_mod_content(content: &str) -> GoManifest {
    let mut manifest = GoManifest::default();
    let mut block: Option<String> = None;
    let mut pending_replace: Option<String> = None;

    for raw_line in content.lines() {
        let indirect = raw_line.contains("// indirect");
        let line = strip_go_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(left) = pending_replace.take() {
            parse_go_mod_directive(
                "replace",
                &format!("{} {}", left, line),
                indirect,
                &mut manifest,
            );
            continue;
        }

        if let Some(block_name) = block.clone() {
            if line == ")" {
                block = None;
                continue;
            }
            if block_name == "replace" && line.ends_with("=>") {
                pending_replace = Some(line.to_string());
                continue;
            }
            parse_go_mod_directive(&block_name, line, indirect, &mut manifest);
            continue;
        }

        if let Some(name) = line.strip_suffix('(').map(str::trim) {
            if matches!(name, "require" | "replace" | "exclude" | "retract") {
                block = Some(name.to_string());
                continue;
            }
        }

        let mut parts = line.splitn(2, char::is_whitespace);
        let directive = parts.next().unwrap_or("");
        let rest = parts.next().unwrap_or("").trim();
        if directive == "replace" && rest.ends_with("=>") {
            pending_replace = Some(rest.to_string());
        } else {
            parse_go_mod_directive(directive, rest, indirect, &mut manifest);
        }
    }

    manifest
}

fn parse_go_mod_directive(directive: &str, rest: &str, indirect: bool, manifest: &mut GoManifest) {
    match directive {
        "module" => manifest.module_path = rest.split_whitespace().next().map(unquote),
        "go" => manifest.go_version = rest.split_whitespace().next().map(str::to_string),
        "toolchain" => manifest.toolchain = rest.split_whitespace().next().map(str::to_string),
        "require" => {
            let parts: Vec<_> = rest.split_whitespace().collect();
            if parts.len() >= 2 {
                manifest.requires.push(GoRequire {
                    path: unquote(parts[0]),
                    version: Some(unquote(parts[1])),
                    indirect,
                });
            }
        }
        "replace" => {
            if let Some(replace) = parse_replace(rest) {
                manifest.replaces.push(replace);
            }
        }
        "exclude" => {
            let parts: Vec<_> = rest.split_whitespace().collect();
            if parts.len() >= 2 {
                manifest.excludes.push(GoExclude {
                    path: unquote(parts[0]),
                    version: unquote(parts[1]),
                });
            }
        }
        "retract" => manifest.retractions.push(rest.to_string()),
        _ => {}
    }
}

fn parse_replace(rest: &str) -> Option<GoReplace> {
    let (left, right) = rest.split_once("=>")?;
    let left_parts: Vec<_> = left.split_whitespace().collect();
    let right_parts: Vec<_> = right.split_whitespace().collect();
    if left_parts.is_empty() || right_parts.is_empty() {
        return None;
    }
    let old_path = unquote(left_parts[0]);
    let old_version = left_parts.get(1).map(|s| unquote(s));
    let new_path = unquote(right_parts[0]);
    let new_version = right_parts.get(1).map(|s| unquote(s));
    let local_path = is_local_go_path(&new_path).then(|| new_path.clone());
    Some(GoReplace {
        old_path,
        old_version,
        new_path,
        new_version,
        local_path,
        local_base_dir: None,
    })
}

fn strip_go_comment(line: &str) -> &str {
    line.split("//").next().unwrap_or(line)
}

fn unquote(value: &str) -> String {
    value.trim().trim_matches('"').trim_matches('`').to_string()
}

fn is_local_go_path(value: &str) -> bool {
    value.starts_with("./") || value.starts_with("../") || value.starts_with('/') || value == "."
}

fn normalize_join(base: &Path, rel: &str) -> PathBuf {
    let path = base.join(rel);
    fs::canonicalize(&path).unwrap_or(path)
}

fn go_is_available() -> bool {
    let mut cmd = Command::new("go");
    cmd.arg("version");
    run_with_timeout(&mut cmd, Duration::from_secs(10))
        .map(|out| out.status.success())
        .unwrap_or(false)
}

fn go_list_modules(project: &GoProjectRoot) -> anyhow::Result<Vec<GoListModule>> {
    let mut cmd = Command::new("go");
    cmd.args(["list", "-m", "-json", "all"])
        .current_dir(&project.root_path);
    apply_go_workspace_env(&mut cmd, project);
    let output = run_with_timeout(&mut cmd, Duration::from_secs(120))?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "go list -m failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    parse_json_stream::<GoListModule>(&output.stdout)
}

fn go_mod_graph(project: &GoProjectRoot) -> anyhow::Result<Vec<(String, String)>> {
    let mut cmd = Command::new("go");
    cmd.args(["mod", "graph"]).current_dir(&project.root_path);
    apply_go_workspace_env(&mut cmd, project);
    let output = run_with_timeout(&mut cmd, Duration::from_secs(120))?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "go mod graph failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            Some((
                module_key_from_graph(parts.next()?),
                module_key_from_graph(parts.next()?),
            ))
        })
        .collect())
}

fn go_list_package_modules(
    project: &GoProjectRoot,
    include_tests: bool,
) -> anyhow::Result<BTreeSet<String>> {
    let mut cmd = Command::new("go");
    if include_tests {
        cmd.args(["list", "-deps", "-test", "-json", "./..."]);
    } else {
        cmd.args(["list", "-deps", "-json", "./..."]);
    }
    cmd.current_dir(&project.root_path);
    apply_go_workspace_env(&mut cmd, project);
    let output = run_with_timeout(&mut cmd, Duration::from_secs(120))?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "go list -deps failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let packages = parse_json_stream::<GoListPackage>(&output.stdout)?;
    Ok(packages
        .into_iter()
        .filter(|pkg| !pkg.standard.unwrap_or(false))
        .filter_map(|pkg| {
            let module = pkg.module?;
            if include_tests || pkg.for_test.is_none() {
                Some(module_key(&module.path, module.version.as_deref()))
            } else {
                None
            }
        })
        .collect())
}

fn go_env(project: &GoProjectRoot) -> anyhow::Result<GoEnv> {
    #[derive(Deserialize)]
    #[serde(rename_all = "SCREAMING_SNAKE_CASE")]
    struct RawGoEnv {
        goos: Option<String>,
        goarch: Option<String>,
        goversion: Option<String>,
        cgo_enabled: Option<String>,
    }

    let mut cmd = Command::new("go");
    cmd.args([
        "env",
        "-json",
        "GOOS",
        "GOARCH",
        "GOVERSION",
        "GOMOD",
        "GOWORK",
        "CGO_ENABLED",
    ])
    .current_dir(&project.root_path);
    apply_go_workspace_env(&mut cmd, project);
    let output = run_with_timeout(&mut cmd, Duration::from_secs(20))?;
    if !output.status.success() {
        return Err(anyhow::anyhow!("go env failed"));
    }
    let raw: RawGoEnv = serde_json::from_slice(&output.stdout)?;
    Ok(GoEnv {
        goos: raw.goos,
        goarch: raw.goarch,
        goversion: raw.goversion,
        cgo_enabled: raw.cgo_enabled,
    })
}

fn apply_go_workspace_env(cmd: &mut Command, project: &GoProjectRoot) {
    if let Some(go_work_path) = &project.go_work_path {
        cmd.env("GOWORK", go_work_path);
    } else {
        cmd.env("GOWORK", "off");
    }
}

fn parse_json_stream<T>(bytes: &[u8]) -> anyhow::Result<Vec<T>>
where
    T: for<'de> Deserialize<'de>,
{
    let stream = serde_json::Deserializer::from_slice(bytes).into_iter::<T>();
    let mut values = Vec::new();
    for value in stream {
        values.push(value?);
    }
    Ok(values)
}

fn module_key_from_graph(value: &str) -> String {
    if let Some((path, version)) = value.rsplit_once('@') {
        module_key(path, Some(version))
    } else {
        module_key(value, None)
    }
}

fn module_key(path: &str, version: Option<&str>) -> String {
    match version {
        Some(version) if !version.is_empty() => format!("{}@{}", path, version),
        _ => path.to_string(),
    }
}

fn module_identity(path: &str, version: Option<&str>) -> String {
    module_key(path, version)
}

fn go_purl(module_path: &str, version: Option<&str>) -> String {
    let raw = match version {
        Some(version) if !version.is_empty() => {
            format!("pkg:golang/{}@{}", module_path, version)
        }
        _ => format!("pkg:golang/{}", module_path),
    };
    Dependency::auto_fix_and_validate_purl(&raw)
}

fn go_instance_id(
    purl: &str,
    root_rel: &str,
    manifest_rel: &str,
    module_path: &str,
    version: Option<&str>,
) -> String {
    let salt = format!(
        "go:{}:{}:{}:{}",
        root_rel,
        manifest_rel,
        module_path,
        version.unwrap_or("")
    );
    make_instance_id(purl, &salt)
}

fn insert_go_component(
    components: &mut BTreeMap<String, GoComponent>,
    id_by_key: &mut HashMap<String, String>,
    input: GoComponentInput<'_>,
) -> String {
    let purl = go_purl(&input.module_path, input.version);
    let instance_id = go_instance_id(
        &purl,
        input.root_rel,
        input.manifest_rel,
        &input.module_path,
        input.version,
    );
    id_by_key.insert(
        module_key(&input.module_path, input.version),
        instance_id.clone(),
    );

    components
        .entry(instance_id.clone())
        .and_modify(|component| {
            component.scope.insert(input.scope.to_string());
            component
                .evidence_source
                .insert(input.evidence_source.to_string());
            component.direct |= input.direct;
            component.indirect |= input.indirect;
            if component.relationship == "unknown" {
                component.relationship = input.relationship.to_string();
            }
        })
        .or_insert_with(|| GoComponent {
            module_path: input.module_path,
            version: input.version.map(str::to_string),
            requested_version: input.requested_version.map(str::to_string),
            purl,
            instance_id: instance_id.clone(),
            dependencies: BTreeSet::new(),
            project_root: input.root_rel.to_string(),
            manifest_path: input.manifest_rel.to_string(),
            workspace_root: input.workspace_rel.map(str::to_string),
            go_work_path: input.go_work_rel.map(str::to_string),
            scope: BTreeSet::from([input.scope.to_string()]),
            relationship: input.relationship.to_string(),
            direct: input.direct,
            indirect: input.indirect,
            main_module: input.main_module,
            local: input.local,
            workspace_member: input.workspace_member,
            replacement_original: input.replacement_original.map(str::to_string),
            replacement_path: input.replacement_path.map(str::to_string),
            replacement_version: input.replacement_version.map(str::to_string),
            replacement_type: input.replacement_type.map(str::to_string),
            evidence_source: BTreeSet::from([input.evidence_source.to_string()]),
            confidence: input.confidence.to_string(),
            parsing_mode: input.parsing_mode.to_string(),
            go_version: input.go_version.map(str::to_string),
            toolchain_version: input.toolchain_version.map(str::to_string),
            goos: input.goos.map(str::to_string),
            goarch: input.goarch.map(str::to_string),
            cgo_enabled: input.cgo_enabled.map(str::to_string),
            host_active: input.host_active,
            excluded_versions: input.excluded_versions.map(str::to_string),
            retractions: input.retractions.map(str::to_string),
        });

    instance_id
}

fn effective_require(
    require: &GoRequire,
    manifest: &GoManifest,
    project_root: &Path,
    base_path: &Path,
    workspace_root: Option<&Path>,
) -> EffectiveRequire {
    if let Some(replace) = find_replace(require, &manifest.replaces) {
        if let Some(local_path) = &replace.local_path {
            let local_base = replace.local_base_dir.as_deref().unwrap_or(project_root);
            let local_root = normalize_join(local_base, local_path);
            let local_manifest = parse_go_mod(&local_root.join("go.mod")).unwrap_or_default();
            let module_path = local_manifest
                .module_path
                .unwrap_or_else(|| replace.old_path.clone());
            let replacement_path =
                portable_local_replacement_path(base_path, &local_root, local_path);
            return EffectiveRequire {
                module_path,
                version: None,
                local: true,
                workspace_member: workspace_root.is_some_and(|root| local_root.starts_with(root))
                    && local_root.join("go.mod").exists(),
                replacement_original: Some(module_identity(
                    &replace.old_path,
                    replace
                        .old_version
                        .as_deref()
                        .or(require.version.as_deref()),
                )),
                replacement_path: Some(replacement_path),
                replacement_version: None,
                replacement_type: Some("local".to_string()),
                evidence_source: "go.mod-replace",
                confidence: if local_root.join("go.mod").exists() {
                    "medium"
                } else {
                    "low"
                },
            };
        }
        return EffectiveRequire {
            module_path: replace.new_path.clone(),
            version: replace
                .new_version
                .clone()
                .or_else(|| require.version.clone()),
            local: false,
            workspace_member: false,
            replacement_original: Some(module_identity(
                &replace.old_path,
                replace
                    .old_version
                    .as_deref()
                    .or(require.version.as_deref()),
            )),
            replacement_path: Some(replace.new_path.clone()),
            replacement_version: replace.new_version.clone(),
            replacement_type: Some("module".to_string()),
            evidence_source: "go.mod-replace",
            confidence: "medium",
        };
    }

    EffectiveRequire {
        module_path: require.path.clone(),
        version: require.version.clone(),
        local: false,
        workspace_member: false,
        replacement_original: None,
        replacement_path: None,
        replacement_version: None,
        replacement_type: None,
        evidence_source: "go.mod-require",
        confidence: "medium",
    }
}

fn portable_local_replacement_path(base_path: &Path, local_root: &Path, declared: &str) -> String {
    if local_root.starts_with(base_path) {
        get_manifest_rel_path(base_path, local_root)
    } else {
        declared.to_string()
    }
}

fn find_replace<'a>(require: &GoRequire, replaces: &'a [GoReplace]) -> Option<&'a GoReplace> {
    replaces.iter().find(|replace| {
        replace.old_path == require.path
            && (replace.old_version.is_none() || replace.old_version == require.version)
    })
}

fn is_excluded(require: &GoRequire, excludes: &[GoExclude]) -> bool {
    excludes.iter().any(|exclude| {
        exclude.path == require.path
            && require
                .version
                .as_ref()
                .is_some_and(|version| version == &exclude.version)
    })
}

fn apply_require_metadata(
    components: &mut BTreeMap<String, GoComponent>,
    id_by_key: &HashMap<String, String>,
    requires: &[GoRequire],
) {
    for require in requires {
        let key = module_key(&require.path, require.version.as_deref());
        if let Some(id) = id_by_key.get(&key) {
            if let Some(component) = components.get_mut(id) {
                component.requested_version = require.version.clone();
                component.indirect = require.indirect;
                component.direct = true;
                component.relationship = "direct".to_string();
                component
                    .evidence_source
                    .insert("go.mod-require".to_string());
            }
        }
    }
}

fn apply_package_scopes(
    components: &mut BTreeMap<String, GoComponent>,
    id_by_key: &HashMap<String, String>,
    modules: BTreeSet<String>,
    scope: &str,
) {
    for key in modules {
        if let Some(id) = id_by_key.get(&key) {
            if let Some(component) = components.get_mut(id) {
                component.scope.remove("unknown");
                component.scope.insert(scope.to_string());
                component.host_active = Some(true);
                component.evidence_source.insert("go-list-deps".to_string());
            }
        }
    }
}

fn add_vendor_modules(
    components: &mut BTreeMap<String, GoComponent>,
    id_by_key: &mut HashMap<String, String>,
    project: &GoProjectRoot,
    manifest: &GoManifest,
    context: StaticGoContext<'_>,
) {
    let vendor_path = project.root_path.join("vendor/modules.txt");
    let Ok(content) = fs::read_to_string(&vendor_path) else {
        return;
    };
    for vendor_module in parse_vendor_modules(&content) {
        insert_go_component(
            components,
            id_by_key,
            GoComponentInput {
                module_path: vendor_module.path,
                version: vendor_module.version.as_deref(),
                requested_version: vendor_module.version.as_deref(),
                root_rel: context.root_rel,
                manifest_rel: context.manifest_rel,
                workspace_rel: context.workspace_rel,
                go_work_rel: context.go_work_rel,
                scope: "unknown",
                relationship: "unknown",
                direct: vendor_module.explicit,
                indirect: false,
                main_module: false,
                local: vendor_module.replacement.is_some(),
                workspace_member: false,
                replacement_original: None,
                replacement_path: vendor_module.replacement.as_deref(),
                replacement_version: None,
                replacement_type: vendor_module.replacement.as_deref().map(|_| "module"),
                evidence_source: "vendor/modules.txt",
                confidence: "high",
                parsing_mode: "vendor-fallback",
                go_version: manifest.go_version.as_deref(),
                toolchain_version: manifest.toolchain.as_deref(),
                goos: None,
                goarch: None,
                cgo_enabled: None,
                host_active: None,
                excluded_versions: None,
                retractions: None,
            },
        );
    }
}

#[derive(Default)]
struct VendorModule {
    path: String,
    version: Option<String>,
    replacement: Option<String>,
    explicit: bool,
}

fn parse_vendor_modules(content: &str) -> Vec<VendorModule> {
    let mut modules = Vec::new();
    let mut current: Option<VendorModule> = None;

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if let Some(rest) = line.strip_prefix("# ") {
            if let Some(module) = current.take() {
                modules.push(module);
            }
            let (left, replacement) = rest
                .split_once("=>")
                .map(|(l, r)| (l.trim(), Some(r.trim().to_string())))
                .unwrap_or((rest, None));
            let parts: Vec<_> = left.split_whitespace().collect();
            if let Some(path) = parts.first() {
                current = Some(VendorModule {
                    path: (*path).to_string(),
                    version: parts.get(1).map(|s| (*s).to_string()),
                    replacement,
                    explicit: false,
                });
            }
        } else if line.starts_with("## explicit") {
            if let Some(module) = &mut current {
                module.explicit = true;
            }
        }
    }
    if let Some(module) = current {
        modules.push(module);
    }
    modules
}

fn components_to_dependencies(components: BTreeMap<String, GoComponent>) -> Vec<Dependency> {
    components
        .into_values()
        .filter_map(|component| {
            DependencyBuilder::default()
                .name(component.module_path.clone())
                .version(component.version.clone())
                .declared_version(component.requested_version.clone())
                .r#type(DependencyType::Library)
                .purl(component.purl)
                .instance_id(component.instance_id)
                .dependencies(component.dependencies.into_iter().collect())
                .go_module_path(Some(component.module_path))
                .go_project_root(Some(component.project_root))
                .go_manifest_path(Some(component.manifest_path))
                .go_workspace_root(component.workspace_root)
                .go_go_work_path(component.go_work_path)
                .go_scope(Some(scope_string(&component.scope)))
                .go_relationship(Some(component.relationship))
                .go_direct(Some(component.direct))
                .go_indirect(Some(component.indirect))
                .go_main_module(Some(component.main_module))
                .go_local(Some(component.local))
                .go_workspace_member(Some(component.workspace_member))
                .go_replacement_original(component.replacement_original)
                .go_replacement_path(component.replacement_path)
                .go_replacement_version(component.replacement_version)
                .go_replacement_type(component.replacement_type)
                .go_evidence_source(Some(
                    component
                        .evidence_source
                        .into_iter()
                        .collect::<Vec<_>>()
                        .join(","),
                ))
                .go_confidence(Some(component.confidence))
                .go_parsing_mode(Some(component.parsing_mode))
                .go_version(component.go_version)
                .go_toolchain_version(component.toolchain_version)
                .go_goos(component.goos)
                .go_goarch(component.goarch)
                .go_cgo_enabled(component.cgo_enabled)
                .go_host_active(component.host_active)
                .go_excluded_versions(component.excluded_versions)
                .go_retractions(component.retractions)
                .location(None)
                .build()
                .ok()
        })
        .collect()
}

fn scope_string(scopes: &BTreeSet<String>) -> String {
    let values: Vec<_> = scopes
        .iter()
        .filter(|scope| scope.as_str() != "unknown" || scopes.len() == 1)
        .cloned()
        .collect();
    if values.is_empty() {
        "unknown".to_string()
    } else {
        values.join(",")
    }
}

fn excludes_string(excludes: &[GoExclude]) -> Option<String> {
    strings_join(
        &excludes
            .iter()
            .map(|exclude| module_identity(&exclude.path, Some(&exclude.version)))
            .collect::<Vec<_>>(),
    )
}

fn strings_join(values: &[String]) -> Option<String> {
    if values.is_empty() {
        None
    } else {
        Some(values.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::configuration::RustScopeFilter;

    fn config(base: &Path) -> SbomProducerConfiguration {
        SbomProducerConfiguration {
            use_debug: false,
            base_path: base.to_path_buf(),
            rust_scope: RustScopeFilter::Prod,
            dynamic: false,
        }
    }

    fn temp_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn parses_go_mod_require_replace_exclude_retract() {
        let manifest = parse_go_mod_content(
            r#"
module example.com/app
go 1.22
toolchain go1.22.5
require (
    github.com/gin-gonic/gin v1.10.0
    golang.org/x/sys v0.28.0 // indirect
)
replace github.com/gin-gonic/gin => github.com/fork/gin v1.10.1
exclude golang.org/x/sys v0.27.0
retract [v1.0.0, v1.0.2]
"#,
        );
        assert_eq!(manifest.module_path.as_deref(), Some("example.com/app"));
        assert_eq!(manifest.requires.len(), 2);
        assert!(manifest.requires[1].indirect);
        assert_eq!(manifest.replaces[0].new_path, "github.com/fork/gin");
        assert_eq!(manifest.excludes[0].version, "v0.27.0");
        assert_eq!(manifest.retractions[0], "[v1.0.0, v1.0.2]");
    }

    #[test]
    fn parses_multiline_replace_and_go_work_replaces() {
        let manifest = parse_go_mod_content(
            r#"
module example.com/app
replace github.com/example/lib v1.2.0 =>
    github.com/fork/lib v1.2.1
"#,
        );
        assert_eq!(manifest.replaces.len(), 1);
        assert_eq!(manifest.replaces[0].new_path, "github.com/fork/lib");
        assert_eq!(manifest.replaces[0].new_version.as_deref(), Some("v1.2.1"));

        let workspace = parse_go_work_content(
            r#"
go 1.22
toolchain go1.22.5
use ./service
replace (
    example.com/shared => ./shared
)
"#,
        );
        assert_eq!(workspace.uses, vec!["./service"]);
        assert_eq!(workspace.toolchain.as_deref(), Some("go1.22.5"));
        assert_eq!(workspace.replaces.len(), 1);
        assert_eq!(
            workspace.replaces[0].local_path.as_deref(),
            Some("./shared")
        );
    }

    #[test]
    fn static_single_module_outputs_main_dependency_and_ignores_go_sum() {
        let root = temp_root("sbom-generator-go-single");
        fs::write(
            root.join("go.mod"),
            "module example.com/app\n\ngo 1.22\nrequire github.com/a/lib v1.2.3\n",
        )
        .unwrap();
        fs::write(
            root.join("go.sum"),
            "github.com/stale/lib v9.9.9 h1:abc\ngithub.com/stale/lib v9.9.9/go.mod h1:def\n",
        )
        .unwrap();

        let producer = GoProducer::default();
        let deps = producer
            .find_dependencies(&[root.join("go.mod"), root.join("go.sum")], &config(&root))
            .unwrap();

        assert!(deps.iter().any(|d| d.purl == "pkg:golang/example.com/app"));
        assert!(deps
            .iter()
            .any(|d| d.purl == "pkg:golang/github.com/a/lib@v1.2.3"));
        assert!(!deps.iter().any(|d| d.purl.contains("stale")));
        let main = deps
            .iter()
            .find(|d| d.purl == "pkg:golang/example.com/app")
            .unwrap();
        assert_eq!(main.dependencies.len(), 1);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn static_multiple_modules_are_physically_isolated() {
        let root = temp_root("sbom-generator-go-multi");
        fs::create_dir_all(root.join("app")).unwrap();
        fs::create_dir_all(root.join("tool")).unwrap();
        fs::write(
            root.join("app/go.mod"),
            "module example.com/app\nrequire github.com/a/lib v1.2.3\n",
        )
        .unwrap();
        fs::write(
            root.join("tool/go.mod"),
            "module example.com/tool\nrequire github.com/a/lib v1.2.3\n",
        )
        .unwrap();

        let deps = GoProducer::default()
            .find_dependencies(
                &[root.join("app/go.mod"), root.join("tool/go.mod")],
                &config(&root),
            )
            .unwrap();
        let lib_instances: Vec<_> = deps
            .iter()
            .filter(|d| d.purl == "pkg:golang/github.com/a/lib@v1.2.3")
            .collect();
        assert_eq!(lib_instances.len(), 2);
        assert_ne!(lib_instances[0].instance_id, lib_instances[1].instance_id);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn go_work_discovers_members_without_duplicate_roots() {
        let root = temp_root("sbom-generator-go-work");
        fs::create_dir_all(root.join("service")).unwrap();
        fs::create_dir_all(root.join("shared")).unwrap();
        fs::write(
            root.join("go.work"),
            "go 1.22\ntoolchain go1.22.5\nuse (\n ./service\n ./shared\n)\nreplace example.com/shared => ./shared\n",
        )
        .unwrap();
        fs::write(
            root.join("service/go.mod"),
            "module example.com/service\nrequire example.com/shared v0.0.0\n",
        )
        .unwrap();
        fs::write(root.join("shared/go.mod"), "module example.com/shared\n").unwrap();

        let paths = vec![
            root.join("go.work"),
            root.join("service/go.mod"),
            root.join("shared/go.mod"),
        ];
        let projects = discover_go_projects(&paths, &root);
        assert_eq!(projects.len(), 2);
        let canonical_root = fs::canonicalize(&root).unwrap();
        assert!(projects
            .iter()
            .all(|p| p.workspace_root.as_ref() == Some(&canonical_root)));

        let deps = GoProducer::default()
            .find_dependencies(&paths, &config(&root))
            .unwrap();
        let service = deps
            .iter()
            .find(|d| d.purl == "pkg:golang/example.com/service")
            .unwrap();
        let shared_dependency = deps
            .iter()
            .find(|d| {
                d.purl == "pkg:golang/example.com/shared"
                    && service.dependencies.contains(&d.instance_id)
            })
            .unwrap();
        assert_eq!(shared_dependency.go_workspace_member, Some(true));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn preserves_pseudo_versions_v2_paths_and_incompatible_versions() {
        let root = temp_root("sbom-generator-go-versions");
        fs::write(
            root.join("go.mod"),
            "module example.com/app\nrequire (\n github.com/example/lib/v2 v2.3.0\n github.com/example/pseudo v0.0.0-20240102123456-abcdef123456\n github.com/example/old v2.0.0+incompatible\n)\n",
        )
        .unwrap();
        let deps = GoProducer::default()
            .find_dependencies(&[root.join("go.mod")], &config(&root))
            .unwrap();
        assert!(deps
            .iter()
            .any(|d| d.purl == "pkg:golang/github.com/example/lib/v2@v2.3.0"));
        assert!(deps
            .iter()
            .any(|d| d.purl.contains("v0.0.0-20240102123456-abcdef123456")));
        assert!(deps.iter().any(|d| d.purl.contains("v2.0.0+incompatible")));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn parses_vendor_modules_without_using_vendor_as_project_root() {
        let root = temp_root("sbom-generator-go-vendor");
        fs::create_dir_all(root.join("vendor")).unwrap();
        fs::write(root.join("go.mod"), "module example.com/app\n").unwrap();
        fs::write(
            root.join("vendor/modules.txt"),
            "# github.com/vendor/lib v1.0.0\n## explicit; go 1.22\ngithub.com/vendor/lib/pkg\n",
        )
        .unwrap();
        fs::write(root.join("vendor/go.mod"), "module should.not/scan\n").unwrap();
        let deps = GoProducer::default()
            .find_dependencies(
                &[root.join("go.mod"), root.join("vendor/modules.txt")],
                &config(&root),
            )
            .unwrap();
        assert!(deps
            .iter()
            .any(|d| d.purl == "pkg:golang/github.com/vendor/lib@v1.0.0"));
        assert!(!deps.iter().any(|d| d.purl.contains("should.not")));

        let projects =
            discover_go_projects(&[root.join("go.mod"), root.join("vendor/go.mod")], &root);
        assert_eq!(projects.len(), 1);
        let _ = fs::remove_dir_all(root);
    }
}
