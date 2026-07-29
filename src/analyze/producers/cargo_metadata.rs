use crate::model::configuration::RustScopeFilter;
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyType};
use crate::utils::command::run_with_timeout;
use crate::utils::file_utils::{get_manifest_rel_path, make_instance_id};
use anyhow::Context;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum RustScope {
    Normal,
    Build,
    Dev,
    Unknown,
}

impl RustScope {
    pub fn as_str(self) -> &'static str {
        match self {
            RustScope::Normal => "normal",
            RustScope::Build => "build",
            RustScope::Dev => "dev",
            RustScope::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RustRelationship {
    Direct,
    Transitive,
    Unknown,
}

impl RustRelationship {
    pub fn as_str(&self) -> &'static str {
        match self {
            RustRelationship::Direct => "direct",
            RustRelationship::Transitive => "transitive",
            RustRelationship::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RustActivation {
    Unconditional,
    Conditional,
    TargetSpecificInactiveOnHost,
    HostActive,
    Unknown,
}

impl RustActivation {
    pub fn as_str(&self) -> &'static str {
        match self {
            RustActivation::Unconditional => "unconditional",
            RustActivation::Conditional => "conditional",
            RustActivation::TargetSpecificInactiveOnHost => "target-specific-inactive-on-host",
            RustActivation::HostActive => "host-active",
            RustActivation::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug)]
pub struct CargoEdge {
    pub child_id: String,
    pub scopes: BTreeSet<RustScope>,
    pub target_conditions: BTreeSet<String>,
}

#[derive(Clone, Debug)]
pub struct CargoNode {
    pub id: String,
    pub name: String,
    pub version: String,
    pub purl: String,
    pub instance_id: String,
    pub is_proc_macro: bool,
    pub scopes: BTreeSet<RustScope>,
    pub relationship: RustRelationship,
    pub target_conditions: BTreeSet<String>,
    pub activation: RustActivation,
    pub all_target_present: Option<bool>,
    pub host_active: Option<bool>,
    pub dependencies: Vec<String>,
}

impl CargoNode {
    fn scopes_string(&self) -> String {
        scopes_to_string(&self.scopes)
    }
}

#[derive(Clone, Debug)]
pub struct CargoProjectGraph {
    pub project_root: PathBuf,
    pub source_cargo_lock: PathBuf,
    pub nodes: Vec<CargoNode>,
}

pub fn metadata_dependencies_for_project(
    project_dir: &Path,
    base_path: &Path,
    scope_filter: RustScopeFilter,
) -> anyhow::Result<Vec<Dependency>> {
    let graph = metadata_graph_for_project(project_dir, base_path)?;
    Ok(graph_to_dependencies(&graph, base_path, scope_filter))
}

pub fn metadata_graph_for_project(
    project_dir: &Path,
    base_path: &Path,
) -> anyhow::Result<CargoProjectGraph> {
    let json = run_cargo_metadata(project_dir)?;
    let host_triple = rust_host_triple().ok();
    let all_target_keys = cargo_tree_package_keys(project_dir, "all").ok();
    let host_target_keys = host_triple
        .as_deref()
        .and_then(|host| cargo_tree_package_keys(project_dir, host).ok());

    let root_rel = get_manifest_rel_path(base_path, project_dir);
    let mut nodes = parse_package_nodes(&json, &root_rel);
    let edges = parse_resolve_edges(&json);
    let roots = resolve_roots(&json);

    propagate_scopes(&mut nodes, &edges, &roots);
    classify_targets(
        &mut nodes,
        all_target_keys.as_ref(),
        host_target_keys.as_ref(),
    );

    Ok(CargoProjectGraph {
        project_root: project_dir.to_path_buf(),
        source_cargo_lock: project_dir.join("Cargo.lock"),
        nodes,
    })
}

pub fn graph_to_dependencies(
    graph: &CargoProjectGraph,
    base_path: &Path,
    scope_filter: RustScopeFilter,
) -> Vec<Dependency> {
    let id_to_node: HashMap<_, _> = graph.nodes.iter().map(|node| (&node.id, node)).collect();
    let root_rel = get_manifest_rel_path(base_path, &graph.project_root);
    let lock_rel = get_manifest_rel_path(base_path, &graph.source_cargo_lock);

    graph
        .nodes
        .iter()
        .filter(|node| rust_scope_filter_includes(scope_filter, &node.scopes))
        .filter_map(|node| {
            let child_ids: Vec<String> = node
                .dependencies
                .iter()
                .filter_map(|child_id| id_to_node.get(child_id).copied())
                .filter(|child| rust_scope_filter_includes(scope_filter, &child.scopes))
                .map(|child| child.instance_id.clone())
                .collect();

            DependencyBuilder::default()
                .name(node.name.clone())
                .version(Some(node.version.clone()))
                .declared_version(Some(node.version.clone()))
                .rust_dependency_scope(Some(node.scopes_string()))
                .rust_dependency_relationship(Some(node.relationship.as_str().to_string()))
                .rust_is_direct(Some(node.relationship == RustRelationship::Direct))
                .rust_target_conditions(target_conditions_string(&node.target_conditions))
                .rust_activation(Some(node.activation.as_str().to_string()))
                .rust_is_proc_macro(Some(node.is_proc_macro))
                .rust_project_root(Some(root_rel.clone()))
                .rust_source_cargo_lock(Some(lock_rel.clone()))
                .rust_resolved_graph_confirmed(Some(true))
                .rust_all_target_present(node.all_target_present)
                .rust_host_active(node.host_active)
                .r#type(DependencyType::Library)
                .purl(node.purl.clone())
                .instance_id(node.instance_id.clone())
                .dependencies(child_ids)
                .location(None)
                .build()
                .ok()
        })
        .collect()
}

pub fn write_rust_only_51_csv(
    deps: &[Dependency],
    output_dir: &Path,
) -> anyhow::Result<Option<PathBuf>> {
    #[derive(Default)]
    struct RowAgg {
        name: String,
        version: String,
        purl: String,
        project_roots: BTreeSet<String>,
        resolved_confirmed: bool,
        scopes: BTreeSet<String>,
        direct_any: bool,
        relationship_direct_any: bool,
        relationship_transitive_any: bool,
        host_active_any: bool,
        all_target_present_any: bool,
        target_conditions: BTreeSet<String>,
        is_proc_macro_any: bool,
        activations: BTreeSet<String>,
    }

    let mut rows: BTreeMap<(String, String), RowAgg> = BTreeMap::new();
    for dep in deps {
        let Some(version) = &dep.version else {
            continue;
        };
        if !RUST_ONLY_51
            .iter()
            .any(|(name, target_version)| dep.name == *name && version == target_version)
        {
            continue;
        }

        let entry = rows
            .entry((dep.name.clone(), version.clone()))
            .or_insert_with(|| RowAgg {
                name: dep.name.clone(),
                version: version.clone(),
                purl: dep.purl.clone(),
                ..RowAgg::default()
            });

        if let Some(project_root) = &dep.rust_project_root {
            if !project_root.is_empty() {
                entry.project_roots.insert(project_root.clone());
            }
        }
        if let Some(scopes) = &dep.rust_dependency_scope {
            for scope in scopes.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                entry.scopes.insert(scope.to_string());
            }
        }
        if let Some(relationship) = &dep.rust_dependency_relationship {
            entry.relationship_direct_any |= relationship == RustRelationship::Direct.as_str();
            entry.relationship_transitive_any |=
                relationship == RustRelationship::Transitive.as_str();
        }
        entry.direct_any |= dep.rust_is_direct.unwrap_or(false);
        entry.resolved_confirmed |= dep.rust_resolved_graph_confirmed.unwrap_or(false);
        entry.host_active_any |= dep.rust_host_active.unwrap_or(false);
        entry.all_target_present_any |= dep.rust_all_target_present.unwrap_or(false);
        if let Some(activation) = &dep.rust_activation {
            entry.host_active_any |= activation == RustActivation::HostActive.as_str();
            entry.activations.insert(activation.clone());
        }
        if let Some(target_conditions) = &dep.rust_target_conditions {
            for target in target_conditions
                .split(';')
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                entry.target_conditions.insert(target.to_string());
            }
        }
        entry.is_proc_macro_any |= dep.rust_is_proc_macro.unwrap_or(false);
    }

    if rows.is_empty() {
        return Ok(None);
    }

    let path = output_dir.join("rust_only_51_scope_target_classification.csv");
    let mut csv = String::from("name,version,purl,project_roots,resolved_confirmed,scopes,direct,relationship,host_active,all_target_present,target_specific,target_conditions,is_proc_macro,classification\n");
    for row in rows.into_values() {
        let scopes = if row.scopes.is_empty() {
            "unknown".to_string()
        } else {
            ordered_scope_strings(&row.scopes).join(",")
        };
        let relationship = if row.relationship_direct_any {
            "direct"
        } else if row.relationship_transitive_any {
            "transitive"
        } else {
            "unknown"
        };
        let activation = if row
            .activations
            .contains(RustActivation::TargetSpecificInactiveOnHost.as_str())
        {
            RustActivation::TargetSpecificInactiveOnHost.as_str()
        } else if row.host_active_any {
            RustActivation::HostActive.as_str()
        } else if row
            .activations
            .contains(RustActivation::Conditional.as_str())
        {
            RustActivation::Conditional.as_str()
        } else {
            RustActivation::Unknown.as_str()
        };
        let is_proc_macro = row.is_proc_macro_any.to_string();
        let values = vec![
            row.name,
            row.version,
            row.purl,
            row.project_roots.into_iter().collect::<Vec<_>>().join(";"),
            row.resolved_confirmed.to_string(),
            scopes.clone(),
            row.direct_any.to_string(),
            relationship.to_string(),
            row.host_active_any.to_string(),
            row.all_target_present_any.to_string(),
            (!row.target_conditions.is_empty()).to_string(),
            row.target_conditions
                .into_iter()
                .collect::<Vec<_>>()
                .join(";"),
            is_proc_macro.clone(),
            display_classification(&scopes, relationship, activation, &is_proc_macro),
        ];
        csv.push_str(
            &values
                .iter()
                .map(|value| csv_escape(value))
                .collect::<Vec<_>>()
                .join(","),
        );
        csv.push('\n');
    }
    fs::write(&path, csv).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(Some(path))
}

fn ordered_scope_strings(scopes: &BTreeSet<String>) -> Vec<String> {
    ["normal", "build", "dev", "unknown"]
        .iter()
        .filter(|scope| scopes.contains(**scope))
        .map(|scope| scope.to_string())
        .collect()
}

fn run_cargo_metadata(project_dir: &Path) -> anyhow::Result<Value> {
    let mut cmd = Command::new("cargo");
    cmd.args([
        "metadata",
        "--format-version=1",
        "--locked",
        "--all-features",
    ])
    .current_dir(project_dir);
    let output = run_with_timeout(&mut cmd, Duration::from_secs(180))?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "cargo metadata failed in {}: {}",
            project_dir.display(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn rust_host_triple() -> anyhow::Result<String> {
    let mut cmd = Command::new("rustc");
    cmd.arg("-vV");
    let output = run_with_timeout(&mut cmd, Duration::from_secs(15))?;
    if !output.status.success() {
        return Err(anyhow::anyhow!("rustc -vV failed"));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("host: ").map(str::to_string))
        .ok_or_else(|| anyhow::anyhow!("rustc -vV did not report host triple"))
}

fn cargo_tree_package_keys(project_dir: &Path, target: &str) -> anyhow::Result<BTreeSet<String>> {
    let mut cmd = Command::new("cargo");
    cmd.args(["tree", "--locked", "--all-features", "--target", target])
        .current_dir(project_dir);
    let output = run_with_timeout(&mut cmd, Duration::from_secs(180))?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "cargo tree --target {} failed in {}: {}",
            target,
            project_dir.display(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout
        .lines()
        .filter_map(package_key_from_tree_line)
        .collect())
}

fn package_key_from_tree_line(line: &str) -> Option<String> {
    let stripped = line
        .trim_start_matches(|c: char| {
            c.is_whitespace() || matches!(c, '├' | '└' | '─' | '│' | ' ' | '+' | '-' | '\\' | '`')
        })
        .trim();
    let mut parts = stripped.split_whitespace();
    let name = parts.next()?.trim_end_matches(',');
    let version = parts.find_map(|part| part.strip_prefix('v'))?;
    Some(format!("{}@{}", name, version))
}

fn parse_package_nodes(json: &Value, root_rel: &str) -> Vec<CargoNode> {
    json.get("packages")
        .and_then(|p| p.as_array())
        .into_iter()
        .flatten()
        .filter_map(|pkg| {
            let id = pkg.get("id")?.as_str()?.to_string();
            let name = pkg.get("name")?.as_str()?.to_string();
            let version = pkg.get("version")?.as_str()?.to_string();
            let purl =
                Dependency::auto_fix_and_validate_purl(&format!("pkg:cargo/{}@{}", name, version));
            let salt = format!("cargo:{}:{}", root_rel, id);
            let instance_id = make_instance_id(&purl, &salt);
            let is_proc_macro = pkg
                .get("targets")
                .and_then(|targets| targets.as_array())
                .into_iter()
                .flatten()
                .any(|target| {
                    target
                        .get("kind")
                        .and_then(|kind| kind.as_array())
                        .into_iter()
                        .flatten()
                        .any(|kind| kind.as_str() == Some("proc-macro"))
                });

            Some(CargoNode {
                id,
                name,
                version,
                purl,
                instance_id,
                is_proc_macro,
                scopes: BTreeSet::new(),
                relationship: RustRelationship::Unknown,
                target_conditions: BTreeSet::new(),
                activation: RustActivation::Unknown,
                all_target_present: None,
                host_active: None,
                dependencies: Vec::new(),
            })
        })
        .collect()
}

fn parse_resolve_edges(json: &Value) -> HashMap<String, Vec<CargoEdge>> {
    let mut result = HashMap::new();
    if let Some(nodes) = json
        .get("resolve")
        .and_then(|r| r.get("nodes"))
        .and_then(|n| n.as_array())
    {
        for node in nodes {
            let Some(parent_id) = node.get("id").and_then(|i| i.as_str()) else {
                continue;
            };
            let mut edges = Vec::new();
            if let Some(deps) = node.get("deps").and_then(|d| d.as_array()) {
                for dep in deps {
                    let Some(child_id) = dep.get("pkg").and_then(|p| p.as_str()) else {
                        continue;
                    };
                    let (scopes, target_conditions) = parse_dep_kinds(dep);
                    edges.push(CargoEdge {
                        child_id: child_id.to_string(),
                        scopes,
                        target_conditions,
                    });
                }
            }
            result.insert(parent_id.to_string(), edges);
        }
    }
    result
}

fn parse_dep_kinds(dep: &Value) -> (BTreeSet<RustScope>, BTreeSet<String>) {
    let mut scopes = BTreeSet::new();
    let mut targets = BTreeSet::new();
    if let Some(dep_kinds) = dep.get("dep_kinds").and_then(|d| d.as_array()) {
        for dep_kind in dep_kinds {
            scopes.insert(match dep_kind.get("kind") {
                Some(value) if value.is_null() => RustScope::Normal,
                Some(value) if value.as_str() == Some("build") => RustScope::Build,
                Some(value) if value.as_str() == Some("dev") => RustScope::Dev,
                _ => RustScope::Unknown,
            });
            if let Some(target) = dep_kind.get("target").and_then(|t| t.as_str()) {
                targets.insert(target.to_string());
            }
        }
    }
    if scopes.is_empty() {
        scopes.insert(RustScope::Unknown);
    }
    (scopes, targets)
}

fn resolve_roots(json: &Value) -> Vec<String> {
    let mut roots = Vec::new();
    if let Some(root) = json
        .get("resolve")
        .and_then(|resolve| resolve.get("root"))
        .and_then(|root| root.as_str())
    {
        roots.push(root.to_string());
    }
    if let Some(members) = json.get("workspace_members").and_then(|m| m.as_array()) {
        for member in members.iter().filter_map(|m| m.as_str()) {
            if !roots.iter().any(|root| root == member) {
                roots.push(member.to_string());
            }
        }
    }
    roots
}

pub fn propagate_scopes(
    nodes: &mut [CargoNode],
    edges: &HashMap<String, Vec<CargoEdge>>,
    roots: &[String],
) {
    let id_to_idx: HashMap<String, usize> = nodes
        .iter()
        .enumerate()
        .map(|(idx, node)| (node.id.clone(), idx))
        .collect();
    let mut queue = VecDeque::new();
    let root_set: BTreeSet<String> = roots.iter().cloned().collect();

    for root_id in roots {
        let Some(root_idx) = id_to_idx.get(root_id).copied() else {
            continue;
        };
        if nodes[root_idx].scopes.insert(RustScope::Normal) {
            queue.push_back(root_idx);
        }
        for edge in edges.get(root_id).into_iter().flatten() {
            let Some(child_idx) = id_to_idx.get(&edge.child_id).copied() else {
                continue;
            };
            let mut changed = false;
            let seed_scopes = non_unknown_scopes(&edge.scopes);
            for scope in seed_scopes {
                changed |= add_scope(&mut nodes[child_idx], scope);
            }
            nodes[child_idx].relationship = RustRelationship::Direct;
            apply_target_conditions(&mut nodes[child_idx], &edge.target_conditions);
            if changed {
                queue.push_back(child_idx);
            }
        }
    }

    while let Some(current_idx) = queue.pop_front() {
        if root_set.contains(&nodes[current_idx].id) {
            continue;
        }
        let current_scopes = non_unknown_scopes(&nodes[current_idx].scopes);
        let current_targets = nodes[current_idx].target_conditions.clone();
        if current_scopes.is_empty() {
            continue;
        }
        let current_id = nodes[current_idx].id.clone();
        for edge in edges.get(&current_id).into_iter().flatten() {
            let Some(child_idx) = id_to_idx.get(&edge.child_id).copied() else {
                continue;
            };
            let mut changed = false;
            for scope in &current_scopes {
                changed |= add_scope(&mut nodes[child_idx], *scope);
            }
            if nodes[child_idx].relationship == RustRelationship::Unknown {
                nodes[child_idx].relationship = RustRelationship::Transitive;
            }
            apply_target_conditions(&mut nodes[child_idx], &current_targets);
            apply_target_conditions(&mut nodes[child_idx], &edge.target_conditions);
            if changed {
                queue.push_back(child_idx);
            }
        }
    }

    for node in nodes {
        if node.scopes.is_empty() {
            node.scopes.insert(RustScope::Unknown);
        }
        if node.relationship == RustRelationship::Unknown
            && roots.iter().any(|root| root == &node.id)
        {
            node.relationship = RustRelationship::Direct;
        }
        if node.activation == RustActivation::Unknown {
            node.activation = if node.target_conditions.is_empty() {
                RustActivation::Unconditional
            } else {
                RustActivation::Conditional
            };
        }
        node.dependencies = edges
            .get(&node.id)
            .into_iter()
            .flatten()
            .map(|edge| edge.child_id.clone())
            .collect();
    }
}

fn add_scope(node: &mut CargoNode, scope: RustScope) -> bool {
    if scope != RustScope::Unknown {
        node.scopes.remove(&RustScope::Unknown);
    }
    node.scopes.insert(scope)
}

fn non_unknown_scopes(scopes: &BTreeSet<RustScope>) -> Vec<RustScope> {
    scopes
        .iter()
        .copied()
        .filter(|scope| *scope != RustScope::Unknown)
        .collect()
}

fn apply_target_conditions(node: &mut CargoNode, targets: &BTreeSet<String>) {
    if !targets.is_empty() {
        node.target_conditions.extend(targets.iter().cloned());
        if node.activation == RustActivation::Unknown
            || node.activation == RustActivation::Unconditional
        {
            node.activation = RustActivation::Conditional;
        }
    }
}

fn classify_targets(
    nodes: &mut [CargoNode],
    all_target_keys: Option<&BTreeSet<String>>,
    host_target_keys: Option<&BTreeSet<String>>,
) {
    for node in nodes {
        let key = format!("{}@{}", node.name, node.version);
        node.all_target_present = all_target_keys.map(|keys| keys.contains(&key));
        node.host_active = host_target_keys.map(|keys| keys.contains(&key));
        if node.host_active == Some(true) {
            node.activation = RustActivation::HostActive;
        } else if node.all_target_present == Some(true) && node.host_active == Some(false) {
            node.activation = RustActivation::TargetSpecificInactiveOnHost;
        }
    }
}

fn rust_scope_filter_includes(filter: RustScopeFilter, scopes: &BTreeSet<RustScope>) -> bool {
    scopes.iter().any(|scope| filter.includes(scope.as_str()))
}

pub fn scopes_to_string(scopes: &BTreeSet<RustScope>) -> String {
    let values: Vec<_> = scopes.iter().map(|scope| scope.as_str()).collect();
    if values.is_empty() {
        "unknown".to_string()
    } else {
        values.join(",")
    }
}

fn target_conditions_string(targets: &BTreeSet<String>) -> Option<String> {
    if targets.is_empty() {
        None
    } else {
        Some(targets.iter().cloned().collect::<Vec<_>>().join(";"))
    }
}

fn display_classification(
    scopes: &str,
    relationship: &str,
    activation: &str,
    is_proc_macro: &str,
) -> String {
    if is_proc_macro == "true" {
        return "proc-macro".to_string();
    }
    if activation == RustActivation::TargetSpecificInactiveOnHost.as_str() {
        return "target-specific-host-inactive".to_string();
    }
    if scopes.contains(',') {
        return "multi-scope".to_string();
    }
    if scopes == "unknown" || relationship == "unknown" {
        return "unknown".to_string();
    }
    format!("{}-{}", scopes, relationship)
}

fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

const RUST_ONLY_51: &[(&str, &str)] = &[
    ("embed-resource", "3.0.5"),
    ("fixedbitset", "0.5.7"),
    ("icu_locid", "1.5.0"),
    ("icu_locid_transform", "1.5.0"),
    ("icu_locid_transform_data", "1.5.0"),
    ("icu_provider_macros", "1.5.0"),
    ("id-arena", "2.3.0"),
    ("leb128fmt", "0.1.0"),
    ("multimap", "0.10.0"),
    ("multimap", "0.10.1"),
    ("petgraph", "0.8.3"),
    ("prettyplease", "0.2.25"),
    ("prettyplease", "0.2.29"),
    ("prettyplease", "0.2.33"),
    ("prettyplease", "0.2.37"),
    ("prost-build", "0.14.3"),
    ("prost-build", "0.14.4"),
    ("prost-types", "0.14.3"),
    ("prost-types", "0.14.4"),
    ("pulldown-cmark-to-cmark", "22.0.0"),
    ("pulldown-cmark", "0.13.3"),
    ("pulldown-cmark", "0.13.4"),
    ("r-efi", "5.2.0"),
    ("r-efi", "5.3.0"),
    ("r-efi", "6.0.0"),
    ("rustc_version", "0.4.1"),
    ("semver", "1.0.26"),
    ("semver", "1.0.28"),
    ("tonic-build", "0.14.6"),
    ("tonic-prost-build", "0.14.6"),
    ("unicase", "2.9.0"),
    ("unicode-xid", "0.2.6"),
    ("utf16_iter", "1.0.5"),
    ("vswhom-sys", "0.1.3"),
    ("vswhom", "0.1.0"),
    ("wasip2", "1.0.1+wasi-0.2.4"),
    ("wasip2", "1.0.3+wasi-0.2.9"),
    ("wasip3", "0.4.0+wasi-0.3.0-rc-2026-01-06"),
    ("wasm-encoder", "0.244.0"),
    ("wasm-metadata", "0.244.0"),
    ("wasmparser", "0.244.0"),
    ("winreg", "0.55.0"),
    ("wit-bindgen-core", "0.51.0"),
    ("wit-bindgen-rust-macro", "0.51.0"),
    ("wit-bindgen-rust", "0.51.0"),
    ("wit-bindgen", "0.46.0"),
    ("wit-bindgen", "0.51.0"),
    ("wit-bindgen", "0.57.1"),
    ("wit-component", "0.244.0"),
    ("wit-parser", "0.244.0"),
    ("write16", "1.0.0"),
];

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, proc_macro: bool) -> CargoNode {
        CargoNode {
            id: id.to_string(),
            name: id.to_string(),
            version: "1.0.0".to_string(),
            purl: format!("pkg:cargo/{}@1.0.0", id),
            instance_id: id.to_string(),
            is_proc_macro: proc_macro,
            scopes: BTreeSet::new(),
            relationship: RustRelationship::Unknown,
            target_conditions: BTreeSet::new(),
            activation: RustActivation::Unknown,
            all_target_present: None,
            host_active: None,
            dependencies: Vec::new(),
        }
    }

    fn edge(child: &str, scope: RustScope) -> CargoEdge {
        CargoEdge {
            child_id: child.to_string(),
            scopes: BTreeSet::from([scope]),
            target_conditions: BTreeSet::new(),
        }
    }

    fn target_edge(child: &str, scope: RustScope, target: &str) -> CargoEdge {
        CargoEdge {
            child_id: child.to_string(),
            scopes: BTreeSet::from([scope]),
            target_conditions: BTreeSet::from([target.to_string()]),
        }
    }

    fn dep<'a>(nodes: &'a [CargoNode], id: &str) -> &'a CargoNode {
        nodes.iter().find(|node| node.id == id).unwrap()
    }

    #[test]
    fn normal_scope_propagates_from_root() {
        let mut nodes = vec![
            node("root", false),
            node("A", false),
            node("B", false),
            node("C", false),
        ];
        let edges = HashMap::from([
            ("root".to_string(), vec![edge("A", RustScope::Normal)]),
            ("A".to_string(), vec![edge("B", RustScope::Normal)]),
            ("B".to_string(), vec![edge("C", RustScope::Normal)]),
        ]);
        propagate_scopes(&mut nodes, &edges, &["root".to_string()]);
        assert_eq!(scopes_to_string(&dep(&nodes, "A").scopes), "normal");
        assert_eq!(dep(&nodes, "A").relationship, RustRelationship::Direct);
        assert_eq!(dep(&nodes, "B").relationship, RustRelationship::Transitive);
        assert_eq!(scopes_to_string(&dep(&nodes, "C").scopes), "normal");
    }

    #[test]
    fn build_closure_does_not_become_normal() {
        let mut nodes = vec![
            node("root", false),
            node("A", false),
            node("B", false),
            node("C", false),
        ];
        let edges = HashMap::from([
            ("root".to_string(), vec![edge("A", RustScope::Build)]),
            ("A".to_string(), vec![edge("B", RustScope::Normal)]),
            ("B".to_string(), vec![edge("C", RustScope::Normal)]),
        ]);
        propagate_scopes(&mut nodes, &edges, &["root".to_string()]);
        assert_eq!(scopes_to_string(&dep(&nodes, "A").scopes), "build");
        assert_eq!(scopes_to_string(&dep(&nodes, "B").scopes), "build");
        assert_eq!(scopes_to_string(&dep(&nodes, "C").scopes), "build");
        assert_eq!(dep(&nodes, "A").relationship, RustRelationship::Direct);
        assert_eq!(dep(&nodes, "B").relationship, RustRelationship::Transitive);
    }

    #[test]
    fn dev_closure_propagates() {
        let mut nodes = vec![node("root", false), node("A", false), node("B", false)];
        let edges = HashMap::from([
            ("root".to_string(), vec![edge("A", RustScope::Dev)]),
            ("A".to_string(), vec![edge("B", RustScope::Normal)]),
        ]);
        propagate_scopes(&mut nodes, &edges, &["root".to_string()]);
        assert_eq!(scopes_to_string(&dep(&nodes, "A").scopes), "dev");
        assert_eq!(scopes_to_string(&dep(&nodes, "B").scopes), "dev");
        assert_eq!(dep(&nodes, "B").relationship, RustRelationship::Transitive);
    }

    #[test]
    fn multi_scope_is_preserved() {
        let mut nodes = vec![
            node("root", false),
            node("A", false),
            node("B", false),
            node("X", false),
        ];
        let edges = HashMap::from([
            (
                "root".to_string(),
                vec![edge("A", RustScope::Normal), edge("B", RustScope::Build)],
            ),
            ("A".to_string(), vec![edge("X", RustScope::Normal)]),
            ("B".to_string(), vec![edge("X", RustScope::Normal)]),
        ]);
        propagate_scopes(&mut nodes, &edges, &["root".to_string()]);
        assert_eq!(scopes_to_string(&dep(&nodes, "X").scopes), "normal,build");
    }

    #[test]
    fn cycle_reaches_fixed_point() {
        let mut nodes = vec![
            node("root", false),
            node("A", false),
            node("B", false),
            node("C", false),
        ];
        let edges = HashMap::from([
            ("root".to_string(), vec![edge("A", RustScope::Build)]),
            ("A".to_string(), vec![edge("B", RustScope::Build)]),
            ("B".to_string(), vec![edge("C", RustScope::Normal)]),
            ("C".to_string(), vec![edge("A", RustScope::Normal)]),
        ]);
        propagate_scopes(&mut nodes, &edges, &["root".to_string()]);
        assert_eq!(scopes_to_string(&dep(&nodes, "A").scopes), "build");
        assert_eq!(scopes_to_string(&dep(&nodes, "B").scopes), "build");
        assert_eq!(scopes_to_string(&dep(&nodes, "C").scopes), "build");
    }

    #[test]
    fn target_specific_edge_preserves_condition() {
        let mut nodes = vec![node("root", false), node("A", false)];
        let edges = HashMap::from([(
            "root".to_string(),
            vec![target_edge("A", RustScope::Normal, "cfg(windows)")],
        )]);
        propagate_scopes(&mut nodes, &edges, &["root".to_string()]);
        let a = dep(&nodes, "A");
        assert_eq!(scopes_to_string(&a.scopes), "normal");
        assert_eq!(a.activation, RustActivation::Conditional);
        assert!(a.target_conditions.contains("cfg(windows)"));
    }

    #[test]
    fn proc_macro_is_independent_from_scope() {
        let mut nodes = vec![node("root", false), node("macro_pkg", true)];
        let edges = HashMap::from([(
            "root".to_string(),
            vec![edge("macro_pkg", RustScope::Build)],
        )]);
        propagate_scopes(&mut nodes, &edges, &["root".to_string()]);
        let macro_pkg = dep(&nodes, "macro_pkg");
        assert!(macro_pkg.is_proc_macro);
        assert_eq!(scopes_to_string(&macro_pkg.scopes), "build");
    }

    #[test]
    fn physical_identity_includes_project_root() {
        let json = serde_json::json!({
            "packages": [{
                "id": "registry+https://github.com/rust-lang/crates.io-index#foo@1.0.0",
                "name": "foo",
                "version": "1.0.0",
                "targets": []
            }]
        });
        let nodes_a = parse_package_nodes(&json, "a");
        let nodes_b = parse_package_nodes(&json, "b");
        assert_ne!(nodes_a[0].instance_id, nodes_b[0].instance_id);
    }
}
