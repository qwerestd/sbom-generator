use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::Path;

use crate::analyze::producers::python::model::{
    ActivationStatus, DependencyRelationship, EvidenceConfidence, PythonDependency,
    PythonDependencyEdge, PythonDependencyRef, PythonEvidence, PythonMetadataKind,
    PythonProjectRoot, PythonResolvedProject, PythonScope, PythonScopeEvidence,
};
use crate::analyze::producers::python::normalize::canonicalize_name;
use crate::analyze::producers::python::parser::pyproject::parse_pyproject;
use crate::analyze::producers::python::parser::requirements::parse_requirements_file;
use crate::analyze::producers::python::parser::uv_lock::parse_uv_lock;
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyType};
use crate::utils::file_utils::{get_manifest_rel_path, make_instance_id};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct MergeKey {
    canonical_name: String,
    version: Option<String>,
}

pub fn resolve_python_project(project: &PythonProjectRoot) -> PythonResolvedProject {
    let mut project = project.clone();
    let mut parsed_dependencies = Vec::new();
    let mut warnings = Vec::new();

    for source in &project.sources {
        match source.kind {
            PythonMetadataKind::PyprojectToml => {
                let parsed = parse_pyproject(&source.path, &project);
                if project.project_name.is_none() {
                    project.project_name = parsed.project_name;
                }
                parsed_dependencies.extend(parsed.dependencies);
                warnings.extend(parsed.warnings);
            }
            PythonMetadataKind::UvLock => {
                let parsed = parse_uv_lock(&source.path, &project);
                parsed_dependencies.extend(parsed.dependencies);
                warnings.extend(parsed.warnings);
            }
            PythonMetadataKind::RequirementsTxt => {
                let parsed = parse_requirements_file(&source.path, &project);
                parsed_dependencies.extend(parsed.dependencies);
                warnings.extend(parsed.warnings);
            }
            _ => warnings.push(format!(
                "Python metadata source {} at {} is not implemented yet",
                source.kind.as_str(),
                source.path.display()
            )),
        }
    }

    parsed_dependencies.sort_by_key(|dep| {
        (
            dep.resolved_version.is_none(),
            dep.source_kind != PythonMetadataKind::UvLock,
        )
    });
    let dependencies = merge_dependencies(parsed_dependencies, &mut warnings);
    PythonResolvedProject {
        root: project,
        dependencies,
        warnings,
    }
}

pub fn merge_dependencies(
    dependencies: Vec<PythonDependency>,
    warnings: &mut Vec<String>,
) -> Vec<PythonDependency> {
    let mut merged: BTreeMap<MergeKey, PythonDependency> = BTreeMap::new();
    let mut exact_keys_by_name: HashMap<String, BTreeSet<MergeKey>> = HashMap::new();

    for dep in dependencies {
        if dep.canonical_name.starts_with("__requirements_include__") {
            continue;
        }

        let key = if dep.resolved_version.is_some() {
            MergeKey {
                canonical_name: dep.canonical_name.clone(),
                version: dep.resolved_version.clone(),
            }
        } else if let Some(existing_key) =
            single_existing_key(&exact_keys_by_name, &dep.canonical_name)
        {
            existing_key
        } else {
            MergeKey {
                canonical_name: dep.canonical_name.clone(),
                version: None,
            }
        };

        let entry = merged.entry(key.clone()).or_insert_with(|| dep.clone());
        if entry.canonical_name == dep.canonical_name {
            merge_dependency_fields(entry, dep, warnings);
        }

        if key.version.is_some() {
            exact_keys_by_name
                .entry(key.canonical_name.clone())
                .or_default()
                .insert(key);
        }
    }

    let mut merged_values: Vec<PythonDependency> = merged.into_values().collect();
    let id_lookup = build_ref_lookup(&merged_values);
    for dep in &mut merged_values {
        let mut converted_edges = Vec::new();
        let mut seen = BTreeSet::new();
        for edge in &dep.dependencies {
            if let Some(target) = resolve_edge(&edge.target, &id_lookup, warnings) {
                let marker = edge.marker.clone();
                let seed_scope = edge.seed_scope.clone();
                if seen.insert((
                    target.canonical_name.clone(),
                    target.version.clone(),
                    marker.clone(),
                    seed_scope.clone(),
                )) {
                    let mut converted = edge.clone();
                    converted.target = target;
                    converted_edges.push(converted);
                }
            }
        }
        dep.dependencies = converted_edges;
    }

    propagate_scopes(&mut merged_values);
    merged_values
}

pub fn to_existing_dependencies(
    project: &PythonResolvedProject,
    base_path: &Path,
) -> Vec<Dependency> {
    let id_lookup = build_dependency_id_lookup(project, base_path);
    let mut result = Vec::with_capacity(project.dependencies.len());

    for dep in &project.dependencies {
        let purl = match &dep.resolved_version {
            Some(version) => format!("pkg:pypi/{}@{}", dep.canonical_name, version),
            None => format!("pkg:pypi/{}", dep.canonical_name),
        };
        let source_rel = get_manifest_rel_path(base_path, &dep.source_path);
        let root_rel = get_manifest_rel_path(base_path, &dep.project_root);
        let physical_salt = format!(
            "pypi:{}:{}:{}:{}",
            root_rel,
            source_rel,
            dep.source_kind.as_str(),
            dep.canonical_name
        );
        let instance_id = make_instance_id(&purl, &physical_salt);
        let child_ids = dep
            .dependencies
            .iter()
            .filter_map(|edge| {
                id_lookup.get(&(
                    edge.target.canonical_name.clone(),
                    edge.target.version.clone(),
                ))
            })
            .cloned()
            .collect();

        if let Ok(converted) = DependencyBuilder::default()
            .name(dep.display_name.clone())
            .version(dep.resolved_version.clone())
            .declared_version(dep.declared_version.clone())
            .python_dependency_scope(Some(dep.scopes_string()))
            .python_source_type(Some(dep.source_kind.as_str().to_string()))
            .python_manifest_path(Some(source_rel))
            .python_project_root(Some(root_rel))
            .python_confidence(best_confidence(&dep.evidence).map(|c| c.as_str().to_string()))
            .python_is_project_package(Some(dep.is_project_package))
            .python_dependency_relationship(Some(dep.relationship.as_str().to_string()))
            .python_is_direct(Some(dep.relationship == DependencyRelationship::Direct))
            .python_marker(marker_string(dep))
            .python_activation(Some(dep.activation.as_str().to_string()))
            .r#type(DependencyType::Library)
            .purl(purl)
            .instance_id(instance_id)
            .dependencies(child_ids)
            .location(None)
            .build()
        {
            result.push(converted);
        }
    }

    result
}

fn single_existing_key(
    exact_keys_by_name: &HashMap<String, BTreeSet<MergeKey>>,
    canonical_name: &str,
) -> Option<MergeKey> {
    let keys = exact_keys_by_name.get(canonical_name)?;
    if keys.len() == 1 {
        keys.iter().next().cloned()
    } else {
        None
    }
}

fn merge_dependency_fields(
    target: &mut PythonDependency,
    source: PythonDependency,
    warnings: &mut Vec<String>,
) {
    if target.resolved_version.is_none() {
        target.resolved_version = source.resolved_version;
    }
    if target.declared_version.is_none() {
        target.declared_version = source.declared_version;
    }
    if target.display_name == target.canonical_name && source.display_name != source.canonical_name
    {
        target.display_name = source.display_name;
    }
    target.scopes.extend(source.scopes);
    target.is_project_package |= source.is_project_package;
    target.is_editable |= source.is_editable;
    target.is_local_path |= source.is_local_path;
    if target.relationship != DependencyRelationship::Direct {
        target.relationship = source.relationship;
    }
    if source.activation == ActivationStatus::Conditional {
        target.activation = ActivationStatus::Conditional;
    }
    target.markers.extend(source.markers);
    target.evidence.extend(source.evidence);
    target.scope_evidence.extend(source.scope_evidence);

    for edge in source.dependencies {
        if !target
            .dependencies
            .iter()
            .any(|existing| same_edge(existing, &edge))
        {
            target.dependencies.push(edge);
        }
    }

    if target.resolved_version.is_none() && target.dependencies.len() > 1 {
        warnings.push(format!(
            "dependency {} has unresolved version and multiple edge candidates",
            target.canonical_name
        ));
    }
}

fn same_edge(left: &PythonDependencyEdge, right: &PythonDependencyEdge) -> bool {
    left.target == right.target
        && left.marker == right.marker
        && left.seed_scope == right.seed_scope
}

fn propagate_scopes(dependencies: &mut [PythonDependency]) {
    let lookup = dependency_index_lookup(dependencies);
    let mut queue = VecDeque::new();

    for (idx, dep) in dependencies.iter_mut().enumerate() {
        if dep.is_project_package {
            continue;
        }

        let scopes = non_unknown_scopes(&dep.scopes);
        if !scopes.is_empty() {
            dep.relationship = DependencyRelationship::Direct;
            if dep.activation == ActivationStatus::Unknown {
                dep.activation = ActivationStatus::Unconditional;
            }
            queue.push_back(idx);
        }
    }

    let project_indices: Vec<_> = dependencies
        .iter()
        .enumerate()
        .filter_map(|(idx, dep)| dep.is_project_package.then_some(idx))
        .collect();

    for project_idx in project_indices {
        let edges = dependencies[project_idx].dependencies.clone();
        for edge in edges {
            let Some(child_idx) = resolve_edge_index(&edge.target, &lookup) else {
                continue;
            };
            if dependencies[child_idx].is_project_package {
                continue;
            }

            let scope = edge.seed_scope.clone().unwrap_or(PythonScope::Prod);
            let project_root = dependencies[project_idx].project_root.clone();
            let seed_package = dependencies[child_idx].canonical_name.clone();
            let source_path = edge
                .evidence
                .first()
                .map(|e| e.source_path.clone())
                .unwrap_or_else(|| dependencies[project_idx].source_path.clone());
            let source_kind = dependencies[project_idx].source_kind.clone();
            let changed = add_scope_with_evidence(
                &mut dependencies[child_idx],
                scope.clone(),
                PythonScopeEvidence {
                    scope,
                    project_root,
                    seed_package,
                    source_path,
                    source_kind,
                },
            );
            dependencies[child_idx].relationship = DependencyRelationship::Direct;
            apply_marker(&mut dependencies[child_idx], edge.marker.as_deref());
            if dependencies[child_idx].activation == ActivationStatus::Unknown {
                dependencies[child_idx].activation = ActivationStatus::Unconditional;
            }
            if changed {
                queue.push_back(child_idx);
            }
        }
    }

    while let Some(current_idx) = queue.pop_front() {
        let current_scopes = non_unknown_scopes(&dependencies[current_idx].scopes);
        if current_scopes.is_empty() {
            continue;
        }
        let current_scope_evidence = dependencies[current_idx].scope_evidence.clone();
        let current_markers = dependencies[current_idx].markers.clone();
        let edges = dependencies[current_idx].dependencies.clone();

        for edge in edges {
            let Some(child_idx) = resolve_edge_index(&edge.target, &lookup) else {
                continue;
            };
            if dependencies[child_idx].is_project_package {
                continue;
            }

            let mut changed = false;
            apply_marker(&mut dependencies[child_idx], edge.marker.as_deref());
            if !current_markers.is_empty() {
                for marker in &current_markers {
                    apply_marker(&mut dependencies[child_idx], Some(marker));
                }
            }

            for scope in &current_scopes {
                let evidence = current_scope_evidence
                    .iter()
                    .find(|e| e.scope == *scope)
                    .cloned()
                    .unwrap_or_else(|| PythonScopeEvidence {
                        scope: scope.clone(),
                        project_root: dependencies[current_idx].project_root.clone(),
                        seed_package: dependencies[current_idx].canonical_name.clone(),
                        source_path: dependencies[current_idx].source_path.clone(),
                        source_kind: dependencies[current_idx].source_kind.clone(),
                    });
                changed |=
                    add_scope_with_evidence(&mut dependencies[child_idx], scope.clone(), evidence);
            }

            if dependencies[child_idx].relationship == DependencyRelationship::Unknown {
                dependencies[child_idx].relationship = DependencyRelationship::Transitive;
            }
            if dependencies[child_idx].activation == ActivationStatus::Unknown {
                dependencies[child_idx].activation = ActivationStatus::Unconditional;
            }
            if changed {
                queue.push_back(child_idx);
            }
        }
    }

    for dep in dependencies {
        if dep.activation == ActivationStatus::Unknown
            && !non_unknown_scopes(&dep.scopes).is_empty()
        {
            dep.activation = ActivationStatus::Unconditional;
        }
    }
}

fn dependency_index_lookup(
    dependencies: &[PythonDependency],
) -> HashMap<(String, Option<String>), usize> {
    dependencies
        .iter()
        .enumerate()
        .map(|(idx, dep)| {
            (
                (dep.canonical_name.clone(), dep.resolved_version.clone()),
                idx,
            )
        })
        .collect()
}

fn resolve_edge_index(
    edge: &PythonDependencyRef,
    lookup: &HashMap<(String, Option<String>), usize>,
) -> Option<usize> {
    lookup
        .get(&(edge.canonical_name.clone(), edge.version.clone()))
        .copied()
}

fn non_unknown_scopes(scopes: &BTreeSet<PythonScope>) -> Vec<PythonScope> {
    scopes
        .iter()
        .filter(|scope| **scope != PythonScope::Unknown)
        .cloned()
        .collect()
}

fn add_scope_with_evidence(
    dep: &mut PythonDependency,
    scope: PythonScope,
    evidence: PythonScopeEvidence,
) -> bool {
    if scope != PythonScope::Unknown {
        dep.scopes.remove(&PythonScope::Unknown);
    }
    let changed = dep.scopes.insert(scope.clone());
    if !dep.scope_evidence.iter().any(|existing| {
        existing.scope == scope
            && existing.seed_package == evidence.seed_package
            && existing.source_path == evidence.source_path
    }) {
        dep.scope_evidence.push(evidence);
    }
    changed
}

fn apply_marker(dep: &mut PythonDependency, marker: Option<&str>) {
    if let Some(marker) = marker.filter(|m| !m.trim().is_empty()) {
        dep.markers.insert(marker.to_string());
        dep.activation = ActivationStatus::Conditional;
    }
}

fn marker_string(dep: &PythonDependency) -> Option<String> {
    if dep.markers.is_empty() {
        None
    } else {
        Some(dep.markers.iter().cloned().collect::<Vec<_>>().join(" && "))
    }
}

fn build_ref_lookup(
    dependencies: &[PythonDependency],
) -> HashMap<(String, Option<String>), PythonDependencyRef> {
    dependencies
        .iter()
        .map(|dep| {
            (
                (dep.canonical_name.clone(), dep.resolved_version.clone()),
                PythonDependencyRef {
                    canonical_name: dep.canonical_name.clone(),
                    version: dep.resolved_version.clone(),
                },
            )
        })
        .collect()
}

fn resolve_edge(
    edge: &PythonDependencyRef,
    lookup: &HashMap<(String, Option<String>), PythonDependencyRef>,
    warnings: &mut Vec<String>,
) -> Option<PythonDependencyRef> {
    if let Some(dep) = lookup.get(&(edge.canonical_name.clone(), edge.version.clone())) {
        return Some(dep.clone());
    }

    if edge.version.is_none() {
        let matches: Vec<_> = lookup
            .iter()
            .filter(|((name, _), _)| name == &edge.canonical_name)
            .map(|(_, dep)| dep.clone())
            .collect();
        if matches.len() == 1 {
            return matches.into_iter().next();
        }
        if matches.len() > 1 {
            warnings.push(format!(
                "ambiguous Python dependency edge target {}; multiple versions exist",
                edge.canonical_name
            ));
        }
    }

    None
}

fn build_dependency_id_lookup(
    project: &PythonResolvedProject,
    base_path: &Path,
) -> HashMap<(String, Option<String>), String> {
    project
        .dependencies
        .iter()
        .map(|dep| {
            let purl = match &dep.resolved_version {
                Some(version) => format!("pkg:pypi/{}@{}", dep.canonical_name, version),
                None => format!("pkg:pypi/{}", dep.canonical_name),
            };
            let source_rel = get_manifest_rel_path(base_path, &dep.source_path);
            let root_rel = get_manifest_rel_path(base_path, &dep.project_root);
            let physical_salt = format!(
                "pypi:{}:{}:{}:{}",
                root_rel,
                source_rel,
                dep.source_kind.as_str(),
                dep.canonical_name
            );
            (
                (dep.canonical_name.clone(), dep.resolved_version.clone()),
                make_instance_id(&purl, &physical_salt),
            )
        })
        .collect()
}

fn best_confidence(evidence: &[PythonEvidence]) -> Option<EvidenceConfidence> {
    evidence.iter().map(|e| e.confidence.clone()).min()
}

#[allow(dead_code)]
fn _canonical_key(name: &str, version: Option<String>) -> MergeKey {
    MergeKey {
        canonical_name: canonicalize_name(name),
        version,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::producers::python::model::{
        PythonMetadataKind, PythonMetadataSource, PythonProjectContext, PythonScope,
        PythonSourcePriority,
    };
    use std::fs;
    use std::path::PathBuf;

    fn source(kind: PythonMetadataKind, path: PathBuf) -> PythonMetadataSource {
        let is_lockfile = kind == PythonMetadataKind::UvLock;
        PythonMetadataSource {
            kind,
            path,
            priority: if is_lockfile {
                PythonSourcePriority::ResolvedLockfile
            } else {
                PythonSourcePriority::DeclaredManifest
            },
            is_lockfile,
        }
    }

    #[test]
    fn merges_uv_exact_with_pyproject_scope_and_preserves_graph() {
        let root = std::env::temp_dir().join(format!(
            "sbom-generator-python-merge-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("pyproject.toml"),
            r#"
[project]
name = "demo"
dependencies = ["numpy>=2", "requests>=2"]
"#,
        )
        .unwrap();
        fs::write(
            root.join("uv.lock"),
            r#"
[[package]]
name = "demo"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "numpy" }, { name = "requests" }]

[[package]]
name = "numpy"
version = "2.2.6"

[[package]]
name = "requests"
version = "2.32.3"
dependencies = [{ name = "urllib3" }]

[[package]]
name = "urllib3"
version = "2.2.0"
"#,
        )
        .unwrap();

        let project = PythonProjectRoot {
            root_path: root.clone(),
            project_name: None,
            context: PythonProjectContext::Normal,
            sources: vec![
                source(PythonMetadataKind::UvLock, root.join("uv.lock")),
                source(
                    PythonMetadataKind::PyprojectToml,
                    root.join("pyproject.toml"),
                ),
            ],
        };

        let resolved = resolve_python_project(&project);
        let numpy = resolved
            .dependencies
            .iter()
            .find(|dep| dep.canonical_name == "numpy")
            .unwrap();
        assert_eq!(numpy.resolved_version.as_deref(), Some("2.2.6"));
        assert_eq!(numpy.declared_version.as_deref(), Some(">=2"));
        assert!(numpy.scopes.contains(&PythonScope::Prod));

        let converted = to_existing_dependencies(&resolved, &root);
        let requests = converted.iter().find(|dep| dep.name == "requests").unwrap();
        let urllib3 = converted.iter().find(|dep| dep.name == "urllib3").unwrap();
        assert!(requests.dependencies.contains(&urllib3.instance_id));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn same_package_same_version_different_roots_have_different_instances() {
        let root = std::env::temp_dir().join(format!(
            "sbom-generator-python-physical-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("a")).unwrap();
        fs::create_dir_all(root.join("b")).unwrap();
        for sub in ["a", "b"] {
            fs::write(
                root.join(sub).join("uv.lock"),
                r#"
[[package]]
name = "numpy"
version = "2.2.6"
"#,
            )
            .unwrap();
        }

        let project_a = PythonProjectRoot {
            root_path: root.join("a"),
            project_name: None,
            context: PythonProjectContext::Normal,
            sources: vec![source(PythonMetadataKind::UvLock, root.join("a/uv.lock"))],
        };
        let project_b = PythonProjectRoot {
            root_path: root.join("b"),
            project_name: None,
            context: PythonProjectContext::Normal,
            sources: vec![source(PythonMetadataKind::UvLock, root.join("b/uv.lock"))],
        };

        let deps_a = to_existing_dependencies(&resolve_python_project(&project_a), &root);
        let deps_b = to_existing_dependencies(&resolve_python_project(&project_b), &root);
        assert_eq!(deps_a[0].purl, deps_b[0].purl);
        assert_ne!(deps_a[0].instance_id, deps_b[0].instance_id);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn propagates_uv_dev_scope_to_transitive_dependencies() {
        let root = temp_root("sbom-generator-python-dev-propagation");
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("pyproject.toml"),
            r#"
[project]
name = "tsurugi-dbapi"
"#,
        )
        .unwrap();
        fs::write(
            root.join("uv.lock"),
            r#"
[[package]]
name = "tsurugi-dbapi"
source = { editable = "." }

[package.dev-dependencies]
dev = [{ name = "mkdocs-material" }]

[[package]]
name = "mkdocs-material"
version = "9.7.6"
dependencies = [{ name = "babel" }]

[[package]]
name = "babel"
version = "2.17.0"
"#,
        )
        .unwrap();

        let resolved = resolve_python_project(&project_with_sources(&root));
        let mkdocs_material = find_dep(&resolved, "mkdocs-material");
        assert!(mkdocs_material.scopes.contains(&PythonScope::Dev));
        assert_eq!(mkdocs_material.relationship, DependencyRelationship::Direct);

        let babel = find_dep(&resolved, "babel");
        assert!(babel.scopes.contains(&PythonScope::Dev));
        assert_eq!(babel.relationship, DependencyRelationship::Transitive);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn preserves_multi_scope_reachability() {
        let root = temp_root("sbom-generator-python-multiscope");
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("pyproject.toml"),
            r#"
[project]
name = "demo"
dependencies = ["a"]

[project.optional-dependencies]
dev = ["b"]
"#,
        )
        .unwrap();
        fs::write(
            root.join("uv.lock"),
            r#"
[[package]]
name = "demo"
source = { virtual = "." }
dependencies = [{ name = "a" }]

[package.dev-dependencies]
dev = [{ name = "b" }]

[[package]]
name = "a"
version = "1.0.0"
dependencies = [{ name = "x" }]

[[package]]
name = "b"
version = "1.0.0"
dependencies = [{ name = "x" }]

[[package]]
name = "x"
version = "1.0.0"
"#,
        )
        .unwrap();

        let resolved = resolve_python_project(&project_with_sources(&root));
        let x = find_dep(&resolved, "x");
        assert!(x.scopes.contains(&PythonScope::Prod));
        assert!(x.scopes.contains(&PythonScope::Dev));
        assert_eq!(x.scopes_string(), "prod,dev");
        assert_eq!(x.relationship, DependencyRelationship::Transitive);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn preserves_marker_and_conditional_activation() {
        let root = temp_root("sbom-generator-python-marker");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("pyproject.toml"), "[project]\nname = \"demo\"\n").unwrap();
        fs::write(
            root.join("uv.lock"),
            r#"
[[package]]
name = "demo"
source = { virtual = "." }

[package.dev-dependencies]
dev = [{ name = "mkdocs" }]

[[package]]
name = "mkdocs"
version = "1.6.1"
dependencies = [{ name = "colorama", marker = "sys_platform == 'win32'" }]

[[package]]
name = "colorama"
version = "0.4.6"
"#,
        )
        .unwrap();

        let resolved = resolve_python_project(&project_with_sources(&root));
        let colorama = find_dep(&resolved, "colorama");
        assert!(colorama.scopes.contains(&PythonScope::Dev));
        assert_eq!(colorama.relationship, DependencyRelationship::Transitive);
        assert_eq!(colorama.activation, ActivationStatus::Conditional);
        assert!(colorama.markers.contains("sys_platform == 'win32'"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn isolates_scope_propagation_per_python_project_root() {
        let root = temp_root("sbom-generator-python-isolation");
        fs::create_dir_all(root.join("a")).unwrap();
        fs::create_dir_all(root.join("b")).unwrap();
        fs::write(root.join("a/pyproject.toml"), "[project]\nname = \"a\"\n").unwrap();
        fs::write(root.join("b/pyproject.toml"), "[project]\nname = \"b\"\n").unwrap();
        fs::write(
            root.join("a/uv.lock"),
            r#"
[[package]]
name = "a"
source = { virtual = "." }
dependencies = [{ name = "numpy" }]

[[package]]
name = "numpy"
version = "2.2.6"
"#,
        )
        .unwrap();
        fs::write(
            root.join("b/uv.lock"),
            r#"
[[package]]
name = "b"
source = { virtual = "." }

[package.dev-dependencies]
dev = [{ name = "numpy" }]

[[package]]
name = "numpy"
version = "2.2.6"
"#,
        )
        .unwrap();

        let resolved_a = resolve_python_project(&PythonProjectRoot {
            root_path: root.join("a"),
            project_name: None,
            context: PythonProjectContext::Normal,
            sources: vec![
                source(
                    PythonMetadataKind::PyprojectToml,
                    root.join("a/pyproject.toml"),
                ),
                source(PythonMetadataKind::UvLock, root.join("a/uv.lock")),
            ],
        });
        let resolved_b = resolve_python_project(&PythonProjectRoot {
            root_path: root.join("b"),
            project_name: None,
            context: PythonProjectContext::Normal,
            sources: vec![
                source(
                    PythonMetadataKind::PyprojectToml,
                    root.join("b/pyproject.toml"),
                ),
                source(PythonMetadataKind::UvLock, root.join("b/uv.lock")),
            ],
        });

        let numpy_a = find_dep(&resolved_a, "numpy");
        let numpy_b = find_dep(&resolved_b, "numpy");
        assert_eq!(numpy_a.scopes_string(), "prod");
        assert_eq!(numpy_b.scopes_string(), "dev");

        let deps_a = to_existing_dependencies(&resolved_a, &root);
        let deps_b = to_existing_dependencies(&resolved_b, &root);
        let instance_a = deps_a.iter().find(|dep| dep.name == "numpy").unwrap();
        let instance_b = deps_b.iter().find(|dep| dep.name == "numpy").unwrap();
        assert_ne!(instance_a.instance_id, instance_b.instance_id);

        let logical_scopes: BTreeSet<_> = numpy_a
            .scopes
            .union(&numpy_b.scopes)
            .map(PythonScope::as_str)
            .collect();
        assert_eq!(logical_scopes, BTreeSet::from(["dev", "prod"]));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn propagation_terminates_on_cycles() {
        let root = temp_root("sbom-generator-python-cycle");
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("pyproject.toml"),
            r#"
[project]
name = "demo"

[project.optional-dependencies]
dev = ["a"]
"#,
        )
        .unwrap();
        fs::write(
            root.join("uv.lock"),
            r#"
[[package]]
name = "a"
version = "1.0.0"
dependencies = [{ name = "b" }]

[[package]]
name = "b"
version = "1.0.0"
dependencies = [{ name = "c" }]

[[package]]
name = "c"
version = "1.0.0"
dependencies = [{ name = "a" }]
"#,
        )
        .unwrap();

        let resolved = resolve_python_project(&project_with_sources(&root));
        for name in ["a", "b", "c"] {
            assert!(find_dep(&resolved, name).scopes.contains(&PythonScope::Dev));
        }
        assert_eq!(
            find_dep(&resolved, "a").relationship,
            DependencyRelationship::Direct
        );
        assert_eq!(
            find_dep(&resolved, "b").relationship,
            DependencyRelationship::Transitive
        );
        assert_eq!(
            find_dep(&resolved, "c").relationship,
            DependencyRelationship::Transitive
        );

        let _ = fs::remove_dir_all(root);
    }

    fn temp_root(prefix: &str) -> PathBuf {
        std::env::temp_dir().join(format!("{}-{}", prefix, std::process::id()))
    }

    fn project_with_sources(root: &Path) -> PythonProjectRoot {
        PythonProjectRoot {
            root_path: root.to_path_buf(),
            project_name: None,
            context: PythonProjectContext::Normal,
            sources: vec![
                source(
                    PythonMetadataKind::PyprojectToml,
                    root.join("pyproject.toml"),
                ),
                source(PythonMetadataKind::UvLock, root.join("uv.lock")),
            ],
        }
    }

    fn find_dep<'a>(project: &'a PythonResolvedProject, name: &str) -> &'a PythonDependency {
        project
            .dependencies
            .iter()
            .find(|dep| dep.canonical_name == name)
            .unwrap_or_else(|| panic!("missing dependency {}", name))
    }
}
