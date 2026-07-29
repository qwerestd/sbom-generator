use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::Path;

use crate::analyze::producers::python::model::{
    ActivationStatus, DependencyRelationship, EvidenceConfidence, PythonDependency,
    PythonDependencyEdge, PythonDependencyRef, PythonEvidence, PythonEvidenceKind,
    PythonMetadataKind, PythonProjectRoot, PythonScope,
};
use crate::analyze::producers::python::normalize::canonicalize_name;

#[derive(Default)]
pub struct UvLockParseResult {
    pub dependencies: Vec<PythonDependency>,
    pub warnings: Vec<String>,
}

pub fn parse_uv_lock(path: &Path, project: &PythonProjectRoot) -> UvLockParseResult {
    let mut result = UvLockParseResult::default();
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) => {
            result.warnings.push(format!(
                "failed to read uv.lock {}: {}",
                path.display(),
                err
            ));
            return result;
        }
    };
    let parsed: toml::Value = match toml::from_str(&content) {
        Ok(value) => value,
        Err(err) => {
            result.warnings.push(format!(
                "failed to parse uv.lock {}: {}",
                path.display(),
                err
            ));
            return result;
        }
    };

    let Some(packages) = parsed.get("package").and_then(|v| v.as_array()) else {
        return result;
    };

    let mut version_count_by_name: HashMap<String, usize> = HashMap::new();
    for package in packages {
        if let Some(name) = package.get("name").and_then(|v| v.as_str()) {
            *version_count_by_name
                .entry(canonicalize_name(name))
                .or_default() += 1;
        }
    }

    for package in packages {
        let Some(name) = package.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let version = package
            .get("version")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let canonical_name = canonicalize_name(name);
        let mut scopes = BTreeSet::new();
        scopes.insert(PythonScope::Unknown);

        let mut dependencies = Vec::new();
        if let Some(raw_deps) = package.get("dependencies").and_then(|v| v.as_array()) {
            for dep in raw_deps {
                if let Some(edge) = parse_edge(
                    dep,
                    None,
                    &canonical_name,
                    path,
                    project,
                    &version_count_by_name,
                    &mut result.warnings,
                ) {
                    dependencies.push(edge);
                }
            }
        }

        if let Some(dev_groups) = package.get("dev-dependencies").and_then(|v| v.as_table()) {
            for (group, raw_deps) in dev_groups {
                let seed_scope = scope_from_uv_group(group);
                if let Some(raw_deps) = raw_deps.as_array() {
                    for dep in raw_deps {
                        if let Some(edge) = parse_edge(
                            dep,
                            Some(seed_scope.clone()),
                            &canonical_name,
                            path,
                            project,
                            &version_count_by_name,
                            &mut result.warnings,
                        ) {
                            dependencies.push(edge);
                        }
                    }
                }
            }
        }

        let source = package.get("source");
        let is_project_package = source
            .and_then(|s| s.get("virtual").or_else(|| s.get("editable")))
            .is_some()
            || project
                .project_name
                .as_ref()
                .map(|project_name| canonicalize_name(project_name) == canonical_name)
                .unwrap_or(false);
        let is_editable = source.and_then(|s| s.get("editable")).is_some();
        let is_local_path = source.and_then(|s| s.get("path")).is_some() || is_editable;

        let mut evidence = vec![PythonEvidence {
            kind: PythonEvidenceKind::LockfileExact,
            source_path: path.to_path_buf(),
            project_root: project.root_path.clone(),
            confidence: EvidenceConfidence::High,
            detail: version
                .as_ref()
                .map(|v| format!("{}=={}", canonical_name, v))
                .or_else(|| Some(canonical_name.clone())),
        }];

        if !dependencies.is_empty() {
            evidence.push(PythonEvidence {
                kind: PythonEvidenceKind::LockfileDependencyEdge,
                source_path: path.to_path_buf(),
                project_root: project.root_path.clone(),
                confidence: EvidenceConfidence::High,
                detail: Some(format!("{} edges", dependencies.len())),
            });
        }

        result.dependencies.push(PythonDependency {
            canonical_name,
            display_name: name.to_string(),
            resolved_version: version,
            declared_version: None,
            scopes,
            source_kind: PythonMetadataKind::UvLock,
            project_root: project.root_path.clone(),
            source_path: path.to_path_buf(),
            is_project_package,
            is_editable,
            is_local_path,
            relationship: DependencyRelationship::Unknown,
            activation: ActivationStatus::Unknown,
            markers: BTreeSet::new(),
            evidence,
            scope_evidence: Vec::new(),
            dependencies,
        });
    }

    result
}

fn parse_edge(
    dep: &toml::Value,
    seed_scope: Option<PythonScope>,
    from_name: &str,
    path: &Path,
    project: &PythonProjectRoot,
    version_count_by_name: &HashMap<String, usize>,
    warnings: &mut Vec<String>,
) -> Option<PythonDependencyEdge> {
    let dep_name = dep.get("name").and_then(|v| v.as_str())?;
    let dep_canonical = canonicalize_name(dep_name);
    let dep_version = dep
        .get("version")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    if dep_version.is_none()
        && version_count_by_name
            .get(&dep_canonical)
            .copied()
            .unwrap_or(0)
            > 1
    {
        warnings.push(format!(
            "ambiguous uv.lock edge {} -> {} in {}; multiple versions exist",
            from_name,
            dep_canonical,
            path.display()
        ));
        return None;
    }

    let marker = dep
        .get("marker")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    Some(PythonDependencyEdge {
        target: PythonDependencyRef {
            canonical_name: dep_canonical,
            version: dep_version,
        },
        marker,
        seed_scope,
        evidence: vec![PythonEvidence {
            kind: PythonEvidenceKind::LockfileDependencyEdge,
            source_path: path.to_path_buf(),
            project_root: project.root_path.clone(),
            confidence: EvidenceConfidence::High,
            detail: Some(format!("{} -> {}", from_name, dep_name)),
        }],
    })
}

fn scope_from_uv_group(group: &str) -> PythonScope {
    match group.to_lowercase().as_str() {
        "dev" | "develop" | "docs" | "doc" => PythonScope::Dev,
        "test" | "tests" => PythonScope::Test,
        "build" => PythonScope::Build,
        _ => PythonScope::Optional,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::producers::python::model::{
        PythonMetadataKind, PythonMetadataSource, PythonProjectContext, PythonSourcePriority,
    };
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn parses_packages_and_edges() {
        let root =
            std::env::temp_dir().join(format!("sbom-generator-uv-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let path = root.join("uv.lock");
        fs::write(
            &path,
            r#"
[[package]]
name = "demo"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
  { name = "numpy" },
  { name = "requests" },
]

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
            project_name: Some("demo".to_string()),
            context: PythonProjectContext::Normal,
            sources: vec![PythonMetadataSource {
                kind: PythonMetadataKind::UvLock,
                path: PathBuf::new(),
                priority: PythonSourcePriority::ResolvedLockfile,
                is_lockfile: true,
            }],
        };

        let result = parse_uv_lock(&path, &project);
        assert!(result.warnings.is_empty());
        let demo = result
            .dependencies
            .iter()
            .find(|d| d.canonical_name == "demo")
            .unwrap();
        assert!(demo.is_project_package);
        assert!(demo
            .dependencies
            .iter()
            .any(|d| d.target.canonical_name == "numpy"));
        assert!(result
            .dependencies
            .iter()
            .any(|d| d.canonical_name == "urllib3"));

        let _ = fs::remove_dir_all(root);
    }
}
