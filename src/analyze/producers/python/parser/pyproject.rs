use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use lazy_static::lazy_static;
use regex::Regex;

use crate::analyze::producers::python::model::{
    ActivationStatus, DependencyRelationship, EvidenceConfidence, PythonDependency, PythonEvidence,
    PythonEvidenceKind, PythonMetadataKind, PythonProjectRoot, PythonScope, PythonScopeEvidence,
};
use crate::analyze::producers::python::normalize::canonicalize_name;

lazy_static! {
    static ref SPEC_RE: Regex = Regex::new(
        r"(?i)^\s*([A-Z0-9][A-Z0-9_.\-]*)(?:\[[^\]]+\])?\s*(?:(==|===|~=|!=|>=|<=|>|<)\s*([A-Z0-9][A-Z0-9_.!\+\-]*))?"
    )
    .unwrap();
}

#[derive(Default)]
pub struct PyprojectParseResult {
    pub project_name: Option<String>,
    pub dependencies: Vec<PythonDependency>,
    pub warnings: Vec<String>,
}

pub fn parse_pyproject(path: &Path, project: &PythonProjectRoot) -> PyprojectParseResult {
    let mut result = PyprojectParseResult::default();
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) => {
            result.warnings.push(format!(
                "failed to read pyproject {}: {}",
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
                "failed to parse pyproject {}: {}",
                path.display(),
                err
            ));
            return result;
        }
    };

    let Some(project_table) = parsed.get("project").and_then(|v| v.as_table()) else {
        return result;
    };

    result.project_name = project_table
        .get("name")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    if let Some(dependencies) = project_table.get("dependencies").and_then(|v| v.as_array()) {
        for dep in dependencies.iter().filter_map(|v| v.as_str()) {
            if let Some(dep) = parse_dependency_spec(dep, path, project, PythonScope::Prod, None) {
                result.dependencies.push(dep);
            }
        }
    }

    if let Some(optional_groups) = project_table
        .get("optional-dependencies")
        .and_then(|v| v.as_table())
    {
        for (group, deps) in optional_groups {
            let scope = scope_from_optional_group(group);
            if let Some(deps) = deps.as_array() {
                for dep in deps.iter().filter_map(|v| v.as_str()) {
                    if let Some(dep) =
                        parse_dependency_spec(dep, path, project, scope.clone(), Some(group))
                    {
                        result.dependencies.push(dep);
                    }
                }
            }
        }
    }

    result
}

fn parse_dependency_spec(
    spec: &str,
    source_path: &Path,
    project: &PythonProjectRoot,
    scope: PythonScope,
    optional_group: Option<&str>,
) -> Option<PythonDependency> {
    let spec_without_marker = spec.split(';').next().unwrap_or(spec).trim();
    let direct_ref_name = spec_without_marker
        .split(" @ ")
        .next()
        .unwrap_or(spec_without_marker);
    let captures = SPEC_RE.captures(direct_ref_name)?;
    let raw_name = captures.get(1)?.as_str();
    let op = captures.get(2).map(|m| m.as_str());
    let raw_version = captures.get(3).map(|m| m.as_str());

    let resolved_version = match (op, raw_version) {
        (Some("==") | Some("==="), Some(v)) if !v.contains('*') => Some(v.to_string()),
        (None, Some(v)) if !v.contains('*') => Some(v.to_string()),
        _ => None,
    };
    let declared_version = raw_version.map(|v| match op {
        Some(op) => format!("{}{}", op, v),
        None => v.to_string(),
    });

    let mut scopes = BTreeSet::new();
    scopes.insert(scope.clone());

    let mut evidence = vec![PythonEvidence {
        kind: if resolved_version.is_some() {
            PythonEvidenceKind::ManifestExact
        } else {
            PythonEvidenceKind::ManifestRange
        },
        source_path: source_path.to_path_buf(),
        project_root: project.root_path.clone(),
        confidence: EvidenceConfidence::Medium,
        detail: Some(spec.to_string()),
    }];

    if let Some(group) = optional_group {
        evidence.push(PythonEvidence {
            kind: PythonEvidenceKind::OptionalDependencyGroup,
            source_path: source_path.to_path_buf(),
            project_root: project.root_path.clone(),
            confidence: EvidenceConfidence::Medium,
            detail: Some(group.to_string()),
        });
    }

    Some(PythonDependency {
        canonical_name: canonicalize_name(raw_name),
        display_name: raw_name.to_string(),
        resolved_version,
        declared_version,
        scopes,
        source_kind: PythonMetadataKind::PyprojectToml,
        project_root: project.root_path.clone(),
        source_path: source_path.to_path_buf(),
        is_project_package: false,
        is_editable: spec.contains(" @ file://"),
        is_local_path: spec.contains(" @ file://"),
        relationship: DependencyRelationship::Direct,
        activation: ActivationStatus::Unconditional,
        markers: BTreeSet::new(),
        evidence,
        scope_evidence: vec![PythonScopeEvidence {
            scope,
            project_root: project.root_path.clone(),
            seed_package: canonicalize_name(raw_name),
            source_path: source_path.to_path_buf(),
            source_kind: PythonMetadataKind::PyprojectToml,
        }],
        dependencies: Vec::new(),
    })
}

fn scope_from_optional_group(group: &str) -> PythonScope {
    match group.to_lowercase().as_str() {
        "dev" | "develop" => PythonScope::Dev,
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
    fn parses_pep621_dependencies_and_optional_groups() {
        let root = std::env::temp_dir().join(format!(
            "sbom-generator-pyproject-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let path = root.join("pyproject.toml");
        fs::write(
            &path,
            r#"
[project]
name = "demo"
dependencies = ["requests>=2", "numpy==2.2.6"]

[project.optional-dependencies]
dev = ["pytest>=8"]
test = ["hypothesis==6.0.0"]
"#,
        )
        .unwrap();

        let project = PythonProjectRoot {
            root_path: root.clone(),
            project_name: None,
            context: PythonProjectContext::Normal,
            sources: vec![PythonMetadataSource {
                kind: PythonMetadataKind::PyprojectToml,
                path: PathBuf::new(),
                priority: PythonSourcePriority::DeclaredManifest,
                is_lockfile: false,
            }],
        };
        let result = parse_pyproject(&path, &project);
        assert_eq!(result.project_name.as_deref(), Some("demo"));
        assert!(
            result
                .dependencies
                .iter()
                .any(|d| d.canonical_name == "numpy"
                    && d.resolved_version.as_deref() == Some("2.2.6"))
        );
        assert!(result
            .dependencies
            .iter()
            .any(|d| { d.canonical_name == "pytest" && d.scopes.contains(&PythonScope::Dev) }));

        let _ = fs::remove_dir_all(root);
    }
}
