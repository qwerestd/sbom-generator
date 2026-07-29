use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use lazy_static::lazy_static;
use regex::Regex;

use crate::analyze::producers::python::model::{
    ActivationStatus, DependencyRelationship, EvidenceConfidence, PythonDependency, PythonEvidence,
    PythonEvidenceKind, PythonMetadataKind, PythonProjectRoot, PythonScope, PythonScopeEvidence,
};
use crate::analyze::producers::python::normalize::canonicalize_name;

lazy_static! {
    static ref REQ_RE: Regex = Regex::new(
        r"(?i)^\s*([A-Z0-9][A-Z0-9_.\-]*)(?:\[[^\]]+\])?\s*(?:(==|===|~=|!=|>=|<=|>|<)\s*([A-Z0-9][A-Z0-9_.!\+\-]*))?"
    )
    .unwrap();
}

#[derive(Default)]
pub struct RequirementsParseResult {
    pub dependencies: Vec<PythonDependency>,
    pub warnings: Vec<String>,
}

pub fn parse_requirements_file(
    path: &Path,
    project: &PythonProjectRoot,
) -> RequirementsParseResult {
    let mut result = RequirementsParseResult::default();
    let mut visited = HashSet::new();
    let mut active = HashSet::new();
    parse_file(path, project, &mut visited, &mut active, &mut result);
    result
}

fn parse_file(
    path: &Path,
    project: &PythonProjectRoot,
    visited: &mut HashSet<PathBuf>,
    active: &mut HashSet<PathBuf>,
    result: &mut RequirementsParseResult,
) {
    let key = stable_path_key(path);
    if active.contains(&key) {
        result.warnings.push(format!(
            "requirements include cycle detected at {}",
            path.display()
        ));
        return;
    }
    if visited.contains(&key) {
        return;
    }

    active.insert(key.clone());
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) => {
            result.warnings.push(format!(
                "failed to read requirements file {}: {}",
                path.display(),
                err
            ));
            active.remove(&key);
            return;
        }
    };

    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    for raw_line in content.lines() {
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }

        if let Some(include) =
            include_target(line, "-r").or_else(|| include_target(line, "--requirement"))
        {
            let include_path = base_dir.join(include);
            result.dependencies.push(include_marker_dependency(
                path,
                &include_path,
                project,
                PythonEvidenceKind::RequirementsInclude,
            ));
            parse_file(&include_path, project, visited, active, result);
            continue;
        }

        if let Some(constraint) =
            include_target(line, "-c").or_else(|| include_target(line, "--constraint"))
        {
            let constraint_path = base_dir.join(constraint);
            result.dependencies.push(include_marker_dependency(
                path,
                &constraint_path,
                project,
                PythonEvidenceKind::RequirementsConstraint,
            ));
            parse_file(&constraint_path, project, visited, active, result);
            continue;
        }

        if line.starts_with('-') || line.starts_with('.') || line.starts_with('/') {
            result.warnings.push(format!(
                "unsupported requirements entry in {}: {}",
                path.display(),
                line
            ));
            continue;
        }

        if let Some(dep) = parse_requirement_line(line, path, project) {
            result.dependencies.push(dep);
        }
    }

    active.remove(&key);
    visited.insert(key);
}

fn parse_requirement_line(
    line: &str,
    source_path: &Path,
    project: &PythonProjectRoot,
) -> Option<PythonDependency> {
    let line_without_marker = line.split(';').next().unwrap_or(line).trim();
    let normalized_direct_ref = line_without_marker
        .split(" @ ")
        .next()
        .unwrap_or(line_without_marker);
    let captures = REQ_RE.captures(normalized_direct_ref)?;

    let raw_name = captures.get(1)?.as_str();
    let op = captures.get(2).map(|m| m.as_str());
    let raw_version = captures.get(3).map(|m| m.as_str());
    let canonical_name = canonicalize_name(raw_name);

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
    let scope = scope_from_filename(source_path);
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
        detail: Some(line.to_string()),
    }];

    if scope != PythonScope::Unknown {
        evidence.push(PythonEvidence {
            kind: PythonEvidenceKind::FilenameHeuristic,
            source_path: source_path.to_path_buf(),
            project_root: project.root_path.clone(),
            confidence: EvidenceConfidence::Medium,
            detail: Some(scope.as_str().to_string()),
        });
    }

    Some(PythonDependency {
        canonical_name: canonical_name.clone(),
        display_name: raw_name.to_string(),
        resolved_version,
        declared_version,
        scopes,
        source_kind: PythonMetadataKind::RequirementsTxt,
        project_root: project.root_path.clone(),
        source_path: source_path.to_path_buf(),
        is_project_package: false,
        is_editable: line.starts_with("-e "),
        is_local_path: line.contains(" @ file://"),
        relationship: DependencyRelationship::Direct,
        activation: ActivationStatus::Unconditional,
        markers: BTreeSet::new(),
        evidence,
        scope_evidence: vec![PythonScopeEvidence {
            scope,
            project_root: project.root_path.clone(),
            seed_package: canonical_name.clone(),
            source_path: source_path.to_path_buf(),
            source_kind: PythonMetadataKind::RequirementsTxt,
        }],
        dependencies: Vec::new(),
    })
}

fn include_marker_dependency(
    source_path: &Path,
    include_path: &Path,
    project: &PythonProjectRoot,
    kind: PythonEvidenceKind,
) -> PythonDependency {
    let mut scopes = BTreeSet::new();
    scopes.insert(PythonScope::Unknown);
    PythonDependency {
        canonical_name: format!("__requirements_include__{}", include_path.display()),
        display_name: include_path.display().to_string(),
        resolved_version: None,
        declared_version: None,
        scopes,
        source_kind: PythonMetadataKind::RequirementsTxt,
        project_root: project.root_path.clone(),
        source_path: source_path.to_path_buf(),
        is_project_package: false,
        is_editable: false,
        is_local_path: false,
        relationship: DependencyRelationship::Unknown,
        activation: ActivationStatus::Unknown,
        markers: BTreeSet::new(),
        evidence: vec![PythonEvidence {
            kind,
            source_path: source_path.to_path_buf(),
            project_root: project.root_path.clone(),
            confidence: EvidenceConfidence::Medium,
            detail: Some(include_path.display().to_string()),
        }],
        scope_evidence: Vec::new(),
        dependencies: Vec::new(),
    }
}

fn strip_comment(line: &str) -> &str {
    line.split('#').next().unwrap_or(line)
}

fn include_target<'a>(line: &'a str, flag: &str) -> Option<&'a str> {
    line.strip_prefix(flag)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn stable_path_key(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

pub fn scope_from_filename(path: &Path) -> PythonScope {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();

    if name.contains("prod") || name.contains("base") {
        PythonScope::Prod
    } else if name.contains("dev") {
        PythonScope::Dev
    } else if name.contains("test") {
        PythonScope::Test
    } else if name.contains("build") {
        PythonScope::Build
    } else {
        PythonScope::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::producers::python::model::{
        PythonMetadataKind, PythonMetadataSource, PythonProjectContext, PythonSourcePriority,
    };
    use std::fs;

    fn project(root: PathBuf) -> PythonProjectRoot {
        PythonProjectRoot {
            root_path: root,
            project_name: None,
            context: PythonProjectContext::Normal,
            sources: vec![PythonMetadataSource {
                kind: PythonMetadataKind::RequirementsTxt,
                path: PathBuf::new(),
                priority: PythonSourcePriority::DeclaredManifest,
                is_lockfile: false,
            }],
        }
    }

    #[test]
    fn parses_include_and_avoids_cycle() {
        let root =
            std::env::temp_dir().join(format!("sbom-generator-req-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("requirements")).unwrap();
        fs::write(
            root.join("requirements.txt"),
            "-r requirements/base.txt\nrequests>=2\n",
        )
        .unwrap();
        fs::write(
            root.join("requirements/base.txt"),
            "-r ../requirements.txt\nnumpy==2.2.6\n",
        )
        .unwrap();

        let result =
            parse_requirements_file(&root.join("requirements.txt"), &project(root.clone()));
        assert!(result.warnings.iter().any(|w| w.contains("cycle")));
        assert!(
            result
                .dependencies
                .iter()
                .any(|d| d.canonical_name == "numpy"
                    && d.resolved_version.as_deref() == Some("2.2.6"))
        );
        assert!(result.dependencies.iter().any(
            |d| d.canonical_name == "requests" && d.declared_version.as_deref() == Some(">=2")
        ));

        let _ = fs::remove_dir_all(root);
    }
}
