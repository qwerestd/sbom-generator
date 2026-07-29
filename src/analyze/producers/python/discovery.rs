use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use crate::analyze::producers::python::model::{
    PythonMetadataKind, PythonMetadataSource, PythonProjectContext, PythonProjectRoot,
    PythonSourcePriority,
};

pub fn discover_python_projects(files: &[PathBuf]) -> Vec<PythonProjectRoot> {
    let mut roots: BTreeMap<PathBuf, PythonProjectRoot> = BTreeMap::new();

    for file in files {
        let Some(source) = metadata_source_for(file) else {
            continue;
        };
        let root_path = infer_root_path(file, &source.kind);
        let context = context_for_path(&root_path);

        roots
            .entry(root_path.clone())
            .or_insert_with(|| PythonProjectRoot {
                root_path: root_path.clone(),
                project_name: None,
                context,
                sources: Vec::new(),
            })
            .sources
            .push(source);
    }

    let mut projects: Vec<PythonProjectRoot> = roots.into_values().collect();
    for project in &mut projects {
        project.sources.sort_by(|a, b| {
            a.priority
                .cmp(&b.priority)
                .then_with(|| a.path.cmp(&b.path))
        });
    }
    projects
}

fn metadata_source_for(path: &Path) -> Option<PythonMetadataSource> {
    let file_name = path.file_name()?.to_str()?;
    let (kind, priority, is_lockfile) = match file_name {
        "uv.lock" => (
            PythonMetadataKind::UvLock,
            PythonSourcePriority::ResolvedLockfile,
            true,
        ),
        "pyproject.toml" => (
            PythonMetadataKind::PyprojectToml,
            PythonSourcePriority::DeclaredManifest,
            false,
        ),
        "poetry.lock" => (
            PythonMetadataKind::PoetryLock,
            PythonSourcePriority::ResolvedLockfile,
            true,
        ),
        "Pipfile.lock" => (
            PythonMetadataKind::PipfileLock,
            PythonSourcePriority::ResolvedLockfile,
            true,
        ),
        "setup.py" => (
            PythonMetadataKind::SetupPy,
            PythonSourcePriority::DeclaredManifest,
            false,
        ),
        "setup.cfg" => (
            PythonMetadataKind::SetupCfg,
            PythonSourcePriority::DeclaredManifest,
            false,
        ),
        "conda-lock.yml" | "conda-lock.yaml" => (
            PythonMetadataKind::CondaLock,
            PythonSourcePriority::ResolvedLockfile,
            true,
        ),
        name if is_requirements_file(name, path) => (
            PythonMetadataKind::RequirementsTxt,
            PythonSourcePriority::DeclaredManifest,
            false,
        ),
        _ => return None,
    };

    Some(PythonMetadataSource {
        kind,
        path: path.to_path_buf(),
        priority,
        is_lockfile,
    })
}

fn is_requirements_file(file_name: &str, path: &Path) -> bool {
    if file_name == "requirements.txt" {
        return true;
    }
    if file_name.starts_with("requirements-") && file_name.ends_with(".txt") {
        return true;
    }

    path.parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .is_some_and(|dir| dir == "requirements" && file_name.ends_with(".txt"))
}

fn infer_root_path(path: &Path, kind: &PythonMetadataKind) -> PathBuf {
    if *kind == PythonMetadataKind::RequirementsTxt
        && path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            == Some("requirements")
    {
        return path
            .parent()
            .and_then(|p| p.parent())
            .unwrap_or_else(|| path.parent().unwrap_or(path))
            .to_path_buf();
    }

    path.parent().unwrap_or(path).to_path_buf()
}

fn context_for_path(path: &Path) -> PythonProjectContext {
    let parts: Vec<String> = path
        .components()
        .filter_map(component_as_string)
        .map(|s| s.to_lowercase())
        .collect();

    if parts.iter().any(|p| p == "fixtures" || p == "fixture") {
        PythonProjectContext::Fixtures
    } else if parts.iter().any(|p| p == "examples" || p == "example") {
        PythonProjectContext::Examples
    } else if parts.iter().any(|p| p == "vendor" || p == "third_party") {
        PythonProjectContext::Vendor
    } else if parts.iter().any(|p| p == "tests" || p == "test") {
        PythonProjectContext::Tests
    } else {
        PythonProjectContext::Normal
    }
}

fn component_as_string(component: Component<'_>) -> Option<String> {
    match component {
        Component::Normal(value) => value.to_str().map(|s| s.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_multiple_roots() {
        let files = vec![
            PathBuf::from("repo/a/pyproject.toml"),
            PathBuf::from("repo/a/uv.lock"),
            PathBuf::from("repo/b/requirements.txt"),
            PathBuf::from("repo/c/requirements/base.txt"),
        ];

        let projects = discover_python_projects(&files);
        assert_eq!(projects.len(), 3);
        assert!(projects
            .iter()
            .any(|p| p.root_path == Path::new("repo/a") && p.sources.len() == 2));
        assert!(projects
            .iter()
            .any(|p| p.root_path == Path::new("repo/c") && p.sources.len() == 1));
    }
}
