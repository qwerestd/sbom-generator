use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::{Path, PathBuf};

use anyhow::Result;
use walkdir::WalkDir;

fn should_skip_dir(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };

    matches!(
        name,
        ".git"
            | "node_modules"
            | "target"
            | "dist"
            | "build"
            | ".venv"
            | "venv"
            | "env"
            | ".virtualenv"
            | "site-packages"
            | "__pycache__"
            | ".pytest_cache"
            | ".mypy_cache"
            | ".ruff_cache"
            | ".tox"
            | ".nox"
            | ".eggs"
            | "pip-wheel-metadata"
            | "vendor"
            | "third_party"
            | ".m2"
            | ".gradle"
            | ".idea"
    ) || name.ends_with(".egg-info")
}

pub fn get_files(directory: &str) -> Result<Vec<PathBuf>> {
    let mut files_to_return: Vec<PathBuf> = vec![];

    let directories_to_walk: Vec<String> = vec![directory.to_string()];

    for directory_to_walk in directories_to_walk {
        for entry in WalkDir::new(directory_to_walk.as_str())
            .into_iter()
            .filter_entry(|e| !should_skip_dir(e.path()))
        {
            let dir_entry = entry?;
            let entry = dir_entry.path();

            // we only include if this is a file and not a symlink
            // we should NEVER follow symlink for security reason (an attacker could then
            // attempt to add a symlink outside the repo and read content outside of the
            // repo with a custom rule.
            let should_include = entry.is_file() && !entry.is_symlink();

            if should_include {
                files_to_return.push(entry.to_path_buf());
            }
        }

        for entry in WalkDir::new(directory_to_walk.as_str())
            .into_iter()
            .filter_entry(|e| should_visit_for_go_vendor_modules(e.path()))
        {
            let dir_entry = entry?;
            let entry = dir_entry.path();
            let is_go_vendor_manifest = entry.is_file()
                && !entry.is_symlink()
                && entry.file_name().and_then(|n| n.to_str()) == Some("modules.txt")
                && entry
                    .parent()
                    .and_then(|p| p.file_name())
                    .and_then(|n| n.to_str())
                    == Some("vendor");

            if is_go_vendor_manifest && !files_to_return.iter().any(|p| p == entry) {
                files_to_return.push(entry.to_path_buf());
            }
        }
    }
    Ok(files_to_return)
}

fn should_visit_for_go_vendor_modules(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return true;
    };

    if should_skip_dir(path) && name != "vendor" {
        return false;
    }

    if path
        .components()
        .any(|c| c.as_os_str().to_str().is_some_and(|part| part == "vendor"))
    {
        (path.is_dir()
            && (name == "vendor"
                || path
                    .parent()
                    .and_then(|p| p.file_name())
                    .and_then(|n| n.to_str())
                    == Some("vendor")))
            || (path.is_file()
                && name == "modules.txt"
                && path
                    .parent()
                    .and_then(|p| p.file_name())
                    .and_then(|n| n.to_str())
                    == Some("vendor"))
    } else {
        true
    }
}
pub fn make_instance_id(purl: &str, manifest_rel_path: &str) -> String {
    let mut hasher = DefaultHasher::new();
    purl.hash(&mut hasher);
    manifest_rel_path.hash(&mut hasher);

    format!("{}?package-id={:016x}", purl, hasher.finish())
}

/// 计算清单文件相对于 Git 仓库根目录的标准相对路径（兼容 Windows 路径反斜杠）
pub fn get_manifest_rel_path(workspace_root: &Path, manifest_path: &Path) -> String {
    manifest_path
        .strip_prefix(workspace_root)
        .unwrap_or(manifest_path)
        .to_string_lossy()
        .replace('\\', "/")
}
