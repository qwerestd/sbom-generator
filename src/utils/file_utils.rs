use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::{Path, PathBuf};

use anyhow::Result;
use walkdir::{DirEntry, WalkDir};

/// 需要跳过的构建产物、缓存与版本控制目录，避免无意义的深层遍历与误扫
const IGNORED_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    ".gradle",
    ".vendor",
    ".venv",
    "venv",
    "node_modules",
    "target",
    "dist",
    "build",
    "__pycache__",
    "bower_components",
];

fn is_ignored_dir(entry: &DirEntry, root: &Path) -> bool {
    if entry.path() == root {
        return false;
    }
    if entry.file_type().is_dir() {
        if let Some(name) = entry.file_name().to_str() {
            return IGNORED_DIRS
                .iter()
                .any(|ignored| name.eq_ignore_ascii_case(ignored));
        }
    }
    false
}

pub fn get_files(directory: &str) -> Result<Vec<PathBuf>> {
    let root_path = Path::new(directory);
    if !root_path.exists() {
        anyhow::bail!("directory does not exist: {}", directory);
    }

    let mut files_to_return: Vec<PathBuf> = vec![];

    let walker = WalkDir::new(root_path)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !is_ignored_dir(e, root_path));

    for entry in walker {
        let dir_entry = entry?;
        let path = dir_entry.path();

        // we only include if this is a file and not a symlink
        // we should NEVER follow symlink for security reason (an attacker could then
        // attempt to add a symlink outside the repo and read content outside of the
        // repo with a custom rule.
        if dir_entry.file_type().is_file() && !path.is_symlink() {
            files_to_return.push(path.to_path_buf());
        }
    }
    Ok(files_to_return)
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
