use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::{Path, PathBuf};

use anyhow::Result;
use walkdir::WalkDir;

pub fn get_files(directory: &str) -> Result<Vec<PathBuf>> {
    let mut files_to_return: Vec<PathBuf> = vec![];

    // This is the directory that contains the .git files, we do not need to keep them.
    let git_directory = format!("{}/.git", &directory);

    let directories_to_walk: Vec<String> = vec![directory.to_string()];

    for directory_to_walk in directories_to_walk {
        for entry in WalkDir::new(directory_to_walk.as_str()) {
            let dir_entry = entry?;
            let entry = dir_entry.path();

            // we only include if this is a file and not a symlink
            // we should NEVER follow symlink for security reason (an attacker could then
            // attempt to add a symlink outside the repo and read content outside of the
            // repo with a custom rule.
            let mut should_include = entry.is_file() && !entry.is_symlink();

            // do not include the git directory.
            if entry.starts_with(git_directory.as_str()) {
                should_include = false;
            }

            if should_include {
                files_to_return.push(entry.to_path_buf());
            }
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
