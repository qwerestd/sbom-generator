use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::{env, fs};

/// 推广自 Maven `MavenCliDriver` 的通用跨生态 CLI 探测器与多级缓存引擎。
/// 统一赋能 Maven (`mvn`), Gradle (`gradle`), Go (`go`), Cargo (`cargo`), NPM (`npm`), Python (`python`)：
/// 1. 阶段零：优先识别项目本地 Wrapper 或本地虚拟环境（如 `./mvnw`, `./gradlew`, `.venv/Scripts/python.exe`）
/// 2. 阶段一：进程级内存缓存 (`OnceLock`)，避免重复进程探测开销
/// 3. 阶段二：系统 `PATH` 与生态专属环境变量（`MAVEN_HOME`, `GRADLE_HOME`, `GOROOT`, `CARGO_HOME`, `VIRTUAL_ENV`, `CONDA_PREFIX`）
/// 4. 阶段三：持久化磁盘缓存（`~/.sbom_cli_cache.json`）与存在性安全校验
/// 5. 阶段四：常见 IDE（IntelliJ IDEA / RustRover / GoLand / PyCharm）与标准安装路径毫秒级浅层嗅探
pub struct CliLocator;

static MEMORY_CLI_CACHE: OnceLock<Mutex<HashMap<String, Option<String>>>> = OnceLock::new();

impl CliLocator {
    fn get_cache_map() -> &'static Mutex<HashMap<String, Option<String>>> {
        MEMORY_CLI_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
    }

    fn get_disk_cache_path() -> PathBuf {
        let home_dir = env::var("USERPROFILE")
            .or_else(|_| env::var("HOME"))
            .unwrap_or_else(|_| r"C:\".to_string());
        PathBuf::from(home_dir).join(".sbom_cli_cache.json")
    }

    fn read_disk_cache(tool_key: &str) -> Option<String> {
        let path = Self::get_disk_cache_path();
        let content = fs::read_to_string(path).ok()?;
        let map: HashMap<String, String> = serde_json::from_str(&content).ok()?;
        let cached = map.get(tool_key)?;
        if Path::new(cached).exists() {
            Some(cached.clone())
        } else {
            None
        }
    }

    fn write_disk_cache(tool_key: &str, resolved_path: &str) {
        let path = Self::get_disk_cache_path();
        let mut map: HashMap<String, String> = fs::read_to_string(&path)
            .ok()
            .and_then(|c| serde_json::from_str(&c).ok())
            .unwrap_or_default();
        map.insert(tool_key.to_string(), resolved_path.to_string());
        if let Ok(json_str) = serde_json::to_string_pretty(&map) {
            let _ = fs::write(path, json_str);
        }
    }

    /// 探测项目目录内的本地虚拟环境 Python 解释器（避免误扫全局 Python 环境）
    pub fn resolve_python_for_dir(project_dir: &Path) -> Option<String> {
        // 1. 优先检查项目目录下的本地虚拟环境 (.venv, venv, env, .env)
        let venv_names = [".venv", "venv", "env", ".env"];
        for vname in venv_names {
            let venv_dir = project_dir.join(vname);
            let candidate = if cfg!(target_os = "windows") {
                venv_dir.join("Scripts").join("python.exe")
            } else {
                venv_dir.join("bin").join("python")
            };
            if candidate.exists() {
                return Some(candidate.to_string_lossy().to_string());
            }
        }

        // 2. 检查当前激活的 VIRTUAL_ENV 或 CONDA_PREFIX
        for env_key in ["VIRTUAL_ENV", "CONDA_PREFIX"] {
            if let Ok(venv_root) = env::var(env_key) {
                let root = PathBuf::from(venv_root);
                let candidate = if cfg!(target_os = "windows") {
                    root.join("Scripts").join("python.exe")
                } else {
                    root.join("bin").join("python")
                };
                if candidate.exists() {
                    return Some(candidate.to_string_lossy().to_string());
                }
            }
        }

        // 3. 回退到全局缓存的 Python 探测器
        Self::resolve_global_tool(
            "python",
            &["python3", "python"],
            &["--version"],
            &["PYTHONHOME"],
            &[],
        )
    }

    /// 探测项目目录内的 Maven（优先 `./mvnw` Wrapper，其次全局/IDEA 内置 Maven）
    pub fn resolve_maven_for_dir(project_dir: &Path) -> Option<String> {
        let wrapper = if cfg!(target_os = "windows") {
            project_dir.join("mvnw.cmd")
        } else {
            project_dir.join("mvnw")
        };
        if wrapper.exists() {
            return Some(wrapper.to_string_lossy().to_string());
        }

        Self::resolve_global_tool(
            "maven",
            if cfg!(target_os = "windows") {
                &["mvn.cmd", "mvn"]
            } else {
                &["mvn"]
            },
            &["-v"],
            &["MAVEN_HOME", "M2_HOME"],
            &[
                r"plugins\maven\lib\maven3\bin\mvn.cmd",
                r"plugins\maven-plugin\lib\maven3\bin\mvn.cmd",
                r"bin\mvn.cmd",
            ],
        )
    }

    /// 探测项目目录内的 Gradle（优先 `./gradlew` Wrapper，其次全局 Gradle）
    pub fn resolve_gradle_for_dir(project_dir: &Path) -> Option<String> {
        let wrapper = if cfg!(target_os = "windows") {
            project_dir.join("gradlew.bat")
        } else {
            project_dir.join("gradlew")
        };
        if wrapper.exists() {
            return Some(wrapper.to_string_lossy().to_string());
        }

        Self::resolve_global_tool(
            "gradle",
            if cfg!(target_os = "windows") {
                &["gradle.bat", "gradle"]
            } else {
                &["gradle"]
            },
            &["-v"],
            &["GRADLE_HOME"],
            &[r"bin\gradle.bat"],
        )
    }

    /// 探测 Go 工具链
    pub fn resolve_go() -> Option<String> {
        Self::resolve_global_tool(
            "go",
            if cfg!(target_os = "windows") {
                &["go.exe", "go"]
            } else {
                &["go"]
            },
            &["version"],
            &["GOROOT"],
            &[r"Go\bin\go.exe", r"bin\go.exe"],
        )
    }

    /// 探测通用全局 CLI 工具并缓存结果
    pub fn resolve_global_tool(
        tool_key: &str,
        bin_candidates: &[&str],
        version_args: &[&str],
        home_env_vars: &[&str],
        ide_rel_paths: &[&str],
    ) -> Option<String> {
        if let Ok(guard) = Self::get_cache_map().lock() {
            if let Some(cached) = guard.get(tool_key) {
                return cached.clone();
            }
        }

        let resolved = Self::probe_tool_uncached(
            tool_key,
            bin_candidates,
            version_args,
            home_env_vars,
            ide_rel_paths,
        );

        if let Ok(mut guard) = Self::get_cache_map().lock() {
            guard.insert(tool_key.to_string(), resolved.clone());
        }

        resolved
    }

    fn probe_tool_uncached(
        tool_key: &str,
        bin_candidates: &[&str],
        version_args: &[&str],
        home_env_vars: &[&str],
        ide_rel_paths: &[&str],
    ) -> Option<String> {
        // 1. 检查系统 PATH
        for &bin in bin_candidates {
            if let Ok(out) = Command::new(bin).args(version_args).output() {
                if out.status.success() {
                    return Some(bin.to_string());
                }
            }
        }

        // 2. 检查 *_HOME 环境变量
        for &env_key in home_env_vars {
            if let Ok(home_val) = env::var(env_key) {
                for &bin in bin_candidates {
                    let candidate = PathBuf::from(&home_val).join("bin").join(bin);
                    if candidate.exists() {
                        let s = candidate.to_string_lossy().to_string();
                        Self::write_disk_cache(tool_key, &s);
                        return Some(s);
                    }
                }
            }
        }

        // 3. 检查持久化磁盘缓存
        if let Some(disk_cached) = Self::read_disk_cache(tool_key) {
            return Some(disk_cached);
        }

        // 4. 快速定点嗅探 IDE 与常见安装目录
        if !ide_rel_paths.is_empty() {
            if let Some(found) = Self::scan_ide_and_common_dirs(ide_rel_paths) {
                Self::write_disk_cache(tool_key, &found);
                return Some(found);
            }
        }

        None
    }

    fn scan_ide_and_common_dirs(rel_paths: &[&str]) -> Option<String> {
        let local_app_data = env::var("LOCALAPPDATA").unwrap_or_default();
        let program_files =
            env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".to_string());

        let mut base_dirs = vec![
            PathBuf::from(&program_files).join("JetBrains"),
            PathBuf::from(&program_files).join("Go"),
            PathBuf::from(&local_app_data).join("Programs"),
            PathBuf::from(&local_app_data)
                .join("JetBrains")
                .join("Toolbox")
                .join("apps"),
        ];

        for root in [r"C:\", r"D:\", r"E:\"] {
            if let Ok(entries) = fs::read_dir(root) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        let name_lower = path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_lowercase();
                        if name_lower.contains("idea")
                            || name_lower.contains("jetbrains")
                            || name_lower.contains("maven")
                            || name_lower.contains("gradle")
                            || name_lower.contains("goland")
                        {
                            base_dirs.push(path);
                        }
                    }
                }
            }
        }

        for base_dir in base_dirs {
            if !base_dir.exists() {
                continue;
            }
            for rel in rel_paths {
                let direct_target = base_dir.join(rel);
                if direct_target.exists() {
                    return Some(direct_target.to_string_lossy().to_string());
                }
            }

            let mut queue = VecDeque::new();
            queue.push_back((base_dir, 0usize));

            while let Some((current_dir, depth)) = queue.pop_front() {
                if depth >= 3 {
                    continue;
                }
                if let Ok(entries) = fs::read_dir(&current_dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_dir() {
                            for rel in rel_paths {
                                let target = path.join(rel);
                                if target.exists() {
                                    return Some(target.to_string_lossy().to_string());
                                }
                            }
                            queue.push_back((path, depth + 1));
                        }
                    }
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_tool_cargo_and_memory_cache() {
        let path = CliLocator::resolve_global_tool(
            "cargo",
            &["cargo.exe", "cargo"],
            &["--version"],
            &["CARGO_HOME"],
            &[],
        );
        assert!(
            path.is_some(),
            "cargo should be discoverable in test environment"
        );

        // 再次获取，触发内存缓存分支
        let cached = CliLocator::resolve_global_tool(
            "cargo",
            &["cargo.exe", "cargo"],
            &["--version"],
            &["CARGO_HOME"],
            &[],
        );
        assert_eq!(path, cached);
    }

    #[test]
    fn test_resolve_wrapper_in_dir() {
        let temp_dir = env::temp_dir().join("sbom_test_wrapper");
        let _ = fs::create_dir_all(&temp_dir);

        let wrapper_name = if cfg!(target_os = "windows") {
            "mvnw.cmd"
        } else {
            "mvnw"
        };
        let wrapper_file = temp_dir.join(wrapper_name);
        let _ = fs::write(&wrapper_file, "echo mvn");

        let resolved = CliLocator::resolve_maven_for_dir(&temp_dir);
        assert!(resolved.is_some());
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_resolve_python_for_dir_and_disk_cache() {
        let temp_dir = env::temp_dir().join("sbom_test_py_venv");
        let venv_dir = temp_dir.join(".venv").join(if cfg!(target_os = "windows") {
            "Scripts"
        } else {
            "bin"
        });
        let _ = fs::create_dir_all(&venv_dir);

        let py_name = if cfg!(target_os = "windows") {
            "python.exe"
        } else {
            "python"
        };
        let py_file = venv_dir.join(py_name);
        let _ = fs::write(&py_file, "echo python");

        let resolved = CliLocator::resolve_python_for_dir(&temp_dir);
        assert!(resolved.is_some());
        assert!(resolved.unwrap().contains(".venv"));
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
