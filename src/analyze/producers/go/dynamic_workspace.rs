use super::{GoDynamicProducer, ModuleSelection};
use crate::utils::cli_driver::CliLocator;
use anyhow::Context;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, OnceLock},
    time::Duration,
};

pub(super) struct WorkspaceContext {
    pub original: Option<PathBuf>,
    pub effective: Option<PathBuf>,
    pub members: Vec<PathBuf>,
    pub missing: Vec<PathBuf>,
    temporary: bool,
}
impl Drop for WorkspaceContext {
    fn drop(&mut self) {
        if self.temporary {
            if let Some(p) = &self.effective {
                let _ = std::fs::remove_file(p);
                let _ = std::fs::remove_file(PathBuf::from(format!("{}.sum", p.display())));
            }
        }
    }
}
impl WorkspaceContext {
    pub fn command(&self, go: &str, dir: &Path) -> Command {
        let mut cmd = Command::new(go);
        cmd.current_dir(dir);
        cmd.env(
            "GOWORK",
            self.effective.as_deref().unwrap_or(Path::new("off")),
        );
        cmd
    }
    pub fn active_for(&self, dir: &Path) -> bool {
        let actual = std::fs::canonicalize(dir).ok();
        actual.is_some_and(|d| {
            self.members
                .iter()
                .any(|p| std::fs::canonicalize(p).ok().as_ref() == Some(&d))
        })
    }
    pub fn disabled() -> Self {
        Self {
            original: None,
            effective: None,
            members: Vec::new(),
            missing: Vec::new(),
            temporary: false,
        }
    }
}

pub(super) struct ModuleEvidence {
    pub graph: Result<String, String>,
    pub selections: Result<HashMap<String, ModuleSelection>, String>,
}

impl GoDynamicProducer {
    pub(super) fn workspace(
        &self,
        dir: &Path,
        go: &str,
    ) -> anyhow::Result<Arc<OnceLock<Result<WorkspaceContext, String>>>> {
        let setting = std::env::var("SBOM_GO_WORKSPACE")
            .ok()
            .or_else(|| std::env::var("GOWORK").ok());
        let file = match setting.as_deref() {
            Some("off") => None,
            Some(p) if !p.is_empty() && p != "auto" => Some(PathBuf::from(p)),
            _ => dir
                .ancestors()
                .map(|p| p.join("go.work"))
                .find(|p| p.is_file()),
        };
        let key = file.clone().unwrap_or_default();
        let cell = self
            .workspaces
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key)
            .or_insert_with(|| Arc::new(OnceLock::new()))
            .clone();
        cell.get_or_init(|| match file {
            Some(file) => Self::read_workspace(&file, go).map_err(|e| format!("{e:#}")),
            None => Ok(WorkspaceContext::disabled()),
        });
        Ok(cell)
    }

    fn read_workspace(file: &Path, go: &str) -> anyhow::Result<WorkspaceContext> {
        let file = std::fs::canonicalize(file)?;
        let base = file.parent().context("Workspace has no parent")?;
        let mut command = Command::new(go);
        command
            .current_dir(base)
            .env("GOWORK", "off")
            .args(["work", "edit", "-json"])
            .arg(&file);
        let output = CliLocator::run_with_timeout(command, Duration::from_secs(15))?;
        anyhow::ensure!(
            output.status.success(),
            "go work edit: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let json: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        Self::workspace_from_json(&file, &json)
    }

    pub(super) fn workspace_from_json(
        file: &Path,
        json: &serde_json::Value,
    ) -> anyhow::Result<WorkspaceContext> {
        let base = file.parent().context("Workspace has no parent")?;
        let mut members = Vec::new();
        let mut missing = Vec::new();
        for item in json["Use"]
            .as_array()
            .context("Workspace has no use entries")?
        {
            let path = PathBuf::from(
                item["DiskPath"]
                    .as_str()
                    .context("Missing workspace member path")?,
            );
            let path = if path.is_absolute() {
                path
            } else {
                base.join(path)
            };
            if path.join("go.mod").is_file() {
                members.push(path)
            } else {
                missing.push(path)
            }
        }
        anyhow::ensure!(
            !members.is_empty(),
            "Workspace has no available member manifests"
        );
        let mut local = std::collections::BTreeMap::new();
        let mut required = std::collections::BTreeSet::new();
        for member in &members {
            let content = std::fs::read_to_string(member.join("go.mod"))?;
            let (name, requirements) = super::GoProducer::module_declarations(&content);
            if let Some(name) = name {
                local.insert(name, member.clone());
            }
            required.extend(requirements);
        }
        let additions: Vec<_> = required
            .into_iter()
            .filter(|(name, version)| local.contains_key(name) && !version.is_empty())
            .filter(|(name, version)| {
                !json["Replace"].as_array().into_iter().flatten().any(|r| {
                    r["Old"]["Path"].as_str() == Some(name.as_str())
                        && r["Old"]["Version"]
                            .as_str()
                            .is_none_or(|v| v.is_empty() || v == version)
                })
            })
            .collect();
        if missing.is_empty() && additions.is_empty() {
            return Ok(WorkspaceContext {
                original: Some(file.into()),
                effective: Some(file.into()),
                members,
                missing,
                temporary: false,
            });
        }
        // A temporary absolute-path workspace permits available members to be
        // queried without editing the user's file or inventing missing modules.
        let mut text = format!(
            "go {}\n",
            json["Go"]
                .as_str()
                .context("Missing workspace Go version")?
        );
        if let Some(toolchain) = json["Toolchain"].as_str().filter(|s| !s.is_empty()) {
            text.push_str(&format!("toolchain {toolchain}\n"));
        }
        text.push_str("use (\n");
        for member in &members {
            text.push_str(&format!(
                " {}\n",
                serde_json::to_string(&member.to_string_lossy())?
            ));
        }
        text.push_str(")\n");
        if let Some(replacements) = json["Replace"].as_array() {
            for item in replacements {
                let old = item["Old"]["Path"]
                    .as_str()
                    .context("Invalid workspace replacement")?;
                let old_version = item["Old"]["Version"].as_str().unwrap_or("");
                let new = item["New"]["Path"]
                    .as_str()
                    .context("Invalid workspace replacement target")?;
                let new_version = item["New"]["Version"].as_str().unwrap_or("");
                let new = if new_version.is_empty() {
                    let p = PathBuf::from(new);
                    if p.is_absolute() { p } else { base.join(p) }
                        .to_string_lossy()
                        .into_owned()
                } else {
                    new.to_string()
                };
                text.push_str(&format!(
                    "replace {} {old_version} => {} {new_version}\n",
                    serde_json::to_string(old)?,
                    serde_json::to_string(&new)?
                ));
            }
        }
        // Version-specific local replacements avoid fetching unpublished
        // placeholder versions of known workspace main modules. Unversioned
        // replacements would conflict with go.work main modules.
        for (name, version) in additions {
            text.push_str(&format!(
                "replace {} {version} => {}\n",
                serde_json::to_string(&name)?,
                serde_json::to_string(&local[&name].to_string_lossy())?
            ));
        }
        if let Some(debug) = json["Godebug"].as_array() {
            for item in debug {
                if let (Some(key), Some(value)) = (item["Key"].as_str(), item["Value"].as_str()) {
                    text.push_str(&format!("godebug {key}={value}\n"));
                }
            }
        }
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "sbom-go-{}-{}.work",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        use std::io::Write;
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        output.write_all(text.as_bytes())?;
        Ok(WorkspaceContext {
            original: Some(file.into()),
            effective: Some(path),
            members,
            missing,
            temporary: true,
        })
    }

    pub(super) fn modules(
        &self,
        workspace: &WorkspaceContext,
        go: &str,
        dir: &Path,
        budget: u64,
    ) -> Arc<OnceLock<ModuleEvidence>> {
        let key = format!(
            "{}:{}:{budget}",
            go,
            workspace.effective.as_deref().unwrap_or(dir).display()
        );
        let cell = self
            .module_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key)
            .or_insert_with(|| Arc::new(OnceLock::new()))
            .clone();
        cell.get_or_init(|| {
            std::thread::scope(|s| {
                let graph = s.spawn(|| {
                    let mut cmd = workspace.command(go, dir);
                    cmd.args(["mod", "graph"]);
                    let output = CliLocator::run_with_timeout(cmd, Duration::from_secs(budget))
                        .map_err(|e| format!("{e:#}"))?;
                    if output.status.success() {
                        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
                    } else {
                        Err(String::from_utf8_lossy(&output.stderr).into_owned())
                    }
                });
                let list = s.spawn(|| {
                    let mut cmd = workspace.command(go, dir);
                    cmd.args(["list", "-mod=readonly", "-m", "-json", "all"]);
                    let output = CliLocator::run_with_timeout(cmd, Duration::from_secs(budget))
                        .map_err(|e| format!("{e:#}"))?;
                    if output.status.success() {
                        Self::parse_module_json(&output.stdout).map_err(|e| format!("{e:#}"))
                    } else {
                        Err(String::from_utf8_lossy(&output.stderr).into_owned())
                    }
                });
                ModuleEvidence {
                    graph: graph.join().unwrap(),
                    selections: list.join().unwrap(),
                }
            })
        });
        cell
    }
}
