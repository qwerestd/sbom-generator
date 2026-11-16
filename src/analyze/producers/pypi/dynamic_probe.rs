use super::{
    Dependency, DependencyType, MarkerEnvironment, ProjectRequirements, PypiDynamicProducer,
};
use crate::utils::cli_driver::CliLocator;
use anyhow::Context;
use std::{io::Write, path::Path, process::Command, time::Duration};

struct Constraints(std::path::PathBuf);
impl Drop for Constraints {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn timeout(name: &str, default: u64) -> Duration {
    Duration::from_secs(
        std::env::var(name)
            .ok()
            .and_then(|s| s.parse().ok())
            .filter(|v| *v > 0)
            .unwrap_or(default),
    )
}

impl PypiDynamicProducer {
    fn query_json(
        &self,
        key: String,
        command: Command,
        budget: Duration,
    ) -> anyhow::Result<serde_json::Value> {
        let cell = self
            .inspect_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key)
            .or_insert_with(|| std::sync::Arc::new(std::sync::OnceLock::new()))
            .clone();
        cell.get_or_init(|| {
            let output =
                CliLocator::run_with_timeout(command, budget).map_err(|e| format!("{e:#}"))?;
            if !output.status.success() {
                return Err(String::from_utf8_lossy(&output.stderr)
                    .chars()
                    .take(4000)
                    .collect());
            }
            serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())
        })
        .as_ref()
        .cloned()
        .map_err(|e| anyhow::anyhow!("{e}"))
    }

    fn resolve_requirements(
        &self,
        python: &str,
        directory: &Path,
        declared: &ProjectRequirements,
    ) -> anyhow::Result<serde_json::Value> {
        anyhow::ensure!(
            declared
                .roots
                .iter()
                .chain(&declared.constraints)
                .all(|r| !matches!(r.version_or_url, Some(pep508_rs::VersionOrUrl::Url(_)))),
            "Automatic wheel resolution does not execute local/VCS/source dependencies"
        );
        let roots: Vec<_> = declared.roots.iter().map(ToString::to_string).collect();
        let constraints: Vec<_> = declared
            .constraints
            .iter()
            .map(ToString::to_string)
            .collect();
        let key = serde_json::to_string(&("resolve", python, &roots, &constraints))?;
        let mut command = Command::new(python);
        command.current_dir(directory).args([
            "-I",
            "-X",
            "utf8",
            "-m",
            "pip",
            "install",
            "--dry-run",
            "--ignore-installed",
            "--only-binary=:all:",
            "--report",
            "-",
            "--quiet",
            "--disable-pip-version-check",
            "--no-input",
            "--retries",
            "1",
            "--timeout",
            "15",
        ]);
        let mut guard = None;
        if !constraints.is_empty() {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "sbom-python-constraints-{}-{}.txt",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?;
            let cleanup = Constraints(path);
            file.write_all(constraints.join("\n").as_bytes())?;
            drop(file);
            command.arg("--constraint").arg(&cleanup.0);
            guard = Some(cleanup);
        }
        command.args(roots);
        let report = self.query_json(key, command, timeout("SBOM_PYTHON_RESOLVE_TIMEOUT", 120))?;
        drop(guard);
        let installs = report
            .get("install")
            .and_then(|v| v.as_array())
            .context("pip resolution report has no install list")?;
        anyhow::ensure!(
            !installs.is_empty(),
            "pip selected no packages for the declared roots"
        );
        Ok(serde_json::json!({"installed": installs, "environment": report.get("environment")}))
    }

    pub(super) fn probe_project(
        &self,
        python: &str,
        directory: &Path,
        declared: &ProjectRequirements,
        app: &str,
        salt: &str,
    ) -> anyhow::Result<Vec<Dependency>> {
        let mut command = Command::new(python);
        command
            .current_dir(directory)
            .args(["-I", "-X", "utf8", "-m", "pip", "inspect"]);
        let inspected = self.query_json(
            format!("inspect:{python}"),
            command,
            timeout("SBOM_PYTHON_TIMEOUT", 30),
        );
        let mut problems = Vec::new();
        let mut partial = None;
        if let Ok(json) = &inspected {
            match Self::parse_evidence(json, declared, app, salt, false) {
                Ok(mut deps) => {
                    Self::label_evidence(&mut deps, json, python, "pip-inspect", true)?;
                    return Ok(deps);
                }
                Err(e) => problems.push(format!("Installed environment: {e:#}")),
            }
            partial = Self::parse_evidence(json, declared, app, salt, true).ok();
        } else if let Err(e) = &inspected {
            problems.push(format!("pip inspect: {e:#}"));
        }
        let resolution_disabled = std::env::var("SBOM_PYTHON_RESOLVE")
            .is_ok_and(|v| v == "0" || v.eq_ignore_ascii_case("false"));
        if !resolution_disabled {
            match self.resolve_requirements(python, directory, declared) {
                Ok(json) => match Self::parse_evidence(&json, declared, app, salt, false) {
                    Ok(mut deps) => {
                        Self::label_evidence(
                            &mut deps,
                            &json,
                            python,
                            "pip-resolve-report",
                            false,
                        )?;
                        deps[0].properties.insert(
                            "sbom:python:inspection-notes".into(),
                            serde_json::to_string(&problems)?,
                        );
                        return Ok(deps);
                    }
                    Err(e) => problems.push(format!("Resolved graph: {e:#}")),
                },
                Err(e) => problems.push(format!("Wheel-only resolution: {e:#}")),
            }
        }
        if let Some(mut deps) = partial {
            Self::label_evidence(
                &mut deps,
                inspected.as_ref().unwrap(),
                python,
                "pip-inspect",
                true,
            )?;
            deps[0].properties.insert(
                "sbom:python:probe-notes".into(),
                serde_json::to_string(&problems)?,
            );
            return Ok(deps);
        }
        anyhow::bail!("{}", problems.join("; "))
    }

    fn parse_evidence(
        json: &serde_json::Value,
        declared: &ProjectRequirements,
        app: &str,
        salt: &str,
        partial: bool,
    ) -> anyhow::Result<Vec<Dependency>> {
        let environment: MarkerEnvironment = serde_json::from_value(
            json.get("environment")
                .context("Python report missing environment")?
                .clone(),
        )?;
        Self::parse_inspect_policy(
            json,
            app,
            &declared.roots,
            &declared.constraints,
            Some(&environment),
            salt,
            partial,
        )
    }

    fn label_evidence(
        deps: &mut [Dependency],
        json: &serde_json::Value,
        python: &str,
        method: &str,
        installed: bool,
    ) -> anyhow::Result<()> {
        for dep in deps {
            dep.properties
                .insert("sbom:analysis:method".into(), method.into());
            dep.properties.insert(
                "sbom:python:installed-evidence".into(),
                installed.to_string(),
            );
            dep.properties
                .insert("sbom:python:interpreter".into(), python.into());
            if dep.r#type == DependencyType::Application {
                dep.properties.insert(
                    "sbom:python:environment".into(),
                    serde_json::to_string(&json["environment"])?,
                );
                dep.properties.insert(
                    "sbom:python:scope".into(),
                    "declared-roots-and-active-extras".into(),
                );
            }
        }
        Ok(())
    }
}
