use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::path::PathBuf;
use std::process::Command;

use anyhow::Context;
use pep508_rs::{ExtraName, MarkerEnvironment, Requirement, VersionOrUrl};

use crate::analyze::producers::dynamic_producer::DynamicProducer;
use crate::analyze::producers::pypi::requirements::{
    parse_requirement, version_matches, ProjectRequirements,
};
use crate::model::configuration::Configuration;
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyLocation, DependencyType};
use crate::utils::cli_driver::CliLocator;
use crate::utils::file_utils::make_instance_id;

type PipInspectCell = std::sync::Arc<std::sync::OnceLock<Result<serde_json::Value, String>>>;

#[derive(Default)]
pub struct PypiDynamicProducer {
    inspect_cache: std::sync::Mutex<std::collections::HashMap<String, PipInspectCell>>,
}

impl DynamicProducer for PypiDynamicProducer {
    fn is_applicable(&self, config: &Configuration) -> bool {
        let dir = PathBuf::from(&config.directory);
        ["requirements.txt", "pyproject.toml", "Pipfile"]
            .iter()
            .any(|f| dir.join(f).exists())
            && CliLocator::resolve_python_for_dir(&dir).is_some()
    }

    fn detect_dependencies(&self, config: &Configuration) -> anyhow::Result<Vec<Dependency>> {
        let work_dir = PathBuf::from(&config.directory);
        let declared = ProjectRequirements::load(&work_dir)?;
        anyhow::ensure!(
            !declared.roots.is_empty(),
            "没有可确认的 Python 根依赖，回退静态解析"
        );
        let py_bin = CliLocator::resolve_python_for_dir(&work_dir)
            .ok_or_else(|| anyhow::anyhow!("当前宿主机未找到 Python 解释器"))?;
        let cell = {
            let mut guard = self.inspect_cache.lock().unwrap_or_else(|e| e.into_inner());
            guard
                .entry(py_bin.clone())
                .or_insert_with(|| std::sync::Arc::new(std::sync::OnceLock::new()))
                .clone()
        };
        let inspect_res = cell.get_or_init(|| {
            let mut cmd = Command::new(&py_bin);
            // Isolate from project PYTHONPATH/sitecustomize/pip.py while querying the selected interpreter.
            cmd.args(["-I", "-X", "utf8", "-m", "pip", "inspect"])
                .current_dir(&work_dir);
            let output = CliLocator::run_with_timeout(cmd, std::time::Duration::from_secs(15))
                .map_err(|e| format!("{e:#}"))?;
            if !output.status.success() {
                return Err(format!(
                    "pip inspect 执行失败: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            serde_json::from_slice(&output.stdout).map_err(|e| format!("{e:#}"))
        });
        let json = inspect_res
            .as_ref()
            .map_err(|msg| anyhow::anyhow!("{msg}"))?;
        let env: MarkerEnvironment = serde_json::from_value(
            json.get("environment")
                .context("pip inspect 缺少 environment")?
                .clone(),
        )?;
        let app_name = work_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("python-app");
        let manifest = ["pyproject.toml", "requirements.txt", "Pipfile"]
            .iter()
            .map(|name| work_dir.join(name))
            .find(|p| p.exists())
            .context("Python manifest missing")?;
        let salt = manifest.to_string_lossy().replace('\\', "/");
        let mut deps = Self::parse_inspect(
            json,
            app_name,
            &declared.roots,
            &declared.constraints,
            Some(&env),
            &salt,
        )?;
        for dep in &mut deps {
            dep.properties
                .insert("sbom:analysis:method".into(), "pip-inspect".into());
            if dep.r#type == DependencyType::Application {
                dep.properties.insert(
                    "sbom:python:environment".into(),
                    serde_json::to_string(&env)?,
                );
                dep.properties.insert(
                    "sbom:python:scope".into(),
                    "runtime-with-declared-extras".into(),
                );
            }
        }
        Ok(deps)
    }
}

impl PypiDynamicProducer {
    fn validate_source(req: &Requirement, item: &serde_json::Value) -> anyhow::Result<()> {
        if let Some(VersionOrUrl::Url(url)) = &req.version_or_url {
            let actual = item
                .get("direct_url")
                .and_then(|x| x.get("url"))
                .and_then(|x| x.as_str());
            let expected = url.to_string();
            anyhow::ensure!(
                !expected.starts_with("git+")
                    && !expected.contains('#')
                    && actual == Some(expected.as_str()),
                "无法确认 direct URL 来源: {}",
                req.name
            );
        }
        Ok(())
    }

    // Compatibility entry point used by callers that only have root package names.
    pub fn parse_pip_inspect_graph(
        json: &serde_json::Value,
        app_name: &str,
        declared_roots: &HashSet<String>,
        file_salt: &str,
    ) -> anyhow::Result<Vec<Dependency>> {
        let roots: Vec<_> = declared_roots
            .iter()
            .map(|r| parse_requirement(r))
            .collect::<Result<_, _>>()?;
        let env = json
            .get("environment")
            .map(|e| serde_json::from_value(e.clone()))
            .transpose()?;
        Self::parse_inspect(json, app_name, &roots, &[], env.as_ref(), file_salt)
    }

    fn parse_inspect(
        json: &serde_json::Value,
        app_name: &str,
        roots: &[Requirement],
        constraints: &[Requirement],
        env: Option<&MarkerEnvironment>,
        file_salt: &str,
    ) -> anyhow::Result<Vec<Dependency>> {
        let installed = json
            .get("installed")
            .and_then(|v| v.as_array())
            .context("pip inspect 缺少 installed")?;
        anyhow::ensure!(
            !roots.is_empty(),
            "没有项目根依赖，拒绝使用整个 Python 环境"
        );
        let mut packages = BTreeMap::new();
        for item in installed {
            let Some(meta) = item.get("metadata") else {
                continue;
            };
            let Some(name) = meta.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            let name = crate::analyze::producers::pypi::pypi_lock_producer::pep503_normalize(name);
            anyhow::ensure!(
                packages.insert(name.clone(), item).is_none(),
                "Python 环境有重复 distribution: {name}"
            );
        }
        let active = |req: &Requirement, extras: &[ExtraName]| {
            req.marker.evaluate_optional_environment(env, extras)
        };
        let mut enabled: BTreeMap<String, BTreeSet<ExtraName>> = BTreeMap::new();
        let mut queue = VecDeque::new();
        let mut root_names = BTreeSet::new();
        let mut edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let enable = |req: &Requirement,
                      enabled: &mut BTreeMap<String, BTreeSet<ExtraName>>,
                      queue: &mut VecDeque<String>|
         -> anyhow::Result<()> {
            let name = req.name.to_string();
            let item = packages
                .get(&name)
                .with_context(|| format!("Python 环境缺少 {name}，拒绝部分匹配"))?;
            let version = item["metadata"]["version"]
                .as_str()
                .context("installed version missing")?;
            anyhow::ensure!(
                version_matches(req, version)?,
                "Python 安装版本不满足约束: {req}，实际 {version}"
            );
            Self::validate_source(req, item)?;
            for constraint in constraints
                .iter()
                .filter(|c| c.name == req.name && active(c, &[]))
            {
                anyhow::ensure!(
                    version_matches(constraint, version)?,
                    "Python 安装版本不满足 constraints: {constraint}，实际 {version}"
                );
                Self::validate_source(constraint, item)?;
            }
            let is_new = !enabled.contains_key(&name);
            let extras = enabled.entry(name.clone()).or_default();
            let previous = extras.len();
            extras.extend(req.extras.iter().cloned());
            if is_new || extras.len() != previous {
                queue.push_back(name);
            }
            Ok(())
        };
        for req in roots {
            if active(req, &[]) {
                enable(req, &mut enabled, &mut queue)?;
                root_names.insert(req.name.to_string());
            }
        }
        while let Some(name) = queue.pop_front() {
            let extras: Vec<_> = enabled[&name].iter().cloned().collect();
            let meta = &packages[&name]["metadata"];
            for raw in meta
                .get("requires_dist")
                .and_then(|x| x.as_array())
                .into_iter()
                .flatten()
            {
                let req = parse_requirement(raw.as_str().context("invalid requires_dist entry")?)?;
                if !active(&req, &extras) {
                    continue;
                }
                enable(&req, &mut enabled, &mut queue)?;
                edges
                    .entry(name.clone())
                    .or_default()
                    .insert(req.name.to_string());
            }
        }
        let mut result = Vec::new();
        let mut ids = BTreeMap::new();
        for name in enabled.keys() {
            let item = packages[name];
            let version = item["metadata"]["version"]
                .as_str()
                .context("installed version missing")?;
            let purl =
                Dependency::auto_fix_and_validate_purl(&format!("pkg:pypi/{name}@{version}"));
            let id = make_instance_id(&purl, file_salt);
            ids.insert(name.clone(), id.clone());
            let mut properties = BTreeMap::from([(
                "sbom:python:extras".into(),
                serde_json::to_string(&enabled[name])?,
            )]);
            if let Some(source) = item.get("direct_url") {
                properties.insert("sbom:python:source".into(), source.to_string());
            }
            result.push(
                DependencyBuilder::default()
                    .name(name.clone())
                    .version(Some(version.to_string()))
                    .purl(purl)
                    .instance_id(id)
                    .location(Some(DependencyLocation::from_file(std::path::Path::new(
                        file_salt,
                    ))))
                    .properties(properties)
                    .build()
                    .map_err(|e| anyhow::anyhow!(e))?,
            );
        }
        for dep in &mut result {
            dep.dependencies = edges
                .get(&dep.name)
                .into_iter()
                .flatten()
                .filter(|name| *name != &dep.name)
                .map(|name| ids[name].clone())
                .collect();
        }
        let purl = Dependency::auto_fix_and_validate_purl(&format!(
            "pkg:pypi/{}",
            crate::analyze::producers::pypi::pypi_lock_producer::pep503_normalize(app_name)
        ));
        result.insert(
            0,
            DependencyBuilder::default()
                .name(app_name.to_string())
                .version(None)
                .r#type(DependencyType::Application)
                .purl(purl.clone())
                .instance_id(make_instance_id(&purl, file_salt))
                .dependencies(root_names.iter().map(|n| ids[n].clone()).collect())
                .build()
                .map_err(|e| anyhow::anyhow!(e))?,
        );
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn windows_environment() -> MarkerEnvironment {
        serde_json::from_value(serde_json::json!({
            "implementation_name": "cpython", "implementation_version": "3.12.1",
            "os_name": "nt", "platform_machine": "AMD64", "platform_python_implementation": "CPython",
            "platform_release": "11", "platform_system": "Windows", "platform_version": "11",
            "python_full_version": "3.12.1", "python_version": "3.12", "sys_platform": "win32"
        })).unwrap()
    }

    #[test]
    fn markers_extras_and_transitive_extra_propagation_use_inspected_environment() {
        let json = serde_json::json!({"installed": [
            {"metadata": {"name": "client", "version": "1.2", "requires_dist": [
                "transport[tls]>=2; extra == 'socks' and python_version >= '3.10'",
                "linux-only; sys_platform == 'linux'", "windows-only; os_name == 'nt'"
            ]}},
            {"metadata": {"name": "transport", "version": "2.1", "requires_dist": ["cert; extra == 'tls'", "client[socks]>=1"]}},
            {"metadata": {"name": "cert", "version": "3"}},
            {"metadata": {"name": "windows-only", "version": "1"}},
            {"metadata": {"name": "unrelated", "version": "9"}}
        ]});
        let roots = [
            parse_requirement("client[socks]>=1.2; sys_platform == 'win32'").unwrap(),
            parse_requirement("absent; sys_platform == 'linux'").unwrap(),
        ];
        let deps = PypiDynamicProducer::parse_inspect(
            &json,
            "app",
            &roots,
            &[],
            Some(&windows_environment()),
            "test",
        )
        .unwrap();
        assert_eq!(deps.len(), 5);
        assert!(deps.iter().any(|d| d.name == "cert"));
        assert!(!deps
            .iter()
            .any(|d| d.name == "unrelated" || d.name == "linux-only"));
    }

    #[test]
    fn installed_versions_constraints_and_active_transitives_are_validated() {
        let json = serde_json::json!({"installed": [{"metadata": {"name": "client", "version": "1!2.0rc1+cpu"}}]});
        for root in ["client>=2!1.0", "client!=1!2.0rc1+cpu"] {
            assert!(PypiDynamicProducer::parse_inspect(
                &json,
                "app",
                &[parse_requirement(root).unwrap()],
                &[],
                None,
                "test"
            )
            .is_err());
        }
        let root = [parse_requirement("client==1!2.0rc1").unwrap()];
        assert!(PypiDynamicProducer::parse_inspect(&json, "app", &root, &[], None, "test").is_ok());
        let constraints = [parse_requirement("client>=2!1.0").unwrap()];
        assert!(PypiDynamicProducer::parse_inspect(
            &json,
            "app",
            &root,
            &constraints,
            None,
            "test"
        )
        .is_err());
        let missing = serde_json::json!({"installed": [{"metadata": {"name": "client", "version": "1", "requires_dist": ["missing>=2"]}}]});
        assert!(PypiDynamicProducer::parse_inspect(
            &missing,
            "app",
            &[parse_requirement("client").unwrap()],
            &[],
            None,
            "test"
        )
        .is_err());
        assert!(PypiDynamicProducer::parse_inspect(&json, "app", &[], &[], None, "test").is_err());
    }

    #[test]
    fn test_pip_inspect_reachability_pruning() {
        let mock_inspect = serde_json::json!({
            "installed": [
                {
                    "metadata": {
                        "name": "requests",
                        "version": "2.31.0",
                        "requires_dist": [
                            "urllib3 (<3,>=1.21.1)",
                            "PySocks (!=1.5.7,>=1.5.6) ; extra == 'socks'"
                        ]
                    }
                },
                {
                    "metadata": {
                        "name": "urllib3",
                        "version": "2.0.7"
                    }
                },
                {
                    "metadata": {
                        "name": "PySocks",
                        "version": "1.7.1"
                    }
                },
                {
                    "metadata": {
                        "name": "unrelated-global-pkg",
                        "version": "9.9.9"
                    }
                }
            ]
        });

        let mut declared = HashSet::new();
        declared.insert("requests".to_string());

        let deps = PypiDynamicProducer::parse_pip_inspect_graph(
            &mock_inspect,
            "my-py-service",
            &declared,
            "test/py",
        )
        .unwrap();

        // 应仅保留: my-py-service (root) -> requests -> urllib3 (共3个)
        // unrelated-global-pkg 与未激活的 extra PySocks 均被精准剪枝剔除！
        assert_eq!(deps.len(), 3);
        assert!(deps.iter().any(|d| d.name == "requests"));
        assert!(deps.iter().any(|d| d.name == "urllib3"));
        assert!(!deps.iter().any(|d| d.name == "unrelated-global-pkg"));
        assert!(!deps.iter().any(|d| d.name == "PySocks"));
    }

    #[test]
    fn test_pip_inspect_rejects_partial_match() {
        let mock_inspect = serde_json::json!({
            "installed": [
                {
                    "metadata": {
                        "name": "package-a",
                        "version": "1.0.0"
                    }
                }
            ]
        });

        let mut declared = HashSet::new();
        declared.insert("package-a".to_string());
        declared.insert("package-b".to_string()); // package-b 缺失

        let res = PypiDynamicProducer::parse_pip_inspect_graph(
            &mock_inspect,
            "my-py-service",
            &declared,
            "test/py",
        );

        assert!(
            res.is_err(),
            "must reject partial match when package-b is missing"
        );
        let err_str = res.unwrap_err().to_string();
        assert!(err_str.contains("拒绝部分匹配"));
        assert!(err_str.contains("package-b"));
    }
}
