//! Read package metadata without importing code or extracting archives.
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyLocation};
use crate::utils::file_utils::{make_instance_id, ScanOptions};
use std::{
    io::Read,
    path::{Path, PathBuf},
};

fn component(
    name: &str,
    version: Option<&str>,
    ecosystem: &str,
    location: &str,
    method: &str,
) -> anyhow::Result<Dependency> {
    let raw = format!(
        "pkg:{ecosystem}/{name}{}",
        version.map(|v| format!("@{v}")).unwrap_or_default()
    );
    let purl = Dependency::auto_fix_and_validate_purl(&raw);
    let mut dep = DependencyBuilder::default()
        .name(name.into())
        .version(version.map(str::to_owned))
        .purl(purl.clone())
        .instance_id(make_instance_id(&purl, location))
        .location(Some(DependencyLocation::from_file(Path::new(location))))
        .build()
        .map_err(anyhow::Error::msg)?;
    if ecosystem == "maven" {
        if let Some((group, artifact)) = name.rsplit_once('/') {
            dep.group = Some(group.into());
            dep.name = artifact.into();
        }
    }
    dep.properties
        .insert("sbom:analysis:method".into(), method.into());
    dep.properties.insert(
        "sbom:evidence:kind".into(),
        if method == "installed-metadata" {
            "installed"
        } else {
            "artifact"
        }
        .into(),
    );
    Ok(dep)
}
fn python_metadata(text: &str, location: &str, method: &str) -> anyhow::Result<Vec<Dependency>> {
    let header = |key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(key))
            .map(str::trim)
    };
    let name = header("Name:").ok_or_else(|| anyhow::anyhow!("missing Python metadata Name"))?;
    let mut root = component(name, header("Version:"), "pypi", location, method)?;
    let mut result = Vec::new();
    let mut declared = Vec::new();
    for spec in text
        .lines()
        .filter_map(|l| l.strip_prefix("Requires-Dist:"))
        .map(str::trim)
    {
        declared.push(spec);
        use std::str::FromStr;
        let req: pep508_rs::Requirement = pep508_rs::Requirement::from_str(spec)?;
        let mut child = component(req.name.as_ref(), None, "pypi", location, method)?;
        child.instance_id = make_instance_id(&child.purl, &format!("{location}:{spec}"));
        child.version_requirement = Some(spec.to_owned());
        child
            .properties
            .insert("sbom:dependency:declaration".into(), spec.into());
        root.dependencies.push(child.instance_id.clone());
        result.push(child);
    }
    root.properties.insert(
        "sbom:dependency:declarations".into(),
        serde_json::to_string(&declared)?,
    );
    result.push(root);
    Ok(result)
}
pub fn collect(
    files: &[PathBuf],
    options: &ScanOptions,
) -> (Vec<Dependency>, Vec<serde_json::Value>) {
    let mut deps = Vec::new();
    let mut issues = Vec::new();
    for path in files {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let location = path.to_string_lossy();
        let installed = path.components().any(|c| {
            matches!(
                c.as_os_str().to_str(),
                Some("node_modules" | "site-packages" | ".venv" | "venv")
            )
        });
        let result: anyhow::Result<Vec<Dependency>> = (|| {
            if options.installed && installed && name == "package.json" {
                let j: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
                // Subpath package.json files often contain only a module type.
                let Some(n) = j["name"].as_str().filter(|n| !n.trim().is_empty()) else {
                    return Ok(Vec::new());
                };
                let mut dep = component(
                    n,
                    j["version"].as_str(),
                    "npm",
                    &location,
                    "installed-metadata",
                )?;
                let declarations: serde_json::Map<_, _> =
                    ["dependencies", "optionalDependencies", "peerDependencies"]
                        .iter()
                        .filter_map(|cat| j.get(*cat).map(|v| ((*cat).to_owned(), v.clone())))
                        .collect();
                dep.properties.insert(
                    "sbom:dependency:declarations".into(),
                    serde_json::to_string(&declarations)?,
                );
                return Ok(vec![dep]);
            }
            if options.installed && matches!(name, "METADATA" | "PKG-INFO") {
                return python_metadata(
                    &std::fs::read_to_string(path)?,
                    &location,
                    "installed-metadata",
                );
            }
            if options.artifacts
                && matches!(
                    path.extension().and_then(|s| s.to_str()),
                    Some("jar" | "war" | "ear" | "whl" | "zip")
                )
            {
                let mut archive = zip::ZipArchive::new(std::fs::File::open(path)?)?;
                anyhow::ensure!(
                    archive.len() <= 10000,
                    "archive has more than 10000 entries"
                );
                let mut found = Vec::new();
                for i in 0..archive.len() {
                    let mut entry = archive.by_index(i)?;
                    let n = entry.name().to_owned();
                    if n.ends_with(".jar") {
                        issues.push(serde_json::json!({"file":format!("{location}!/{n}"),"status":"nested-archive-not-recursed"}));
                    }
                    if !(n.ends_with("/pom.properties") || n.ends_with(".dist-info/METADATA")) {
                        continue;
                    }
                    anyhow::ensure!(
                        entry.size() <= 2 * 1024 * 1024,
                        "archive metadata exceeds 2 MiB: {n}"
                    );
                    let mut text = String::new();
                    entry
                        .by_ref()
                        .take(2 * 1024 * 1024 + 1)
                        .read_to_string(&mut text)?;
                    let inner = format!("{location}!/{n}");
                    if n.ends_with("METADATA") {
                        found.extend(python_metadata(&text, &inner, "artifact-metadata")?);
                    } else {
                        let values: std::collections::BTreeMap<_, _> = text
                            .lines()
                            .filter_map(|l| l.split_once('='))
                            .map(|(k, v)| (k.trim(), v.trim()))
                            .collect();
                        if let (Some(g), Some(a)) =
                            (values.get("groupId"), values.get("artifactId"))
                        {
                            found.push(component(
                                &format!("{g}/{a}"),
                                values.get("version").copied(),
                                "maven",
                                &inner,
                                "artifact-metadata",
                            )?);
                        }
                    }
                }
                if found.is_empty() {
                    issues.push(serde_json::json!({"file":path,"status":"archive-no-supported-package-metadata"}));
                }
                return Ok(found);
            }
            Ok(Vec::new())
        })();
        match result {
            Ok(found) => deps.extend(found),
            Err(e) => issues.push(serde_json::json!({"file":path,"error":format!("{e:#}")})),
        }
    }
    connect_installations(&mut deps);
    (deps, issues)
}

fn connect_installations(deps: &mut Vec<Dependency>) {
    use std::collections::{BTreeMap, BTreeSet};
    let installed_paths: BTreeMap<_, _> = deps
        .iter()
        .filter(|d| d.purl.starts_with("pkg:npm/") && d.version.is_some())
        .filter_map(|d| {
            Some((
                std::fs::canonicalize(&d.location.as_ref()?.block.file).ok()?,
                d.instance_id.clone(),
            ))
        })
        .collect();
    let count = deps.len();
    for i in 0..count {
        if !deps[i].purl.starts_with("pkg:npm/")
            || deps[i]
                .properties
                .get("sbom:evidence:kind")
                .is_none_or(|v| v != "installed")
        {
            continue;
        }
        let Some(location) = deps[i].location.as_ref().map(|l| l.block.file.clone()) else {
            continue;
        };
        let declarations: serde_json::Value = deps[i]
            .properties
            .get("sbom:dependency:declarations")
            .and_then(|v| serde_json::from_str(v).ok())
            .unwrap_or_default();
        for scope in ["dependencies", "optionalDependencies", "peerDependencies"] {
            if let Some(map) = declarations[scope].as_object() {
                for (name, raw) in map {
                    let target = Path::new(&location)
                        .parent()
                        .into_iter()
                        .flat_map(|p| p.ancestors())
                        .find_map(|dir| {
                            std::fs::canonicalize(
                                dir.join("node_modules").join(name).join("package.json"),
                            )
                            .ok()
                            .and_then(|p| installed_paths.get(&p).cloned())
                        });
                    let id = if let Some(id) = target {
                        id
                    } else {
                        let Ok(mut d) =
                            component(name, None, "npm", &location, "installed-metadata")
                        else {
                            continue;
                        };
                        d.version_requirement = raw.as_str().map(str::to_owned);
                        d.properties
                            .insert(format!("sbom:scope:{scope}"), "true".into());
                        let id = d.instance_id.clone();
                        deps.push(d);
                        id
                    };
                    deps[i].dependencies.push(id);
                }
            }
        }
    }
    fn environment(d: &Dependency) -> Option<PathBuf> {
        let file = Path::new(&d.location.as_ref()?.block.file);
        file.ancestors()
            .find(|p| {
                p.file_name()
                    .is_some_and(|n| n == "site-packages" || n == "dist-packages")
            })
            .and_then(|p| std::fs::canonicalize(p).ok())
    }
    let mut aliases = BTreeMap::new();
    let mut remove = BTreeSet::new();
    for (i, d) in deps.iter().enumerate() {
        if !d.purl.starts_with("pkg:pypi/") || d.version.is_some() {
            continue;
        }
        let Some(env) = environment(d) else { continue };
        let Some(raw) = &d.version_requirement else {
            continue;
        };
        use std::str::FromStr;
        let Ok(req): Result<pep508_rs::Requirement, _> = pep508_rs::Requirement::from_str(raw)
        else {
            continue;
        };
        if matches!(req.version_or_url, Some(pep508_rs::VersionOrUrl::Url(_))) {
            continue;
        }
        let matching: Vec<_> = deps
            .iter()
            .filter(|candidate| {
                candidate.version.is_some()
                    && candidate.purl.split('@').next() == d.purl.split('@').next()
                    && environment(candidate).as_ref() == Some(&env)
                    && crate::analyze::producers::pypi::requirements::version_matches(
                        &req,
                        candidate.version.as_deref().unwrap(),
                    )
                    .unwrap_or(false)
            })
            .collect();
        if let [target] = matching.as_slice() {
            aliases.insert(d.instance_id.clone(), target.instance_id.clone());
            remove.insert(i);
        }
    }
    for d in deps.iter_mut() {
        for child in &mut d.dependencies {
            if let Some(id) = aliases.get(child) {
                *child = id.clone();
            }
        }
        d.dependencies.sort();
        d.dependencies.dedup();
    }
    let mut index = 0;
    deps.retain(|_| {
        let keep = !remove.contains(&index);
        index += 1;
        keep
    });
}
