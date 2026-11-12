use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_yaml::Value;

use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyLocation, DependencyType};
use crate::utils::file_utils::make_instance_id;

pub struct PnpmLockProducer;

fn field<'a>(v: &'a Value, key: &str) -> &'a Value {
    v.get(key).unwrap_or(&Value::Null)
}

fn package_key(key: &str) -> Option<(String, String)> {
    let key = key.trim_start_matches('/').split('(').next()?;
    // v5 uses /name/version; v6+ uses /name@version or name@version.
    let at = key.rfind('@').filter(|i| *i > 0);
    let (name, version) = if let Some(i) = at {
        (&key[..i], &key[i + 1..])
    } else {
        let i = key.rfind('/')?;
        (&key[..i], &key[i + 1..])
    };
    let version = version.split('_').next()?;
    crate::utils::version_spec::manifest_version(Some(version), "npm").0?;
    Some((name.to_owned(), version.to_owned()))
}

impl SbomProducer for PnpmLockProducer {
    fn use_file(&self, path: &Path, _: &SbomProducerConfiguration) -> bool {
        path.file_name().is_some_and(|n| n == "pnpm-lock.yaml")
    }

    fn find_dependencies(
        &self,
        paths: &[PathBuf],
        _: &SbomProducerConfiguration,
    ) -> anyhow::Result<Vec<Dependency>> {
        let mut result = Vec::new();
        for path in paths {
            let content = std::fs::read_to_string(path)?;
            result.extend(parse(&content, path)?);
        }
        Ok(result)
    }
}

fn parse(content: &str, path: &Path) -> anyhow::Result<Vec<Dependency>> {
    let mut result = Vec::new();
    for document in serde_yaml::Deserializer::from_str(content.trim_start_matches('\u{FEFF}')) {
        let doc = Value::deserialize(document)?;
        result.extend(parse_document(doc, path)?);
    }
    anyhow::ensure!(!result.is_empty(), "pnpm lockfile has no supported entries");
    Ok(result)
}

fn parse_document(doc: Value, path: &Path) -> anyhow::Result<Vec<Dependency>> {
    anyhow::ensure!(
        field(&doc, "lockfileVersion") != &Value::Null,
        "missing pnpm lockfileVersion"
    );
    let salt = path.to_string_lossy().replace('\\', "/");
    let location = Some(DependencyLocation::from_file(path));
    let packages = field(&doc, "packages");
    let snapshots = field(&doc, "snapshots");
    let mut entries = snapshots.as_mapping().cloned().unwrap_or_default();
    let covered_packages: BTreeSet<_> = entries
        .keys()
        .filter_map(|k| k.as_str().and_then(package_key))
        .collect();
    let metadata_by_package: BTreeMap<_, _> = packages
        .as_mapping()
        .into_iter()
        .flat_map(|m| m.iter())
        .filter_map(|(k, v)| Some((k.as_str().and_then(package_key)?, v)))
        .collect();
    if let Some(metadata) = packages.as_mapping() {
        for (key, value) in metadata {
            let covered = key
                .as_str()
                .and_then(package_key)
                .is_some_and(|k| covered_packages.contains(&k));
            if !covered {
                entries.insert(key.clone(), value.clone());
            }
        }
    }
    let mut nodes = BTreeMap::new();
    let mut aliases = BTreeMap::new();
    let mut skipped = Vec::new();
    {
        for (key, data) in &entries {
            let Some(raw) = key.as_str() else { continue };
            let Some((name, version)) = package_key(raw) else {
                skipped.push(raw.to_owned());
                continue;
            };
            let purl = Dependency::auto_fix_and_validate_purl(&format!("pkg:npm/{name}@{version}"));
            let id = make_instance_id(&purl, &format!("{salt}:{raw}"));
            aliases.insert(raw.trim_start_matches('/').to_owned(), id.clone());
            nodes.insert(raw.to_owned(), (name, version, purl, id, data.clone()));
        }
    }
    let resolve = |name: &str, value: &Value| -> Option<String> {
        let value = value
            .as_str()
            .or_else(|| field(value, "version").as_str())?;
        if value.starts_with("link:") || value.starts_with("workspace:") {
            return None;
        }
        let raw = value.trim_start_matches('/');
        aliases
            .get(raw)
            .or_else(|| aliases.get(&format!("{name}@{raw}")))
            .or_else(|| aliases.get(&format!("{name}/{raw}")))
            .cloned()
    };
    let children = |data: &Value| -> Vec<String> {
        let mut ids = BTreeSet::new();
        for category in [
            "dependencies",
            "optionalDependencies",
            "devDependencies",
            "peerDependencies",
            "packageManagerDependencies",
        ] {
            if let Some(deps) = field(data, category).as_mapping() {
                for (name, value) in deps {
                    if let Some(id) = name.as_str().and_then(|n| resolve(n, value)) {
                        ids.insert(id);
                    }
                }
            }
        }
        ids.into_iter().collect()
    };
    let mut result = Vec::new();
    for (_, (name, version, purl, id, data)) in nodes {
        let mut dep = DependencyBuilder::default()
            .name(name)
            .version(Some(version))
            .purl(purl)
            .instance_id(id)
            .dependencies(children(&data))
            .location(location.clone())
            .build()
            .map_err(anyhow::Error::msg)?;
        let declared: Vec<_> = ["dependencies", "optionalDependencies", "peerDependencies"]
            .iter()
            .filter_map(|k| data.get(*k))
            .collect();
        dep.properties.insert(
            "sbom:dependency:declarations".into(),
            serde_json::to_string(&declared)?,
        );
        if let Some(meta) =
            metadata_by_package.get(&(dep.name.clone(), dep.version.clone().unwrap_or_default()))
        {
            dep.license = field(meta, "license").as_str().map(str::to_owned);
            dep.properties.insert(
                "sbom:package:resolution".into(),
                serde_json::to_string(field(meta, "resolution"))?,
            );
        }
        result.push(dep);
    }
    // Importers represent workspace applications, not external libraries.
    let importers = field(&doc, "importers");
    let fallback;
    let importers = if let Some(m) = importers.as_mapping() {
        m
    } else {
        fallback = serde_yaml::Mapping::from_iter([(Value::String(".".into()), doc.clone())]);
        &fallback
    };
    for (key, data) in importers {
        let Some(importer) = key.as_str() else {
            continue;
        };
        let manifest = path
            .parent()
            .unwrap_or(Path::new("."))
            .join(importer)
            .join("package.json");
        let json = std::fs::read_to_string(&manifest)
            .ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());
        let name = json
            .as_ref()
            .and_then(|j| j["name"].as_str())
            .unwrap_or_else(|| {
                if importer == "." {
                    path.parent()
                        .and_then(|p| p.file_name())
                        .and_then(|n| n.to_str())
                        .unwrap_or("pnpm-app")
                } else {
                    importer
                }
            })
            .to_owned();
        let version = json
            .as_ref()
            .and_then(|j| j["version"].as_str())
            .unwrap_or("0.0.0")
            .to_owned();
        let purl = Dependency::auto_fix_and_validate_purl(&format!("pkg:npm/{name}@{version}"));
        let mut root = DependencyBuilder::default()
            .name(name)
            .version(Some(version))
            .r#type(DependencyType::Application)
            .instance_id(make_instance_id(
                &purl,
                &format!("{salt}:importer:{importer}"),
            ))
            .purl(purl)
            .dependencies(children(data))
            .location(Some(DependencyLocation::from_file(&manifest)))
            .build()
            .map_err(anyhow::Error::msg)?;
        root.properties.insert(
            "sbom:pnpm:skipped-keys".into(),
            serde_json::to_string(&skipped)?,
        );
        root.properties.insert(
            "sbom:dependency:declarations".into(),
            serde_json::to_string(data)?,
        );
        result.push(root);
    }
    let roots: BTreeMap<_, _> = result
        .iter()
        .filter(|d| d.r#type == DependencyType::Application)
        .filter_map(|d| {
            Some((
                std::fs::canonicalize(Path::new(&d.location.as_ref()?.block.file).parent()?)
                    .ok()?,
                d.instance_id.clone(),
            ))
        })
        .collect();
    for dep in &mut result {
        if dep.r#type != DependencyType::Application {
            continue;
        }
        let Some(raw) = dep.properties.get("sbom:dependency:declarations") else {
            continue;
        };
        let data: Value = serde_json::from_str(raw)?;
        for cat in ["dependencies", "devDependencies", "optionalDependencies"] {
            if let Some(map) = field(&data, cat).as_mapping() {
                for value in map.values() {
                    let v = value
                        .as_str()
                        .or_else(|| field(value, "version").as_str())
                        .unwrap_or("");
                    if let Some(relative) = v.strip_prefix("link:") {
                        let dir = Path::new(&dep.location.as_ref().unwrap().block.file)
                            .parent()
                            .unwrap();
                        if let Ok(target) = std::fs::canonicalize(dir.join(relative)) {
                            if let Some(id) = roots.get(&target) {
                                dep.dependencies.push(id.clone());
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn snapshots_preserve_peer_instances_and_transitive_edges() {
        let deps = parse("lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      a: {specifier: ^1, version: 1.0.0(b@2.0.0)}\npackages:\n  a@1.0.0: {}\n  b@2.0.0: {}\nsnapshots:\n  a@1.0.0(b@2.0.0):\n    dependencies: {b: 2.0.0}\n  a@1.0.0(b@3.0.0): {}\n  b@2.0.0: {}\n", Path::new("pnpm-lock.yaml")).unwrap();
        assert_eq!(deps.len(), 4);
        let root = deps
            .iter()
            .find(|d| d.r#type == DependencyType::Application)
            .unwrap();
        assert_eq!(root.dependencies.len(), 1);
        let a = deps
            .iter()
            .find(|d| root.dependencies.contains(&d.instance_id))
            .unwrap();
        assert_eq!(a.dependencies.len(), 1);
        assert!(deps
            .iter()
            .any(|d| d.name == "b" && a.dependencies.contains(&d.instance_id)));
        let ids: BTreeSet<_> = deps.iter().map(|d| &d.instance_id).collect();
        assert_eq!(ids.len(), deps.len());
    }
    #[test]
    fn old_lock_and_invalid_yaml() {
        let deps = parse("lockfileVersion: 5.4\npackages:\n  /@scope/a/1.2.3:\n    dependencies: {b: 2.0.0}\n  /b/2.0.0: {}\n", Path::new("pnpm-lock.yaml")).unwrap();
        assert_eq!(
            deps.iter()
                .find(|d| d.name == "@scope/a")
                .unwrap()
                .dependencies
                .len(),
            1
        );
        assert!(parse("lockfileVersion: [", Path::new("pnpm-lock.yaml")).is_err());
    }
}
