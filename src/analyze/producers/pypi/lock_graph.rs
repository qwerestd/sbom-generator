//! Universal lock inventories keep platform alternatives; edges must match version, source and marker.
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::str::FromStr;

use anyhow::Context;
use pep508_rs::{MarkerTree, Requirement};

use super::pypi_lock_producer::pep503_normalize;
use super::requirements::{parse_requirement, poetry_spec, version_matches};
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyLocation, DependencyType};
use crate::utils::file_utils::make_instance_id;

fn marker(raw: Option<&toml::Value>) -> anyhow::Result<MarkerTree> {
    match raw {
        None => Ok(MarkerTree::TRUE),
        Some(toml::Value::String(text)) => Ok(MarkerTree::from_str(text)?),
        Some(toml::Value::Array(values)) => {
            let mut tree = MarkerTree::FALSE;
            for value in values {
                tree.or(marker(Some(value))?);
            }
            Ok(tree)
        }
        _ => anyhow::bail!("invalid lock marker"),
    }
}

fn python_marker(raw: &str) -> anyhow::Result<MarkerTree> {
    let mut result = MarkerTree::FALSE;
    for branch in raw.split("||") {
        let constraint = poetry_spec(branch)?;
        if constraint.is_empty() {
            return Ok(MarkerTree::TRUE);
        }
        let mut parts = Vec::new();
        for clause in constraint.split(',') {
            let position = clause
                .find(|c: char| c.is_ascii_digit())
                .context("invalid python-versions")?;
            parts.push(format!(
                "python_full_version {} '{}'",
                &clause[..position],
                &clause[position..]
            ));
        }
        result.or(MarkerTree::from_str(&parts.join(" and "))?);
    }
    Ok(result)
}

struct Entry<'a> {
    raw: &'a toml::Value,
    dep: Dependency,
    marker: MarkerTree,
}

fn requirement(name: &str, value: &toml::Value, uv: bool) -> anyhow::Result<Requirement> {
    let version = value
        .as_str()
        .or_else(|| value.get("version").and_then(|v| v.as_str()))
        .unwrap_or("*");
    let version = if uv && version != "*" {
        format!("=={version}")
    } else {
        poetry_spec(version)?
    };
    let mut req = parse_requirement(&format!("{name}{version}"))?;
    req.marker.and(marker(
        value.get("marker").or_else(|| value.get("markers")),
    )?);
    if let Some(python) = value.get("python").and_then(|v| v.as_str()) {
        req.marker.and(python_marker(python)?);
    }
    if let Some(platform) = value.get("platform").and_then(|v| v.as_str()) {
        req.marker.and(MarkerTree::from_str(&format!(
            "sys_platform == '{platform}'"
        ))?);
    }
    Ok(req)
}

pub(super) fn parse(content: &str, salt: &str, path: &Path) -> anyhow::Result<Vec<Dependency>> {
    let lock: toml::Value = toml::from_str(content)?;
    let Some(packages) = lock.get("package").and_then(|p| p.as_array()) else {
        return Ok(vec![]);
    };
    let uv = path
        .file_name()
        .and_then(|p| p.to_str())
        .is_some_and(|p| p.eq_ignore_ascii_case("uv.lock"));
    let mut entries = Vec::new();
    for package in packages {
        let Some(name) = package.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(version) = package.get("version").and_then(|v| v.as_str()) else {
            continue;
        };
        let mut environment = marker(
            package
                .get("markers")
                .or_else(|| package.get("resolution-markers")),
        )?;
        if let Some(python) = package.get("python-versions").and_then(|v| v.as_str()) {
            environment.and(python_marker(python)?);
        }
        let mut properties = BTreeMap::new();
        let marker_text = environment
            .contents()
            .map(|m| m.to_string())
            .unwrap_or_default();
        if !environment.is_true() {
            properties.insert("sbom:python:marker".into(), marker_text.clone());
        }
        if let Some(source) = package.get("source") {
            properties.insert("sbom:python:source".into(), source.to_string());
        }
        properties.insert(
            "sbom:analysis:method".into(),
            if uv { "uv-lock" } else { "poetry-lock" }.into(),
        );
        if let Some(groups) = package.get("groups") {
            properties.insert("sbom:python:groups".into(), groups.to_string());
        }
        let purl = Dependency::auto_fix_and_validate_purl(&format!(
            "pkg:pypi/{}@{version}",
            pep503_normalize(name)
        ));
        let identity = format!(
            "{salt}|{}|{}",
            package
                .get("source")
                .map(ToString::to_string)
                .unwrap_or_default(),
            marker_text
        );
        let local = uv
            && package
                .get("source")
                .is_some_and(|s| s.get("editable").is_some() || s.get("virtual").is_some());
        let dep = DependencyBuilder::default()
            .name(name.to_string())
            .version(Some(version.to_string()))
            .purl(purl.clone())
            .instance_id(make_instance_id(&purl, &identity))
            .r#type(if local {
                DependencyType::Application
            } else {
                DependencyType::Library
            })
            .properties(properties)
            .location(Some(DependencyLocation::from_file(path)))
            .build()
            .map_err(|e| anyhow::anyhow!(e))?;
        entries.push(Entry {
            raw: package,
            dep,
            marker: environment,
        });
    }
    let mut result: BTreeMap<String, Dependency> = entries
        .iter()
        .map(|e| (e.dep.instance_id.clone(), e.dep.clone()))
        .collect();
    let mut by_name: BTreeMap<String, Vec<&Entry<'_>>> = BTreeMap::new();
    let mut indexed = BTreeSet::new();
    for entry in &entries {
        if indexed.insert(entry.dep.instance_id.clone()) {
            by_name
                .entry(pep503_normalize(&entry.dep.name))
                .or_default()
                .push(entry);
        }
    }
    for entry in &entries {
        let mut declarations: Vec<(String, toml::Value)> = Vec::new();
        let mut collect = |value: &toml::Value| {
            if uv {
                if let Some(items) = value.as_array() {
                    for item in items {
                        if let Some(name) = item
                            .get("name")
                            .and_then(|v| v.as_str())
                            .or_else(|| item.as_str())
                        {
                            declarations.push((
                                name.to_string(),
                                if item.is_str() {
                                    toml::Value::Table(Default::default())
                                } else {
                                    item.clone()
                                },
                            ));
                        }
                    }
                }
            } else if let Some(table) = value.as_table() {
                for (name, spec) in table {
                    if let Some(variants) = spec.as_array() {
                        declarations.extend(variants.iter().map(|v| (name.clone(), v.clone())));
                    } else {
                        declarations.push((name.clone(), spec.clone()));
                    }
                }
            }
        };
        if let Some(value) = entry.raw.get("dependencies") {
            collect(value);
        }
        // A lock inventory covers all groups, while a dynamic scan evaluates the selected environment.
        for section in ["optional-dependencies", "dev-dependencies"] {
            if let Some(groups) = entry.raw.get(section).and_then(|v| v.as_table()) {
                for value in groups.values() {
                    collect(value);
                }
            }
        }
        let mut children = BTreeSet::new();
        let mut unresolved = BTreeSet::new();
        let mut ambiguous = BTreeSet::new();
        for (name, value) in declarations {
            let raw = value
                .as_str()
                .or_else(|| value.get("version").and_then(|v| v.as_str()))
                .unwrap_or("*");
            let branches: Vec<_> = if uv {
                vec![raw]
            } else {
                raw.split("||").collect()
            };
            for branch in branches {
                let mut branch_value = value.clone();
                if value.is_str() {
                    branch_value = toml::Value::String(branch.trim().to_string());
                } else if let Some(table) = branch_value.as_table_mut() {
                    table.insert(
                        "version".into(),
                        toml::Value::String(branch.trim().to_string()),
                    );
                }
                let req = requirement(&name, &branch_value, uv)?;
                let mut condition = entry.marker.clone();
                condition.and(req.marker.clone());
                let candidates: Vec<_> = by_name
                    .get(req.name.as_ref())
                    .into_iter()
                    .flatten()
                    .copied()
                    .filter(|candidate| {
                        if pep503_normalize(&candidate.dep.name) != req.name.as_ref()
                            || candidate.marker.is_disjoint(&condition)
                        {
                            return false;
                        }
                        if let Some(source) = value.get("source") {
                            if let Some(name) = source.as_str() {
                                if candidate
                                    .raw
                                    .get("source")
                                    .and_then(|s| s.get("reference").or_else(|| s.get("name")))
                                    .and_then(|s| s.as_str())
                                    != Some(name)
                                {
                                    return false;
                                }
                            } else if candidate.raw.get("source") != Some(source) {
                                return false;
                            }
                        }
                        true
                    })
                    .filter_map(|candidate| {
                        match version_matches(&req, candidate.dep.version.as_deref().unwrap_or(""))
                        {
                            Ok(true) => Some(Ok(candidate)),
                            Ok(false) => None,
                            Err(e) => Some(Err(e)),
                        }
                    })
                    .collect::<anyhow::Result<_>>()?;
                let overlaps = candidates.iter().enumerate().any(|(i, a)| {
                    candidates.iter().skip(i + 1).any(|b| {
                        let mut overlap = condition.clone();
                        overlap.and(a.marker.clone());
                        !overlap.is_disjoint(&b.marker)
                    })
                });
                if candidates.is_empty() && !condition.is_false() {
                    unresolved.insert(req.to_string());
                } else if overlaps {
                    ambiguous.insert(req.to_string());
                } else {
                    for candidate in candidates {
                        if candidate.dep.instance_id != entry.dep.instance_id {
                            children.insert(candidate.dep.instance_id.clone());
                        }
                    }
                }
            }
        }
        let dep = result.get_mut(&entry.dep.instance_id).unwrap();
        dep.dependencies.extend(children);
        dep.dependencies.sort();
        dep.dependencies.dedup();
        if !unresolved.is_empty() {
            dep.properties.insert(
                "sbom:python:unresolved-edges".into(),
                serde_json::to_string(&unresolved)?,
            );
        }
        if !ambiguous.is_empty() {
            dep.properties.insert(
                "sbom:python:ambiguous-edges".into(),
                serde_json::to_string(&ambiguous)?,
            );
        }
    }
    Ok(result.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uv_edges_match_sources_versions_and_platform_alternatives() {
        let text = r#"
[[package]]
name = "app"
version = "1"
source = { virtual = "." }
dependencies = [
    { name = "platform-lib", marker = "sys_platform == 'win32'" },
    { name = "same-version", version = "1", source = { registry = "https://private.example/simple" } }
]
[[package]]
name = "platform-lib"
version = "1"
resolution-markers = ["sys_platform == 'linux'"]
[[package]]
name = "platform-lib"
version = "2"
resolution-markers = ["sys_platform == 'win32'"]
[[package]]
name = "same-version"
version = "1"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "same-version"
version = "1"
source = { registry = "https://private.example/simple" }
"#;
        let deps = parse(text, "test/uv.lock", Path::new("uv.lock")).unwrap();
        assert_eq!(deps.len(), 5);
        let app = deps.iter().find(|d| d.name == "app").unwrap();
        assert_eq!(app.r#type, DependencyType::Application);
        assert_eq!(app.dependencies.len(), 2);
        let children: Vec<_> = deps
            .iter()
            .filter(|d| app.dependencies.contains(&d.instance_id))
            .collect();
        assert!(children
            .iter()
            .any(|d| d.name == "platform-lib" && d.version.as_deref() == Some("2")));
        assert!(children.iter().any(|d| d.name == "same-version"
            && d.properties["sbom:python:source"].contains("private.example")));
    }

    #[test]
    fn poetry_ranges_choose_matching_versions_and_ambiguous_edges_are_diagnosed() {
        let text = r#"
[[package]]
name = "app"
version = "1"
[package.dependencies]
selected = "^2.0"
ambiguous = "*"
[[package]]
name = "selected"
version = "1.9"
[[package]]
name = "selected"
version = "2.1"
[[package]]
name = "ambiguous"
version = "1"
[[package]]
name = "ambiguous"
version = "2"
"#;
        let deps = parse(text, "test", Path::new("poetry.lock")).unwrap();
        let app = deps.iter().find(|d| d.name == "app").unwrap();
        assert_eq!(app.dependencies.len(), 1);
        assert!(app.properties["sbom:python:ambiguous-edges"].contains("ambiguous"));
        assert!(deps.iter().any(|d| d.name == "selected"
            && d.version.as_deref() == Some("2.1")
            && app.dependencies.contains(&d.instance_id)));
    }

    #[test]
    fn cyclic_lock_graphs_keep_all_packages() {
        let text = r#"
[[package]]
name = "one"
version = "1"
[package.dependencies]
two = "==1"
[[package]]
name = "two"
version = "1"
[package.dependencies]
one = "==1"
"#;
        let deps = parse(text, "test", Path::new("poetry.lock")).unwrap();
        assert_eq!(deps.len(), 2);
        assert!(deps
            .iter()
            .all(|d| d.dependencies.len() == 1 && d.r#type == DependencyType::Library));
    }
}
