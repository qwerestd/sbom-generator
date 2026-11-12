use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyLocation};
use crate::utils::file_utils::make_instance_id;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

pub struct YarnLockProducer;
#[derive(Default)]
struct Entry {
    selectors: Vec<String>,
    version: String,
    children: Vec<(String, String)>,
}
fn unquote(s: &str) -> String {
    s.trim().trim_matches(['\'', '"']).to_owned()
}
fn name(selector: &str) -> Option<&str> {
    let i = selector
        .char_indices()
        .find(|(i, c)| *i > 0 && *c == '@')?
        .0;
    Some(&selector[..i])
}
impl SbomProducer for YarnLockProducer {
    fn use_file(&self, p: &Path, _: &SbomProducerConfiguration) -> bool {
        p.file_name().is_some_and(|n| n == "yarn.lock")
    }
    fn find_dependencies(
        &self,
        paths: &[PathBuf],
        _: &SbomProducerConfiguration,
    ) -> anyhow::Result<Vec<Dependency>> {
        let mut result = Vec::new();
        for path in paths {
            result.extend(parse(&std::fs::read_to_string(path)?, path)?);
        }
        Ok(result)
    }
}
fn parse(text: &str, path: &Path) -> anyhow::Result<Vec<Dependency>> {
    let mut entries = Vec::new();
    if text.contains("__metadata:") {
        let doc: serde_yaml::Value = serde_yaml::from_str(text)?;
        let mapping = doc
            .as_mapping()
            .ok_or_else(|| anyhow::anyhow!("invalid Yarn lock mapping"))?;
        for (key, value) in mapping {
            let Some(key) = key.as_str().filter(|s| *s != "__metadata") else {
                continue;
            };
            let mut entry = Entry {
                selectors: key.split(", ").map(unquote).collect(),
                version: value["version"].as_str().unwrap_or("").into(),
                ..Default::default()
            };
            for cat in ["dependencies", "optionalDependencies"] {
                if let Some(children) = value[cat].as_mapping() {
                    for (n, v) in children {
                        if let (Some(n), Some(v)) = (n.as_str(), v.as_str()) {
                            entry.children.push((n.into(), v.into()));
                        }
                    }
                }
            }
            entries.push(entry);
        }
    } else {
        let mut current: Option<Entry> = None;
        let mut dependency_section = false;
        for line in text.lines() {
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                continue;
            }
            if !line.starts_with(char::is_whitespace) && line.ends_with(':') {
                if let Some(e) = current.take() {
                    entries.push(e)
                }
                current = Some(Entry {
                    selectors: line
                        .trim_end_matches(':')
                        .split(", ")
                        .map(unquote)
                        .collect(),
                    ..Default::default()
                });
                dependency_section = false;
            } else if let Some(e) = &mut current {
                let t = line.trim();
                if let Some(v) = t.strip_prefix("version ") {
                    e.version = unquote(v);
                }
                if line.starts_with("  ") && !line.starts_with("    ") {
                    dependency_section = matches!(t, "dependencies:" | "optionalDependencies:");
                } else if dependency_section {
                    if let Some((n, v)) = t.split_once(char::is_whitespace) {
                        e.children.push((unquote(n), unquote(v)));
                    }
                }
            }
        }
        if let Some(e) = current {
            entries.push(e)
        }
    }
    let salt = path.to_string_lossy();
    let mut aliases = BTreeMap::new();
    let mut nodes = Vec::new();
    for entry in entries {
        let Some(n) = entry
            .selectors
            .first()
            .and_then(|s| name(s))
            .map(str::to_owned)
        else {
            continue;
        };
        if crate::utils::version_spec::manifest_version(Some(&entry.version), "npm")
            .0
            .is_none()
        {
            continue;
        }
        let purl =
            Dependency::auto_fix_and_validate_purl(&format!("pkg:npm/{n}@{}", entry.version));
        let id = make_instance_id(&purl, &format!("{salt}:{}", entry.selectors.join(",")));
        for selector in &entry.selectors {
            aliases.insert(selector.clone(), id.clone());
        }
        nodes.push((n, purl, id, entry));
    }
    let mut result = Vec::new();
    for (n, purl, id, entry) in nodes {
        let children = entry
            .children
            .iter()
            .filter_map(|(n, v)| aliases.get(&format!("{n}@{v}")))
            .cloned()
            .collect();
        let mut dep = DependencyBuilder::default()
            .name(n)
            .version(Some(entry.version))
            .purl(purl)
            .instance_id(id)
            .dependencies(children)
            .location(Some(DependencyLocation::from_file(path)))
            .build()
            .map_err(anyhow::Error::msg)?;
        dep.properties.insert(
            "sbom:graph:declared-edges".into(),
            entry.children.len().to_string(),
        );
        dep.properties.insert(
            "sbom:graph:resolved-edges".into(),
            dep.dependencies.len().to_string(),
        );
        result.push(dep);
    }
    anyhow::ensure!(
        !result.is_empty(),
        "Yarn lock contains no supported package entries"
    );
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn classic_and_berry_edges() {
        for text in ["a@^1:\n  version \"1.0.0\"\n  dependencies:\n    b \"^2\"\nb@^2:\n  version \"2.0.0\"\n", "__metadata:\n  version: 8\n\"a@npm:^1\":\n  version: 1.0.0\n  dependencies:\n    b: \"npm:^2\"\n\"b@npm:^2\":\n  version: 2.0.0\n"] {
let d=parse(text,Path::new("yarn.lock")).unwrap(); assert_eq!(d.len(),2);assert_eq!(d.iter().find(|d|d.name=="a").unwrap().dependencies.len(),1);
}
    }
}
