use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyLocation};
use crate::utils::file_utils::make_instance_id;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
pub struct BunLockProducer;
// JSONC scanner: preserve strings/URLs, remove comments and trailing commas.
fn jsonc(text: &str) -> String {
    let chars: Vec<_> = text.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    let mut quoted = false;
    let mut escaped = false;
    while i < chars.len() {
        let c = chars[i];
        if quoted {
            out.push(c);
            if escaped {
                escaped = false
            } else if c == '\\' {
                escaped = true
            } else if c == '"' {
                quoted = false
            }
            i += 1;
            continue;
        }
        if c == '"' {
            quoted = true;
            out.push(c);
            i += 1;
            continue;
        }
        if c == '/' && chars.get(i + 1) == Some(&'/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1
            }
            continue;
        }
        if c == '/' && chars.get(i + 1) == Some(&'*') {
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1
            }
            i += 2;
            continue;
        }
        if c == ',' {
            let mut j = i + 1;
            while chars.get(j).is_some_and(|c| c.is_whitespace()) {
                j += 1
            }
            if matches!(chars.get(j), Some('}' | ']')) {
                i += 1;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    let chars: Vec<_> = out.chars().collect();
    let mut clean = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for (i, &c) in chars.iter().enumerate() {
        if quoted {
            clean.push(c);
            if escaped {
                escaped = false
            } else if c == '\\' {
                escaped = true
            } else if c == '"' {
                quoted = false
            }
            continue;
        }
        if c == '"' {
            quoted = true;
        }
        if c == ','
            && chars[i + 1..]
                .iter()
                .find(|c| !c.is_whitespace())
                .is_some_and(|c| matches!(c, '}' | ']'))
        {
            continue;
        }
        clean.push(c);
    }
    clean
}
impl SbomProducer for BunLockProducer {
    fn use_file(&self, p: &Path, _: &SbomProducerConfiguration) -> bool {
        p.file_name().is_some_and(|n| n == "bun.lock")
    }
    fn find_dependencies(
        &self,
        paths: &[PathBuf],
        _: &SbomProducerConfiguration,
    ) -> anyhow::Result<Vec<Dependency>> {
        let mut result = Vec::new();
        for path in paths {
            let raw = std::fs::read_to_string(path)?;
            let j: serde_json::Value = serde_json::from_str(&jsonc(&raw))?;
            let packages = j["packages"]
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("unsupported Bun packages structure"))?;
            let mut aliases = BTreeMap::new();
            let mut nodes = Vec::new();
            for (key, value) in packages {
                let Some(spec) = value.get(0).and_then(|v| v.as_str()) else {
                    continue;
                };
                let Some((name, v)) = spec.rsplit_once('@').filter(|(n, _)| !n.is_empty()) else {
                    continue;
                };
                let (version, requirement) =
                    crate::utils::version_spec::manifest_version(Some(v), "npm");
                let purl = Dependency::auto_fix_and_validate_purl(&format!(
                    "pkg:npm/{name}{}",
                    version
                        .as_ref()
                        .map(|v| format!("@{v}"))
                        .unwrap_or_default()
                ));
                let id = make_instance_id(&purl, &format!("{}:{key}", path.display()));
                aliases.insert(key.clone(), id.clone());
                nodes.push((key, name.to_owned(), version, requirement, purl, id, value));
            }
            for (key, name, version, requirement, purl, id, value) in nodes {
                let mut children = Vec::new();
                let mut declarations = Vec::new();
                if let Some(meta) = value.get(2).and_then(|v| v.as_object()) {
                    for category in ["dependencies", "optionalDependencies", "peerDependencies"] {
                        if let Some(map) = meta.get(category).and_then(|v| v.as_object()) {
                            for (n, v) in map {
                                declarations.push(
                                    serde_json::json!({"name":n,"constraint":v,"scope":category}),
                                );
                                let mut prefix = key.as_str();
                                let mut found = None;
                                loop {
                                    if let Some(id) = aliases.get(&format!("{prefix}/{n}")) {
                                        found = Some(id.clone());
                                        break;
                                    }
                                    match prefix.rsplit_once('/') {
                                        Some((p, _)) => prefix = p,
                                        None => break,
                                    }
                                }
                                if let Some(id) = found.or_else(|| aliases.get(n).cloned()) {
                                    children.push(id)
                                }
                            }
                        }
                    }
                }
                let mut dep = DependencyBuilder::default()
                    .name(name)
                    .version(version)
                    .version_requirement(requirement)
                    .purl(purl)
                    .instance_id(id)
                    .dependencies(children)
                    .location(Some(DependencyLocation::from_file(path)))
                    .build()
                    .map_err(anyhow::Error::msg)?;
                dep.properties.insert(
                    "sbom:dependency:declarations".into(),
                    serde_json::to_string(&declarations)?,
                );
                result.push(dep);
            }
        }
        Ok(result)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn comments_and_urls() {
        let j: serde_json::Value =
            serde_json::from_str(&jsonc("{\"url\":\"https://a/b\",// x\n\"list\":[1,],}")).unwrap();
        assert_eq!(j["url"], "https://a/b");
        assert_eq!(j["list"].as_array().unwrap().len(), 1);
    }
}
