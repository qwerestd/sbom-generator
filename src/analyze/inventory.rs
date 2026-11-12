//! Fuse evidence only when instance identity is unambiguous within a project.
use crate::model::dependency::Dependency;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

fn owner(dep: &Dependency) -> String {
    let Some(location) = &dep.location else {
        return dep
            .properties
            .get("sbom:evidence:project")
            .cloned()
            .unwrap_or_else(|| dep.instance_id.clone())
            .replace('\\', "/");
    };
    let file = Path::new(&location.block.file);
    let dir = file.parent().unwrap_or(file);
    let canonical = std::fs::canonicalize(dir).ok();
    let dir = canonical.as_deref().unwrap_or(dir);
    if dep.r#type == crate::model::dependency::DependencyType::Application {
        return dir.to_string_lossy().replace('\\', "/");
    }
    // Workspace manifests and their shared lockfile use a common ownership boundary.
    if dep.purl.starts_with("pkg:npm/") {
        for ancestor in dir.ancestors() {
            if ["pnpm-lock.yaml", "yarn.lock", "bun.lock"]
                .iter()
                .any(|n| ancestor.join(n).is_file())
            {
                return ancestor.to_string_lossy().replace('\\', "/");
            }
        }
    }
    dir.to_string_lossy().replace('\\', "/")
}

fn ownerships(deps: &[Dependency]) -> Vec<String> {
    let mut cache = HashMap::new();
    deps.iter()
        .map(|d| {
            let path = d
                .location
                .as_ref()
                .map(|l| {
                    Path::new(&l.block.file)
                        .parent()
                        .unwrap_or(Path::new(&l.block.file))
                        .to_string_lossy()
                        .into_owned()
                })
                .unwrap_or_else(|| {
                    d.properties
                        .get("sbom:evidence:project")
                        .cloned()
                        .unwrap_or_else(|| d.instance_id.clone())
                });
            cache
                .entry((
                    path,
                    format!("{:?}", d.r#type),
                    d.purl.split('/').next().unwrap_or("").to_owned(),
                ))
                .or_insert_with(|| owner(d))
                .clone()
        })
        .collect()
}
pub fn fuse(mut deps: Vec<Dependency>) -> Vec<Dependency> {
    let mut instances = BTreeMap::<String, Dependency>::new();
    for dep in deps {
        instances
            .entry(dep.instance_id.clone())
            .and_modify(|existing| {
                existing
                    .dependencies
                    .extend(dep.dependencies.iter().cloned());
                existing.properties.extend(dep.properties.clone());
            })
            .or_insert(dep);
    }
    deps = instances.into_values().collect();
    let owners = ownerships(&deps);
    fn identity(purl: &str) -> &str {
        match (purl.rfind('@'), purl.rfind('/')) {
            (Some(a), Some(s)) if a > s => &purl[..a],
            _ => purl,
        }
    }
    let mut declaration_aliases = HashMap::new();
    let mut declaration_removed = BTreeSet::new();
    for i in 0..deps.len() {
        if deps[i].version.is_some()
            || deps[i].r#type != crate::model::dependency::DependencyType::Library
        {
            continue;
        }
        let Some(requirement) = deps[i].version_requirement.as_deref() else {
            continue;
        };
        let candidates: Vec<_> = deps
            .iter()
            .enumerate()
            .filter(|(j, d)| {
                if d.version.is_none()
                    || d.r#type != deps[i].r#type
                    || owners[*j] != owners[i]
                    || identity(&d.purl) != identity(&deps[i].purl)
                {
                    return false;
                }
                if deps[i].purl.starts_with("pkg:npm/") || deps[i].purl.starts_with("pkg:cargo/") {
                    let raw = requirement.strip_prefix('=').unwrap_or(requirement);
                    semver::VersionReq::parse(raw)
                        .ok()
                        .zip(semver::Version::parse(d.version.as_deref().unwrap()).ok())
                        .is_some_and(|(r, v)| r.matches(&v))
                } else if deps[i].purl.starts_with("pkg:pypi/") {
                    use std::str::FromStr;
                    let raw = if requirement.starts_with(['<', '>', '=', '!', '~']) {
                        format!("{}{}", deps[i].name, requirement)
                    } else {
                        requirement.to_owned()
                    };
                    let req: Result<pep508_rs::Requirement, _> =
                        pep508_rs::Requirement::from_str(&raw);
                    req.ok().is_some_and(|r| {
                        crate::analyze::producers::pypi::requirements::version_matches(
                            &r,
                            d.version.as_deref().unwrap(),
                        )
                        .unwrap_or(false)
                    })
                } else {
                    false
                }
            })
            .map(|(j, _)| j)
            .collect();
        if candidates.len() == 1 {
            let winner = candidates[0];
            declaration_aliases.insert(
                deps[i].instance_id.clone(),
                deps[winner].instance_id.clone(),
            );
            let declaration = serde_json::json!({"requirement":requirement,"location":deps[i].location.as_ref().map(|l|&l.block.file)});
            let key = format!("sbom:evidence:declaration:{}", deps[i].instance_id);
            deps[winner].properties.insert(key, declaration.to_string());
            declaration_removed.insert(i);
        }
    }
    for d in &mut deps {
        for child in &mut d.dependencies {
            if let Some(id) = declaration_aliases.get(child) {
                *child = id.clone();
            }
        }
    }
    deps = deps
        .into_iter()
        .enumerate()
        .filter_map(|(i, d)| (!declaration_removed.contains(&i)).then_some(d))
        .collect();
    let owners = ownerships(&deps);
    let mut groups: BTreeMap<(String, String, String), Vec<usize>> = BTreeMap::new();
    for (i, dep) in deps.iter().enumerate() {
        groups
            .entry((
                owners[i].clone(),
                dep.purl.clone(),
                format!("{:?}", dep.r#type),
            ))
            .or_default()
            .push(i);
    }
    let mut aliases = HashMap::new();
    let mut removed = BTreeSet::new();
    for indexes in groups.values() {
        let mut by_source: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for &i in indexes {
            let source = deps[i]
                .location
                .as_ref()
                .map(|l| l.block.file.clone())
                .unwrap_or_else(|| {
                    deps[i]
                        .properties
                        .get("sbom:analysis:method")
                        .cloned()
                        .unwrap_or_default()
                });
            let parser = deps[i]
                .properties
                .get("sbom:evidence:parser")
                .or_else(|| deps[i].properties.get("sbom:analysis:method"))
                .cloned()
                .unwrap_or_default();
            by_source
                .entry(format!("{parser}:{source}"))
                .or_default()
                .push(i);
        }
        // Multiple peer/installation contexts in one source are distinct instances.
        if by_source.len() < 2 || by_source.values().any(|v| v.len() != 1) {
            continue;
        }
        let winner = indexes
            .iter()
            .copied()
            .max_by_key(|&i| {
                let p = deps[i]
                    .location
                    .as_ref()
                    .map(|l| l.block.file.as_str())
                    .unwrap_or("");
                2 * usize::from(
                    p.ends_with("lock") || p.ends_with("lock.yaml") || p.ends_with("lock.json"),
                ) + usize::from(
                    deps[i]
                        .properties
                        .get("sbom:analysis:method")
                        .is_some_and(|m| m != "static"),
                )
            })
            .unwrap();
        let mut evidence = BTreeSet::new();
        for &i in indexes {
            evidence.insert(serde_json::json!({"location":deps[i].location.as_ref().map(|l| &l.block.file),"properties":deps[i].properties}).to_string());
            if i == winner {
                continue;
            }
            let other = deps[i].clone();
            aliases.insert(other.instance_id.clone(), deps[winner].instance_id.clone());
            deps[winner].dependencies.extend(other.dependencies);
            if deps[winner].license.is_none() {
                deps[winner].license = other.license;
            }
            for (key, value) in other.properties {
                deps[winner].properties.entry(key).or_insert(value);
            }
            removed.insert(i);
        }
        deps[winner].properties.insert(
            "sbom:evidence:sources".into(),
            format!("[{}]", evidence.into_iter().collect::<Vec<_>>().join(",")),
        );
    }
    let mut result: Vec<_> = deps
        .into_iter()
        .enumerate()
        .filter_map(|(i, d)| (!removed.contains(&i)).then_some(d))
        .collect();
    for dep in &mut result {
        for edge in &mut dep.dependencies {
            if let Some(target) = aliases.get(edge) {
                *edge = target.clone();
            }
        }
        dep.dependencies.sort();
        dep.dependencies.dedup();
        remap_properties(dep, &aliases);
    }
    result
}

pub fn remap_properties(dep: &mut Dependency, aliases: &HashMap<String, String>) {
    for key in ["sbom:go:module-requires", "sbom:go:source-imports"] {
        if let Some(raw) = dep.properties.get_mut(key) {
            if let Ok(mut ids) = serde_json::from_str::<Vec<String>>(raw) {
                for id in &mut ids {
                    if let Some(target) = aliases.get(id) {
                        *id = target.clone();
                    }
                }
                *raw = serde_json::to_string(&ids).unwrap();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::dependency::{DependencyBuilder, DependencyLocation, DependencyType};
    fn d(name: &str, version: Option<&str>, file: &str, context: &str) -> Dependency {
        let purl = format!(
            "pkg:npm/{name}{}",
            version.map(|v| format!("@{v}")).unwrap_or_default()
        );
        DependencyBuilder::default()
            .name(name.into())
            .version(version.map(str::to_owned))
            .purl(purl.clone())
            .instance_id(crate::utils::file_utils::make_instance_id(&purl, context))
            .location(Some(DependencyLocation::from_file(Path::new(file))))
            .build()
            .unwrap()
    }
    #[test]
    fn compatible_declaration_joins_one_locked_instance() {
        let locked = d("lib", Some("1.2.0"), "target/fusion/lock.yaml", "locked");
        let mut declaration = d("lib", None, "target/fusion/package.json", "declaration");
        declaration.version_requirement = Some("^1".into());
        let mut root = d("app", Some("1.0.0"), "target/fusion/package.json", "root");
        root.r#type = DependencyType::Application;
        root.dependencies.push(declaration.instance_id.clone());
        let merged = fuse(vec![locked.clone(), declaration, root]);
        assert_eq!(merged.len(), 2);
        assert_eq!(
            merged
                .iter()
                .find(|d| d.name == "app")
                .unwrap()
                .dependencies,
            vec![locked.instance_id]
        );
    }
    #[test]
    fn peer_contexts_and_independent_applications_are_not_collapsed() {
        let a = d("lib", Some("1.0.0"), "target/fusion/lock.yaml", "peer-a");
        let b = d("lib", Some("1.0.0"), "target/fusion/lock.yaml", "peer-b");
        let c = d(
            "lib",
            Some("1.0.0"),
            "target/fusion/package.json",
            "manifest",
        );
        assert_eq!(fuse(vec![a, b, c]).len(), 3);
        let mut a = d(
            "same",
            Some("1.0.0"),
            "target/fusion/left/package.json",
            "left",
        );
        a.r#type = DependencyType::Application;
        let mut b = d(
            "same",
            Some("1.0.0"),
            "target/fusion/right/package.json",
            "right",
        );
        b.r#type = DependencyType::Application;
        assert_eq!(fuse(vec![a, b]).len(), 2);
    }
    #[test]
    fn incompatible_constraint_is_preserved() {
        let locked = d("lib", Some("1.0.0"), "target/fusion/lock.yaml", "lock");
        let mut declaration = d("lib", None, "target/fusion/package.json", "manifest");
        declaration.version_requirement = Some("^2".into());
        assert_eq!(fuse(vec![locked, declaration]).len(), 2);
    }
}
