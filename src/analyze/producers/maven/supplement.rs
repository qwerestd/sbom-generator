//! Conditional and build dependencies remain separate evidence from runtime resolution.
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyLocation};
use crate::utils::file_utils::make_instance_id;
use std::path::Path;
fn tag<'a>(n: tree_sitter::Node<'a>, text: &'a str) -> &'a str {
    let mut c = n.walk();
    for child in n.named_children(&mut c) {
        if child.kind() == "STag" {
            let mut c = child.walk();
            for name in child.named_children(&mut c) {
                if name.kind() == "Name" {
                    return name.utf8_text(text.as_bytes()).unwrap_or("");
                }
            }
        }
    }
    ""
}
fn child_text(n: tree_sitter::Node<'_>, key: &str, text: &str) -> Option<String> {
    let mut c = n.walk();
    for content in n.named_children(&mut c).filter(|n| n.kind() == "content") {
        let mut c = content.walk();
        for child in content.named_children(&mut c) {
            if tag(child, text) == key {
                let mut c = child.walk();
                for value in child.named_children(&mut c) {
                    if value.kind() == "content" {
                        return value
                            .utf8_text(text.as_bytes())
                            .ok()
                            .map(|s| s.trim().to_owned());
                    }
                }
            }
        }
    }
    None
}
pub fn profile_ids(path: &Path) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Some(tree) = crate::utils::tree_sitter::tree::get_tree(
        &text,
        &crate::utils::tree_sitter::language::get_tree_sitter_xml(),
    ) else {
        return Vec::new();
    };
    let mut ids = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(n) = stack.pop() {
        if tag(n, &text) == "profile" {
            if let Some(id) = child_text(n, "id", &text) {
                ids.push(id)
            }
        }
        let mut c = n.walk();
        stack.extend(n.named_children(&mut c));
    }
    ids.sort();
    ids.dedup();
    ids
}
pub fn collect(path: &Path) -> anyhow::Result<Vec<Dependency>> {
    let text = std::fs::read_to_string(path)?;
    let tree = crate::utils::tree_sitter::tree::get_tree(
        &text,
        &crate::utils::tree_sitter::language::get_tree_sitter_xml(),
    )
    .ok_or_else(|| anyhow::anyhow!("invalid XML"))?;
    let mut deps = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(n) = stack.pop() {
        let kind = tag(n, &text);
        let mut profile = None;
        let mut managed = false;
        let mut build = kind == "plugin";
        let mut ancestor = n.parent();
        while let Some(p) = ancestor {
            match tag(p, &text) {
                "profile" => profile = child_text(p, "id", &text),
                "dependencyManagement" | "pluginManagement" => managed = true,
                "plugin" | "plugins" => build = true,
                _ => {}
            }
            ancestor = p.parent();
        }
        if matches!(kind, "dependency" | "plugin") && !managed && (profile.is_some() || build) {
            if let Some(name) = child_text(n, "artifactId", &text) {
                let group = child_text(n, "groupId", &text)
                    .or_else(|| (kind == "plugin").then(|| "org.apache.maven.plugins".into()));
                if let Some(group) = group {
                    let raw = child_text(n, "version", &text);
                    let (version, requirement) =
                        crate::utils::version_spec::manifest_version(raw.as_deref(), "maven");
                    let purl = Dependency::auto_fix_and_validate_purl(&format!(
                        "pkg:maven/{group}/{name}{}",
                        version
                            .as_ref()
                            .map(|v| format!("@{v}"))
                            .unwrap_or_default()
                    ));
                    let context = format!(
                        "{}:{}:{}",
                        path.display(),
                        profile.as_deref().unwrap_or("default"),
                        if build { "build" } else { "project" }
                    );
                    let mut d = DependencyBuilder::default()
                        .name(name)
                        .group(Some(group))
                        .version(version)
                        .version_requirement(requirement)
                        .purl(purl.clone())
                        .instance_id(make_instance_id(&purl, &context))
                        .location(Some(DependencyLocation::from_file(path)))
                        .build()
                        .map_err(anyhow::Error::msg)?;
                    d.properties.insert(
                        "sbom:scope".into(),
                        if build {
                            "build-plugin".into()
                        } else {
                            child_text(n, "scope", &text).unwrap_or_else(|| "compile".into())
                        },
                    );
                    if let Some(p) = profile {
                        d.properties.insert("sbom:maven:profile".into(), p);
                        d.properties
                            .insert("sbom:dependency:conditional".into(), "true".into());
                    }
                    deps.push(d);
                }
            }
        }
        let mut c = n.walk();
        stack.extend(n.named_children(&mut c));
    }
    Ok(deps)
}
