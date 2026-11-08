use crate::analyze::producers::dynamic_producer::DynamicProducer;
use crate::model::configuration::Configuration;
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyType};
use crate::utils::cli_driver::CliLocator;
use crate::utils::file_utils::make_instance_id;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::process::Command;

#[derive(Default)]
pub struct CargoDynamicProducer {}

impl DynamicProducer for CargoDynamicProducer {
    fn is_applicable(&self, configuration: &Configuration) -> bool {
        let mut path = PathBuf::from(&configuration.directory);
        path.push("Cargo.toml");
        path.exists()
    }

    fn detect_dependencies(
        &self,
        configuration: &Configuration,
    ) -> anyhow::Result<Vec<Dependency>> {
        let mut cmd = Command::new("cargo");
        cmd.args(["metadata", "--format-version=1", "--all-features"])
            .current_dir(&configuration.directory);

        let output = CliLocator::run_with_timeout(cmd, std::time::Duration::from_secs(15))?;

        if !output.status.success() {
            let stderr_str = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("Cargo metadata 执行失败: {}", stderr_str));
        }

        let stdout_str = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value = serde_json::from_str(&stdout_str)?;

        Ok(Self::parse_cargo_metadata_json(&json))
    }
}

impl CargoDynamicProducer {
    pub fn parse_cargo_metadata_json(json: &serde_json::Value) -> Vec<Dependency> {
        struct PkgMeta {
            name: String,
            version: String,
            purl: String,
            instance_id: String,
        }

        let mut id_to_meta: HashMap<String, PkgMeta> = HashMap::new();

        if let Some(packages) = json.get("packages").and_then(|p| p.as_array()) {
            for pkg in packages {
                if let (Some(id), Some(name), Some(version)) = (
                    pkg.get("id").and_then(|i| i.as_str()),
                    pkg.get("name").and_then(|n| n.as_str()),
                    pkg.get("version").and_then(|v| v.as_str()),
                ) {
                    let raw_purl = format!("pkg:cargo/{}@{}", name, version);
                    let valid_purl = Dependency::auto_fix_and_validate_purl(&raw_purl);
                    let instance_id = make_instance_id(&valid_purl, id);

                    id_to_meta.insert(
                        id.to_string(),
                        PkgMeta {
                            name: name.to_string(),
                            version: version.to_string(),
                            purl: valid_purl,
                            instance_id,
                        },
                    );
                }
            }
        }

        let mut workspace_members: HashSet<String> = HashSet::new();
        if let Some(members) = json.get("workspace_members").and_then(|m| m.as_array()) {
            workspace_members = members
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
        }

        let mut id_to_child_ids: HashMap<String, Vec<String>> = HashMap::new();

        if let Some(nodes) = json
            .get("resolve")
            .and_then(|r| r.get("nodes"))
            .and_then(|n| n.as_array())
        {
            for node in nodes {
                if let Some(parent_id) = node.get("id").and_then(|i| i.as_str()) {
                    let mut child_ids = vec![];

                    if let Some(deps) = node.get("deps").and_then(|d| d.as_array()) {
                        for dep_obj in deps {
                            if let Some(cid) = dep_obj.get("pkg").and_then(|p| p.as_str()) {
                                child_ids.push(cid.to_string());
                            }
                        }
                    }
                    id_to_child_ids.insert(parent_id.to_string(), child_ids);
                }
            }
        }

        let mut reachable_ids: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<String> = VecDeque::new();

        for member_id in &workspace_members {
            reachable_ids.insert(member_id.clone());
            queue.push_back(member_id.clone());
        }

        while let Some(current_id) = queue.pop_front() {
            if let Some(children) = id_to_child_ids.get(&current_id) {
                for child_id in children {
                    if !reachable_ids.contains(child_id) {
                        reachable_ids.insert(child_id.clone());
                        queue.push_back(child_id.clone());
                    }
                }
            }
        }

        let mut final_deps = vec![];

        for id in &reachable_ids {
            if let Some(meta) = id_to_meta.get(id) {
                let mut edge_instance_ids = vec![];

                if let Some(children) = id_to_child_ids.get(id) {
                    for child_id in children {
                        if reachable_ids.contains(child_id) {
                            if let Some(child_meta) = id_to_meta.get(child_id) {
                                edge_instance_ids.push(child_meta.instance_id.clone());
                            }
                        }
                    }
                }

                let dep_type = if workspace_members.contains(id) {
                    DependencyType::Application
                } else {
                    DependencyType::Library
                };

                if let Ok(dep) = DependencyBuilder::default()
                    .name(meta.name.clone())
                    .version(Some(meta.version.clone()))
                    .r#type(dep_type)
                    .purl(meta.purl.clone())
                    .instance_id(meta.instance_id.clone())
                    .dependencies(edge_instance_ids)
                    .location(None)
                    .build()
                {
                    final_deps.push(dep);
                }
            }
        }

        final_deps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cargo_metadata_json() {
        let meta_json = serde_json::json!({
            "packages": [
                {
                    "id": "my-crate 0.1.0 (path+file:///my-crate)",
                    "name": "my-crate",
                    "version": "0.1.0"
                },
                {
                    "id": "serde 1.0.203 (registry+https://github.com/rust-lang/crates.io-index)",
                    "name": "serde",
                    "version": "1.0.203"
                },
                {
                    "id": "serde_derive 1.0.203 (registry+https://github.com/rust-lang/crates.io-index)",
                    "name": "serde_derive",
                    "version": "1.0.203"
                }
            ],
            "workspace_members": [
                "my-crate 0.1.0 (path+file:///my-crate)"
            ],
            "resolve": {
                "nodes": [
                    {
                        "id": "my-crate 0.1.0 (path+file:///my-crate)",
                        "deps": [
                            {
                                "name": "serde",
                                "pkg": "serde 1.0.203 (registry+https://github.com/rust-lang/crates.io-index)"
                            }
                        ]
                    },
                    {
                        "id": "serde 1.0.203 (registry+https://github.com/rust-lang/crates.io-index)",
                        "deps": [
                            {
                                "name": "serde_derive",
                                "pkg": "serde_derive 1.0.203 (registry+https://github.com/rust-lang/crates.io-index)"
                            }
                        ]
                    },
                    {
                        "id": "serde_derive 1.0.203 (registry+https://github.com/rust-lang/crates.io-index)",
                        "deps": []
                    }
                ]
            }
        });

        let deps = CargoDynamicProducer::parse_cargo_metadata_json(&meta_json);
        assert_eq!(deps.len(), 3);
        let root_dep = deps
            .iter()
            .find(|d| d.name == "my-crate")
            .expect("must find root");
        assert_eq!(root_dep.r#type, DependencyType::Application);
        assert_eq!(root_dep.dependencies.len(), 1);

        let serde_dep = deps
            .iter()
            .find(|d| d.name == "serde")
            .expect("must find serde");
        assert_eq!(serde_dep.r#type, DependencyType::Library);
        assert_eq!(serde_dep.dependencies.len(), 1);
    }
}
