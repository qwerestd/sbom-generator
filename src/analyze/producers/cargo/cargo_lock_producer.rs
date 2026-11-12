use std::fs;
use std::path::{Path, PathBuf};

use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::model::dependency::{Dependency, DependencyLocation};
use crate::utils::file_utils::make_instance_id;
use crate::utils::graph_utils::{build_reachable_dag, RawGraphNode};

#[derive(Clone, Default)]
pub struct CargoProducer {}

impl SbomProducer for CargoProducer {
    fn use_file(&self, path: &Path, _config: &SbomProducerConfiguration) -> bool {
        path.file_name()
            .map(|name| name == "Cargo.lock")
            .unwrap_or(false)
    }

    fn find_dependencies(
        &self,
        paths: &[PathBuf],
        _config: &SbomProducerConfiguration,
    ) -> anyhow::Result<Vec<Dependency>> {
        let mut all_dependencies = Vec::new();

        for lock_path in paths {
            let content = fs::read_to_string(lock_path)?;
            let file_salt = lock_path.to_string_lossy().replace('\\', "/");
            let location = Some(DependencyLocation::from_file(lock_path));

            let file_deps = Self::parse_cargo_lock(&content, &file_salt, location)?;
            all_dependencies.extend(file_deps);
        }

        Ok(all_dependencies)
    }
}

impl CargoProducer {
    fn parse_cargo_lock(
        content: &str,
        file_salt: &str,
        location: Option<DependencyLocation>,
    ) -> anyhow::Result<Vec<Dependency>> {
        let lock_toml: toml::Value = toml::from_str(content)?;

        let Some(packages) = lock_toml.get("package").and_then(|p| p.as_array()) else {
            return Ok(vec![]);
        };

        let mut raw_nodes = Vec::with_capacity(packages.len());

        for pkg in packages {
            let Some(name) = pkg.get("name").and_then(|n| n.as_str()) else {
                continue;
            };
            let Some(version) = pkg.get("version").and_then(|v| v.as_str()) else {
                continue;
            };

            let raw_purl = format!("pkg:cargo/{}@{}", name, version);
            let valid_purl = Dependency::auto_fix_and_validate_purl(&raw_purl);
            let source = pkg
                .get("source")
                .and_then(|v| v.as_str())
                .unwrap_or("local");
            let instance_id = make_instance_id(&valid_purl, &format!("{file_salt}:{source}"));

            let mut raw_deps = Vec::new();
            if let Some(deps) = pkg.get("dependencies").and_then(|d| d.as_array()) {
                for d_val in deps {
                    if let Some(d_str) = d_val.as_str() {
                        let mut iter = d_str.split_whitespace();
                        let d_name = iter.next().unwrap_or("").to_string();
                        let d_ver = iter
                            .next()
                            .filter(|tok| !tok.starts_with('('))
                            .map(|s| s.to_string());
                        if !d_name.is_empty() {
                            raw_deps.push((d_name, d_ver));
                        }
                    }
                }
            }

            raw_nodes.push(RawGraphNode {
                group: None,
                name: name.to_string(),
                version: Some(version.to_string()),
                purl: valid_purl,
                instance_id,
                raw_deps,
                lookup_key: name.to_string(),
                force_root: source == "local",
                location: location.clone(),
            });
        }

        Ok(build_reachable_dag(raw_nodes))
    }
}
