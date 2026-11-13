use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyLocation, DependencyType};
use crate::utils::file_utils::make_instance_id;

#[derive(Clone, Default)]
pub struct NpmLockProducer {}

impl SbomProducer for NpmLockProducer {
    fn is_complete(&self, paths: &[PathBuf], deps: &[Dependency]) -> bool {
        // An unsupported v1 lock or a skipped entry must not suppress the manifest.
        let expected = paths.iter().try_fold(0usize, |count, path| {
            let json: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()?;
            let packages = json.get("packages")?.as_object()?;
            for package in packages.values() {
                for category in [
                    "dependencies",
                    "devDependencies",
                    "optionalDependencies",
                    "peerDependencies",
                ] {
                    if let Some(declared) = package.get(category).and_then(|v| v.as_object()) {
                        if declared
                            .keys()
                            .any(|name| !deps.iter().any(|d| &d.name == name))
                        {
                            return None;
                        }
                    }
                }
            }
            if packages.is_empty()
                || packages
                    .values()
                    .any(|p| p.get("link").and_then(|v| v.as_bool()) == Some(true))
            {
                return None;
            }
            Some(count + packages.len())
        });
        expected == Some(deps.len()) && !deps.is_empty()
    }
    fn use_file(&self, path: &Path, _config: &SbomProducerConfiguration) -> bool {
        path.file_name().is_some_and(|n| {
            n.eq_ignore_ascii_case("package-lock.json")
                || n.eq_ignore_ascii_case("npm-shrinkwrap.json")
        })
    }

    fn find_dependencies(
        &self,
        paths: &[PathBuf],
        _config: &SbomProducerConfiguration,
    ) -> anyhow::Result<Vec<Dependency>> {
        let mut result = Vec::new();

        for p in paths {
            let content = std::fs::read_to_string(p)?;
            let clean_content = content.trim_start_matches('\u{FEFF}').trim();
            let file_salt = p.to_string_lossy().replace('\\', "/");
            let location = Some(DependencyLocation::from_file(p));

            match serde_json::from_str::<serde_json::Value>(clean_content) {
                Ok(json) => {
                    result.extend(Self::parse_npm_lock(&json, &file_salt, location)?);
                }
                Err(e) => {
                    anyhow::bail!("invalid package-lock.json {}: {e}", p.display());
                }
            }
        }
        Ok(result)
    }
}

impl NpmLockProducer {
    fn parse_npm_lock(
        json: &serde_json::Value,
        file_salt: &str,
        location: Option<DependencyLocation>,
    ) -> anyhow::Result<Vec<Dependency>> {
        let Some(packages) = json.get("packages").and_then(|p| p.as_object()) else {
            if json
                .get("dependencies")
                .and_then(|v| v.as_object())
                .is_some()
            {
                fn expand(
                    value: &serde_json::Value,
                    parent: &str,
                    packages: &mut serde_json::Map<String, serde_json::Value>,
                ) {
                    if let Some(deps) = value.get("dependencies").and_then(|v| v.as_object()) {
                        for (name, data) in deps {
                            let path = if parent.is_empty() {
                                format!("node_modules/{name}")
                            } else {
                                format!("{parent}/node_modules/{name}")
                            };
                            let mut entry = data.clone();
                            entry["name"] = name.clone().into();
                            if let Some(required) = data.get("requires") {
                                entry["dependencies"] = required.clone();
                            } else {
                                entry.as_object_mut().unwrap().remove("dependencies");
                            }
                            packages.insert(path.clone(), entry);
                            expand(data, &path, packages);
                        }
                    }
                }
                let mut packages = serde_json::Map::new();
                let root_deps: serde_json::Map<_, _> = json["dependencies"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(n, v)| (n.clone(), v["version"].clone()))
                    .collect();
                packages.insert("".into(), serde_json::json!({"name":json.get("name").and_then(|v|v.as_str()).unwrap_or("npm-app"),"version":json.get("version").and_then(|v|v.as_str()).unwrap_or("0.0.0"),"dependencies":root_deps}));
                expand(json, "", &mut packages);
                return Self::parse_npm_lock(
                    &serde_json::json!({"packages":packages}),
                    file_salt,
                    location,
                );
            }
            return Ok(vec![]);
        };

        struct RawNode {
            pkg_path: String,
            name: String,
            version: String,
            license: Option<String>,
            purl: String,
            instance_id: String,
            dep_names: Vec<String>,
            is_root: bool,
        }

        let mut nodes = Vec::with_capacity(packages.len());
        let mut path_to_id: HashMap<String, String> = HashMap::with_capacity(packages.len());

        for (pkg_path, pkg_data) in packages {
            let is_root = pkg_path.is_empty();
            if !is_root && !Self::is_os_compatible(pkg_data) {
                continue;
            }

            let name = match pkg_data.get("name").and_then(|n| n.as_str()) {
                Some(n) => n.to_string(),
                None => {
                    if is_root {
                        json.get("name")
                            .and_then(|n| n.as_str())
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| {
                                Path::new(file_salt)
                                    .parent()
                                    .and_then(|p| p.file_name())
                                    .and_then(|n| n.to_str())
                                    .unwrap_or("npm-app")
                                    .to_string()
                            })
                    } else if let Some(idx) = pkg_path.rfind("node_modules/") {
                        pkg_path[idx + 13..].to_string()
                    } else {
                        pkg_path.rsplit('/').next().unwrap_or(pkg_path).to_string()
                    }
                }
            };

            let version = match pkg_data.get("version").and_then(|v| v.as_str()) {
                Some(v) => v.to_string(),
                None => {
                    if is_root {
                        json.get("version")
                            .and_then(|v| v.as_str())
                            .unwrap_or("0.0.0")
                            .to_string()
                    } else {
                        continue;
                    }
                }
            };

            let purl = format!("pkg:npm/{}@{}", name, version);
            let valid_purl = Dependency::auto_fix_and_validate_purl(&purl);

            let combined_salt = if is_root {
                format!("{}:ROOT", file_salt)
            } else {
                format!("{}:{}", file_salt, pkg_path)
            };
            let instance_id = make_instance_id(&valid_purl, &combined_salt);

            path_to_id.insert(pkg_path.clone(), instance_id.clone());

            let mut dep_names = Vec::new();
            let mut seen_deps = std::collections::HashSet::new();

            // 关键增强：不仅读取 dependencies，还需完整提取 optionalDependencies 和 peerDependencies，
            // 且对根条目额外提取 devDependencies，防止依赖边缺失
            let dep_categories: &[&str] = if is_root {
                &[
                    "dependencies",
                    "devDependencies",
                    "optionalDependencies",
                    "peerDependencies",
                ]
            } else {
                &["dependencies", "optionalDependencies", "peerDependencies"]
            };

            for &cat in dep_categories {
                if let Some(deps) = pkg_data.get(cat).and_then(|d| d.as_object()) {
                    for dep_name in deps.keys() {
                        if seen_deps.insert(dep_name.clone()) {
                            dep_names.push(dep_name.clone());
                        }
                    }
                }
            }

            nodes.push(RawNode {
                pkg_path: pkg_path.clone(),
                name,
                version,
                license: pkg_data
                    .get("license")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned),
                purl: valid_purl,
                instance_id,
                dep_names,
                is_root,
            });
        }

        let mut final_deps = Vec::with_capacity(nodes.len());

        for node in nodes {
            let mut child_ids = Vec::with_capacity(node.dep_names.len());

            for d_name in &node.dep_names {
                if let Some(target_id) = Self::resolve_npm_dep(&node.pkg_path, d_name, &path_to_id)
                {
                    child_ids.push(target_id.clone());
                }
            }

            let dep_type = if node.is_root {
                DependencyType::Application
            } else {
                DependencyType::Library
            };

            let declared_count = node.dep_names.len();
            if let Ok(mut dep) = DependencyBuilder::default()
                .name(node.name)
                .version(Some(node.version))
                .license(node.license)
                .r#type(dep_type)
                .purl(node.purl)
                .instance_id(node.instance_id)
                .dependencies(child_ids)
                .location(location.clone())
                .build()
            {
                dep.properties.insert(
                    "sbom:graph:declared-edges".into(),
                    declared_count.to_string(),
                );
                dep.properties.insert(
                    "sbom:graph:resolved-edges".into(),
                    dep.dependencies.len().to_string(),
                );
                final_deps.push(dep);
            }
        }

        Ok(final_deps)
    }

    fn resolve_npm_dep<'a>(
        caller_pkg_path: &str,
        dep_name: &str,
        path_to_id: &'a HashMap<String, String>,
    ) -> Option<&'a String> {
        let mut curr = caller_pkg_path;

        loop {
            let candidate = if curr.is_empty() {
                format!("node_modules/{}", dep_name)
            } else {
                format!("{}/node_modules/{}", curr, dep_name)
            };

            if let Some(id) = path_to_id.get(&candidate) {
                return Some(id);
            }

            if curr.is_empty() {
                break;
            }

            if let Some(idx) = curr.rfind("/node_modules/") {
                curr = &curr[..idx];
            } else {
                curr = "";
            }
        }

        None
    }

    fn is_os_compatible(pkg_data: &serde_json::Value) -> bool {
        let Some(os_arr) = pkg_data.get("os").and_then(|v| v.as_array()) else {
            return true;
        };
        let items: Vec<&str> = os_arr.iter().filter_map(|v| v.as_str()).collect();
        if items.is_empty() {
            return true;
        }
        let host_os = match std::env::consts::OS {
            "windows" => "win32",
            "macos" => "darwin",
            other => other,
        };
        if items.iter().any(|s| s.strip_prefix('!') == Some(host_os)) {
            return false;
        }
        if items.iter().any(|s| !s.starts_with('!')) {
            return items.contains(&host_os);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_npm_lock_producer_use_file() {
        let producer = NpmLockProducer::default();
        let config = SbomProducerConfiguration {
            base_path: PathBuf::from("."),
            use_debug: false,
        };
        assert!(producer.use_file(Path::new("package-lock.json"), &config));
        assert!(producer.use_file(Path::new("sub/package-lock.json"), &config));
        assert!(!producer.use_file(Path::new("package.json"), &config));
    }

    #[test]
    fn test_npm_lock_os_compatibility_filter() {
        let host_os = match std::env::consts::OS {
            "windows" => "win32",
            "macos" => "darwin",
            other => other,
        };
        let other_os = if host_os == "win32" { "linux" } else { "win32" };
        let excluded = serde_json::json!({ "os": [other_os] });
        let negated = serde_json::json!({ "os": [format!("!{host_os}")] });
        let allowed = serde_json::json!({ "os": [host_os, other_os] });
        let unrestricted = serde_json::json!({});

        assert!(!NpmLockProducer::is_os_compatible(&excluded));
        assert!(!NpmLockProducer::is_os_compatible(&negated));
        assert!(NpmLockProducer::is_os_compatible(&allowed));
        assert!(NpmLockProducer::is_os_compatible(&unrestricted));
    }

    #[test]
    fn test_npm_lock_producer_v2_v3_parsing() {
        let lock_json = serde_json::json!({
            "name": "my-web-app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "my-web-app",
                    "version": "1.0.0",
                    "dependencies": {
                        "express": "^4.18.2",
                        "lodash": "^4.17.21"
                    }
                },
                "node_modules/express": {
                    "version": "4.18.2",
                    "license": "MIT",
                    "dependencies": {
                        "qs": "6.11.0"
                    }
                },
                "node_modules/express/node_modules/qs": {
                    "version": "6.11.0"
                },
                "node_modules/lodash": {
                    "version": "4.17.21"
                }
            }
        });

        let deps =
            NpmLockProducer::parse_npm_lock(&lock_json, "my-web-app/package-lock.json", None)
                .unwrap();

        // 包含项目根节点 (my-web-app: Application) 以及 3 个库 (express, qs, lodash)
        assert_eq!(deps.len(), 4);

        let root_dep = deps
            .iter()
            .find(|d| d.name == "my-web-app")
            .expect("must find root app");
        assert_eq!(root_dep.r#type, DependencyType::Application);
        assert_eq!(root_dep.version.as_deref(), Some("1.0.0"));
        // 关键断言：验证项目根节点连接到了其直接依赖 (express 和 lodash) 的边！
        assert_eq!(root_dep.dependencies.len(), 2);

        let express_dep = deps
            .iter()
            .find(|d| d.name == "express")
            .expect("must find express");
        assert_eq!(express_dep.version.as_deref(), Some("4.18.2"));
        assert_eq!(express_dep.license.as_deref(), Some("MIT"));
        assert_eq!(
            express_dep.dependencies.len(),
            1,
            "express should depend on qs"
        );

        let lodash_dep = deps
            .iter()
            .find(|d| d.name == "lodash")
            .expect("must find lodash");
        assert_eq!(lodash_dep.version.as_deref(), Some("4.17.21"));
        assert!(lodash_dep.dependencies.is_empty());
    }

    #[test]
    fn test_npm_lock_producer_optional_and_peer_dependencies() {
        let lock_json = serde_json::json!({
            "name": "edge-case-app",
            "version": "2.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "edge-case-app",
                    "version": "2.0.0",
                    "optionalDependencies": {
                        "opt-pkg": "^1.0.0"
                    },
                    "peerDependencies": {
                        "peer-pkg": "^2.0.0"
                    }
                },
                "node_modules/opt-pkg": {
                    "version": "1.0.0",
                    "peerDependencies": {
                        "peer-pkg": "^2.0.0"
                    }
                },
                "node_modules/peer-pkg": {
                    "version": "2.0.0"
                }
            }
        });

        let deps =
            NpmLockProducer::parse_npm_lock(&lock_json, "edge-case-app/package-lock.json", None)
                .unwrap();

        assert_eq!(deps.len(), 3);
        let root_dep = deps
            .iter()
            .find(|d| d.name == "edge-case-app")
            .expect("must find root");
        // 根节点同时解析出 optional 和 peer 依赖边
        assert_eq!(root_dep.dependencies.len(), 2);

        let opt_dep = deps
            .iter()
            .find(|d| d.name == "opt-pkg")
            .expect("must find opt-pkg");
        // 子包 opt-pkg 也正确解析了 peerDependencies 依赖边到 peer-pkg
        assert_eq!(opt_dep.dependencies.len(), 1);
    }
}
