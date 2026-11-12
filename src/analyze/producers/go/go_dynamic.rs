use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::process::Command;

use crate::analyze::producers::dynamic_producer::DynamicProducer;
use crate::analyze::producers::go::go_producer::GoProducer;
use crate::model::configuration::Configuration;
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyLocation, DependencyType};
use crate::utils::cli_driver::CliLocator;
use crate::utils::file_utils::make_instance_id;

#[derive(Default)]
pub struct GoDynamicProducer {
    env_cache: std::sync::OnceLock<Option<String>>,
}

#[derive(Clone)]
struct ModuleSelection {
    original_version: Option<String>,
    name: String,
    version: Option<String>,
}

impl DynamicProducer for GoDynamicProducer {
    fn is_applicable(&self, configuration: &Configuration) -> bool {
        let dir = Path::new(&configuration.directory);
        dir.join("go.mod").exists() && CliLocator::resolve_go().is_some()
    }

    fn detect_dependencies(
        &self,
        configuration: &Configuration,
    ) -> anyhow::Result<Vec<Dependency>> {
        let work_dir = Path::new(&configuration.directory);
        let go_bin = CliLocator::resolve_go()
            .ok_or_else(|| anyhow::anyhow!("未检测到可用的 go 可执行文件"))?;

        let (graph_res, mvs_res) = std::thread::scope(|s| {
            let g_handle = s.spawn(|| {
                let mut graph_cmd = Command::new(&go_bin);
                graph_cmd
                    .args(["mod", "graph"])
                    .current_dir(work_dir)
                    .env("GOWORK", "off");
                CliLocator::run_with_timeout(graph_cmd, std::time::Duration::from_secs(15))
            });
            let m_handle = s.spawn(|| {
                let mut mvs_cmd = Command::new(&go_bin);
                mvs_cmd
                    .args(["list", "-mod=readonly", "-m", "-json", "all"])
                    .current_dir(work_dir)
                    .env("GOWORK", "off");
                CliLocator::run_with_timeout(mvs_cmd, std::time::Duration::from_secs(15))
            });
            (g_handle.join().unwrap(), m_handle.join().unwrap())
        });

        let graph_output = graph_res?;
        if !graph_output.status.success() {
            let stderr = String::from_utf8_lossy(&graph_output.stderr);
            anyhow::bail!("go mod graph 执行失败: {}", stderr.trim());
        }

        let graph_stdout = String::from_utf8_lossy(&graph_output.stdout);

        let mvs_output = mvs_res?;
        anyhow::ensure!(
            mvs_output.status.success(),
            "go list -m -json all 执行失败: {}",
            String::from_utf8_lossy(&mvs_output.stderr)
        );
        let selections = Self::parse_module_json(&mvs_output.stdout)?;

        let file_salt = work_dir.join("go.mod").to_string_lossy().replace('\\', "/");

        let mut deps = Self::parse_graph(&graph_stdout, Some(selections.clone()), &file_salt)?;
        for dep in &mut deps {
            dep.properties.insert(
                "sbom:go:module-requires".into(),
                serde_json::to_string(&dep.dependencies)?,
            );
            dep.properties
                .insert("sbom:analysis:method".into(), "go-module-graph".into());
        }
        let mut command = Command::new(&go_bin);
        command
            .args(["list", "-mod=readonly", "-deps", "-test", "-json", "./..."])
            .current_dir(work_dir)
            .env("GOWORK", "off");
        let source_result =
            CliLocator::run_with_timeout(command, std::time::Duration::from_secs(45)).and_then(
                |output| {
                    anyhow::ensure!(
                        output.status.success(),
                        "{}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                    Self::apply_package_imports(&output.stdout, &selections, &mut deps)
                },
            );
        if let Err(error) = source_result {
            eprintln!(
                " -> [Go] 源码导入图未完成 ({error:#})，保留模块要求图: {}",
                work_dir.display()
            );
        }
        let go_env_str = self.env_cache.get_or_init(|| {
            let mut command = Command::new(&go_bin);
            command
                .args(["env", "-json", "GOOS", "GOARCH", "GOFLAGS", "GOVERSION"])
                .current_dir(work_dir)
                .env("GOWORK", "off");
            if let Ok(output) =
                CliLocator::run_with_timeout(command, std::time::Duration::from_secs(5))
            {
                if output.status.success() {
                    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
                        return Some(value.to_string());
                    }
                }
            }
            None
        });
        if let Some(env_val) = go_env_str {
            for dep in deps
                .iter_mut()
                .filter(|d| d.r#type == DependencyType::Application)
            {
                dep.properties
                    .insert("sbom:go:environment".into(), env_val.clone());
            }
        }
        Ok(deps)
    }
}

impl GoDynamicProducer {
    fn parse_module_json(bytes: &[u8]) -> anyhow::Result<HashMap<String, ModuleSelection>> {
        let mut selections = HashMap::new();
        for value in serde_json::Deserializer::from_slice(bytes).into_iter::<serde_json::Value>() {
            let value = value?;
            anyhow::ensure!(
                value.get("Error").is_none(),
                "Go module error: {}",
                value["Error"]
            );
            let path = value["Path"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Go module missing Path"))?;
            let original_version = value["Version"].as_str().map(str::to_string);
            let replacement = value.get("Replace");
            if let Some(replacement) = replacement {
                anyhow::ensure!(
                    replacement.get("Error").is_none(),
                    "Go replacement error: {}",
                    replacement["Error"]
                );
            }
            let version = replacement
                .map(|r| r["Version"].as_str().map(str::to_string))
                .unwrap_or_else(|| original_version.clone());
            let name = if replacement.is_some() && version.is_some() {
                replacement
                    .and_then(|r| r["Path"].as_str())
                    .ok_or_else(|| anyhow::anyhow!("replacement missing Path"))?
            } else {
                path
            };
            selections.insert(
                path.to_string(),
                ModuleSelection {
                    original_version,
                    name: name.to_string(),
                    version,
                },
            );
        }
        anyhow::ensure!(!selections.is_empty(), "Go module list is empty");
        Ok(selections)
    }

    fn apply_package_imports(
        bytes: &[u8],
        selections: &HashMap<String, ModuleSelection>,
        deps: &mut [Dependency],
    ) -> anyhow::Result<()> {
        let packages: Vec<serde_json::Value> = serde_json::Deserializer::from_slice(bytes)
            .into_iter()
            .collect::<Result<_, _>>()?;
        anyhow::ensure!(!packages.is_empty(), "没有可分析的 Go package");
        let module_ids: HashMap<_, _> = deps
            .iter()
            .map(|d| (d.name.as_str(), d.instance_id.clone()))
            .collect();
        let mut package_modules = HashMap::new();
        for package in &packages {
            anyhow::ensure!(
                package.get("Error").is_none()
                    && package
                        .get("DepsErrors")
                        .and_then(|v| v.as_array())
                        .is_none_or(Vec::is_empty)
                    && package.get("Incomplete").and_then(|v| v.as_bool()) != Some(true),
                "Go package graph incomplete: {}",
                package["ImportPath"]
            );
            if package["Standard"] == true {
                continue;
            }
            if let (Some(import), Some(module)) = (
                package["ImportPath"].as_str(),
                package["Module"]["Path"].as_str(),
            ) {
                let selected = selections
                    .get(module)
                    .ok_or_else(|| anyhow::anyhow!("unselected module for {import}: {module}"))?;
                let id = module_ids
                    .get(selected.name.as_str())
                    .ok_or_else(|| anyhow::anyhow!("module identity missing: {module}"))?;
                package_modules.insert(import, id.clone());
            }
        }
        let mut edges: HashMap<String, std::collections::BTreeSet<String>> = HashMap::new();
        for package in &packages {
            let Some(from) = package["ImportPath"]
                .as_str()
                .and_then(|p| package_modules.get(p))
            else {
                continue;
            };
            for import in package["Imports"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|i| i.as_str())
            {
                let mapped = package
                    .get("ImportMap")
                    .and_then(|m| m.get(import))
                    .and_then(|v| v.as_str())
                    .unwrap_or(import);
                if let Some(to) = package_modules.get(mapped) {
                    if from != to {
                        edges.entry(from.clone()).or_default().insert(to.clone());
                    }
                }
            }
        }
        // Commit only after complete parsing: failed source analysis must not erase module evidence.
        for dep in deps {
            dep.dependencies = edges
                .remove(&dep.instance_id)
                .unwrap_or_default()
                .into_iter()
                .collect();
            dep.properties.insert(
                "sbom:go:source-imports".into(),
                serde_json::to_string(&dep.dependencies)?,
            );
            dep.properties
                .insert("sbom:analysis:method".into(), "go-package-imports".into());
            dep.properties
                .insert("sbom:go:include-tests".into(), "true".into());
        }
        Ok(())
    }

    fn parse_mvs_list(mvs_output: &str) -> HashMap<String, ModuleSelection> {
        let mut active_map: HashMap<String, ModuleSelection> = HashMap::new();

        for line in mvs_output.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            if let Some((left, right)) = line.split_once("=>") {
                let mut original = left.split_whitespace();
                let orig_mod = original.next().unwrap_or("");
                let original_version = original.next().map(str::to_string);
                let mut right_parts = right.split_whitespace();
                let new_mod = right_parts.next().unwrap_or("");
                let new_ver = right_parts.next().map(|v| v.to_string());
                if !orig_mod.is_empty() {
                    let final_name = if new_ver.is_some() { new_mod } else { orig_mod };
                    active_map.insert(
                        orig_mod.to_string(),
                        ModuleSelection {
                            original_version,
                            name: final_name.to_string(),
                            version: new_ver,
                        },
                    );
                }
            } else {
                let mut parts = line.split_whitespace();
                if let Some(mod_name) = parts.next() {
                    if let Some(ver) = parts.next() {
                        active_map.insert(
                            mod_name.to_string(),
                            ModuleSelection {
                                original_version: Some(ver.to_string()),
                                name: mod_name.to_string(),
                                version: Some(ver.to_string()),
                            },
                        );
                    } else {
                        active_map.insert(
                            mod_name.to_string(),
                            ModuleSelection {
                                original_version: None,
                                name: mod_name.to_string(),
                                version: None,
                            },
                        );
                    }
                }
            }
        }

        active_map
    }

    fn split_graph_token(token: &str) -> (&str, Option<&str>) {
        match token.rsplit_once('@') {
            Some((name, ver)) => (name, Some(ver)),
            None => (token, None),
        }
    }

    pub fn parse_go_mod_graph(
        graph_output: &str,
        mvs_output: Option<&str>,
        file_salt: &str,
    ) -> anyhow::Result<Vec<Dependency>> {
        Self::parse_graph(
            graph_output,
            mvs_output.map(Self::parse_mvs_list),
            file_salt,
        )
    }

    fn parse_graph(
        graph_output: &str,
        mvs_map: Option<HashMap<String, ModuleSelection>>,
        file_salt: &str,
    ) -> anyhow::Result<Vec<Dependency>> {
        struct NodeMeta {
            module: String,
            version: Option<String>,
            purl: String,
            instance_id: String,
            is_root: bool,
        }

        let mut nodes_map: HashMap<String, NodeMeta> = HashMap::new();
        let mut adj_list: HashMap<String, Vec<String>> = HashMap::new();
        let mut in_degree: HashMap<String, usize> = HashMap::new();

        let resolve_and_register = |raw_token: &str,
                                    nodes_map: &mut HashMap<String, NodeMeta>,
                                    in_degree: &mut HashMap<String, usize>|
         -> Option<String> {
            let (mod_name, raw_ver_opt) = Self::split_graph_token(raw_token);

            if mod_name == "go" || mod_name == "toolchain" || mod_name.is_empty() {
                return None;
            }

            let is_root = raw_ver_opt.is_none();

            let (resolved_name, resolved_ver) = if is_root {
                (mod_name.to_string(), None)
            } else if let Some(ref mvs) = mvs_map {
                let selected = mvs.get(mod_name)?;
                (selected.name.clone(), selected.version.clone())
            } else {
                (mod_name.to_string(), raw_ver_opt.map(str::to_string))
            };

            let raw_purl = match &resolved_ver {
                Some(v) => format!("pkg:golang/{resolved_name}@{v}"),
                None => format!("pkg:golang/{resolved_name}"),
            };
            let valid_purl = Dependency::auto_fix_and_validate_purl(&raw_purl);
            let instance_id = make_instance_id(&valid_purl, file_salt);

            nodes_map
                .entry(instance_id.clone())
                .and_modify(|existing| {
                    if is_root {
                        existing.is_root = true;
                    }
                })
                .or_insert_with(|| NodeMeta {
                    module: resolved_name,
                    version: resolved_ver,
                    purl: valid_purl,
                    instance_id: instance_id.clone(),
                    is_root,
                });

            in_degree.entry(instance_id.clone()).or_insert(0);
            Some(instance_id)
        };

        if let Some(selections) = &mvs_map {
            for (name, selected) in selections {
                let token = selected
                    .original_version
                    .as_ref()
                    .map(|v| format!("{name}@{v}"))
                    .unwrap_or_else(|| name.clone());
                resolve_and_register(&token, &mut nodes_map, &mut in_degree);
            }
        }

        for line in graph_output.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let (Some(parent_tok), Some(child_tok)) = (parts.next(), parts.next()) else {
                continue;
            };

            let parent_id_opt = resolve_and_register(parent_tok, &mut nodes_map, &mut in_degree);
            let child_id_opt = resolve_and_register(child_tok, &mut nodes_map, &mut in_degree);

            let (parent_name, parent_version) = Self::split_graph_token(parent_tok);
            if let (Some(selected), Some(version)) = (
                mvs_map.as_ref().and_then(|m| m.get(parent_name)),
                parent_version,
            ) {
                if selected.original_version.as_deref() != Some(version) {
                    continue;
                }
            }

            if let (Some(parent_id), Some(child_id)) = (parent_id_opt, child_id_opt) {
                if parent_id == child_id {
                    continue;
                }
                let children = adj_list.entry(parent_id).or_default();
                if !children.contains(&child_id) {
                    children.push(child_id.clone());
                    *in_degree.entry(child_id).or_insert(0) += 1;
                }
            }
        }

        if nodes_map.is_empty() {
            return Ok(vec![]);
        }

        let mut queue: VecDeque<String> = VecDeque::new();
        let mut reachable: HashSet<String> = HashSet::new();

        for (id, meta) in &nodes_map {
            if (mvs_map.is_some() || meta.is_root || in_degree.get(id).copied().unwrap_or(0) == 0)
                && reachable.insert(id.clone())
            {
                queue.push_back(id.clone());
            }
        }

        while let Some(curr) = queue.pop_front() {
            if let Some(children) = adj_list.get(&curr) {
                for child in children {
                    if reachable.insert(child.clone()) {
                        queue.push_back(child.clone());
                    }
                }
            }
        }

        let mut final_deps = Vec::with_capacity(reachable.len());
        for (id, meta) in nodes_map {
            if !reachable.contains(&id) {
                continue;
            }

            let valid_children: Vec<String> = adj_list
                .get(&id)
                .map(|list| {
                    list.iter()
                        .filter(|cid| reachable.contains(*cid))
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();

            let group = GoProducer::extract_go_namespace(&meta.module);
            let dep_type = if meta.is_root {
                DependencyType::Application
            } else {
                DependencyType::Library
            };

            if let Ok(dep) = DependencyBuilder::default()
                .group(group)
                .name(meta.module)
                .version(meta.version)
                .r#type(dep_type)
                .purl(meta.purl)
                .instance_id(meta.instance_id)
                .dependencies(valid_children)
                .location(Some(DependencyLocation::from_file(Path::new(file_salt))))
                .build()
            {
                final_deps.push(dep);
            }
        }

        final_deps.sort_by(|a, b| a.instance_id.cmp(&b.instance_id));
        Ok(final_deps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_modules_preserve_replacements_and_isolated_selected_modules() {
        let modules = br#"{"Path":"example.com/app","Main":true}
            {"Path":"example.com/old","Version":"v1.0.0","Replace":{"Path":"example.com/fork","Version":"v2.0.0"}}
            {"Path":"example.com/local","Version":"v1.0.0","Replace":{"Path":"C:/directory with spaces/sdk","Dir":"C:/directory with spaces/sdk"}}
            {"Path":"example.com/isolated","Version":"v3.0.0"}"#;
        let selections = GoDynamicProducer::parse_module_json(modules).unwrap();
        let deps = GoDynamicProducer::parse_graph("", Some(selections), "go.mod").unwrap();
        assert_eq!(deps.len(), 4);
        assert!(deps
            .iter()
            .any(|d| d.name == "example.com/fork" && d.version.as_deref() == Some("v2.0.0")));
        assert!(deps
            .iter()
            .any(|d| d.name == "example.com/local" && d.version.is_none()));
        assert!(GoDynamicProducer::parse_module_json(
            br#"{"Path":"bad","Error":{"Err":"unavailable"}}"#
        )
        .is_err());
    }

    #[test]
    fn package_imports_are_aggregated_without_partial_commit() {
        let modules = br#"{"Path":"example.com/app","Main":true}
            {"Path":"example.com/lib","Version":"v1.0.0"}
            {"Path":"example.com/unused","Version":"v1.0.0"}"#;
        let selections = GoDynamicProducer::parse_module_json(modules).unwrap();
        let mut deps = GoDynamicProducer::parse_graph(
            "example.com/app example.com/unused@v1.0.0",
            Some(selections.clone()),
            "go.mod",
        )
        .unwrap();
        let packages = br#"{"ImportPath":"fmt","Standard":true}
            {"ImportPath":"example.com/lib","Module":{"Path":"example.com/lib"},"Imports":["fmt"]}
            {"ImportPath":"example.com/app","Module":{"Path":"example.com/app"},"Imports":["fmt","alias"],"ImportMap":{"alias":"example.com/lib"}}"#;
        GoDynamicProducer::apply_package_imports(packages, &selections, &mut deps).unwrap();
        let lib = deps
            .iter()
            .find(|d| d.name == "example.com/lib")
            .unwrap()
            .instance_id
            .clone();
        let root = deps
            .iter()
            .find(|d| d.r#type == DependencyType::Application)
            .unwrap();
        assert_eq!(root.dependencies, vec![lib]);
        let before = root.dependencies.clone();
        assert!(GoDynamicProducer::apply_package_imports(
            br#"{"ImportPath":"example.com/app","Incomplete":true}"#,
            &selections,
            &mut deps
        )
        .is_err());
        assert_eq!(
            deps.iter()
                .find(|d| d.r#type == DependencyType::Application)
                .unwrap()
                .dependencies,
            before
        );
    }

    #[test]
    fn replacements_preserve_identity_and_stale_versions_do_not_add_edges() {
        let graph = "example.com/app example.com/old@v1.0.0\nexample.com/app example.com/local@v1.0.0\nexample.com/old@v0.9.0 example.com/local@v1.0.0\n";
        let selected = "\nexample.com/app\nexample.com/old v1.0.0 => example.com/fork v2.0.0\nexample.com/local v1.0.0 => ./local\n";
        let deps = GoDynamicProducer::parse_go_mod_graph(graph, Some(selected), "go.mod").unwrap();
        assert_eq!(deps.len(), 3);
        let fork = deps.iter().find(|d| d.name == "example.com/fork").unwrap();
        assert_eq!(fork.version.as_deref(), Some("v2.0.0"));
        assert!(fork.dependencies.is_empty());
        let local = deps.iter().find(|d| d.name == "example.com/local").unwrap();
        assert!(local.version.is_none());
        assert_eq!(local.purl, "pkg:golang/example.com/local");
        let root = deps
            .iter()
            .find(|d| d.r#type == DependencyType::Application)
            .unwrap();
        assert!(root.version.is_none());
        assert_eq!(root.dependencies.len(), 2);
    }

    #[test]
    fn test_parse_go_mod_graph_with_mvs() {
        let graph_output = r#"
github.com/bnbu/demo-service go@1.22.0
github.com/bnbu/demo-service github.com/gin-gonic/gin@v1.9.1
github.com/bnbu/demo-service github.com/pkg/errors@v0.9.1
github.com/gin-gonic/gin@v1.9.1 github.com/bytedance/sonic@v1.9.1
github.com/gin-gonic/gin@v1.9.1 golang.org/x/sys@v0.5.0
github.com/bytedance/sonic@v1.9.1 golang.org/x/sys@v0.8.0
"#;

        let mvs_output = r#"
github.com/bnbu/demo-service
github.com/bytedance/sonic v1.9.1
github.com/gin-gonic/gin v1.9.1
github.com/pkg/errors v0.9.1
golang.org/x/sys v0.8.0
"#;

        let deps =
            GoDynamicProducer::parse_go_mod_graph(graph_output, Some(mvs_output), "test/go.mod")
                .expect("should parse go mod graph");

        assert_eq!(deps.len(), 5);
        assert!(deps
            .iter()
            .any(|d| d.name == "golang.org/x/sys" && d.version.as_deref() == Some("v0.8.0")));
        assert!(!deps
            .iter()
            .any(|d| d.name == "golang.org/x/sys" && d.version.as_deref() == Some("v0.5.0")));

        let root = deps
            .iter()
            .find(|d| d.name == "github.com/bnbu/demo-service")
            .expect("root exists");
        assert_eq!(root.r#type, DependencyType::Application);
        assert_eq!(root.dependencies.len(), 2);
    }
}
