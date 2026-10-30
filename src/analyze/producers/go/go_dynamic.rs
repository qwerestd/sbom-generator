use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::process::Command;

use crate::analyze::producers::dynamic_producer::DynamicProducer;
use crate::analyze::producers::go::go_producer::GoProducer;
use crate::model::configuration::Configuration;
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyType};
use crate::utils::cli_driver::CliLocator;
use crate::utils::file_utils::make_instance_id;

#[derive(Default)]
pub struct GoDynamicProducer {}

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

        let graph_output = Command::new(&go_bin)
            .args(["mod", "graph"])
            .current_dir(work_dir)
            .output()?;

        if !graph_output.status.success() {
            let stderr = String::from_utf8_lossy(&graph_output.stderr);
            anyhow::bail!("go mod graph 执行失败: {}", stderr.trim());
        }

        let graph_stdout = String::from_utf8_lossy(&graph_output.stdout);

        let mvs_stdout = Command::new(&go_bin)
            .args(["list", "-m", "all"])
            .current_dir(work_dir)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string());

        let file_salt = work_dir.join("go.mod").to_string_lossy().replace('\\', "/");

        Self::parse_go_mod_graph(&graph_stdout, mvs_stdout.as_deref(), &file_salt)
    }
}

impl GoDynamicProducer {
    fn parse_mvs_list(mvs_output: &str) -> HashMap<String, Option<String>> {
        let mut active_map: HashMap<String, Option<String>> = HashMap::new();

        for (idx, line) in mvs_output.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            if let Some((left, right)) = line.split_once("=>") {
                let orig_mod = left.split_whitespace().next().unwrap_or("");
                let mut right_parts = right.split_whitespace();
                let _new_mod = right_parts.next().unwrap_or("");
                let new_ver = right_parts.next().map(|v| v.to_string());
                if !orig_mod.is_empty() {
                    active_map.insert(orig_mod.to_string(), new_ver);
                }
            } else {
                let mut parts = line.split_whitespace();
                if let Some(mod_name) = parts.next() {
                    if let Some(ver) = parts.next() {
                        active_map.insert(mod_name.to_string(), Some(ver.to_string()));
                    } else if idx == 0 {
                        active_map.insert(mod_name.to_string(), Some("0.0.0".to_string()));
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
        let mvs_map = mvs_output.map(Self::parse_mvs_list);

        struct NodeMeta {
            module: String,
            version: String,
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

            let resolved_ver = if is_root {
                "0.0.0".to_string()
            } else if let Some(ref mvs) = mvs_map {
                match mvs.get(mod_name) {
                    Some(Some(selected_ver)) => selected_ver.clone(),
                    Some(None) => return None,
                    None => return None,
                }
            } else {
                raw_ver_opt.unwrap_or("0.0.0").to_string()
            };

            let raw_purl = format!("pkg:golang/{}@{}", mod_name, resolved_ver);
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
                    module: mod_name.to_string(),
                    version: resolved_ver,
                    purl: valid_purl,
                    instance_id: instance_id.clone(),
                    is_root,
                });

            in_degree.entry(instance_id.clone()).or_insert(0);
            Some(instance_id)
        };

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
            if (meta.is_root || in_degree.get(id).copied().unwrap_or(0) == 0)
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
                .version(Some(meta.version))
                .r#type(dep_type)
                .purl(meta.purl)
                .instance_id(meta.instance_id)
                .dependencies(valid_children)
                .location(None)
                .build()
            {
                final_deps.push(dep);
            }
        }

        Ok(final_deps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
