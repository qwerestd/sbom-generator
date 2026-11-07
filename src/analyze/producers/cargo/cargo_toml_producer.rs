use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::model::dependency::{Dependency, DependencyBuilder, DependencyLocation, DependencyType};
use crate::utils::context_resolver::HierarchicalContext;
use crate::utils::file_utils::make_instance_id;

/// 推广自 Maven `<parent>` 与 `<dependencyManagement>` 的 `Cargo.toml` 静态解析器：
/// - 第一趟：扫描工作区根 `Cargo.toml` 的 `[workspace.package]` 与 `[workspace.dependencies]` 构建受管版本上下文
/// - 第二趟：解析成员 Crate 的 `Cargo.toml`，自动决议 `version.workspace = true` 与 `dep = { workspace = true }`
#[derive(Clone, Default)]
pub struct CargoTomlProducer {}

impl SbomProducer for CargoTomlProducer {
    fn use_file(&self, path: &Path, _config: &SbomProducerConfiguration) -> bool {
        path.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n == "Cargo.toml")
    }

    fn find_dependencies(
        &self,
        paths: &[PathBuf],
        config: &SbomProducerConfiguration,
    ) -> anyhow::Result<Vec<Dependency>> {
        let mut workspace_ctx = HierarchicalContext::new();

        // 1. 尝试从项目根目录及所有候选 Cargo.toml 收集 [workspace] 级属性与受管版本
        let root_toml = config.base_path.join("Cargo.toml");
        if root_toml.exists() {
            if let Ok(content) = fs::read_to_string(&root_toml) {
                Self::collect_workspace_context(&content, &mut workspace_ctx);
            }
        }
        for p in paths {
            {
                let content = fs::read_to_string(p)?;
                Self::collect_workspace_context(&content, &mut workspace_ctx);
            }
        }

        // 2. 第二趟：解析各个 Cargo.toml 并结合 workspace_ctx 补全继承版本
        let mut all_deps = Vec::new();
        for p in paths {
            {
                let content = fs::read_to_string(p)?;
                let file_salt = p.to_string_lossy().replace('\\', "/");
                all_deps.extend(Self::parse_single_cargo_toml(
                    &content,
                    &file_salt,
                    p,
                    &workspace_ctx,
                )?);
            }
        }

        Ok(all_deps)
    }
}

impl CargoTomlProducer {
    pub fn collect_workspace_context(content: &str, ctx: &mut HierarchicalContext) {
        let Ok(toml_val) = toml::from_str::<toml::Value>(content) else {
            return;
        };
        let Some(ws) = toml_val.get("workspace").and_then(|w| w.as_table()) else {
            return;
        };

        if let Some(ws_pkg) = ws.get("package").and_then(|p| p.as_table()) {
            if let Some(ver) = ws_pkg.get("version").and_then(|v| v.as_str()) {
                ctx.insert_property("workspace.version", ver);
            }
        }

        if let Some(ws_deps) = ws.get("dependencies").and_then(|d| d.as_table()) {
            for (dep_key, dep_val) in ws_deps {
                if let Some((pkg_name, Some(ver))) = Self::extract_dep_spec(dep_key, dep_val) {
                    let clean_ver = Self::sanitize_cargo_ver(&ver);
                    if !clean_ver.is_empty() {
                        ctx.insert_managed_version(dep_key.clone(), clean_ver.clone());
                        ctx.insert_managed_version(pkg_name, clean_ver);
                    }
                }
            }
        }
    }

    pub fn parse_single_cargo_toml(
        content: &str,
        file_salt: &str,
        file_path: &Path,
        workspace_ctx: &HierarchicalContext,
    ) -> anyhow::Result<Vec<Dependency>> {
        let toml_val: toml::Value = toml::from_str(content)?;
        let Some(pkg) = toml_val.get("package").and_then(|p| p.as_table()) else {
            // 纯虚拟 Workspace 根清单无 [package] 段时跳过自身实体，仅提供上下文
            return Ok(vec![]);
        };

        let Some(crate_name) = pkg.get("name").and_then(|n| n.as_str()) else {
            return Ok(vec![]);
        };

        let crate_version = match pkg.get("version") {
            Some(v) if v.is_str() => v.as_str().unwrap_or("0.0.0").to_string(),
            Some(v)
                if v.as_table()
                    .and_then(|t| t.get("workspace"))
                    .and_then(|w| w.as_bool())
                    == Some(true) =>
            {
                workspace_ctx
                    .properties
                    .get("workspace.version")
                    .cloned()
                    .unwrap_or_else(|| "0.0.0".to_string())
            }
            _ => "0.0.0".to_string(),
        };

        let location = Some(DependencyLocation::from_file(file_path));
        let root_purl = format!("pkg:cargo/{}@{}", crate_name, crate_version);
        let root_id = make_instance_id(&root_purl, file_salt);

        let mut leaf_deps = Vec::new();
        let mut child_ids = Vec::new();
        let mut seen = HashSet::new();

        for sec in ["dependencies", "dev-dependencies", "build-dependencies"] {
            if let Some(table) = toml_val.get(sec).and_then(|t| t.as_table()) {
                for (dep_key, dep_val) in table {
                    let Some((real_name, raw_ver_opt)) = Self::extract_dep_spec(dep_key, dep_val)
                    else {
                        continue;
                    };

                    let resolved_ver = workspace_ctx
                        .resolve_version(&real_name, raw_ver_opt.as_deref())
                        .or_else(|| workspace_ctx.resolve_version(dep_key, raw_ver_opt.as_deref()))
                        .or_else(|| raw_ver_opt.clone())
                        .map(|v| Self::sanitize_cargo_ver(&v))
                        .filter(|v| !v.is_empty());

                    let (resolved_ver, requirement) = crate::utils::version_spec::manifest_version(
                        resolved_ver.as_deref(),
                        "cargo",
                    );
                    let purl_str = match &resolved_ver {
                        Some(v) => format!("pkg:cargo/{}@{}", real_name, v),
                        None => format!("pkg:cargo/{}", real_name),
                    };

                    let valid_purl = Dependency::auto_fix_and_validate_purl(&purl_str);
                    let child_id = make_instance_id(&valid_purl, file_salt);

                    if !seen.insert(child_id.clone()) {
                        continue;
                    }
                    child_ids.push(child_id.clone());

                    if let Ok(dep) = DependencyBuilder::default()
                        .name(real_name)
                        .version(resolved_ver)
                        .version_requirement(requirement)
                        .r#type(DependencyType::Library)
                        .purl(valid_purl)
                        .instance_id(child_id)
                        .dependencies(vec![])
                        .location(location.clone())
                        .build()
                    {
                        leaf_deps.push(dep);
                    }
                }
            }
        }

        let root_dep = DependencyBuilder::default()
            .name(crate_name.to_string())
            .version(Some(crate_version))
            .r#type(DependencyType::Application)
            .purl(root_purl)
            .instance_id(root_id)
            .dependencies(child_ids)
            .location(location)
            .build()
            .map_err(|e| anyhow::anyhow!(e))?;

        let mut all = Vec::with_capacity(leaf_deps.len() + 1);
        all.push(root_dep);
        all.extend(leaf_deps);
        Ok(all)
    }

    fn extract_dep_spec(dep_key: &str, val: &toml::Value) -> Option<(String, Option<String>)> {
        if let Some(ver_str) = val.as_str() {
            return Some((dep_key.to_string(), Some(ver_str.to_string())));
        }
        if let Some(table) = val.as_table() {
            if table.contains_key("path")
                && !table.contains_key("version")
                && !table.contains_key("workspace")
            {
                return None;
            }
            let real_name = table
                .get("package")
                .and_then(|p| p.as_str())
                .unwrap_or(dep_key)
                .to_string();

            if table.get("workspace").and_then(|w| w.as_bool()) == Some(true) {
                return Some((real_name, Some("workspace".to_string())));
            }
            let ver = table
                .get("version")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            return Some((real_name, ver));
        }
        None
    }

    fn sanitize_cargo_ver(raw: &str) -> String {
        raw.trim().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cargo_workspace_inheritance() {
        let root_ws_toml = r#"
[workspace]
members = ["crates/api"]

[workspace.package]
version = "2.1.0"

[workspace.dependencies]
tokio = { version = "1.37.0", features = ["full"] }
serde = "1.0.210"
"#;

        let member_toml = r#"
[package]
name = "my-api-crate"
version.workspace = true

[dependencies]
tokio = { workspace = true }
serde.workspace = true
anyhow = "^1.0.89"
"#;

        let mut ctx = HierarchicalContext::new();
        CargoTomlProducer::collect_workspace_context(root_ws_toml, &mut ctx);

        let deps = CargoTomlProducer::parse_single_cargo_toml(
            member_toml,
            "crates/api/Cargo.toml",
            Path::new("crates/api/Cargo.toml"),
            &ctx,
        )
        .unwrap();

        assert_eq!(deps.len(), 4);
        let root = deps.iter().find(|d| d.name == "my-api-crate").unwrap();
        assert_eq!(root.version.as_deref(), Some("2.1.0"));
        assert!(deps.iter().any(|d| d.name == "tokio"
            && d.version.is_none()
            && d.version_requirement.as_deref() == Some("1.37.0")));
        assert!(deps.iter().any(|d| d.name == "serde"
            && d.version.is_none()
            && d.version_requirement.as_deref() == Some("1.0.210")));
    }
}
