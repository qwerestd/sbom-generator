use std::fs;
use std::io::Write;
use std::path::PathBuf;

use serde_cyclonedx::cyclonedx::v_1_6::{
    ComponentBuilder, CycloneDxBuilder, DependencyBuilder as CdxDependencyBuilder,
};

use crate::model::configuration::Configuration;
use crate::model::dependency::Dependency;

// =====================================================================
// 【视觉定序神器】：利用 Rust 结构体声明顺序 = JSON输出顺序 的特性
// =====================================================================
#[derive(serde::Serialize)]
struct TopOrderedSbom<'a> {
    #[serde(rename = "bomFormat")]
    bom_format: &'a str,
    #[serde(rename = "specVersion")]
    spec_version: &'a str,
    version: i32,
    metadata: serde_json::Value,
    components: serde_json::Value,
    dependencies: serde_json::Value,
}

pub fn generate_sbom(
    dependencies: Vec<Dependency>,
    configuration: &Configuration,
    warnings: &[String],
) -> anyhow::Result<()> {
    let output_path = PathBuf::from(&configuration.output);
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    let tmp_path = output_path.with_extension(format!(
        "{}tmp",
        output_path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| format!("{e}."))
            .unwrap_or_default()
    ));
    let mut file = fs::File::create(&tmp_path)?;

    let mut components = Vec::new();
    let mut cdx_dependencies = Vec::new();

    // 🚨 注意：这里改为借用引用 `&dependencies`，为了后续 JSON 增强时依然能读取原始数据
    for d in &dependencies {
        let mut component_builder = ComponentBuilder::default();

        // 这里的 type 先给个默认值，稍后在 JSON 降维打击中动态覆写为真实类型
        component_builder.name(d.name.to_string()).type_("library");

        if let Some(g) = &d.group {
            component_builder.group(g.clone());
        }

        if let Some(v) = &d.version {
            component_builder.version(v.clone());
        }

        if !d.purl.is_empty() {
            component_builder.purl(d.purl.clone());
        }

        // 🚀 【防线加固】：严格优先使用 instance_id 作为全局唯一主键
        if !d.instance_id.is_empty() {
            component_builder.bom_ref(d.instance_id.clone());
        } else if !d.purl.is_empty() {
            component_builder.bom_ref(d.purl.clone());
        }

        components.push(component_builder.build().map_err(|e| {
            anyhow::anyhow!(
                "failed to build CycloneDX component for {} ({}): {}",
                d.name,
                d.purl,
                e
            )
        })?);

        let mut dep_node_builder = CdxDependencyBuilder::default();

        // 🚀 【防线加固】：拓扑节点同理，严格绑定身份证
        if !d.instance_id.is_empty() {
            dep_node_builder.ref_(d.instance_id.clone());
        } else if !d.purl.is_empty() {
            dep_node_builder.ref_(d.purl.clone());
        }

        if !d.dependencies.is_empty() {
            dep_node_builder.depends_on(d.dependencies.clone());
        }

        if let Ok(dep_node) = dep_node_builder.build() {
            cdx_dependencies.push(dep_node);
        }
    }

    let cyclonedx = CycloneDxBuilder::default()
        .bom_format("CycloneDX")
        .spec_version("1.6")
        .version(1)
        .components(components)
        .dependencies(cdx_dependencies)
        .build()
        .map_err(|e| anyhow::anyhow!("CycloneDX 构建失败: {}", e))?;

    // --- [动态数据组装] ---
    let mut raw_val = serde_json::to_value(&cyclonedx)?;
    let raw_obj = raw_val
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("CycloneDX output was not a JSON object"))?;

    let real_now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let metadata_val = serde_json::json!({
        "timestamp": real_now,
        "tools": [
            {
                "vendor": "BNBU_DS",
                "name": "sbom-generator",
                "version": env!("CARGO_PKG_VERSION")
            }
        ],
        "properties": warnings
            .iter()
            .enumerate()
            .map(|(idx, warning)| {
                serde_json::json!({
                    "name": format!("sbom-generator:warning:{}", idx),
                    "value": warning
                })
            })
            .collect::<Vec<_>>()
    });

    // =====================================================================
    // 🚀 【神技：JSON 降维打击】：直接在序列化层注入高级特性，避开繁琐的 Builder
    // =====================================================================
    if let Some(components_arr) = raw_obj.get_mut("components").and_then(|c| c.as_array_mut()) {
        for (i, d) in dependencies.iter().enumerate() {
            if let Some(comp_obj) = components_arr.get_mut(i).and_then(|c| c.as_object_mut()) {
                // 【方向四兑现：App/Lib 身份细化】
                let cdx_type = serde_json::to_string(&d.r#type)
                    .unwrap_or_else(|_| "\"library\"".to_string())
                    .replace('"', "");
                comp_obj.insert("type".to_string(), serde_json::json!(cdx_type));

                let mut properties = Vec::new();

                if let Some(declared_version) = &d.declared_version {
                    properties.push(serde_json::json!({
                        "name": "sbom-generator:declaredVersion",
                        "value": declared_version
                    }));
                }

                if let Some(scope) = &d.rust_dependency_scope {
                    properties.push(serde_json::json!({
                        "name": "sbom-generator:rust:dependencyScope",
                        "value": scope
                    }));
                    properties.push(serde_json::json!({
                        "name": "sbom-generator:rust:dependencyScopes",
                        "value": scope
                    }));
                }

                if let Some(relationship) = &d.rust_dependency_relationship {
                    properties.push(serde_json::json!({
                        "name": "sbom-generator:rust:relationship",
                        "value": relationship
                    }));
                }

                if let Some(is_direct) = d.rust_is_direct {
                    properties.push(serde_json::json!({
                        "name": "sbom-generator:rust:direct",
                        "value": is_direct.to_string()
                    }));
                }

                if let Some(target_conditions) = &d.rust_target_conditions {
                    properties.push(serde_json::json!({
                        "name": "sbom-generator:rust:targetConditions",
                        "value": target_conditions
                    }));
                }

                if let Some(activation) = &d.rust_activation {
                    properties.push(serde_json::json!({
                        "name": "sbom-generator:rust:activation",
                        "value": activation
                    }));
                }

                if let Some(is_proc_macro) = d.rust_is_proc_macro {
                    properties.push(serde_json::json!({
                        "name": "sbom-generator:rust:isProcMacro",
                        "value": is_proc_macro.to_string()
                    }));
                }

                if let Some(project_root) = &d.rust_project_root {
                    properties.push(serde_json::json!({
                        "name": "sbom-generator:rust:projectRoot",
                        "value": project_root
                    }));
                }

                if let Some(source_cargo_lock) = &d.rust_source_cargo_lock {
                    properties.push(serde_json::json!({
                        "name": "sbom-generator:rust:sourceCargoLock",
                        "value": source_cargo_lock
                    }));
                }

                if let Some(confirmed) = d.rust_resolved_graph_confirmed {
                    properties.push(serde_json::json!({
                        "name": "sbom-generator:rust:resolvedGraphConfirmed",
                        "value": confirmed.to_string()
                    }));
                }

                if let Some(all_target_present) = d.rust_all_target_present {
                    properties.push(serde_json::json!({
                        "name": "sbom-generator:rust:allTargetPresent",
                        "value": all_target_present.to_string()
                    }));
                }

                if let Some(host_active) = d.rust_host_active {
                    properties.push(serde_json::json!({
                        "name": "sbom-generator:rust:hostActive",
                        "value": host_active.to_string()
                    }));
                }

                if let Some(scope) = &d.python_dependency_scope {
                    properties.push(serde_json::json!({
                        "name": "sbom-generator:python:dependencyScope",
                        "value": scope
                    }));
                    properties.push(serde_json::json!({
                        "name": "sbom-generator:python:scopes",
                        "value": scope
                    }));
                }

                if let Some(relationship) = &d.python_dependency_relationship {
                    properties.push(serde_json::json!({
                        "name": "sbom-generator:python:relationship",
                        "value": relationship
                    }));
                }

                if let Some(is_direct) = d.python_is_direct {
                    properties.push(serde_json::json!({
                        "name": "sbom-generator:python:direct",
                        "value": is_direct.to_string()
                    }));
                }

                if let Some(marker) = &d.python_marker {
                    properties.push(serde_json::json!({
                        "name": "sbom-generator:python:marker",
                        "value": marker
                    }));
                }

                if let Some(activation) = &d.python_activation {
                    properties.push(serde_json::json!({
                        "name": "sbom-generator:python:activation",
                        "value": activation
                    }));
                }

                if let Some(source_type) = &d.python_source_type {
                    properties.push(serde_json::json!({
                        "name": "sbom-generator:python:sourceType",
                        "value": source_type
                    }));
                }

                if let Some(manifest_path) = &d.python_manifest_path {
                    properties.push(serde_json::json!({
                        "name": "sbom-generator:python:manifestPath",
                        "value": manifest_path
                    }));
                }

                if let Some(project_root) = &d.python_project_root {
                    properties.push(serde_json::json!({
                        "name": "sbom-generator:python:projectRoot",
                        "value": project_root
                    }));
                }

                if let Some(confidence) = &d.python_confidence {
                    properties.push(serde_json::json!({
                        "name": "sbom-generator:python:confidence",
                        "value": confidence
                    }));
                }

                if let Some(is_project_package) = d.python_is_project_package {
                    properties.push(serde_json::json!({
                        "name": "sbom-generator:python:isProjectPackage",
                        "value": is_project_package.to_string()
                    }));
                }

                push_property(
                    &mut properties,
                    "sbom-generator:go:modulePath",
                    &d.go_module_path,
                );
                push_property(
                    &mut properties,
                    "sbom-generator:go:projectRoot",
                    &d.go_project_root,
                );
                push_property(
                    &mut properties,
                    "sbom-generator:go:manifestPath",
                    &d.go_manifest_path,
                );
                push_property(
                    &mut properties,
                    "sbom-generator:go:workspaceRoot",
                    &d.go_workspace_root,
                );
                push_property(
                    &mut properties,
                    "sbom-generator:go:goWorkPath",
                    &d.go_go_work_path,
                );
                push_property(&mut properties, "sbom-generator:go:scope", &d.go_scope);
                push_property(
                    &mut properties,
                    "sbom-generator:go:relationship",
                    &d.go_relationship,
                );
                push_bool_property(&mut properties, "sbom-generator:go:direct", d.go_direct);
                push_bool_property(&mut properties, "sbom-generator:go:indirect", d.go_indirect);
                push_bool_property(
                    &mut properties,
                    "sbom-generator:go:mainModule",
                    d.go_main_module,
                );
                push_bool_property(&mut properties, "sbom-generator:go:local", d.go_local);
                push_bool_property(
                    &mut properties,
                    "sbom-generator:go:workspaceMember",
                    d.go_workspace_member,
                );
                push_property(
                    &mut properties,
                    "sbom-generator:go:replacementOriginal",
                    &d.go_replacement_original,
                );
                push_property(
                    &mut properties,
                    "sbom-generator:go:replacementPath",
                    &d.go_replacement_path,
                );
                push_property(
                    &mut properties,
                    "sbom-generator:go:replacementVersion",
                    &d.go_replacement_version,
                );
                push_property(
                    &mut properties,
                    "sbom-generator:go:replacementType",
                    &d.go_replacement_type,
                );
                push_property(
                    &mut properties,
                    "sbom-generator:go:evidenceSource",
                    &d.go_evidence_source,
                );
                push_property(
                    &mut properties,
                    "sbom-generator:go:confidence",
                    &d.go_confidence,
                );
                push_property(
                    &mut properties,
                    "sbom-generator:go:parsingMode",
                    &d.go_parsing_mode,
                );
                push_property(
                    &mut properties,
                    "sbom-generator:go:goVersion",
                    &d.go_version,
                );
                push_property(
                    &mut properties,
                    "sbom-generator:go:toolchainVersion",
                    &d.go_toolchain_version,
                );
                push_property(&mut properties, "sbom-generator:go:goos", &d.go_goos);
                push_property(&mut properties, "sbom-generator:go:goarch", &d.go_goarch);
                push_property(
                    &mut properties,
                    "sbom-generator:go:cgoEnabled",
                    &d.go_cgo_enabled,
                );
                push_bool_property(
                    &mut properties,
                    "sbom-generator:go:hostActive",
                    d.go_host_active,
                );
                push_property(
                    &mut properties,
                    "sbom-generator:go:excludedVersions",
                    &d.go_excluded_versions,
                );
                push_property(
                    &mut properties,
                    "sbom-generator:go:retractions",
                    &d.go_retractions,
                );

                if let Some(loc) = &d.location {
                    properties.push(serde_json::json!({
                        "name": "syft:location:0:path",
                        "value": loc.block.file
                    }));
                }

                if !properties.is_empty() {
                    comp_obj.insert("properties".to_string(), serde_json::json!(properties));
                }
            }
        }
    }

    // --- [过继给定序结构体] ---
    let final_output = TopOrderedSbom {
        bom_format: "CycloneDX",
        spec_version: "1.6",
        version: 1,
        metadata: metadata_val,
        components: raw_obj
            .remove("components")
            .unwrap_or(serde_json::Value::Null),
        dependencies: raw_obj
            .remove("dependencies")
            .unwrap_or(serde_json::Value::Null),
    };

    let value_to_write = serde_json::to_string_pretty(&final_output)?;
    file.write_all(value_to_write.as_bytes())?;
    file.sync_all()?;
    drop(file);
    fs::rename(tmp_path, output_path)?;

    Ok(())
}

fn push_property(properties: &mut Vec<serde_json::Value>, name: &str, value: &Option<String>) {
    if let Some(value) = value.as_ref().filter(|value| !value.is_empty()) {
        properties.push(serde_json::json!({
            "name": name,
            "value": value
        }));
    }
}

fn push_bool_property(properties: &mut Vec<serde_json::Value>, name: &str, value: Option<bool>) {
    if let Some(value) = value {
        properties.push(serde_json::json!({
            "name": name,
            "value": value.to_string()
        }));
    }
}
