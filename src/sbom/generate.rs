use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::sync::OnceLock;

use serde_cyclonedx::cyclonedx::v_1_6::{
    ComponentBuilder, CycloneDxBuilder, DependencyBuilder as CdxDependencyBuilder,
};

use crate::model::configuration::Configuration;
use crate::model::dependency::Dependency;
use crate::utils::license_resolver::LicenseResolver;
use crate::utils::osv_scanner::{OsvScanner, VulnerabilityInfo};

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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    vulnerabilities: Vec<serde_json::Value>,
}

fn license_choice(value: &str) -> serde_json::Value {
    if value.split_whitespace().any(|part| {
        ["OR", "AND", "WITH"]
            .iter()
            .any(|op| part.eq_ignore_ascii_case(op))
    }) {
        return serde_json::json!([{ "expression": value }]);
    }

    static SPDX_IDS: OnceLock<std::collections::HashSet<String>> = OnceLock::new();
    let ids = SPDX_IDS.get_or_init(|| {
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../../resources/schemas/spdx.schema.json"))
                .expect("bundled SPDX license schema must be valid JSON");
        schema["enum"]
            .as_array()
            .expect("bundled SPDX license schema must list IDs")
            .iter()
            .filter_map(|id| id.as_str().map(str::to_owned))
            .collect()
    });
    if ids.contains(value) {
        serde_json::json!([{ "license": { "id": value } }])
    } else {
        serde_json::json!([{ "license": { "name": value } }])
    }
}

pub fn generate_sbom(
    dependencies: Vec<Dependency>,
    configuration: &Configuration,
) -> anyhow::Result<()> {
    let mut components = Vec::new();
    let mut cdx_dependencies = Vec::new();

    // 🚨 启动 OSV 漏洞联动扫描引擎（融合在线 OSV.dev Batch API + 毫秒级离线知识库）
    let vuln_map = OsvScanner::scan_dependencies(
        &dependencies,
        Some(configuration.directory.as_str()),
        configuration.dynamic,
    );

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

        components.push(
            component_builder
                .build()
                .map_err(|e| anyhow::anyhow!("invalid component: {e}"))?,
        );

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
        .ok_or_else(|| anyhow::anyhow!("CycloneDX serialization did not produce an object"))?;

    let real_now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let metadata_val = serde_json::json!({
        "timestamp": real_now,
        "tools": [
            {
                "vendor": "BNBU_DS",
                "name": "sbom-generator",
                "version": env!("CARGO_PKG_VERSION")
            }
        ]
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

                // 【核心补强 1：开源许可证合规元数据 (License Metadata) 注入】
                if let Some(spdx_lic) = LicenseResolver::resolve_license(d) {
                    comp_obj.insert("licenses".to_string(), license_choice(&spdx_lic));
                }

                // 【方向二兑现：注入文件物理路径与 OSV 风险标签 (Properties)】
                let mut props = Vec::new();
                if let Some(loc) = &d.location {
                    let rel_path = std::path::Path::new(&loc.block.file)
                        .strip_prefix(&configuration.directory)
                        .map(|p| p.to_string_lossy().replace('\\', "/"))
                        .unwrap_or_else(|_| loc.block.file.replace('\\', "/"));
                    let clean_path = rel_path.trim_start_matches('/').to_string();
                    props.push(serde_json::json!({
                        "name": "syft:location:0:path",
                        "value": if clean_path.is_empty() { loc.block.file.replace('\\', "/") } else { clean_path }
                    }));
                }
                if let Some(vulns) = vuln_map.get(&d.instance_id) {
                    let ids: Vec<&str> = vulns.iter().map(|v| v.id.as_str()).collect();
                    props.push(serde_json::json!({
                        "name": "osv:vulnerabilities",
                        "value": ids.join(", ")
                    }));
                }
                // 【核心新增：动态依赖加载状态注入】
                let status_str = match d.dynamic_status {
                    crate::model::dependency::DynamicLoadStatus::Loaded => "loaded",
                    crate::model::dependency::DynamicLoadStatus::Dormant => "dormant",
                    crate::model::dependency::DynamicLoadStatus::NotTraced => "untraced",
                };
                props.push(serde_json::json!({
                    "name": "sbom:runtime:status",
                    "value": status_str
                }));
                if !props.is_empty() {
                    comp_obj.insert("properties".to_string(), serde_json::Value::Array(props));
                }
            }
        }
    }

    // 组装 CycloneDX 1.6 标准 `vulnerabilities` 列表（按漏洞 ID 归并受影响的实例 ref）
    let mut grouped_vulns: BTreeMap<String, (VulnerabilityInfo, Vec<String>)> = BTreeMap::new();
    for (instance_id, vulns) in &vuln_map {
        for v in vulns {
            let entry = grouped_vulns
                .entry(v.id.clone())
                .or_insert_with(|| (v.clone(), Vec::new()));
            if !entry.1.contains(instance_id) {
                entry.1.push(instance_id.clone());
            }
        }
    }

    let cdx_vulnerabilities: Vec<serde_json::Value> = grouped_vulns
        .into_values()
        .map(|(info, affected_refs)| {
            let affects: Vec<serde_json::Value> = affected_refs
                .into_iter()
                .map(|r| serde_json::json!({ "ref": r }))
                .collect();
            let recommendation = info
                .fixed_version
                .as_ref()
                .map(|fv| format!("建议升级至安全版本 >= {}", fv))
                .unwrap_or_else(|| "请关注上游官方安全补丁".to_string());

            serde_json::json!({
                "id": info.id,
                "source": {
                    "name": info.source,
                    "url": "https://osv.dev"
                },
                "ratings": [
                    {
                        "severity": info.severity.to_lowercase(),
                        "score": info.score,
                        "method": "CVSSv3"
                    }
                ],
                "description": info.summary,
                "recommendation": recommendation,
                "affects": affects
            })
        })
        .collect();

    if !cdx_vulnerabilities.is_empty() {
        println!(
            " -> 🚨 [OSV 漏洞扫描器] 检出 {} 个高危/中危 CVE/GHSA 漏洞，波及 {} 个组件实例！",
            cdx_vulnerabilities.len(),
            vuln_map.len()
        );
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
        vulnerabilities: cdx_vulnerabilities,
    };

    let value_to_write = serde_json::to_string_pretty(&final_output)?;
    let mut file = fs::File::create(configuration.output.as_str())?;
    file.write_all(value_to_write.as_bytes())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::license_choice;

    #[test]
    fn license_choice_uses_spdx_expression_id_or_name() {
        assert_eq!(
            license_choice("MIT OR Apache-2.0")[0]["expression"],
            "MIT OR Apache-2.0"
        );
        assert_eq!(license_choice("MIT")[0]["license"]["id"], "MIT");
        assert_eq!(
            license_choice("Custom Proprietary")[0]["license"]["name"],
            "Custom Proprietary"
        );
    }
}
