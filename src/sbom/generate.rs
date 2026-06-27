use std::fs;
use std::io::Write;

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
) -> anyhow::Result<()> {
    let mut file = fs::File::create(configuration.output.as_str()).expect("cannot create file");

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

        components.push(component_builder.build().unwrap());

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
    let raw_obj = raw_val.as_object_mut().unwrap();

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

                // 【方向二兑现：注入文件物理路径 (Properties)】
                if let Some(loc) = &d.location {
                    comp_obj.insert(
                        "properties".to_string(),
                        serde_json::json!([
                            {
                                "name": "syft:location:0:path",
                                "value": loc.block.file
                            }
                        ]),
                    );
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

    Ok(())
}
