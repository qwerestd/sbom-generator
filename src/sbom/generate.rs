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
    metadata: serde_json::Value, // <--- 强行把 metadata 排在第四位！
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

    for d in dependencies {
        let mut component_builder = ComponentBuilder::default();
        component_builder.name(d.name.to_string()).type_("library");

        if let Some(g) = d.group {
            component_builder.group(g);
        }

        if let Some(v) = d.version {
            component_builder.version(&v);
        }

        if !d.purl.is_empty() {
            component_builder.purl(d.purl.clone());
            component_builder.bom_ref(d.purl.clone());
        }

        components.push(component_builder.build().unwrap());

        if !d.purl.is_empty() {
            let mut dep_node_builder = CdxDependencyBuilder::default();
            dep_node_builder.ref_(d.purl.clone());

            if !d.dependencies.is_empty() {
                dep_node_builder.depends_on(d.dependencies);
            }

            if let Ok(dep_node) = dep_node_builder.build() {
                cdx_dependencies.push(dep_node);
            }
        }
    }

    let cyclonedx = CycloneDxBuilder::default()
        .bom_format("CycloneDX")
        .spec_version("1.6")
        .version(1)
        .components(components)
        .dependencies(cdx_dependencies)
        .build()
        .unwrap();

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

    // --- [过继给定序结构体] ---
    // 利用 .remove() 方法，把原JSON里的两棵巨无霸数据树直接“摘”出来塞进结构体
    // 全程发生的是内存指针转移（Move），没有产生任何深拷贝，执行效率极高
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
