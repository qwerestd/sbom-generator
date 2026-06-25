use std::fs;
use std::io::Write;

// 注意：这里新增引入了 DependencyBuilder，用于构建依赖图节点
use serde_cyclonedx::cyclonedx::v_1_6::{
    ComponentBuilder, CycloneDxBuilder, DependencyBuilder as CdxDependencyBuilder,
};

use crate::model::configuration::Configuration;
use crate::model::dependency::Dependency;

pub fn generate_sbom(
    dependencies: Vec<Dependency>,
    configuration: &Configuration,
) -> anyhow::Result<()> {
    let mut file = fs::File::create(configuration.output.as_str()).expect("cannot create file");

    let mut components = Vec::new();
    let mut cdx_dependencies = Vec::new();

    // 放弃使用 into_iter().map().collect()，改用 for 循环，
    // 因为我们现在一次迭代要同时生成 Component（组件）和 CdxDependency（依赖关系）
    for d in dependencies {
        // --- [1. 构建组件列表 (components)] ---
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
            // 【关键修复】：必须给组件分配 bom-ref，依赖树才能引用到它！
            component_builder.bom_ref(d.purl.clone());
        }

        components.push(component_builder.build().unwrap());

        // --- [2. 构建依赖关系树 (dependencies)] ---
        if !d.purl.is_empty() {
            let mut dep_node_builder = CdxDependencyBuilder::default();
            // ref_ 对应规范里的 "ref" 字段（因为 ref 是 Rust 关键字，所以加了下划线）
            dep_node_builder.ref_(d.purl.clone());

            // 如果它有子依赖，则填入 dependsOn 字段
            if !d.dependencies.is_empty() {
                dep_node_builder.depends_on(d.dependencies);
            }

            // 将该节点推入关系树数组
            if let Ok(dep_node) = dep_node_builder.build() {
                cdx_dependencies.push(dep_node);
            }
        }
    }

    // --- [3. 组装最终的 SBOM] ---
    let cyclonedx = CycloneDxBuilder::default()
        .bom_format("CycloneDX")
        .spec_version("1.6")
        .version(1)
        .components(components)
        .dependencies(cdx_dependencies)
        .build();

    let value_to_write =
        serde_json::to_string(&cyclonedx.unwrap()).expect("cannot get CycloneDX file");
    file.write_all(value_to_write.as_bytes())?;

    Ok(())
}
