use std::fs;
use std::io::Write;

use serde_cyclonedx::cyclonedx::v_1_6::{ComponentBuilder, CycloneDxBuilder};

use crate::model::configuration::Configuration;
use crate::model::dependency::Dependency;

pub fn generate_sbom(
    dependencies: Vec<Dependency>,
    configuration: &Configuration,
) -> anyhow::Result<()> {
    let mut file = fs::File::create(configuration.output.as_str()).expect("cannot create file");
    let components: Vec<serde_cyclonedx::cyclonedx::v_1_6::Component> = dependencies
        .into_iter()
        .map(|d| {
            let mut binding = ComponentBuilder::default();
            let mut component_builder = binding.name(d.name.to_string()).type_("library");

            if let Some(v) = d.version {
                component_builder = component_builder.version(&v);
                if !d.purl.is_empty() {
                    component_builder = component_builder.purl(d.purl);
                }
            }

            component_builder.build().unwrap()
        })
        .collect();
    let cyclonedx = CycloneDxBuilder::default()
        .bom_format("CycloneDX")
        .spec_version("1.6")
        .version(1)
        .components(components)
        .build();

    let value_to_write =
        serde_json::to_string(&cyclonedx.unwrap()).expect("cannot get CycloneDX file");
    file.write_all(value_to_write.as_bytes())?;
    Ok(())
}
