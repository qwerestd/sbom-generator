use std::path::Path;

use crate::analyze::producers::dynamic_producer::DynamicProducer;
use crate::analyze::producers::maven::cli_driver::MavenCliDriver;
use crate::model::configuration::Configuration;
use crate::model::dependency::Dependency;

#[derive(Default)]
pub struct MavenDynamicProducer {}

impl DynamicProducer for MavenDynamicProducer {
    fn is_applicable(&self, configuration: &Configuration) -> bool {
        let dir = Path::new(&configuration.directory);
        dir.join("pom.xml").exists() && MavenCliDriver::is_available_for_dir(dir)
    }

    fn detect_dependencies(
        &self,
        configuration: &Configuration,
    ) -> anyhow::Result<Vec<Dependency>> {
        let dir = Path::new(&configuration.directory);
        MavenCliDriver::generate_dependencies(dir).map_err(|e| anyhow::anyhow!(e))
    }
}
