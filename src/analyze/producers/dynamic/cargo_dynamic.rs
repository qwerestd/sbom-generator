use crate::analyze::producers::cargo_metadata::{
    metadata_dependencies_for_project, write_rust_only_51_csv,
};
use crate::analyze::producers::dynamic_producer::DynamicProducer;
use crate::model::configuration::Configuration;
use crate::model::dependency::Dependency;
use std::path::PathBuf;

#[derive(Default)]
pub struct CargoDynamicProducer {}

impl DynamicProducer for CargoDynamicProducer {
    fn is_applicable(&self, configuration: &Configuration) -> bool {
        let mut path = PathBuf::from(&configuration.directory);
        path.push("Cargo.toml");
        path.exists()
    }

    fn detect_dependencies(
        &self,
        configuration: &Configuration,
    ) -> anyhow::Result<Vec<Dependency>> {
        let project_dir = PathBuf::from(&configuration.directory);
        let deps = metadata_dependencies_for_project(
            &project_dir,
            &project_dir,
            configuration.rust_scope,
        )?;
        if let Ok(Some(path)) = write_rust_only_51_csv(&deps, &project_dir) {
            eprintln!("[Cargo] wrote Rust-only validation CSV: {}", path.display());
        }
        Ok(deps)
    }
}
