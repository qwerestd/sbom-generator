use std::path::{Path, PathBuf};

use crate::model::dependency::Dependency;

pub struct SbomProducerConfiguration {
    pub use_debug: bool,
    pub base_path: PathBuf,
}

pub struct Discovery {
    pub dependencies: Vec<Dependency>,
    pub complete: bool,
    pub files: Vec<PathBuf>,
}

/// Generic trait for SBOM producer
pub trait SbomProducer: Sync {
    fn discover(
        &self,
        paths: &[PathBuf],
        config: &SbomProducerConfiguration,
    ) -> anyhow::Result<Discovery> {
        let mut dependencies = self.find_dependencies_checked(paths, config)?;
        let complete = self.is_complete(paths, &dependencies);
        for dep in &mut dependencies {
            dep.properties
                .entry("sbom:analysis:method".into())
                .or_insert_with(|| "static".into());
            dep.properties.insert(
                "sbom:evidence:parser".into(),
                std::any::type_name::<Self>().into(),
            );
            dep.properties
                .insert("sbom:evidence:files".into(), serde_json::to_string(paths)?);
            dep.properties
                .insert("sbom:evidence:complete".into(), complete.to_string());
        }
        Ok(Discovery {
            dependencies,
            complete,
            files: paths.to_vec(),
        })
    }
    /// Only an explicitly complete resolution may suppress lower-priority inputs.
    fn is_complete(&self, _paths: &[PathBuf], _deps: &[Dependency]) -> bool {
        false
    }
    /// Validate readable structured inputs before invoking permissive extractors.
    fn find_dependencies_checked(
        &self,
        paths: &[PathBuf],
        configuration: &SbomProducerConfiguration,
    ) -> anyhow::Result<Vec<Dependency>> {
        use anyhow::Context;
        for path in paths {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("cannot read {}", path.display()))?;
            let content = content.trim_start_matches('\u{FEFF}');
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if name.ends_with(".json") || name == "pipfile.lock" {
                serde_json::from_str::<serde_json::Value>(content)
                    .with_context(|| format!("invalid JSON in {}", path.display()))?;
            } else if name.ends_with(".toml")
                || matches!(
                    name.as_str(),
                    "cargo.lock" | "poetry.lock" | "uv.lock" | "pipfile"
                )
            {
                toml::from_str::<toml::Value>(content)
                    .with_context(|| format!("invalid TOML in {}", path.display()))?;
            } else if name == "pom.xml" {
                let tree = crate::utils::tree_sitter::tree::get_tree(
                    content,
                    &crate::utils::tree_sitter::language::get_tree_sitter_xml(),
                )
                .ok_or_else(|| anyhow::anyhow!("cannot parse XML in {}", path.display()))?;
                anyhow::ensure!(
                    !tree.root_node().has_error(),
                    "invalid XML in {}",
                    path.display()
                );
            }
        }
        self.find_dependencies(paths, configuration)
    }
    /// Report if a file should be scanned or not
    fn use_file(&self, path: &Path, configuration: &SbomProducerConfiguration) -> bool;
    fn find_dependencies(
        &self,
        paths: &[PathBuf],
        configuration: &SbomProducerConfiguration,
    ) -> anyhow::Result<Vec<Dependency>>;
}
