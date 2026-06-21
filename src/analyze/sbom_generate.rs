use crate::analyze::producers::cargo_producer::CargoProducer;
use crate::analyze::producers::maven::maven_producer::MavenProducerBuilder;
use crate::analyze::producers::npm_producer::NpmProducer;
use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::analyze::producers::pypi_producer::PypiProducer;
use crate::model::configuration::Configuration;
use crate::sbom::generate::generate_sbom;
use crate::utils::file_utils::get_files;
use std::path::PathBuf;
/// Analyze paths, find dependencies and write the SBOM to disk.
/// The [configuration] is the configuration of the tool (directory to scan, etc)
pub fn analyze(configuration: &Configuration) -> anyhow::Result<()> {
    let mut dependencies = vec![];
    if configuration.use_debug {
        configuration.print_configuration();
    }

    let all_producers: Vec<Box<dyn SbomProducer>> = vec![
        Box::new(MavenProducerBuilder::default().build().unwrap()),
        Box::new(NpmProducer::default()),
        Box::new(CargoProducer::default()),
        Box::new(PypiProducer::default()),
    ];

    let all_files = get_files(configuration.directory.as_str()).expect("cannot read directory");
    let producer_configuration = SbomProducerConfiguration {
        base_path: PathBuf::from(configuration.directory.clone()),
        use_debug: configuration.use_debug,
    };

    for sbom_producer in all_producers {
        let producer_files = all_files
            .clone()
            .iter()
            .filter(|f| sbom_producer.use_file(f, &producer_configuration))
            .map(|v| (*v).clone())
            .collect::<Vec<PathBuf>>();

        let dependencies_found =
            sbom_producer.find_dependencies(producer_files.as_slice(), &producer_configuration);

        if let Ok(deps) = dependencies_found {
            dependencies.extend(deps);
        }
    }

    for dep in dependencies.iter() {
        let dep_file = dep
            .location
            .as_ref()
            .map(|v| v.block.file.clone())
            .unwrap_or("no file".to_string());
        let dep_line = dep.location.as_ref().map(|v| v.block.start.line);
        println!(
            "dependency name={} version={}, file={}, line={:?}",
            dep.name,
            dep.version.clone().unwrap_or("no version".to_string()),
            dep_file,
            dep_line
        )
    }
    generate_sbom(dependencies, configuration).expect("cannot generate SBOM");
    Ok(())
}
