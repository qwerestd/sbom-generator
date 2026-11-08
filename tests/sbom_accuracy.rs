use sbom_generator::{
    model::{
        configuration::Configuration,
        dependency::{DependencyBuilder, DynamicLoadStatus},
    },
    sbom::generate::generate_sbom,
};
use std::{collections::HashSet, fs, path::Path};

#[test]
fn generated_metadata_distinguishes_source_and_runtime_evidence() {
    let output =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test_outputs/accuracy_evidence.json");
    fs::create_dir_all(output.parent().unwrap()).unwrap();
    let config = Configuration {
        directory: "nonexistent-evidence-fixture".into(),
        output: output.to_string_lossy().into(),
        use_debug: false,
        dynamic: false,
        allow_exec: false,
    };
    let deps = vec![
        DependencyBuilder::default()
            .name("@scope/unknown".into())
            .purl("pkg:npm/@scope/unknown".into())
            .dynamic_status(DynamicLoadStatus::Referenced)
            .build()
            .unwrap(),
        DependencyBuilder::default()
            .name("observed".into())
            .purl("pkg:npm/observed@1.0.0".into())
            .license(Some("MIT OR Apache-2.0".into()))
            .dynamic_status(DynamicLoadStatus::Loaded)
            .build()
            .unwrap(),
        DependencyBuilder::default()
            .name("unobserved".into())
            .purl("pkg:npm/unobserved@1.0.0".into())
            .dynamic_status(DynamicLoadStatus::Dormant)
            .build()
            .unwrap(),
    ];
    generate_sbom(deps, &config).unwrap();
    let bom: serde_json::Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    let cs = bom["components"].as_array().unwrap();
    let property = |i: usize, name: &str| {
        cs[i]["properties"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == name)
            .map(|p| p["value"].as_str().unwrap().to_owned())
    };
    assert_eq!(cs[0]["purl"], "pkg:npm/%40scope/unknown");
    assert!(cs[0].get("licenses").is_none());
    assert_eq!(
        property(0, "sbom:runtime:status").as_deref(),
        Some("untraced")
    );
    assert_eq!(
        property(0, "sbom:source:referenced").as_deref(),
        Some("true")
    );
    assert!(property(0, "sbom:reachability:used").is_none());
    assert_eq!(cs[1]["licenses"][0]["expression"], "MIT OR Apache-2.0");
    assert_eq!(
        property(1, "sbom:runtime:status").as_deref(),
        Some("loaded")
    );
    assert_eq!(
        property(2, "sbom:runtime:status").as_deref(),
        Some("dormant")
    );
    assert!(property(2, "sbom:reachability:used").is_none());
}

#[test]
fn benchmark_snapshots_have_valid_package_identities_and_closed_graphs() {
    for file in [
        "test/juice-shop/juice-shop_sbom.json",
        "test/mircoservices/microservices-demo_sbom.json",
        "test/opentelemetry/opentelemetry-demo_sbom.json",
        "test/quickstarts/quickstarts_sbom.json",
    ] {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(file);
        if !path.exists() {
            continue;
        }
        let bom: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let cs = bom["components"].as_array().unwrap();
        let mut refs = HashSet::new();
        for c in cs {
            let reference = c["bom-ref"].as_str().unwrap();
            assert!(
                refs.insert(reference),
                "duplicate ref in {file}: {reference}"
            );
            let purl = c["purl"].as_str().unwrap();
            assert!(
                purl.parse::<packageurl::PackageUrl>().is_ok(),
                "invalid PURL in {file}: {purl}"
            );
        }
        for node in bom["dependencies"].as_array().unwrap() {
            assert!(
                refs.contains(node["ref"].as_str().unwrap()),
                "unknown source in {file}"
            );
            for target in node["dependsOn"].as_array().into_iter().flatten() {
                assert!(
                    refs.contains(target.as_str().unwrap()),
                    "dangling ref in {file}: {target}"
                );
            }
        }
    }
}
