use sbom_generator::{analyze::sbom_generate::analyze, model::configuration::Configuration};
use std::{fs, path::PathBuf};

fn fixture(name: &str) -> (PathBuf, Configuration) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/test_outputs/review_regressions")
        .join(name);
    fs::create_dir_all(&dir).unwrap();
    let cfg = Configuration {
        directory: dir.to_string_lossy().into_owned(),
        output: dir.join("result.json").to_string_lossy().into_owned(),
        use_debug: false,
        dynamic: false,
        allow_exec: false,
    };
    (dir, cfg)
}

#[test]
fn malformed_manifests_fail_without_overwriting_previous_output() {
    for (name, file, content) in [
        ("npm_invalid", "package.json", "{broken"),
        ("cargo_invalid", "Cargo.toml", "[package"),
        ("python_invalid", "pyproject.toml", "[project"),
        (
            "maven_invalid",
            "pom.xml",
            "<project><artifactId>bad</project>",
        ),
    ] {
        let (dir, cfg) = fixture(name);
        fs::write(dir.join(file), content).unwrap();
        fs::write(&cfg.output, "previous output").unwrap();
        let err = analyze(&cfg, false).expect_err(file);
        assert!(format!("{err:#}").contains("invalid"), "{err:#}");
        assert_eq!(fs::read_to_string(&cfg.output).unwrap(), "previous output");
    }
}

#[test]
fn malformed_lock_can_fall_back_to_valid_manifest_with_warning() {
    let (dir, cfg) = fixture("npm_fallback");
    fs::write(dir.join("package-lock.json"), "{broken").unwrap();
    fs::write(
        dir.join("package.json"),
        r#"{"name":"root","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}"#,
    )
    .unwrap();
    analyze(&cfg, false).unwrap();
    let bom: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&cfg.output).unwrap()).unwrap();
    assert!(bom["components"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["name"] == "left-pad"));
}

#[test]
fn root_dynamic_probe_cannot_hide_independent_nested_project() {
    let (dir, cfg) = fixture("npm_nested");
    fs::create_dir_all(dir.join("node_modules")).unwrap();
    fs::create_dir_all(dir.join("independent")).unwrap();
    fs::write(
        dir.join("package.json"),
        r#"{"name":"root","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}"#,
    )
    .unwrap();
    fs::write(
        dir.join("independent/package.json"),
        r#"{"name":"nested","version":"1.0.0","dependencies":{"is-number":"7.0.0"}}"#,
    )
    .unwrap();
    analyze(&cfg, true).unwrap();
    let bom: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&cfg.output).unwrap()).unwrap();
    let components = bom["components"].as_array().unwrap();
    for name in ["left-pad", "is-number"] {
        assert_eq!(components.iter().filter(|c| c["name"] == name).count(), 1);
    }
}
