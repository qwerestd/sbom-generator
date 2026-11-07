use std::fs;
use std::path::Path;
use std::process::Command;

fn workspace() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn generator_cli_handles_multilanguage_project_and_errors() {
    let exe = env!("CARGO_BIN_EXE_sbom-generator");
    let output = workspace().join("target/test_outputs/cli_workflow_sbom.json");
    fs::create_dir_all(output.parent().unwrap()).unwrap();

    let plain = Command::new(exe)
        .current_dir(workspace())
        .args(["-i", "examples/fullstack-ecommerce", "-o"])
        .arg(&output)
        .arg("-s")
        .output()
        .unwrap();
    assert!(
        plain.status.success(),
        "{}",
        String::from_utf8_lossy(&plain.stderr)
    );
    assert!(!String::from_utf8_lossy(&plain.stdout).contains("Dependency Tree Summary"));
    let bom: serde_json::Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(bom["bomFormat"], "CycloneDX");
    let components = bom["components"].as_array().unwrap();
    assert!(components
        .iter()
        .any(|c| c["purl"].as_str().unwrap_or("").starts_with("pkg:npm/")));
    assert!(components
        .iter()
        .any(|c| c["purl"].as_str().unwrap_or("").starts_with("pkg:pypi/")));
    assert!(components
        .iter()
        .any(|c| c["purl"].as_str().unwrap_or("").starts_with("pkg:maven/")));

    let tree = Command::new(exe)
        .current_dir(workspace())
        .args(["-i", "examples/polyglot-showcase", "-o"])
        .arg(&output)
        .args(["-s", "--tree"])
        .output()
        .unwrap();
    assert!(tree.status.success());
    assert!(String::from_utf8_lossy(&tree.stdout).contains("Dependency Tree Summary"));
    assert!(String::from_utf8_lossy(&tree.stdout).contains("MIT OR Apache-2.0"));

    for args in [
        vec!["--unknown"],
        vec!["-i", "does-not-exist", "-o", "out.json", "-s"],
    ] {
        let result = Command::new(exe)
            .current_dir(workspace())
            .args(args)
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(!String::from_utf8_lossy(&result.stderr).contains("panicked"));
    }
}

#[test]
fn comparison_cli_exports_report_and_rejects_invalid_input() {
    let exe = env!("CARGO_BIN_EXE_sbom_compare");
    let sample = workspace().join("examples/fullstack-ecommerce/fullstack-ecommerce_sbom.json");
    let output = workspace().join("target/test_outputs/cli_workflow_comparison.md");
    fs::create_dir_all(output.parent().unwrap()).unwrap();
    let result = Command::new(exe)
        .current_dir(workspace())
        .arg("--our-sbom")
        .arg(&sample)
        .arg("--competitor-sbom")
        .arg(&sample)
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report = fs::read_to_string(output).unwrap();
    assert!(report.contains("100.00"), "{report}");

    let invalid = Command::new(exe).arg("--unknown").output().unwrap();
    assert!(!invalid.status.success());
    assert!(!String::from_utf8_lossy(&invalid.stderr).contains("panicked"));
}
