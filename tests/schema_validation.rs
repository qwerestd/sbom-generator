use std::fs;
use std::path::Path;

#[test]
fn example_sboms_match_cyclonedx_1_6_schema() {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../resources/schemas/bom-1.6.schema.json")).unwrap();
    let spdx: serde_json::Value =
        serde_json::from_str(include_str!("../resources/schemas/spdx.schema.json")).unwrap();
    let jsf: serde_json::Value =
        serde_json::from_str(include_str!("../resources/schemas/jsf-0.82.schema.json")).unwrap();
    let registry = jsonschema::Registry::new()
        .add("http://cyclonedx.org/schema/spdx.schema.json", spdx)
        .unwrap()
        .add("http://cyclonedx.org/schema/jsf-0.82.schema.json", jsf)
        .unwrap()
        .prepare()
        .unwrap();
    let validator = jsonschema::options()
        .with_registry(&registry)
        .build(&schema)
        .unwrap();

    for relative in [
        "examples/fullstack-ecommerce/fullstack-ecommerce_sbom.json",
        "examples/polyglot-showcase/polyglot-showcase_sbom.json",
        "examples/security-edgecases/security-edgecases_sbom.json",
    ] {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
        let bom: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let errors: Vec<String> = validator
            .iter_errors(&bom)
            .take(10)
            .map(|e| format!("{}: {e}", e.instance_path()))
            .collect();
        assert!(errors.is_empty(), "{}: {}", relative, errors.join("; "));
    }
}
