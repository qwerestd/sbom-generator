use std::{collections::BTreeMap, fs, path::Path, process::Command};

fn counted<T: Ord>(values: impl IntoIterator<Item = T>) -> BTreeMap<T, u64> {
    let mut counts = BTreeMap::new();
    for value in values {
        *counts.entry(value).or_default() += 1;
    }
    counts
}

#[test]
fn controlled_fixtures_generate_valid_schema_purls_and_closed_graphs() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let schema = |name: &str| -> serde_json::Value {
        serde_json::from_slice(&fs::read(root.join("resources/schemas").join(name)).unwrap())
            .unwrap()
    };
    let registry = jsonschema::Registry::new()
        .add(
            "http://cyclonedx.org/schema/spdx.schema.json",
            schema("spdx.schema.json"),
        )
        .unwrap()
        .add(
            "http://cyclonedx.org/schema/jsf-0.82.schema.json",
            schema("jsf-0.82.schema.json"),
        )
        .unwrap()
        .prepare()
        .unwrap();
    let validator = jsonschema::options()
        .with_registry(&registry)
        .build(&schema("bom-1.6.schema.json"))
        .unwrap();
    let output = root.join("target/test_outputs/controlled_schema");
    fs::create_dir_all(&output).unwrap();
    let mut checked = 0;
    for entry in fs::read_dir(root.join("test/controlled")).unwrap() {
        let fixture = entry.unwrap().path();
        if !fixture.join("expected.json").exists() {
            continue;
        }
        let expected: serde_json::Value =
            serde_json::from_slice(&fs::read(fixture.join("expected.json")).unwrap()).unwrap();
        if expected["expect_failure"] == true {
            continue;
        }
        let dest = output
            .join(fixture.file_name().unwrap())
            .with_extension("json");
        let result = Command::new(env!("CARGO_BIN_EXE_sbom-generator"))
            .current_dir(root)
            .arg("-i")
            .arg(&fixture)
            .arg("-o")
            .arg(&dest)
            .arg("-s")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}: {}",
            fixture.display(),
            String::from_utf8_lossy(&result.stderr)
        );
        let bom: serde_json::Value = serde_json::from_slice(&fs::read(dest).unwrap()).unwrap();
        let errors: Vec<_> = validator.iter_errors(&bom).map(|e| e.to_string()).collect();
        assert!(errors.is_empty(), "{}: {:?}", fixture.display(), errors);
        let mut refs = std::collections::HashSet::new();
        for c in bom["components"].as_array().unwrap() {
            assert!(refs.insert(c["bom-ref"].as_str().unwrap()));
            assert!(c["purl"]
                .as_str()
                .unwrap()
                .parse::<packageurl::PackageUrl>()
                .is_ok());
        }
        let components = bom["components"].as_array().unwrap();
        for (kind, field) in [("library", "libraries"), ("application", "applications")] {
            let actual = counted(
                components
                    .iter()
                    .filter(|c| c["type"] == kind)
                    .map(|c| c["purl"].as_str().unwrap().to_string()),
            );
            let wanted: BTreeMap<String, u64> =
                serde_json::from_value(expected[field].clone()).unwrap();
            assert_eq!(actual, wanted, "{}: {field}", fixture.display());
        }
        let by_ref: BTreeMap<_, _> = components
            .iter()
            .map(|c| (c["bom-ref"].as_str().unwrap(), c))
            .collect();
        let mut edges = Vec::new();
        let mut scoped_edges = Vec::new();
        let source_path = |c: &serde_json::Value| -> String {
            c["properties"]
                .as_array()
                .unwrap()
                .iter()
                .find(|p| p["name"].as_str().unwrap().ends_with(":path"))
                .unwrap()["value"]
                .as_str()
                .unwrap()
                .replace('\\', "/")
        };
        for node in bom["dependencies"].as_array().unwrap() {
            assert!(refs.contains(node["ref"].as_str().unwrap()));
            for child in node["dependsOn"].as_array().into_iter().flatten() {
                assert!(refs.contains(child.as_str().unwrap()));
                let source = by_ref[node["ref"].as_str().unwrap()];
                let target = by_ref[child.as_str().unwrap()];
                let a = source["purl"].as_str().unwrap().to_string();
                let b = target["purl"].as_str().unwrap().to_string();
                edges.push(vec![a.clone(), b.clone()]);
                scoped_edges.push(vec![a, source_path(source), b, source_path(target)]);
                if expected["same_source_edges"] == true {
                    assert_eq!(source_path(source), source_path(target));
                }
            }
        }
        let wanted: Vec<Vec<String>> = serde_json::from_value(expected["edges"].clone()).unwrap();
        assert_eq!(
            counted(edges),
            counted(wanted),
            "{}: edges",
            fixture.display()
        );
        if let Some(scoped) = expected.get("scoped_edges") {
            let wanted: Vec<Vec<String>> = serde_json::from_value(scoped.clone()).unwrap();
            assert_eq!(
                counted(scoped_edges),
                counted(wanted),
                "{}: instance edges",
                fixture.display()
            );
        }
        checked += 1;
    }
    assert_eq!(
        checked, 9,
        "All nine valid controlled fixtures must be checked"
    );
}
