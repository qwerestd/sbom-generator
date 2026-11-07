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

#[test]
fn manifest_ranges_are_preserved_without_inventing_versions() {
    let (dir, cfg) = fixture("version_ranges");
    fs::write(dir.join("package.json"), r#"{"name":"range-demo","version":"1.0.0","dependencies":{"range-demo-npm":"^1.2.3","pinned-demo":"1.2.3","any-demo":"*","tag-demo":"latest"}}"#).unwrap();
    fs::write(
        dir.join("requirements.txt"),
        "python-range>=1.0,<2.0\npython-pinned==1.2.3\n",
    )
    .unwrap();
    fs::write(dir.join("Cargo.toml"), "[package]\nname='range-demo'\nversion='1.0.0'\n[dependencies]\ncargo-range='1.2.3'\ncargo-pinned='=1.2.3'\n").unwrap();
    analyze(&cfg, false).unwrap();
    let bom: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&cfg.output).unwrap()).unwrap();
    let components = bom["components"].as_array().unwrap();
    for (name, requirement) in [
        ("range-demo-npm", "^1.2.3"),
        ("any-demo", "*"),
        ("tag-demo", "latest"),
        ("python-range", ">=1.0,<2.0"),
        ("cargo-range", "1.2.3"),
    ] {
        let c = components.iter().find(|c| c["name"] == name).unwrap();
        assert!(c.get("version").is_none(), "{c}");
        assert!(!c["purl"].as_str().unwrap().contains('@'), "{c}");
        assert!(
            c["properties"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p["name"] == "sbom:version:requirement" && p["value"] == requirement),
            "{c}"
        );
    }
    for name in ["pinned-demo", "python-pinned", "cargo-pinned"] {
        let c = components.iter().find(|c| c["name"] == name).unwrap();
        assert_eq!(c["version"], "1.2.3");
    }
}

#[test]
fn java_ranges_and_python_prereleases_are_handled_end_to_end() {
    let (dir, cfg) = fixture("java_ranges_python_prerelease");
    fs::write(dir.join("pom.xml"), "<project><modelVersion>4.0.0</modelVersion><groupId>org.example</groupId><artifactId>app</artifactId><version>1.0</version><dependencies><dependency><groupId>org.example</groupId><artifactId>java-range</artifactId><version>[1.0,2.0)</version></dependency></dependencies></project>").unwrap();
    fs::write(
        dir.join("build.gradle"),
        "dependencies { implementation 'org.example:gradle-range:1.+' }",
    )
    .unwrap();
    fs::write(
        dir.join("requirements.txt"),
        "python-rc==2.0rc1\npython-post==1!2.0.post1+cpu\n",
    )
    .unwrap();
    analyze(&cfg, false).unwrap();
    let bom: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&cfg.output).unwrap()).unwrap();
    let cs = bom["components"].as_array().unwrap();
    for (name, req) in [("java-range", "[1.0,2.0)"), ("gradle-range", "1.+")] {
        let c = cs.iter().find(|c| c["name"] == name).unwrap();
        assert!(c.get("version").is_none(), "{c}");
        assert!(!c["purl"].as_str().unwrap().contains('@'));
        assert!(c["properties"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "sbom:version:requirement" && p["value"] == req));
    }
    for (name, ver) in [("python-rc", "2.0rc1"), ("python-post", "1!2.0.post1+cpu")] {
        assert_eq!(
            cs.iter().find(|c| c["name"] == name).unwrap()["version"],
            ver
        );
    }
    let refs: std::collections::HashSet<_> =
        cs.iter().filter_map(|c| c["bom-ref"].as_str()).collect();
    for dep in bom["dependencies"].as_array().unwrap() {
        assert!(refs.contains(dep["ref"].as_str().unwrap()));
        for child in dep["dependsOn"].as_array().into_iter().flatten() {
            assert!(refs.contains(child.as_str().unwrap()));
        }
    }
}
