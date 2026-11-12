use sbom_generator::{
    analyze::sbom_generate::analyze_with_options, model::configuration::Configuration,
    utils::file_utils::ScanOptions,
};
use std::{fs, io::Write, path::PathBuf};
fn fixture(name: &str) -> (PathBuf, Configuration) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/test_outputs/discovery_inventory")
        .join(name);
    fs::create_dir_all(&dir).unwrap();
    let cfg = Configuration {
        directory: dir.to_string_lossy().into_owned(),
        output: dir.join("bom.json").to_string_lossy().into_owned(),
        use_debug: false,
        dynamic: false,
        allow_exec: false,
    };
    (dir, cfg)
}
fn assert_closed(j: &serde_json::Value) {
    let refs: std::collections::HashSet<_> = j["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["bom-ref"].as_str().unwrap())
        .collect();
    assert_eq!(refs.len(), j["components"].as_array().unwrap().len());
    for d in j["dependencies"].as_array().unwrap() {
        assert!(refs.contains(d["ref"].as_str().unwrap()));
        for c in d["dependsOn"].as_array().into_iter().flatten() {
            assert!(refs.contains(c.as_str().unwrap()));
        }
    }
}
#[test]
fn all_mode_adds_installations_archives_and_keeps_source() {
    let (dir, cfg) = fixture("modes");
    fs::write(
        dir.join("package.json"),
        r#"{"name":"app","version":"1.0.0","dependencies":{"unknown":"^1"}}"#,
    )
    .unwrap();
    fs::create_dir_all(dir.join("node_modules/installed")).unwrap();
    fs::write(
        dir.join("node_modules/installed/package.json"),
        r#"{"name":"installed","version":"2.0.0","dependencies":{"installed-child":"^1","absent-installed":"^2"}}"#,
    )
    .unwrap();
    fs::create_dir_all(dir.join(".venv/Lib/site-packages/demo-3.dist-info")).unwrap();
    fs::create_dir_all(dir.join("node_modules/installed-child")).unwrap();
    fs::write(
        dir.join("node_modules/installed-child/package.json"),
        r#"{"name":"installed-child","version":"1.0.0"}"#,
    )
    .unwrap();
    fs::write(
        dir.join(".venv/Lib/site-packages/demo-3.dist-info/METADATA"),
        "Name: demo\nVersion: 3.0\nRequires-Dist: transport>=1; sys_platform == 'linux'\n",
    )
    .unwrap();
    fs::create_dir_all(dir.join("dist")).unwrap();
    let file = fs::File::create(dir.join("dist/app.jar")).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file(
        "META-INF/maven/example/archived/pom.properties",
        zip::write::SimpleFileOptions::default(),
    )
    .unwrap();
    zip.write_all(b"groupId=example\nartifactId=archived\nversion=4.0\n")
        .unwrap();
    zip.finish().unwrap();
    analyze_with_options(&cfg, false, &ScanOptions::default()).unwrap();
    let source: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&cfg.output).unwrap()).unwrap();
    assert!(!source["components"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["name"] == "installed"));
    analyze_with_options(
        &cfg,
        false,
        &ScanOptions {
            installed: true,
            artifacts: true,
            exclude_dirs: vec![],
        },
    )
    .unwrap();
    let all: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&cfg.output).unwrap()).unwrap();
    for name in [
        "unknown",
        "installed",
        "demo",
        "transport",
        "archived",
        "installed-child",
        "absent-installed",
    ] {
        assert!(
            all["components"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c["name"] == name),
            "missing {name}"
        );
    }
    assert_closed(&all);
    assert!(all["metadata"].get("properties").is_none());
    assert_eq!(
        all["metadata"]["tools"]["components"][0]["name"],
        "sbom-generator"
    );
    let diagnostics: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(format!("{}.scan.json", cfg.output)).unwrap())
            .unwrap();
    assert!(diagnostics["scan"].is_array());
    assert!(diagnostics["components"].is_array());
    analyze_with_options(
        &cfg,
        false,
        &ScanOptions {
            installed: true,
            artifacts: true,
            exclude_dirs: vec!["node_modules".into()],
        },
    )
    .unwrap();
    let excluded: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&cfg.output).unwrap()).unwrap();
    assert!(!excluded["components"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["name"] == "installed"));
}
#[test]
fn legacy_lock_scoped_transitives_and_missing_declarations() {
    let (dir, cfg) = fixture("npm_v1");
    fs::write(dir.join("npm-shrinkwrap.json"),r#"{"lockfileVersion":1,"name":"app","version":"1.0.0","dependencies":{"a":{"version":"1.0.0","requires":{"@scope/b":"^2"},"dependencies":{"@scope/b":{"version":"2.0.0"}}}}}"#).unwrap();
    fs::write(
        dir.join("package.json"),
        r#"{"name":"app","version":"1.0.0","dependencies":{"a":"^1","missing":"~3.0.0"}}"#,
    )
    .unwrap();
    analyze_with_options(&cfg, false, &ScanOptions::default()).unwrap();
    let j: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&cfg.output).unwrap()).unwrap();
    let cs = j["components"].as_array().unwrap();
    assert!(cs
        .iter()
        .any(|c| c["name"] == "@scope/b" && c["version"] == "2.0.0"));
    assert!(cs
        .iter()
        .any(|c| c["name"] == "missing" && c.get("version").is_none()));
    assert_eq!(cs.iter().filter(|c| c["name"] == "a").count(), 1);
    assert_closed(&j);
}
#[test]
fn cargo_cycles_and_target_dependencies_survive_inventory() {
    let (dir, cfg) = fixture("cargo_cycle");
    fs::write(dir.join("Cargo.lock"),"version=3\n[[package]]\nname='a'\nversion='1.0.0'\nsource='registry+https://example.test'\ndependencies=['b']\n[[package]]\nname='b'\nversion='2.0.0'\nsource='registry+https://example.test'\ndependencies=['a']\n").unwrap();
    fs::write(dir.join("Cargo.toml"),"[package]\nname='app'\nversion='1.0.0'\n[target.'cfg(windows)'.dependencies]\nplatform-only='1.0'\n").unwrap();
    analyze_with_options(&cfg, false, &ScanOptions::default()).unwrap();
    let j: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&cfg.output).unwrap()).unwrap();
    for name in ["a", "b", "platform-only"] {
        assert!(j["components"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == name && c["type"] == "library"));
    }
    assert_closed(&j);
}
#[test]
fn conditional_maven_and_python_groups_are_inventoried() {
    let (dir, cfg) = fixture("conditional");
    fs::write(dir.join("pom.xml"),"<project><modelVersion>4.0.0</modelVersion><groupId>x</groupId><artifactId>app</artifactId><version>1</version><profiles><profile><id>optional</id><dependencies><dependency><groupId>x</groupId><artifactId>profile-lib</artifactId><version>2</version></dependency></dependencies></profile></profiles><build><plugins><plugin><artifactId>maven-test-plugin</artifactId><version>1.0</version></plugin></plugins></build></project>").unwrap();
    fs::write(dir.join("pyproject.toml"),"[project]\nname='app'\nversion='1.0'\n[dependency-groups]\ntest=['pytest>=8']\n[project.optional-dependencies]\nweb=['fastapi>=0.1']\n").unwrap();
    analyze_with_options(&cfg, false, &ScanOptions::default()).unwrap();
    let j: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&cfg.output).unwrap()).unwrap();
    for name in ["profile-lib", "maven-test-plugin", "pytest", "fastapi"] {
        assert!(
            j["components"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c["name"] == name),
            "missing {name}"
        );
    }
    assert_closed(&j);
}
