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
fn partial_lock_does_not_hide_manifest_and_pnpm_collects_transitives() {
    let (dir, cfg) = fixture("partial_npm_lock");
    fs::write(
        dir.join("package-lock.json"),
        r#"{"packages":{"":{"name":"app","version":"1.0.0"},"node_modules/missing":{}}}"#,
    )
    .unwrap();
    fs::write(
        dir.join("package.json"),
        r#"{"name":"app","version":"1.0.0","dependencies":{"missing":"2.0.0"}}"#,
    )
    .unwrap();
    analyze(&cfg, false).unwrap();
    let json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&cfg.output).unwrap()).unwrap();
    assert!(json["components"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["name"] == "missing"));

    let (dir, cfg) = fixture("pnpm_multidoc");
    fs::write(
        dir.join("package.json"),
        r#"{"name":"app","version":"1.0.0"}"#,
    )
    .unwrap();
    fs::write(dir.join("pnpm-lock.yaml"), "---\nlockfileVersion: '9.0'\npackages:\n  manager@1.0.0: {}\n---\nlockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      a: {version: 1.0.0}\npackages:\n  a@1.0.0: {}\n  b@2.0.0: {}\nsnapshots:\n  a@1.0.0:\n    dependencies: {b: 2.0.0}\n  b@2.0.0: {}\n").unwrap();
    analyze(&cfg, false).unwrap();
    let json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&cfg.output).unwrap()).unwrap();
    for name in ["manager", "a", "b"] {
        assert!(json["components"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == name));
    }
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
fn unresolved_manifest_ranges_are_preserved_without_inventing_versions() {
    let (dir, cfg) = fixture("version_ranges");
    fs::write(dir.join("package.json"), r#"{"name":"range-demo","version":"1.0.0","dependencies":{"range-demo-npm":"^1.2.3","pinned-demo":"1.2.3","any-demo":"*","tag-demo":"latest"}}"#).unwrap();
    fs::write(
        dir.join("requirements.txt"),
        "python-range>=1.0,<2.0\npython-pinned==1.2.3\npython-hashed==1.2.3 --hash=sha256:abc\npython-combined>=1.0,==1.2.3\n",
    )
    .unwrap();
    fs::write(dir.join("Cargo.toml"), "[package]\nname='range-demo'\nversion='1.0.0'\n[dependencies]\ncargo-range='1.2.3'\ncargo-pinned='=1.2.3'\n").unwrap();
    analyze(&cfg, false).unwrap();
    let bom: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&cfg.output).unwrap()).unwrap();
    let components = bom["components"].as_array().unwrap();
    for name in [
        "range-demo-npm",
        "any-demo",
        "tag-demo",
        "python-range",
        "cargo-range",
    ] {
        let c = components.iter().find(|c| c["name"] == name).unwrap();
        assert!(
            c.get("version").is_none_or(|v| v.is_null()),
            "unresolved {name} must not invent a version"
        );
        assert!(c["properties"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "sbom:version:status" && p["value"] == "unresolved"));
    }
    for name in [
        "pinned-demo",
        "python-pinned",
        "python-hashed",
        "python-combined",
        "cargo-pinned",
    ] {
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
    for name in ["java-range", "gradle-range"] {
        assert!(cs
            .iter()
            .any(|c| c["name"] == name && c.get("version").is_none_or(|v| v.is_null())));
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

#[test]
fn go_catalog_matches_syft_replacements_without_checksum_or_workspace_leaks() {
    let (dir, cfg) = fixture("go_syft_policy");
    fs::write(
        dir.join("go.work"),
        "go 1.22\nreplace example.com/required => example.com/workspace-leak v9.0.0\n",
    )
    .unwrap();
    fs::write(dir.join("go.mod"), "module example.com/app\ngo 1.22\nrequire (\nexample.com/required v1.0.0\nexample.com/local v1.0.0\nexample.com/excluded v1.0.0\n)\nreplace example.com/local => ./local\nreplace example.com/unused => example.com/fork v2.0.0\nexclude example.com/excluded v1.0.0\n").unwrap();
    fs::write(dir.join("go.sum"), "example.com/historical v8.0.0 h1:abc\n").unwrap();
    fs::create_dir_all(dir.join("empty")).unwrap();
    fs::write(dir.join("empty/go.mod"), "module example.com/empty\n").unwrap();
    fs::write(
        dir.join("empty/go.sum"),
        "example.com/stale v7.0.0 h1:abc\n",
    )
    .unwrap();
    fs::create_dir_all(dir.join("sum-only")).unwrap();
    fs::write(
        dir.join("sum-only/go.sum"),
        "example.com/orphan v6.0.0 h1:abc\n",
    )
    .unwrap();
    analyze(&cfg, false).unwrap();
    let bom: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&cfg.output).unwrap()).unwrap();
    let cs = bom["components"].as_array().unwrap();
    assert_eq!(cs.len(), 5);
    for (name, version) in [
        ("example.com/required", "v1.0.0"),
        ("example.com/fork", "v2.0.0"),
    ] {
        assert_eq!(
            cs.iter().find(|c| c["name"] == name).unwrap()["version"],
            version
        );
    }
    let local = cs
        .iter()
        .find(|c| c["name"] == "example.com/local")
        .unwrap();
    assert!(local.get("version").is_none());
    assert_eq!(local["purl"], "pkg:golang/example.com/local");
    let refs: std::collections::HashSet<_> =
        cs.iter().filter_map(|c| c["bom-ref"].as_str()).collect();
    for edge in bom["dependencies"].as_array().unwrap() {
        assert!(refs.contains(edge["ref"].as_str().unwrap()));
        for child in edge["dependsOn"].as_array().into_iter().flatten() {
            assert!(refs.contains(child.as_str().unwrap()));
        }
    }
}

#[test]
fn go_dynamic_scan_builds_real_local_import_graph_when_toolchain_is_available() {
    if !std::process::Command::new("go")
        .arg("version")
        .output()
        .is_ok_and(|o| o.status.success())
    {
        eprintln!("Go toolchain unavailable; structured-output unit tests still run");
        return;
    }
    let (dir, cfg) = fixture("go_dynamic_source");
    fs::create_dir_all(dir.join("lib")).unwrap();
    fs::write(dir.join("go.mod"), "module example.com/app\ngo 1.20\nrequire example.com/local v0.0.0\nreplace example.com/local => ./lib\n").unwrap();
    fs::write(
        dir.join("main.go"),
        "package main\nimport \"example.com/local\"\nfunc main() { local.Value() }\n",
    )
    .unwrap();
    fs::write(
        dir.join("lib/go.mod"),
        "module example.com/local\ngo 1.20\n",
    )
    .unwrap();
    fs::write(
        dir.join("lib/lib.go"),
        "package local\nfunc Value() int { return 1 }\n",
    )
    .unwrap();
    analyze(&cfg, true).unwrap();
    let bom: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&cfg.output).unwrap()).unwrap();
    let cs = bom["components"].as_array().unwrap();
    let root = cs.iter().find(|c| c["name"] == "example.com/app").unwrap();
    assert!(
        root["properties"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "sbom:analysis:method" && p["value"] == "go-package-imports"),
        "{root}"
    );
    let edge = bom["dependencies"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["ref"] == root["bom-ref"])
        .unwrap();
    assert_eq!(edge["dependsOn"].as_array().unwrap().len(), 1);
    let child = cs
        .iter()
        .find(|c| c["bom-ref"] == edge["dependsOn"][0])
        .unwrap();
    assert_eq!(child["name"], "example.com/local");
    assert!(child.get("version").is_none());
}
