use std::{fs, path::Path, process::Command};

fn cli(input: &Path, output: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_sbom-generator"));
    c.args(["--scan-mode", "source", "-i"])
        .arg(input)
        .arg("-o")
        .arg(output);
    c.env("SBOM_PYTHON_RESOLVE", "0");
    c
}

#[test]
fn native_go_workspace_survives_missing_member_without_mutating_inputs() {
    if Command::new("go").arg("version").output().is_err() {
        eprintln!("Go unavailable; native workspace integration not exercised");
        return;
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target/test_outputs/native_workspace_improvement");
    for name in ["a", "b", "unrelated"] {
        fs::create_dir_all(root.join(name)).unwrap();
    }
    let workspace = "go 1.22\nuse (\n ./a\n ./b\n ./unrelated\n ./missing\n)\n";
    fs::write(root.join("go.work"), workspace).unwrap();
    fs::write(
        root.join("a/go.mod"),
        "module example.test/a\ngo 1.22\nrequire example.test/b v0.0.0\n",
    )
    .unwrap();
    fs::write(
        root.join("a/a.go"),
        "package a\nimport \"example.test/b\"\nvar X = b.X\n",
    )
    .unwrap();
    fs::write(root.join("b/go.mod"), "module example.test/b\ngo 1.22\n").unwrap();
    fs::write(root.join("b/b.go"), "package b\nconst X = 1\n").unwrap();
    fs::write(
        root.join("unrelated/go.mod"),
        "module example.test/unrelated\ngo 1.22\n",
    )
    .unwrap();
    let output = root.join("out.json");
    let run = cli(&root.join("a"), &output)
        .env("GOPROXY", "off")
        .env("GOSUMDB", "off")
        .env("SBOM_GO_WORKSPACE", root.join("go.work"))
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(stdout.contains("[Go] 动态探测部分成功"), "{stdout}");
    let bom: serde_json::Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    let components = bom["components"].as_array().unwrap();
    assert!(components.iter().any(|c| c["name"] == "example.test/b"));
    assert!(!components
        .iter()
        .any(|c| c["name"] == "example.test/unrelated"));
    let refs: std::collections::HashSet<_> = components
        .iter()
        .map(|c| c["bom-ref"].as_str().unwrap())
        .collect();
    assert!(bom["dependencies"]
        .as_array()
        .unwrap()
        .iter()
        .all(|n| n["dependsOn"]
            .as_array()
            .into_iter()
            .flatten()
            .all(|t| refs.contains(t.as_str().unwrap()))));
    assert_eq!(fs::read_to_string(root.join("go.work")).unwrap(), workspace);
    assert!(!root.join("missing").exists());
    let diagnostic = fs::read_to_string(root.join("out.json.scan.json")).unwrap();
    assert!(diagnostic.contains("missing-members"));
}

fn wheel(directory: &Path, name: &str, requires: Option<&str>) {
    use std::io::Write;
    let normalized = name.replace('-', "_");
    let file =
        fs::File::create(directory.join(format!("{normalized}-1.0.0-py3-none-any.whl"))).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let dist = format!("{normalized}-1.0.0.dist-info");
    let metadata = format!(
        "Metadata-Version: 2.1\nName: {name}\nVersion: 1.0.0\n{}\n",
        requires
            .map(|r| format!("Requires-Dist: {r}\n"))
            .unwrap_or_default()
    );
    for (path,text) in [(format!("{dist}/METADATA"),metadata),
        (format!("{dist}/WHEEL"),"Wheel-Version: 1.0\nGenerator: test-fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n".into()),
        (format!("{dist}/RECORD"),String::new())] {
        zip.start_file(path,zip::write::SimpleFileOptions::default()).unwrap();zip.write_all(text.as_bytes()).unwrap();
    }
    zip.finish().unwrap();
}

#[test]
fn native_pip_dry_run_resolves_local_wheels_without_installing_them() {
    let Some(launcher) = sbom_generator::utils::cli_driver::CliLocator::resolve_python_for_dir(
        Path::new(env!("CARGO_MANIFEST_DIR")),
    ) else {
        eprintln!("Python unavailable; native pip integration not exercised");
        return;
    };
    let selected = Command::new(&launcher)
        .args(["-I", "-c", "import sys; print(sys.executable)"])
        .output()
        .unwrap();
    assert!(selected.status.success());
    let python = String::from_utf8_lossy(&selected.stdout).trim().to_owned();
    assert!(Path::new(&python).is_file());
    let root =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test_outputs/native_pip_improvement");
    fs::create_dir_all(root.join("wheels")).unwrap();
    fs::create_dir_all(root.join("project")).unwrap();
    wheel(
        &root.join("wheels"),
        "sbom-fixture-alpha",
        Some("sbom-fixture-beta==1.0.0"),
    );
    wheel(&root.join("wheels"), "sbom-fixture-beta", None);
    fs::write(
        root.join("project/requirements.txt"),
        "sbom-fixture-alpha==1.0.0\n",
    )
    .unwrap();
    let output = root.join("out.json");
    let run = cli(&root.join("project"), &output)
        .env("SBOM_PYTHON_EXECUTABLE", &python)
        .env_remove("SBOM_PYTHON_ENV_MAP")
        .env("SBOM_PYTHON_RESOLVE", "1")
        .env("PIP_NO_INDEX", "1")
        .env("PIP_FIND_LINKS", root.join("wheels"))
        .env("PIP_REQUIRE_VIRTUALENV", "0")
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(String::from_utf8_lossy(&run.stdout).contains("[PyPI] 动态探测成功"));
    let bom: serde_json::Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert!(bom["components"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["name"] == "sbom-fixture-beta"));
    let diagnostic = fs::read_to_string(root.join("out.json.scan.json")).unwrap();
    assert!(diagnostic.contains("pip-resolve-report") && diagnostic.contains("installed-evidence"));
    let check=Command::new(&python).args(["-I","-c","import importlib.metadata as m; print(any(d.metadata['Name']=='sbom-fixture-alpha' for d in m.distributions()))"]).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&check.stdout).trim(), "False");
}
