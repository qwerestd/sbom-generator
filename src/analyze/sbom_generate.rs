use std::collections::HashMap;
use std::path::PathBuf;

use crate::analyze::producers::cargo::cargo_dynamic::CargoDynamicProducer;
use crate::analyze::producers::cargo::cargo_lock_producer::CargoProducer;
use crate::analyze::producers::cargo::cargo_toml_producer::CargoTomlProducer;
use crate::analyze::producers::dynamic_producer::DynamicProducer;
use crate::analyze::producers::go::go_dynamic::GoDynamicProducer;
use crate::analyze::producers::go::go_producer::GoProducer;
use crate::analyze::producers::gradle::gradle_dynamic::GradleDynamicProducer;
use crate::analyze::producers::gradle::gradle_producer::GradleProducer;
use crate::analyze::producers::maven::maven_dynamic::MavenDynamicProducer;
use crate::analyze::producers::maven::maven_producer::MavenProducerBuilder;
use crate::analyze::producers::npm::bun_lock_producer::BunLockProducer;
use crate::analyze::producers::npm::npm_dynamic::NpmDynamicProducer;
use crate::analyze::producers::npm::npm_lock_producer::NpmLockProducer;
use crate::analyze::producers::npm::npm_producer::NpmProducer;
use crate::analyze::producers::npm::pnpm_lock_producer::PnpmLockProducer;
use crate::analyze::producers::npm::yarn_lock_producer::YarnLockProducer;
use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::analyze::producers::pypi::pypi_dynamic::PypiDynamicProducer;
use crate::analyze::producers::pypi::pypi_lock_producer::PypiLockProducer;
use crate::analyze::producers::pypi::pypi_producer::PypiProducer;
use crate::analyze::producers::pypi::pyproject_producer::PyprojectProducer;

use crate::model::configuration::Configuration;
use crate::model::dependency::Dependency;
use crate::sbom::generate::generate_sbom_with_diagnostics;
use crate::utils::file_utils::{get_files_with_options, ScanOptions};

type DynamicProjectOutcome = (Vec<Dependency>, bool, serde_json::Value);
type StaticDirectoryOutcome = anyhow::Result<(Vec<Dependency>, Vec<serde_json::Value>)>;
type ResultSlot<T> = std::sync::Mutex<Option<T>>;

fn collect_dynamic_projects(
    configuration: &Configuration,
    ecosystem: &str,
    producer: Option<&dyn DynamicProducer>,
    project_dirs: &std::collections::BTreeSet<PathBuf>,
    diagnostics: &mut Vec<serde_json::Value>,
) -> (Vec<Dependency>, std::collections::HashSet<PathBuf>) {
    let mut collected = Vec::new();
    let mut resolved = std::collections::HashSet::new();
    let Some(producer) = producer else {
        return (collected, resolved);
    };
    let directories: Vec<_> = project_dirs.iter().cloned().collect();
    if directories.is_empty() {
        return (collected, resolved);
    }

    let probe_one = |directory: PathBuf| -> (Vec<Dependency>, bool, serde_json::Value) {
        let local = Configuration {
            directory: directory.to_string_lossy().into_owned(),
            output: configuration.output.clone(),
            use_debug: configuration.use_debug,
            dynamic: configuration.dynamic,
            allow_exec: configuration.allow_exec,
        };
        if !producer.is_applicable(&local) {
            let diag = serde_json::json!({"ecosystem":ecosystem,"directory":directory,"method":"package-manager","status":"not-applicable"});
            return (Vec::new(), false, diag);
        }
        match producer.detect_dependencies(&local) {
            Ok(mut deps) if !deps.is_empty() => {
                let diag = serde_json::json!({"ecosystem":ecosystem,"directory":directory,"method":"package-manager","records":deps.len(),"complete":false});
                println!(
                    " -> [{ecosystem}] 动态探测成功: {} ({} 个组件)",
                    directory.display(),
                    deps.len()
                );
                let ids: HashMap<_, _> = deps
                    .iter()
                    .map(|d| {
                        (
                            d.instance_id.clone(),
                            crate::utils::file_utils::make_instance_id(
                                &d.purl,
                                &format!("{}:{}", directory.display(), d.instance_id),
                            ),
                        )
                    })
                    .collect();
                for dep in &mut deps {
                    crate::analyze::inventory::remap_properties(dep, &ids);
                    if let Some(id) = ids.get(&dep.instance_id) {
                        dep.instance_id = id.clone();
                    }
                    for child in &mut dep.dependencies {
                        if let Some(id) = ids.get(child) {
                            *child = id.clone();
                        }
                    }
                    if dep.location.is_none() {
                        let primary = [
                            "package.json",
                            "Cargo.toml",
                            "pom.xml",
                            "build.gradle",
                            "build.gradle.kts",
                            "pyproject.toml",
                            "requirements.txt",
                            "go.mod",
                        ]
                        .iter()
                        .map(|n| directory.join(n))
                        .find(|p| p.is_file());
                        dep.location = primary
                            .map(|p| crate::model::dependency::DependencyLocation::from_file(&p));
                    }
                    dep.properties
                        .entry("sbom:analysis:method".into())
                        .or_insert_with(|| "package-manager".into());
                    dep.properties.insert(
                        "sbom:evidence:project".into(),
                        directory.to_string_lossy().into_owned(),
                    );
                }
                (deps, true, diag)
            }
            Ok(_) => {
                let diag = serde_json::json!({"ecosystem":ecosystem,"directory":directory,"method":"package-manager","records":0});
                (Vec::new(), false, diag)
            }
            Err(error) => {
                let diag = serde_json::json!({"ecosystem":ecosystem,"directory":directory,"method":"package-manager","error":format!("{error:#}")});
                eprintln!(
                    " -> [{ecosystem}] {} 动态探测受挫 ({error:#})，回退静态解析",
                    directory.display()
                );
                (Vec::new(), false, diag)
            }
        }
    };

    let per_project = true;
    let ordered_outcomes: Vec<(PathBuf, Vec<Dependency>, bool, serde_json::Value)> =
        if directories.len() == 1 {
            let dir = directories.into_iter().next().unwrap();
            let (deps, is_resolved, diag) = probe_one(dir.clone());
            vec![(dir, deps, is_resolved, diag)]
        } else {
            let max_workers = match ecosystem {
                "Gradle" | "Maven" => 4,
                _ => std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(4)
                    .clamp(2, 8),
            };
            let worker_count = directories.len().min(max_workers);
            let next_idx = std::sync::atomic::AtomicUsize::new(0);
            let slots: Vec<ResultSlot<DynamicProjectOutcome>> = (0..directories.len())
                .map(|_| std::sync::Mutex::new(None))
                .collect();

            std::thread::scope(|s| {
                for _ in 0..worker_count {
                    s.spawn(|| loop {
                        let idx = next_idx.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if idx >= directories.len() {
                            break;
                        }
                        let res = probe_one(directories[idx].clone());
                        *slots[idx].lock().unwrap_or_else(|e| e.into_inner()) = Some(res);
                    });
                }
            });

            directories
                .into_iter()
                .zip(slots)
                .filter_map(|(dir, slot)| {
                    slot.into_inner()
                        .unwrap_or_else(|e| e.into_inner())
                        .map(|(deps, is_resolved, diag)| (dir, deps, is_resolved, diag))
                })
                .collect()
        };

    for (directory, deps, is_resolved, diag) in ordered_outcomes {
        diagnostics.push(diag);
        if is_resolved {
            collected.extend(deps);
            if per_project {
                resolved.insert(directory);
            } else {
                resolved.extend(project_dirs.iter().cloned());
            }
        }
    }
    (collected, resolved)
}

/// Analyze paths, find dependencies and write the SBOM to disk.
pub fn analyze(configuration: &Configuration, dynamic: bool) -> anyhow::Result<()> {
    analyze_with_options(configuration, dynamic, &ScanOptions::default())
}

pub fn analyze_with_options(
    configuration: &Configuration,
    dynamic: bool,
    options: &ScanOptions,
) -> anyhow::Result<()> {
    let mut raw_collected_deps: Vec<Dependency> = vec![];

    if configuration.use_debug {
        configuration.print_configuration();
    }

    let discovered_files = get_files_with_options(configuration.directory.as_str(), options)?;
    let all_files: Vec<_> = discovered_files
        .iter()
        .filter(|p| {
            !p.strip_prefix(&configuration.directory)
                .unwrap_or(p)
                .components()
                .any(|c| {
                    matches!(
                        c.as_os_str().to_str(),
                        Some("node_modules" | ".venv" | "venv" | "site-packages")
                    )
                })
        })
        .cloned()
        .collect();
    let mut diagnostics = Vec::<serde_json::Value>::new();
    diagnostics.push(serde_json::json!({"stage":"file-discovery","discovered_files":discovered_files.len(),"source_files":all_files.len(),"include_installed":options.installed,"include_artifacts":options.artifacts,"excluded_directories":options.exclude_dirs,"default_skips":[".git",".hg",".svn",".idea",".vscode",".gradle",".vendor","__pycache__","bower_components"],"source_mode_skips":["node_modules",".venv","venv","build","dist","target"]}));
    if options.installed || options.artifacts {
        let (deps, issues) = crate::analyze::installed::collect(&discovered_files, options);
        raw_collected_deps.extend(deps);
        diagnostics.extend(issues);
    }
    let producer_cfg = SbomProducerConfiguration {
        base_path: PathBuf::from(&configuration.directory),
        use_debug: configuration.use_debug,
    };

    // =====================================================================
    // 工业级并发编排引擎：支持 [跨生态多线程并发 + 生态内多目录动态探针并发 + 多级静态责任链降级]
    // =====================================================================
    let run_ecosystem_chain = |eco_name: &str,
                               dyn_producer: Option<&dyn DynamicProducer>,
                               static_producers: &[&dyn SbomProducer]|
     -> anyhow::Result<(Vec<Dependency>, Vec<serde_json::Value>)> {
        let mut eco_deps = Vec::new();
        let mut eco_diagnostics = Vec::new();

        let project_dirs: std::collections::BTreeSet<_> = all_files
            .iter()
            .filter(|f| {
                static_producers
                    .iter()
                    .any(|p| p.use_file(f, &producer_cfg))
            })
            .filter_map(|f| f.parent().map(std::path::Path::to_path_buf))
            .collect();
        let (dynamic_deps, _resolved_dirs) = if dynamic {
            collect_dynamic_projects(
                configuration,
                eco_name,
                dyn_producer,
                &project_dirs,
                &mut eco_diagnostics,
            )
        } else {
            Default::default()
        };
        eco_deps.extend(dynamic_deps);
        // Dynamic and static evidence describe different inventories and must coexist.

        // --- 轨道二：静态责任链队列 ---
        {
            // 步骤 A：筛选出全仓库内当前生态的所有潜在清单文件
            let candidate_files: Vec<PathBuf> = all_files
                .iter()
                .filter(|f| {
                    static_producers
                        .iter()
                        .any(|p| p.use_file(f, &producer_cfg))
                })
                .cloned()
                .collect();

            if candidate_files.is_empty() {
                return Ok((eco_deps, eco_diagnostics));
            }

            // 若当前生态仅有一个静态解析器（如 Maven 需跨目录构建父子 POM 上下文、Gradle 需跨目录共享属性或 Go 独立 go.mod 清单），
            // 直接将全部候选文件整体移交，保证多模块继承不丢失上下文。
            if static_producers.len() == 1 {
                let deps = static_producers[0]
                    .discover(&candidate_files, &producer_cfg)
                    .map_err(|e| anyhow::anyhow!("{eco_name} static analysis failed: {e:#}"))?;
                eco_diagnostics.push(serde_json::json!({"ecosystem":eco_name,"files":deps.files,"complete":deps.complete,"records":deps.dependencies.len()}));
                eco_deps.extend(deps.dependencies);
                return Ok((eco_deps, eco_diagnostics));
            }

            // 步骤 B：当存在多级回退链（如 Lockfile -> Manifest）时，按各自父目录独立竞争
            let mut project_dirs: std::collections::BTreeMap<PathBuf, Vec<PathBuf>> =
                std::collections::BTreeMap::new();
            for f in candidate_files {
                if let Some(parent) = f.parent() {
                    project_dirs
                        .entry(parent.to_path_buf())
                        .or_default()
                        .push(f);
                }
            }

            // 步骤 C：在【单文件夹作用域】内并发跑责任链
            let dir_entries: Vec<(PathBuf, Vec<PathBuf>)> = project_dirs.into_iter().collect();
            let run_one_dir =
                |files_in_dir: &[PathBuf]| -> anyhow::Result<(Vec<Dependency>, Vec<serde_json::Value>)> {
                    let mut dir_deps = Vec::new();
                    let mut dir_diags = Vec::new();
                    let mut failures = Vec::new();
                    let mut usable = false;
                    for producer in static_producers {
                        let matched: Vec<PathBuf> = files_in_dir
                            .iter()
                            .filter(|f| producer.use_file(f, &producer_cfg))
                            .cloned()
                            .collect();

                        if !matched.is_empty() {
                            match producer.discover(&matched, &producer_cfg) {
                                Ok(discovery) => {
                                    dir_diags.push(serde_json::json!({"ecosystem":eco_name,"files":discovery.files,"complete":discovery.complete,"records":discovery.dependencies.len()}));
                                    if discovery.dependencies.is_empty() {
                                        continue;
                                    }
                                    dir_deps.extend(discovery.dependencies);
                                    usable = true;
                                    for failure in &failures {
                                        eprintln!("warning: {failure}; used fallback manifest");
                                    }
                                    failures.clear();
                                    // 只截断当前子文件夹的队列，保证其他子项目可独立降级
                                    // Later sources enrich scopes and relationships even after full resolution.
                                }
                                Err(e) => {
                                    dir_diags.push(serde_json::json!({"ecosystem":eco_name,"files":matched,"error":format!("{e:#}")}));
                                    failures.push(format!("{eco_name}: {matched:?}: {e:#}"));
                                }
                            }
                        }
                    }
                    if !failures.is_empty() && !usable {
                        anyhow::bail!("Static analysis incomplete: {}", failures.join("; "));
                    }
                    Ok((dir_deps, dir_diags))
                };

            if dir_entries.len() <= 1 {
                for (_proj_dir, files_in_dir) in &dir_entries {
                    let (d_deps, d_diags) = run_one_dir(files_in_dir)?;
                    eco_deps.extend(d_deps);
                    eco_diagnostics.extend(d_diags);
                }
            } else {
                let worker_count = dir_entries.len().min(
                    std::thread::available_parallelism()
                        .map(|n| n.get())
                        .unwrap_or(4)
                        .clamp(2, 8),
                );
                let next_idx = std::sync::atomic::AtomicUsize::new(0);
                let slots: Vec<ResultSlot<StaticDirectoryOutcome>> = (0..dir_entries.len())
                    .map(|_| std::sync::Mutex::new(None))
                    .collect();

                std::thread::scope(|s| {
                    for _ in 0..worker_count {
                        s.spawn(|| loop {
                            let idx = next_idx.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            if idx >= dir_entries.len() {
                                break;
                            }
                            let res = run_one_dir(&dir_entries[idx].1);
                            *slots[idx].lock().unwrap_or_else(|e| e.into_inner()) = Some(res);
                        });
                    }
                });

                for slot in slots {
                    if let Some(res) = slot.into_inner().unwrap_or_else(|e| e.into_inner()) {
                        let (d_deps, d_diags) = res?;
                        eco_deps.extend(d_deps);
                        eco_diagnostics.extend(d_diags);
                    }
                }
            }
        }
        Ok((eco_deps, eco_diagnostics))
    };

    // 1. Cargo (Rust) 生态：动态 metadata -> Cargo.lock -> Cargo.toml (支持 Workspace 继承)
    let cargo_dyn = CargoDynamicProducer::default();
    let cargo_lock = CargoProducer::default();
    let cargo_toml = CargoTomlProducer::default();
    let cargo_statics: [&dyn SbomProducer; 2] = [&cargo_lock, &cargo_toml];

    // 2. NPM (JavaScript/TypeScript) 生态：动态 npm ls -> package-lock.json -> package.json (支持 Catalog 继承)
    let npm_dyn = NpmDynamicProducer::default();
    let npm_lock = NpmLockProducer::default();
    let pnpm_lock = PnpmLockProducer;
    let yarn_lock = YarnLockProducer;
    let bun_lock = BunLockProducer;
    let npm_json = NpmProducer::default();
    let npm_statics: [&dyn SbomProducer; 5] =
        [&pnpm_lock, &yarn_lock, &bun_lock, &npm_lock, &npm_json];

    // 3. Maven (Java) 生态：动态 dependency:tree -> 静态双趟 pom.xml AST
    let maven_dyn = MavenDynamicProducer::default();
    let maven_static = MavenProducerBuilder::default().build().unwrap();
    let maven_statics: [&dyn SbomProducer; 1] = [&maven_static];

    // 4. PyPI (Python) 生态：动态虚拟环境 pip inspect (带根可达剪枝) -> poetry.lock/uv.lock/Pipfile.lock -> requirements.txt -> pyproject.toml/Pipfile
    let pypi_dyn = PypiDynamicProducer::default();
    let pypi_lock = PypiLockProducer::default();
    let pypi_req = PypiProducer::default();
    let pyproject = PyprojectProducer::default();
    let pypi_statics: [&dyn SbomProducer; 3] = [&pypi_lock, &pypi_req, &pyproject];

    // 5. Gradle (Java/Kotlin) 生态：动态 gradlew dependencies -> 静态构建脚本与 Version Catalog (支持变量插值与 BOM 继承)
    let gradle_dyn = GradleDynamicProducer::default();
    let gradle_static = GradleProducer::default();
    let gradle_statics: [&dyn SbomProducer; 1] = [&gradle_static];

    // 6. Go (Golang) 生态：动态 go mod graph + MVS -> 静态 go.mod（Syft 风格）
    let go_dyn = GoDynamicProducer::default();
    let go_static = GoProducer::default();
    let go_statics: [&dyn SbomProducer; 1] = [&go_static];

    // 六大生态全并发调度，主线程按固定顺序归并结果以确保输出完全确定性
    let eco_outcomes = std::thread::scope(|s| {
        let h_cargo = s.spawn(|| run_ecosystem_chain("Cargo", Some(&cargo_dyn), &cargo_statics));
        let h_npm = s.spawn(|| run_ecosystem_chain("NPM", Some(&npm_dyn), &npm_statics));
        let h_maven = s.spawn(|| run_ecosystem_chain("Maven", Some(&maven_dyn), &maven_statics));
        let h_pypi = s.spawn(|| run_ecosystem_chain("PyPI", Some(&pypi_dyn), &pypi_statics));
        let h_gradle =
            s.spawn(|| run_ecosystem_chain("Gradle", Some(&gradle_dyn), &gradle_statics));
        let h_go = s.spawn(|| run_ecosystem_chain("Go", Some(&go_dyn), &go_statics));

        vec![
            h_cargo.join().unwrap(),
            h_npm.join().unwrap(),
            h_maven.join().unwrap(),
            h_pypi.join().unwrap(),
            h_gradle.join().unwrap(),
            h_go.join().unwrap(),
        ]
    });

    for outcome in eco_outcomes {
        let (eco_deps, eco_diags) = outcome?;
        raw_collected_deps.extend(eco_deps);
        diagnostics.extend(eco_diags);
    }

    for file in &all_files {
        if file.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
            matches!(
                n,
                "bun.lockb" | "go.work" | "setup.py" | "composer.lock" | "Gemfile.lock"
            )
        }) {
            diagnostics.push(serde_json::json!({"file":file,"status":"unsupported-or-not-independently-cataloged"}));
        }
    }
    // Local npm packages may have been parsed in separate directory chains.
    raw_collected_deps = crate::analyze::inventory::fuse(raw_collected_deps);
    NpmProducer::link_local_dependencies(
        &all_files,
        &mut raw_collected_deps,
        &producer_cfg.base_path,
    )?;

    // =====================================================================
    // 终极拓扑去重与边融合引擎
    // =====================================================================
    raw_collected_deps = crate::analyze::inventory::fuse(raw_collected_deps);
    let mut merged_map: HashMap<String, Dependency> =
        HashMap::with_capacity(raw_collected_deps.len());

    for dep in raw_collected_deps {
        let key = dep.instance_id.clone();

        merged_map
            .entry(key)
            .and_modify(|existing| {
                existing.properties.extend(dep.properties.clone());
                for child_id in &dep.dependencies {
                    if !existing.dependencies.contains(child_id) {
                        existing.dependencies.push(child_id.clone());
                    }
                }
            })
            .or_insert(dep);
    }

    let mut final_dependencies: Vec<Dependency> = merged_map.into_values().collect();

    final_dependencies.sort_by(|a, b| a.instance_id.cmp(&b.instance_id));

    // --- 【终极工程安全网】 ---
    if cfg!(debug_assertions) {
        for dep in &final_dependencies {
            assert!(
                dep.instance_id.contains("?package-id="),
                "🚨 [编译期红线断言] 抓到未隔离节点！组件 <{}> 的 ref 依然是纯 PURL: {}",
                dep.name,
                dep.instance_id
            );
        }
    }

    // =====================================================================
    // 依赖加载可达性监测引擎 (默认仅执行纯静态源码引用扫描；仅当显式开启 --allow-exec 时才执行入口沙箱探针)
    // =====================================================================
    if dynamic {
        crate::analyze::dynamic_monitor::monitor_dependency_loading(
            &configuration.directory,
            &mut final_dependencies,
            configuration.use_debug,
            configuration.allow_exec,
        );
    }

    // Write the inventory without dumping every dependency to the console.
    generate_sbom_with_diagnostics(final_dependencies, configuration, &diagnostics)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::configuration::Configuration;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn independent_projects_probe_separately_and_failures_keep_static_fallback() {
        struct Probe(std::sync::Mutex<Vec<String>>);
        impl DynamicProducer for Probe {
            fn is_applicable(&self, _: &Configuration) -> bool {
                true
            }
            fn detect_dependencies(
                &self,
                config: &Configuration,
            ) -> anyhow::Result<Vec<Dependency>> {
                self.0.lock().unwrap().push(config.directory.clone());
                if config.directory.ends_with("failed") {
                    anyhow::bail!("environment unavailable");
                }
                if config.directory.ends_with("empty") {
                    return Ok(vec![]);
                }
                Ok(vec![crate::model::dependency::DependencyBuilder::default()
                    .name(config.directory.clone())
                    .version(Some("1.0.0".into()))
                    .purl("pkg:pypi/installed@1.0.0".into())
                    .build()
                    .unwrap()])
            }
        }
        for eco in ["Go", "PyPI"] {
            let probe = Probe(Default::default());
            let configuration = Configuration {
                directory: "root".into(),
                output: "unused".into(),
                use_debug: false,
                dynamic: true,
                allow_exec: false,
            };
            let directories = ["root", "root/installed", "root/failed", "root/empty"]
                .map(PathBuf::from)
                .into_iter()
                .collect();
            let (deps, resolved) = collect_dynamic_projects(
                &configuration,
                eco,
                Some(&probe),
                &directories,
                &mut Vec::new(),
            );
            assert_eq!(probe.0.lock().unwrap().len(), 4);
            assert_eq!(deps.len(), 2);
            assert_eq!(resolved.len(), 2);
            assert!(resolved.contains(&PathBuf::from("root")));
            assert!(!resolved.contains(&PathBuf::from("root/failed")));
            assert!(!resolved.contains(&PathBuf::from("root/empty")));
        }
    }

    fn run_test_for_ecosystem(folder_name: &str) {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("resources");
        for part in folder_name.split('/') {
            path.push(part);
        }

        let mut out_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        out_path.push("target");
        out_path.push("test_outputs");
        for part in folder_name.split('/') {
            out_path.push(part);
        }

        if let Some(file_name) = out_path.file_name() {
            let new_name = format!("{}_output.json", file_name.to_string_lossy());
            out_path.set_file_name(new_name);
        }

        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent).expect("无法创建测试输出目录");
        }

        let config = Configuration {
            directory: path.to_string_lossy().to_string(),
            output: out_path.to_string_lossy().to_string(),
            use_debug: true,
            dynamic: false,
            allow_exec: false,
        };

        // 分别用静态轨和动态轨压测该生态
        analyze(&config, false).expect("静态分析失败");
        assert!(out_path.exists(), "SBOM 输出文件应当被创建");
        let _ = analyze(&config, true);

        if out_path.exists() {
            let _ = fs::remove_file(out_path);
        }
    }

    #[test]
    fn test_analyze_npm_ecosystem() {
        run_test_for_ecosystem("npm");
    }

    #[test]
    fn test_analyze_cargo_ecosystem() {
        run_test_for_ecosystem("cargo");
    }

    #[test]
    fn test_analyze_pypi_ecosystem() {
        run_test_for_ecosystem("py");
    }

    #[test]
    fn test_analyze_maven_simple_ecosystem() {
        run_test_for_ecosystem("maven/simple");
    }

    #[test]
    fn test_analyze_maven_hierarchy_ecosystem() {
        run_test_for_ecosystem("maven/hierarchy");
    }

    #[test]
    fn test_analyze_go_ecosystem() {
        run_test_for_ecosystem("go");
    }

    #[test]
    fn test_analyze_polyglot_showcase_with_osv() {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("examples");
        path.push("polyglot-showcase");

        let mut out_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        out_path.push("target");
        out_path.push("test_outputs");
        out_path.push("polyglot_showcase_sbom.json");

        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent).expect("无法创建测试输出目录");
        }

        let config = Configuration {
            directory: path.to_string_lossy().to_string(),
            output: out_path.to_string_lossy().to_string(),
            use_debug: false,
            dynamic: false,
            allow_exec: false,
        };

        analyze(&config, false).expect("多语言靶场分析失败");
        let content = fs::read_to_string(&out_path).expect("读取生成的 SBOM 失败");
        let json: serde_json::Value = serde_json::from_str(&content).unwrap();
        let vulns = json["vulnerabilities"]
            .as_array()
            .expect("应当包含 vulnerabilities 数组");
        assert!(
            vulns.len() >= 10,
            "多语言靶场应至少检出 10 个跨语言 CVE/GHSA 漏洞，实际: {}",
            vulns.len()
        );
        let comps = json["components"]
            .as_array()
            .expect("应当包含 components 数组");
        // These source fixtures have no license declarations. Do not invent
        // licenses from package names or ecosystem-wide defaults.
        assert!(comps.iter().all(|c| c.get("licenses").is_none()));
        assert!(comps.iter().all(|c| {
            c["licenses"].as_array().is_none_or(|licenses| {
                licenses.iter().all(|entry| {
                    entry["license"]["id"].as_str().is_none_or(|id| {
                        !id.split_whitespace()
                            .any(|part| matches!(part, "OR" | "AND" | "WITH"))
                    })
                })
            })
        }));
        let _ = fs::remove_file(out_path);
    }
}
