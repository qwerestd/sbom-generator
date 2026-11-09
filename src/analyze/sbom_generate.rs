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
use crate::analyze::producers::npm::npm_dynamic::NpmDynamicProducer;
use crate::analyze::producers::npm::npm_lock_producer::NpmLockProducer;
use crate::analyze::producers::npm::npm_producer::NpmProducer;
use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::analyze::producers::pypi::pypi_dynamic::PypiDynamicProducer;
use crate::analyze::producers::pypi::pypi_lock_producer::PypiLockProducer;
use crate::analyze::producers::pypi::pypi_producer::PypiProducer;
use crate::analyze::producers::pypi::pyproject_producer::PyprojectProducer;

use crate::model::configuration::Configuration;
use crate::model::dependency::Dependency;
use crate::report::{generate_report, print_report};
use crate::sbom::generate::generate_sbom;
use crate::utils::file_utils::get_files;

/// Analyze paths, find dependencies and write the SBOM to disk.
pub fn analyze(configuration: &Configuration, dynamic: bool) -> anyhow::Result<()> {
    let mut raw_collected_deps: Vec<Dependency> = vec![];

    if configuration.use_debug {
        configuration.print_configuration();
    }

    let all_files = get_files(configuration.directory.as_str())?;
    let producer_cfg = SbomProducerConfiguration {
        base_path: PathBuf::from(&configuration.directory),
        use_debug: configuration.use_debug,
    };

    // =====================================================================
    // 工业级编排引擎：支持 [动态探针 -> 按项目父目录聚类 -> 多级静态责任链降级]
    // =====================================================================
    let mut run_ecosystem_chain = |eco_name: &str,
                                   dyn_producer: Option<&dyn DynamicProducer>,
                                   static_producers: &[&dyn SbomProducer]|
     -> anyhow::Result<()> {
        let project_dirs: std::collections::HashSet<_> = all_files
            .iter()
            .filter(|f| {
                static_producers
                    .iter()
                    .any(|p| p.use_file(f, &producer_cfg))
            })
            .filter_map(|f| f.parent())
            .collect();
        let mut resolved_dynamically = false;

        // --- 轨道一：动态探针 ---
        // A root probe cannot establish coverage of independent nested projects.
        // Use the complete static chain for multi-project repositories.
        if dynamic && project_dirs.len() <= 1 {
            if let Some(dp) = dyn_producer {
                if dp.is_applicable(configuration) {
                    if configuration.use_debug {
                        println!(" -> [{}] 启动动态探针...", eco_name);
                    }
                    match dp.detect_dependencies(configuration) {
                        Ok(deps) if !deps.is_empty() => {
                            println!(
                                " -> [{}] 动态探测成功 (还原 {} 个依赖及完整 DAG 图链路)",
                                eco_name,
                                deps.len()
                            );
                            raw_collected_deps.extend(deps);
                            resolved_dynamically = true;
                        }
                        Ok(_) => {}
                        Err(e) => {
                            eprintln!(" -> [{}] 动态探测受挫 ({})，正在降级...", eco_name, e);
                        }
                    }
                }
            }
        }

        // --- 轨道二：静态责任链队列 ---
        if !resolved_dynamically {
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
                return Ok(());
            }

            // 若当前生态仅有一个静态解析器（如 Maven 需跨目录构建父子 POM 上下文、Gradle 需跨目录共享属性或 Go 协同 go.work+go.mod+go.sum），
            // 直接将全部候选文件整体移交，保证多模块继承不丢失上下文。
            if static_producers.len() == 1 {
                let deps = static_producers[0]
                    .find_dependencies_checked(&candidate_files, &producer_cfg)
                    .map_err(|e| anyhow::anyhow!("{eco_name} static analysis failed: {e:#}"))?;
                raw_collected_deps.extend(deps);
                return Ok(());
            }

            // 步骤 B：当存在多级回退链（如 Lockfile -> Manifest）时，按各自父目录独立竞争
            let mut project_dirs: HashMap<PathBuf, Vec<PathBuf>> = HashMap::new();
            for f in candidate_files {
                if let Some(parent) = f.parent() {
                    project_dirs
                        .entry(parent.to_path_buf())
                        .or_default()
                        .push(f);
                }
            }

            // 步骤 C：在【单文件夹作用域】内跑责任链
            for (_proj_dir, files_in_dir) in project_dirs {
                let mut failures = Vec::new();
                for producer in static_producers {
                    let matched: Vec<PathBuf> = files_in_dir
                        .iter()
                        .filter(|f| producer.use_file(f, &producer_cfg))
                        .cloned()
                        .collect();

                    if !matched.is_empty() {
                        match producer.find_dependencies_checked(&matched, &producer_cfg) {
                            Ok(deps) if !deps.is_empty() => {
                                raw_collected_deps.extend(deps);
                                for failure in &failures {
                                    eprintln!("warning: {failure}; used fallback manifest");
                                }
                                failures.clear();
                                // 只截断当前子文件夹的队列，保证其他子项目可独立降级
                                break;
                            }
                            Ok(_) => {}
                            Err(e) => failures.push(format!("{eco_name}: {matched:?}: {e:#}")),
                        }
                    }
                }
                if !failures.is_empty() {
                    anyhow::bail!("Static analysis incomplete: {}", failures.join("; "));
                }
            }
        }
        Ok(())
    };

    // 1. Cargo (Rust) 生态：动态 metadata -> Cargo.lock -> Cargo.toml (支持 Workspace 继承)
    let cargo_dyn = CargoDynamicProducer::default();
    let cargo_lock = CargoProducer::default();
    let cargo_toml = CargoTomlProducer::default();
    run_ecosystem_chain("Cargo", Some(&cargo_dyn), &[&cargo_lock, &cargo_toml])?;

    // 2. NPM (JavaScript/TypeScript) 生态：动态 npm ls -> package-lock.json -> package.json (支持 Catalog 继承)
    let npm_dyn = NpmDynamicProducer::default();
    let npm_lock = NpmLockProducer::default();
    let npm_json = NpmProducer::default();
    run_ecosystem_chain("NPM", Some(&npm_dyn), &[&npm_lock, &npm_json])?;

    // 3. Maven (Java) 生态：动态 dependency:tree -> 静态双趟 pom.xml AST
    let maven_dyn = MavenDynamicProducer::default();
    let maven_static = MavenProducerBuilder::default().build().unwrap();
    run_ecosystem_chain("Maven", Some(&maven_dyn), &[&maven_static])?;

    // 4. PyPI (Python) 生态：动态虚拟环境 pip inspect (带根可达剪枝) -> poetry.lock/uv.lock/Pipfile.lock -> requirements.txt -> pyproject.toml/Pipfile
    let pypi_dyn = PypiDynamicProducer::default();
    let pypi_lock = PypiLockProducer::default();
    let pypi_req = PypiProducer::default();
    let pyproject = PyprojectProducer::default();
    run_ecosystem_chain(
        "PyPI",
        Some(&pypi_dyn),
        &[&pypi_lock, &pypi_req, &pyproject],
    )?;

    // 5. Gradle (Java/Kotlin) 生态：动态 gradlew dependencies -> 静态构建脚本与 Version Catalog (支持变量插值与 BOM 继承)
    let gradle_dyn = GradleDynamicProducer::default();
    let gradle_static = GradleProducer::default();
    run_ecosystem_chain("Gradle", Some(&gradle_dyn), &[&gradle_static])?;

    // 6. Go (Golang) 生态：动态 go mod graph + MVS -> 静态 go.work + go.mod + go.sum
    let go_dyn = GoDynamicProducer::default();
    let go_static = GoProducer::default();
    run_ecosystem_chain("Go", Some(&go_dyn), &[&go_static])?;

    // Local npm packages may have been parsed in separate directory chains.
    NpmProducer::link_local_dependencies(
        &all_files,
        &mut raw_collected_deps,
        &producer_cfg.base_path,
    )?;

    // =====================================================================
    // 终极拓扑去重与边融合引擎
    // =====================================================================
    let initial_count = raw_collected_deps.len();
    let mut merged_map: HashMap<String, Dependency> = HashMap::with_capacity(initial_count);

    for dep in raw_collected_deps {
        let key = dep.instance_id.clone();

        merged_map
            .entry(key)
            .and_modify(|existing| {
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

    let dedup_count = initial_count - final_dependencies.len();

    println!(
        " -> 融合图谱构建完毕！消除 {} 个冗余节点，最终产出 {} 个绝对隔离 SBOM 实体。",
        dedup_count,
        final_dependencies.len()
    );

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

    if configuration.use_debug {
        for dep in final_dependencies.iter() {
            let dep_file = dep
                .location
                .as_ref()
                .map(|v| v.block.file.clone())
                .unwrap_or_else(|| "runtime/manifest".to_string());
            println!("dep: {} [{}]", dep.instance_id, dep_file);
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

    // 先落盘生成最新 SBOM JSON，再基于新生成的 SBOM 汇总打印逻辑聚合报表与依赖树摘要
    generate_sbom(final_dependencies, configuration)?;
    if let Ok(report) = generate_report(configuration.output.as_str()) {
        print_report(&report);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::configuration::Configuration;
    use std::fs;
    use std::path::PathBuf;

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
