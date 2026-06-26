use crate::analyze::producers::cargo_producer::CargoProducer;
use crate::analyze::producers::dynamic::cargo_dynamic::CargoDynamicProducer;
use crate::analyze::producers::dynamic::npm_dynamic::NpmDynamicProducer;
use crate::analyze::producers::dynamic::pypi_dynamic::PypiDynamicProducer;
use crate::analyze::producers::dynamic_producer::DynamicProducer;
use crate::analyze::producers::maven::maven_producer::MavenProducerBuilder;
use crate::analyze::producers::npm_producer::NpmProducer;
use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::analyze::producers::pypi_producer::PypiProducer;
use crate::model::configuration::Configuration;
use crate::model::dependency::Dependency;
use crate::sbom::generate::generate_sbom;
use crate::utils::file_utils::get_files;
use std::path::PathBuf;

/// Analyze paths, find dependencies and write the SBOM to disk.
pub fn analyze(configuration: &Configuration, dynamic: bool) -> anyhow::Result<()> {
    let mut final_dependencies: Vec<Dependency> = vec![];

    if configuration.use_debug {
        configuration.print_configuration();
    }

    let all_files = get_files(configuration.directory.as_str()).expect("cannot read directory");
    let producer_cfg = SbomProducerConfiguration {
        base_path: PathBuf::from(&configuration.directory),
        use_debug: configuration.use_debug,
    };

    // =====================================================================
    // 核心编排引擎：生态智能调度闭包 (Ecosystem Dispatcher)
    // =====================================================================
    let mut run_dual_track = |eco_name: &str,
                              dyn_producer: Option<&dyn DynamicProducer>,
                              static_producer: &dyn SbomProducer| {
        let mut resolved_by_dynamic = false;

        // --- 轨道一：动态探针 (完美修复 unnecessary_unwrap 报错) ---
        if dynamic {
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
                            final_dependencies.extend(deps);
                            resolved_by_dynamic = true; // 标记动态已决断
                        }
                        Ok(_) => {} // 空依赖则直接降级
                        Err(e) => {
                            eprintln!(" -> [{}] 动态探测受挫 ({})，正在无缝降级...", eco_name, e);
                        }
                    }
                }
            }
        }

        // --- 轨道二：静态 AST 兜底 (仅当动态未命中或报错时才触发) ---
        if !resolved_by_dynamic {
            let target_files: Vec<PathBuf> = all_files
                .iter()
                .filter(|f| static_producer.use_file(f, &producer_cfg))
                .cloned()
                .collect();

            if !target_files.is_empty() {
                match static_producer.find_dependencies(&target_files, &producer_cfg) {
                    Ok(deps) => {
                        println!(
                            " -> [{}] 静态解析完成 (提取 {} 个基础依赖)",
                            eco_name,
                            deps.len()
                        );
                        final_dependencies.extend(deps);
                    }
                    Err(e) => eprintln!(" -> [{}] 静态扫描发生异常: {}", eco_name, e),
                }
            }
        }
    };

    // 按语言生态成对挂载驱动器
    let cargo_dyn = CargoDynamicProducer::default();
    let cargo_static = CargoProducer::default();
    run_dual_track("Cargo", Some(&cargo_dyn), &cargo_static);

    let npm_dyn = NpmDynamicProducer::default();
    let npm_static = NpmProducer::default();
    run_dual_track("NPM", Some(&npm_dyn), &npm_static);

    // Maven 内部已经自带了闭环双轨制，外部动态传 None 即可
    let maven_static = MavenProducerBuilder::default().build().unwrap();
    run_dual_track("Maven", None, &maven_static);

    let pypi_static = PypiProducer::default();
    let pypi_dyn = PypiDynamicProducer::default();
    run_dual_track("PyPI", Some(&pypi_dyn), &pypi_static);

    // 排序
    final_dependencies.sort_by(|a, b| {
        a.group
            .cmp(&b.group)
            .then(a.name.cmp(&b.name))
            .then(a.version.cmp(&b.version))
    });

    // --- 【智能拓扑去重算法】 ---
    // 在 Rust std::vec::Vec::dedup_by 规范中：a 是后一个元素(待删除)，b 是前一个保留的元素
    let initial_count = final_dependencies.len();
    final_dependencies.dedup_by(|a, b| {
        if a.group == b.group && a.name == b.name && a.version == b.version {
            // 如果前一个保留者(b)没有子依赖链路，但后一个被删者(a)有，把 a 的链路抢过来！
            if b.dependencies.is_empty() && !a.dependencies.is_empty() {
                b.dependencies = std::mem::take(&mut a.dependencies);
            }
            true // 判定为重复，抹杀 a
        } else {
            false
        }
    });
    let dedup_count = initial_count - final_dependencies.len();

    println!(
        " -> 融合扫描完毕！去除了 {} 个重复项，最终产出 {} 个有效 SBOM 组件。",
        dedup_count,
        final_dependencies.len()
    );

    if configuration.use_debug {
        for dep in final_dependencies.iter() {
            let dep_file = dep
                .location
                .as_ref()
                .map(|v| v.block.file.clone())
                .unwrap_or_else(|| "runtime".to_string());
            println!(
                "dep: {}@{} [{}]",
                dep.name,
                dep.version.clone().unwrap_or_default(),
                dep_file
            );
        }
    }

    generate_sbom(final_dependencies, configuration).expect("cannot generate SBOM");
    Ok(())
}
