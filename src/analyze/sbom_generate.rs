use crate::analyze::producers::cargo_producer::CargoProducer;
use crate::analyze::producers::dynamic::cargo_dynamic::CargoDynamicProducer;
use crate::analyze::producers::dynamic::npm_dynamic::NpmDynamicProducer;
use crate::analyze::producers::dynamic::pypi_dynamic::PypiDynamicProducer;
use crate::analyze::producers::dynamic_producer::DynamicProducer;
use crate::analyze::producers::maven::maven_producer::MavenProducerBuilder;
use crate::analyze::producers::npm_lock_producer::NpmLockProducer;
use crate::analyze::producers::npm_producer::NpmProducer;
use crate::analyze::producers::producer::{SbomProducer, SbomProducerConfiguration};
use crate::analyze::producers::pypi_producer::PypiProducer;
// use crate::analyze::producers::poetry_lock_producer::PoetryLockProducer; // 若补了poetry可解开

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
    // 升级版编排引擎：支持 [动态轨 -> 静态Lock轨 -> 静态Manifest轨] 链式降级
    // =====================================================================
    let mut run_ecosystem_chain =
        |eco_name: &str,
         dyn_producer: Option<&dyn DynamicProducer>,
         static_producers: &[&dyn SbomProducer]| {
            let mut resolved = false;

            // --- 轨道一：动态探针 ---
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
                                resolved = true;
                            }
                            Ok(_) => {} // 产出0依赖则继续向下流转
                            Err(e) => {
                                eprintln!(
                                    " -> [{}] 动态探测受挫 ({})，正在无缝降级...",
                                    eco_name, e
                                );
                            }
                        }
                    }
                }
            }

            // --- 轨道二：静态责任链队列 (优先级严格由数组元素的先后顺序决定) ---
            if !resolved {
                for producer in static_producers {
                    let target_files: Vec<PathBuf> = all_files
                        .iter()
                        .filter(|f| producer.use_file(f, &producer_cfg))
                        .cloned()
                        .collect();

                    if !target_files.is_empty() {
                        match producer.find_dependencies(&target_files, &producer_cfg) {
                            Ok(deps) if !deps.is_empty() => {
                                println!(
                                    " -> [{}] 静态解析完成 (提取到 {} 个依赖)",
                                    eco_name,
                                    deps.len()
                                );
                                final_dependencies.extend(deps);
                                break; // 【核心决断点】：高优规则一旦拿到数据，立刻截断循环，绝不执行后置规则！
                            }
                            Ok(_) => {
                                // 扫到了文件（如内容为空的 package-lock.json），但依赖数为0，放行给下一顺位
                            }
                            Err(e) => eprintln!(" -> [{}] 静态扫描发生异常: {}", eco_name, e),
                        }
                    }
                }
            }
        };

    // 1. Cargo 生态 (单轨)
    let cargo_dyn = CargoDynamicProducer::default();
    let cargo_static = CargoProducer::default();
    run_ecosystem_chain("Cargo", Some(&cargo_dyn), &[&cargo_static]);

    // 2. NPM 生态 (责任链挂载：Lock 在前，Json 在后)
    let npm_dyn = NpmDynamicProducer::default();
    let npm_lock = NpmLockProducer::default();
    let npm_json = NpmProducer::default();
    run_ecosystem_chain("NPM", Some(&npm_dyn), &[&npm_lock, &npm_json]);

    // 3. Maven 生态
    let maven_static = MavenProducerBuilder::default().build().unwrap();
    run_ecosystem_chain("Maven", None, &[&maven_static]);

    // 4. PyPI 生态
    let pypi_dyn = PypiDynamicProducer::default();
    let pypi_static = PypiProducer::default();
    // let poetry_lock = PoetryLockProducer::default();
    run_ecosystem_chain("PyPI", Some(&pypi_dyn), &[&pypi_static]); // 若写了poetry，改写为 &[&poetry_lock, &pypi_static]

    // 排序
    final_dependencies.sort_by(|a, b| {
        a.group
            .cmp(&b.group)
            .then(a.name.cmp(&b.name))
            .then(a.version.cmp(&b.version))
    });

    // --- 【智能拓扑去重算法】 ---
    let initial_count = final_dependencies.len();
    final_dependencies.dedup_by(|a, b| {
        if a.group == b.group && a.name == b.name && a.version == b.version {
            if b.dependencies.is_empty() && !a.dependencies.is_empty() {
                b.dependencies = std::mem::take(&mut a.dependencies);
            }
            true
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
