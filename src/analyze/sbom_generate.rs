use crate::analyze::producers::cargo_producer::CargoProducer;
use crate::analyze::producers::dynamic::cargo_dynamic::CargoDynamicProducer;
use crate::analyze::producers::dynamic::npm_dynamic::NpmDynamicProducer;
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
    // 1. 初始化空数组
    let mut static_dependencies: Vec<Dependency> = vec![];
    let mut dynamic_dependencies: Vec<Dependency> = vec![];

    if configuration.use_debug {
        configuration.print_configuration();
    }

    let all_producers: Vec<Box<dyn SbomProducer>> = vec![
        Box::new(MavenProducerBuilder::default().build().unwrap()),
        Box::new(NpmProducer::default()),
        Box::new(CargoProducer::default()),
        Box::new(PypiProducer::default()),
    ];

    let all_files = get_files(configuration.directory.as_str()).expect("cannot read directory");
    let producer_configuration = SbomProducerConfiguration {
        base_path: PathBuf::from(configuration.directory.clone()),
        use_debug: configuration.use_debug,
    };

    // --- 【修改点 1：静态探测增加 match 容错与日志，避免吞异常】 ---
    for sbom_producer in all_producers {
        let producer_files = all_files
            .clone()
            .iter()
            .filter(|f| sbom_producer.use_file(f, &producer_configuration))
            .map(|v| (*v).clone())
            .collect::<Vec<PathBuf>>();

        // 如果当前生态没有匹配到任何文件，直接跳过，节省性能
        if producer_files.is_empty() {
            continue;
        }

        match sbom_producer.find_dependencies(producer_files.as_slice(), &producer_configuration) {
            Ok(deps) => {
                println!(" -> [静态] 成功扫描到 {} 个依赖组件", deps.len());
                static_dependencies.extend(deps);
            }
            Err(e) => {
                // 打印出到底是哪个解析器失败了，防止静默阻断其他语言
                eprintln!(" -> [警告] 静态扫描发生错误: {}", e);
            }
        }
    }

    if dynamic {
        println!(
            " -> 静态检测共发现 {} 个依赖组件",
            static_dependencies.len()
        );
        println!(" -> 启动动态检测模块...");

        let dynamic_producers: Vec<Box<dyn DynamicProducer>> = vec![
            Box::new(NpmDynamicProducer::default()),
            Box::new(CargoDynamicProducer::default()),
        ];

        for producer in dynamic_producers {
            if producer.is_applicable(configuration) {
                if configuration.use_debug {
                    println!(" -> 正在执行动态探测...");
                }
                match producer.detect_dependencies(configuration) {
                    Ok(deps) => {
                        dynamic_dependencies.extend(deps);
                    }
                    Err(e) => {
                        eprintln!(" -> [警告] 动态探测执行失败: {}", e);
                    }
                }
            }
        }
        println!(
            " -> 动态检测发现 {} 个运行时依赖组件",
            dynamic_dependencies.len()
        );
    }

    let mut final_dependencies: Vec<Dependency> = vec![];
    final_dependencies.extend(static_dependencies);
    final_dependencies.extend(dynamic_dependencies);

    // 2. 排序 (去重的前提)
    final_dependencies.sort_by(|a, b| {
        a.group
            .cmp(&b.group)
            .then(a.name.cmp(&b.name))
            .then(a.version.cmp(&b.version))
    });

    // --- 【修改点 2：去重逻辑 MUST 移出 `if dynamic` 外面】 ---
    // 哪怕只跑静态扫描，多模块下的包也经常有重复，去重是全生命周期的必须步骤！
    let initial_count = final_dependencies.len();
    final_dependencies
        .dedup_by(|a, b| a.group == b.group && a.name == b.name && a.version == b.version);
    let dedup_count = initial_count - final_dependencies.len();

    println!(
        " -> 融合完毕！总计合并去除了 {} 个重复依赖，最终生效 {} 个依赖组件。",
        dedup_count,
        final_dependencies.len()
    );

    // 3. 打印最终写入的包列表
    for dep in final_dependencies.iter() {
        let dep_file = dep
            .location
            .as_ref()
            .map(|v| v.block.file.clone())
            .unwrap_or("no file".to_string());
        let dep_line = dep.location.as_ref().map(|v| v.block.start.line);

        // 建议：这个打印信息非常多，可以考虑用 if configuration.use_debug 包裹起来，
        // 否则大项目会直接刷屏终端。
        if configuration.use_debug {
            println!(
                "dependency name={} version={}, file={}, line={:?}",
                dep.name,
                dep.version.clone().unwrap_or("no version".to_string()),
                dep_file,
                dep_line
            );
        }
    }

    generate_sbom(final_dependencies, configuration).expect("cannot generate SBOM");
    Ok(())
}
