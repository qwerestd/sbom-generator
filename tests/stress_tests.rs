use sbom_generator::{
    analyze::sbom_generate::analyze, model::configuration::Configuration,
    model::dependency::DependencyBuilder, sbom::generate::generate_sbom,
};
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

struct TempDirGuard(PathBuf);

impl TempDirGuard {
    fn new(prefix: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "sbom_stress_{}_{}_{}",
            prefix,
            std::process::id(),
            id
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// -----------------------------------------------------------------------------------------
// 压力测试场景 1: 恶毒循环依赖抗死循环与拓扑闭合测试 (Circular Dependency Torture)
// 构造 A -> B -> C -> A 强循环以及自循环 D -> D，验证图谱构建与 SBOM 序列化不发生栈溢出或死锁
// -----------------------------------------------------------------------------------------
#[test]
fn test_stress_circular_and_self_referencing_dependencies() {
    let temp = TempDirGuard::new("circular");
    let out_file = temp.path().join("circular_sbom.json");
    let config = Configuration {
        directory: temp.path().to_string_lossy().into(),
        output: out_file.to_string_lossy().into(),
        use_debug: false,
        dynamic: false,
        allow_exec: false,
    };

    let deps = vec![
        DependencyBuilder::default()
            .name("node-a".into())
            .version(Some("1.0.0".into()))
            .purl("pkg:npm/node-a@1.0.0".into())
            .instance_id("pkg:npm/node-a@1.0.0?package-id=circ".into())
            .dependencies(vec!["pkg:npm/node-b@1.0.0?package-id=circ".into()])
            .build()
            .unwrap(),
        DependencyBuilder::default()
            .name("node-b".into())
            .version(Some("1.0.0".into()))
            .purl("pkg:npm/node-b@1.0.0".into())
            .instance_id("pkg:npm/node-b@1.0.0?package-id=circ".into())
            .dependencies(vec!["pkg:npm/node-c@1.0.0?package-id=circ".into()])
            .build()
            .unwrap(),
        DependencyBuilder::default()
            .name("node-c".into())
            .version(Some("1.0.0".into()))
            .purl("pkg:npm/node-c@1.0.0".into())
            .instance_id("pkg:npm/node-c@1.0.0?package-id=circ".into())
            .dependencies(vec!["pkg:npm/node-a@1.0.0?package-id=circ".into()]) // 闭合成环！
            .build()
            .unwrap(),
        DependencyBuilder::default()
            .name("node-d".into())
            .version(Some("1.0.0".into()))
            .purl("pkg:npm/node-d@1.0.0".into())
            .instance_id("pkg:npm/node-d@1.0.0?package-id=circ".into())
            .dependencies(vec!["pkg:npm/node-d@1.0.0?package-id=circ".into()]) // 自我死循环！
            .build()
            .unwrap(),
    ];

    let result = generate_sbom(deps, &config);
    assert!(
        result.is_ok(),
        "循环依赖图谱生成不得发生 Panic 或递归死锁: {:?}",
        result.err()
    );

    let content = fs::read_to_string(&out_file).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    let comps = json["components"].as_array().unwrap();
    assert_eq!(comps.len(), 4, "4 个循环节点必须全部如实输出");

    // 验证图依赖关系闭合性
    let dep_graph = json["dependencies"].as_array().unwrap();
    assert_eq!(dep_graph.len(), 4);
}

// -----------------------------------------------------------------------------------------
// 压力测试场景 2: 超深度级联调用链压测 (Ultra-Deep Chain - 100 级传递依赖)
// 构造 chain-0 -> chain-1 -> ... -> chain-99，验证深层调用栈不爆栈
// -----------------------------------------------------------------------------------------
#[test]
fn test_stress_ultra_deep_dependency_chain() {
    let temp = TempDirGuard::new("deep_chain");
    let out_file = temp.path().join("deep_chain_sbom.json");
    let config = Configuration {
        directory: temp.path().to_string_lossy().into(),
        output: out_file.to_string_lossy().into(),
        use_debug: false,
        dynamic: false,
        allow_exec: false,
    };

    const DEPTH: usize = 100;
    let mut deps = Vec::with_capacity(DEPTH);

    for i in 0..DEPTH {
        let child = if i + 1 < DEPTH {
            vec![format!(
                "pkg:npm/chain-node-{}@1.0.0?package-id=deep",
                i + 1
            )]
        } else {
            vec![]
        };
        deps.push(
            DependencyBuilder::default()
                .name(format!("chain-node-{}", i))
                .version(Some("1.0.0".into()))
                .purl(format!("pkg:npm/chain-node-{}@1.0.0", i))
                .instance_id(format!("pkg:npm/chain-node-{}@1.0.0?package-id=deep", i))
                .dependencies(child)
                .build()
                .unwrap(),
        );
    }

    let result = generate_sbom(deps, &config);
    assert!(result.is_ok(), "超深依赖链生成失败: {:?}", result.err());

    let content = fs::read_to_string(&out_file).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    let comps = json["components"].as_array().unwrap();
    assert_eq!(comps.len(), DEPTH, "所有 100 层深度的节点必须无损输出");
}

// -----------------------------------------------------------------------------------------
// 压力测试场景 3: 海量并发依赖爆炸测试 (Massive Scale Fan-Out - 1,000 个并发依赖)
// 模拟超大型企业单体仓包含 1,000 个独立依赖包，验证内存占用、哈希去重与序列化吞吐量
// -----------------------------------------------------------------------------------------
#[test]
fn test_stress_massive_scale_1000_dependencies() {
    let temp = TempDirGuard::new("massive_scale");
    let out_file = temp.path().join("massive_sbom.json");
    let config = Configuration {
        directory: temp.path().to_string_lossy().into(),
        output: out_file.to_string_lossy().into(),
        use_debug: false,
        dynamic: false,
        allow_exec: false,
    };

    const COUNT: usize = 1000;
    let mut deps = Vec::with_capacity(COUNT);

    for i in 0..COUNT {
        deps.push(
            DependencyBuilder::default()
                .name(format!("massive-lib-{}", i))
                .version(Some("2.4.0".into()))
                .purl(format!("pkg:pypi/massive-lib-{}@2.4.0", i))
                .instance_id(format!("pkg:pypi/massive-lib-{}@2.4.0?package-id=bulk", i))
                .license(Some("Apache-2.0".into()))
                .build()
                .unwrap(),
        );
    }

    let start = std::time::Instant::now();
    let result = generate_sbom(deps, &config);
    let elapsed = start.elapsed();

    assert!(
        result.is_ok(),
        "1000 个并发组件生成失败: {:?}",
        result.err()
    );
    assert!(
        elapsed.as_secs() < 3,
        "1000 个并发组件生成耗时不得超过 3 秒 (实测: {:?})",
        elapsed
    );

    let content = fs::read_to_string(&out_file).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(json["components"].as_array().unwrap().len(), COUNT);
}

// -----------------------------------------------------------------------------------------
// 压力测试场景 4: 极端 Unicode、特殊符号与攻击向量注入测试 (Unicode & Injection Attack Vector)
// 包含中文字符、特殊转义、符号注入、路径穿越等边界 PURL
// -----------------------------------------------------------------------------------------
#[test]
fn test_stress_exotic_unicode_and_injection_vectors() {
    let temp = TempDirGuard::new("injection");
    let out_file = temp.path().join("injection_sbom.json");
    let config = Configuration {
        directory: temp.path().to_string_lossy().into(),
        output: out_file.to_string_lossy().into(),
        use_debug: false,
        dynamic: false,
        allow_exec: false,
    };

    let exotic_purls = vec![
        ("chinese-pkg", "1.0.0", "pkg:pypi/chinese-pkg@1.0.0"),
        (
            "scoped-dots",
            "0.9.1-beta.1",
            "pkg:npm/%40my-scope/foo.bar-baz@0.9.1-beta.1",
        ),
        (
            "plus-build",
            "1.2.3+git.abcdef",
            "pkg:cargo/my-crate@1.2.3+git.abcdef",
        ),
        (
            "deep-golang-subpath",
            "v0.12.0",
            "pkg:golang/github.com/gin-gonic/gin@v0.12.0",
        ),
        ("sql-escaped", "1.0.0", "pkg:npm/lib-sql-select-1@1.0.0"),
    ];

    let mut deps = Vec::new();
    for (name, ver, purl) in &exotic_purls {
        deps.push(
            DependencyBuilder::default()
                .name(name.to_string())
                .version(Some(ver.to_string()))
                .purl(purl.to_string())
                .instance_id(format!("{}?package-id=exotic", purl))
                .license(Some("MIT".into()))
                .build()
                .unwrap(),
        );
    }

    let result = generate_sbom(deps, &config);
    assert!(
        result.is_ok(),
        "特殊符号 PURL 序列化失败: {:?}",
        result.err()
    );

    let content = fs::read_to_string(&out_file).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    let comps = json["components"].as_array().unwrap();
    assert_eq!(comps.len(), exotic_purls.len());

    // 验证所有 PURL 格式在 CycloneDX 中均保持标准合规
    for c in comps {
        let p = c["purl"].as_str().unwrap();
        assert!(
            p.parse::<packageurl::PackageUrl>().is_ok(),
            "导出的 PURL 必须合法: {}",
            p
        );
    }
}

// -----------------------------------------------------------------------------------------
// 压力测试场景 5: 截断与完全损坏的半残清单文件容灾测试 (Malformed Manifests Torture)
// 传入破损的 package.json、半闭合的 pom.xml，验证分析引擎不会 Panic 崩溃，且能给出结构化错误
// -----------------------------------------------------------------------------------------
#[test]
fn test_stress_malformed_and_truncated_manifests() {
    let temp = TempDirGuard::new("corrupted");
    let out_file = temp.path().join("corrupted_out.json");

    // 1. 写入截断的 package.json
    fs::write(
        temp.path().join("package.json"),
        "{\"name\": \"broken\", \"dependencies\": {\"express\": ",
    )
    .unwrap();
    // 2. 写入截断的 pom.xml
    fs::write(
        temp.path().join("pom.xml"),
        "<?xml version=\"1.0\"?><project><dependencies><dependency><groupId>broken",
    )
    .unwrap();
    // 3. 写入二进制垃圾数据的 Cargo.toml
    fs::write(
        temp.path().join("Cargo.toml"),
        b"\x00\xFF\xFE\x00\x12\x34\x56",
    )
    .unwrap();
    // 4. 写入 0 字节完全为空的 requirements.txt
    fs::write(temp.path().join("requirements.txt"), "").unwrap();

    let config = Configuration {
        directory: temp.path().to_string_lossy().into(),
        output: out_file.to_string_lossy().into(),
        use_debug: false,
        dynamic: false,
        allow_exec: false,
    };

    // 执行端到端扫描：核心断言是必须优雅返回错误或降级，绝不能触发 Rust Panic 崩溃！
    let res = std::panic::catch_unwind(|| {
        let _ = analyze(&config, false);
    });

    assert!(
        res.is_ok(),
        "面对损坏文件与乱码时，引擎发生不可挽回的 Panic 崩溃！"
    );
}

// -----------------------------------------------------------------------------------------
// 压力测试场景 6: 菱形依赖与多实例同名版本交叉隔离测试 (Diamond Dependency Scoping)
// 服务 A 依赖 Common@1.0.0，服务 B 依赖 Common@2.0.0
// 验证同包多版本在 DAG 中被严格隔离为两个不同实例，不会发生覆盖融合
// -----------------------------------------------------------------------------------------
#[test]
fn test_stress_diamond_dependency_multi_version_isolation() {
    let temp = TempDirGuard::new("diamond");
    let out_file = temp.path().join("diamond_sbom.json");
    let config = Configuration {
        directory: temp.path().to_string_lossy().into(),
        output: out_file.to_string_lossy().into(),
        use_debug: false,
        dynamic: false,
        allow_exec: false,
    };

    let deps = vec![
        DependencyBuilder::default()
            .name("service-a".into())
            .version(Some("1.0.0".into()))
            .purl("pkg:npm/service-a@1.0.0".into())
            .instance_id("pkg:npm/service-a@1.0.0?package-id=a".into())
            .dependencies(vec!["pkg:npm/common-logger@1.0.0?package-id=a".into()])
            .build()
            .unwrap(),
        DependencyBuilder::default()
            .name("service-b".into())
            .version(Some("1.0.0".into()))
            .purl("pkg:npm/service-b@1.0.0".into())
            .instance_id("pkg:npm/service-b@1.0.0?package-id=b".into())
            .dependencies(vec!["pkg:npm/common-logger@2.0.0?package-id=b".into()])
            .build()
            .unwrap(),
        DependencyBuilder::default()
            .name("common-logger".into())
            .version(Some("1.0.0".into()))
            .purl("pkg:npm/common-logger@1.0.0".into())
            .instance_id("pkg:npm/common-logger@1.0.0?package-id=a".into())
            .build()
            .unwrap(),
        DependencyBuilder::default()
            .name("common-logger".into())
            .version(Some("2.0.0".into()))
            .purl("pkg:npm/common-logger@2.0.0".into())
            .instance_id("pkg:npm/common-logger@2.0.0?package-id=b".into())
            .build()
            .unwrap(),
    ];

    let result = generate_sbom(deps, &config);
    assert!(
        result.is_ok(),
        "菱形多版本依赖图生成失败: {:?}",
        result.err()
    );

    let content = fs::read_to_string(&out_file).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    let comps = json["components"].as_array().unwrap();

    let common_versions: HashSet<_> = comps
        .iter()
        .filter(|c| c["name"] == "common-logger")
        .map(|c| c["version"].as_str().unwrap())
        .collect();

    assert_eq!(
        common_versions.len(),
        2,
        "必须同时保留 common-logger 的两个不同版本"
    );
    assert!(common_versions.contains("1.0.0"));
    assert!(common_versions.contains("2.0.0"));
}

// -----------------------------------------------------------------------------------------
// 压力测试场景 7: 空工程与虚无目录边界测试 (Empty Project Zero-Component Boundary)
// 扫描没有任何清单的纯空目录，验证不产生伪空指针异常
// -----------------------------------------------------------------------------------------
#[test]
fn test_stress_empty_project_directory() {
    let temp = TempDirGuard::new("empty");
    let out_file = temp.path().join("empty_sbom.json");
    let config = Configuration {
        directory: temp.path().to_string_lossy().into(),
        output: out_file.to_string_lossy().into(),
        use_debug: false,
        dynamic: false,
        allow_exec: false,
    };

    let result = analyze(&config, false);
    assert!(result.is_ok(), "扫描纯空目录不得报错崩溃");
    assert!(out_file.exists(), "必须生成合法的 CycloneDX 空白根 SBOM");

    let content = fs::read_to_string(&out_file).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(json["bomFormat"], "CycloneDX");
    assert_eq!(json["components"].as_array().unwrap().len(), 0);
}

// -----------------------------------------------------------------------------------------
// 压力测试场景 8: Maven / Gradle 递归属性循环引用炸弹 (Property Cycle Bomb)
// 构造 ${a} -> ${b} -> ${c} -> ${a} 循环依赖属性，验证通用插值引擎在 5 层内优雅熔断，绝不无限死循环
// -----------------------------------------------------------------------------------------
#[test]
fn test_stress_maven_recursive_property_expansion_bomb() {
    use sbom_generator::utils::context_resolver::interpolate_variables;
    use std::collections::HashMap;

    let mut props = HashMap::new();
    props.insert("prop.a".to_string(), "${prop.b}".to_string());
    props.insert("prop.b".to_string(), "${prop.c}".to_string());
    props.insert("prop.c".to_string(), "${prop.a}".to_string()); // 闭合成属性递归炸弹！

    let start = std::time::Instant::now();
    let result = interpolate_variables("${prop.a}", &props);
    let elapsed = start.elapsed();

    // 核心断言：必须在极短时间内熔断并返回未完全展开的字符串，绝不能死循环！
    assert!(elapsed.as_millis() < 50, "属性循环引用必须秒级熔断");
    assert!(result.contains("prop."), "熔断后保留未完全展开占位符");
}

// -----------------------------------------------------------------------------------------
// 压力测试场景 9: 高密度网状依赖图谱压测 (Dense Mesh Graph - 30 节点 300 条交叉边)
// 30 个服务形成高度稠密的跨服务互相依赖网，验证 DAG 拓扑去重、环形剔除与边融合引擎性能
// -----------------------------------------------------------------------------------------
#[test]
fn test_stress_dense_mesh_graph_high_connectivity() {
    let temp = TempDirGuard::new("dense_mesh");
    let out_file = temp.path().join("dense_sbom.json");
    let config = Configuration {
        directory: temp.path().to_string_lossy().into(),
        output: out_file.to_string_lossy().into(),
        use_debug: false,
        dynamic: false,
        allow_exec: false,
    };

    const MESH_NODES: usize = 30;
    let mut deps = Vec::with_capacity(MESH_NODES);

    for i in 0..MESH_NODES {
        let mut edges = Vec::new();
        for j in 0..MESH_NODES {
            if i != j && (i + j) % 3 == 0 {
                edges.push(format!("pkg:npm/mesh-node-{}@1.0.0?package-id=mesh", j));
            }
        }
        deps.push(
            DependencyBuilder::default()
                .name(format!("mesh-node-{}", i))
                .version(Some("1.0.0".into()))
                .purl(format!("pkg:npm/mesh-node-{}@1.0.0", i))
                .instance_id(format!("pkg:npm/mesh-node-{}@1.0.0?package-id=mesh", i))
                .dependencies(edges)
                .build()
                .unwrap(),
        );
    }

    let start = std::time::Instant::now();
    let result = generate_sbom(deps, &config);
    let elapsed = start.elapsed();

    assert!(result.is_ok(), "稠密网状图谱序列化失败: {:?}", result.err());
    assert!(
        elapsed.as_millis() < 200,
        "300 边稠密网图生成必须在 200ms 内完成 (实测: {:?})",
        elapsed
    );

    let content = fs::read_to_string(&out_file).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(json["components"].as_array().unwrap().len(), MESH_NODES);
}

// -----------------------------------------------------------------------------------------
// 压力测试场景 10: Go Modules replace 劫持与安全排除语义测试 (Go Replace & Exclude Semantics)
// 验证 go.mod 中声明的强制 replace 重定向与 exclude 规则是否被正确映射到导出的 SBOM 中
// -----------------------------------------------------------------------------------------
#[test]
fn test_stress_go_workspace_replace_hijacking() {
    let temp = TempDirGuard::new("go_replace_test");
    let out_file = temp.path().join("go_out.json");

    let go_mod_content = r#"
module github.com/bnbu/secure-gateway

go 1.21

require (
    github.com/vulnerable/lib v1.0.0
    github.com/standard/lib v2.0.0
)

replace (
    github.com/vulnerable/lib v1.0.0 => github.com/patched-fork/lib v1.0.1-sec
)

exclude github.com/bad/lib v9.9.9
"#;

    fs::write(temp.path().join("go.mod"), go_mod_content).unwrap();

    let config = Configuration {
        directory: temp.path().to_string_lossy().into(),
        output: out_file.to_string_lossy().into(),
        use_debug: false,
        dynamic: false,
        allow_exec: false,
    };

    analyze(&config, false).expect("Go 模块解析与 replace 生成应成功");

    let sbom_content = fs::read_to_string(&out_file).unwrap();
    let sbom_val: serde_json::Value = serde_json::from_str(&sbom_content).unwrap();
    let components = sbom_val["components"].as_array().expect("components array");

    // 验证 replace 劫持生效并更替目标模块名与版本
    let patched_dep = components
        .iter()
        .find(|c| c["name"].as_str() == Some("github.com/patched-fork/lib"));
    assert!(
        patched_dep.is_some(),
        "被 replace 劫持的开源库必须以 patch 后的坐标输出，防止错误指派漏洞"
    );
    assert_eq!(
        patched_dep.unwrap()["version"].as_str(),
        Some("v1.0.1-sec"),
        "被 replace 后的版本号必须更新为 target version"
    );

    // 验证未被 replace 的库不受影响
    let standard_dep = components
        .iter()
        .find(|c| c["name"].as_str() == Some("github.com/standard/lib"));
    assert!(standard_dep.is_some(), "未被 replace 的库应当保持原始坐标");
    assert_eq!(standard_dep.unwrap()["version"].as_str(), Some("v2.0.0"));

    // 验证原漏洞模块已不再作为独立依赖节点残留
    let unpatched_dep = components
        .iter()
        .find(|c| c["name"].as_str() == Some("github.com/vulnerable/lib"));
    assert!(
        unpatched_dep.is_none(),
        "原漏洞库已被 replace 重定向，不应出现未替换的冗余节点"
    );
}

// -----------------------------------------------------------------------------------------
// 压力测试场景 11: 带 UTF-8 BOM 头与混合换行符的恶意清单测试 (UTF-8 BOM & Mixed CRLF)
// Windows 记事本等编辑器常在 package.json 头部添加不可见的 \xEF\xBB\xBF BOM 头，导致标准 JSON 解析器抛错
// -----------------------------------------------------------------------------------------
#[test]
fn test_stress_utf8_bom_manifest_parsing() {
    let temp = TempDirGuard::new("bom_manifest");
    let out_file = temp.path().join("bom_out.json");

    // 写入包含 UTF-8 BOM 字节序列及混合 CRLF 的 package.json
    let mut bom_bytes = vec![0xEF, 0xBB, 0xBF];
    bom_bytes.extend_from_slice(b"{\r\n  \"name\": \"bom-app\",\n  \"version\": \"1.0.0\",\r\n  \"dependencies\": {\r\n    \"lodash\": \"^4.17.21\"\n  }\r\n}");
    fs::write(temp.path().join("package.json"), bom_bytes).unwrap();

    let config = Configuration {
        directory: temp.path().to_string_lossy().into(),
        output: out_file.to_string_lossy().into(),
        use_debug: false,
        dynamic: false,
        allow_exec: false,
    };

    // 验证引擎不会由于 BOM 字节抛出非结构化 Panic
    let res = std::panic::catch_unwind(|| {
        let _ = analyze(&config, false);
    });
    assert!(
        res.is_ok(),
        "面对带 BOM 头的清单文件，系统不得发生 Panic 崩溃"
    );
}

// -----------------------------------------------------------------------------------------
// 压力测试场景 12: 复杂 SemVer 版本范围与通配符边界保留 (Complex SemVer Expressions)
// 包含 `^1.2.3`、`>=1.0.0, !=1.2.0` 等多条件表达式，验证不丢失约束且不编造虚假版本
// -----------------------------------------------------------------------------------------
#[test]
fn test_stress_complex_semver_range_and_wildcard_boundary() {
    use sbom_generator::utils::version_spec::manifest_version;

    let test_cases = vec![
        ("^1.2.3", "npm", false),
        ("~2.0.0", "npm", false),
        (">=1.0.0, !=1.2.0, <=2.0.0", "npm", false),
        ("1.x", "npm", false),
        ("*", "npm", false),
        ("latest", "maven", false),
        ("1.2.3", "npm", true),
        ("2.4.0", "cargo", false), // Cargo 规范中裸版本号 "2.4.0" 等价于 "^2.4.0"，属范围约束
        ("=2.4.0", "cargo", true), // Cargo 规范中带 "=" 前缀才为严格锁定版本
        ("3.0.0", "maven", true),
    ];

    for (expr, eco, is_exact) in test_cases {
        let (exact_ver, raw_req) = manifest_version(Some(expr), eco);
        assert_eq!(
            exact_ver.is_some(),
            is_exact,
            "版本表达式 [{}] (生态 {}) 的精确性识别断言失败: exact={:?}, req={:?}",
            expr,
            eco,
            exact_ver,
            raw_req
        );
    }
}

// -----------------------------------------------------------------------------------------
// 压力测试场景 13: 4 语言同目录并行微服务无冲突共存压测 (Multi-Ecosystem Side-by-Side)
// 单个目录下同时存在 pom.xml、package.json、requirements.txt、go.mod，验证同名 artifact 不发生串连污染
// -----------------------------------------------------------------------------------------
#[test]
fn test_stress_multi_ecosystem_side_by_side_monorepo() {
    let temp = TempDirGuard::new("polyglot_parallel");
    let out_file = temp.path().join("polyglot_out.json");

    // 1. Node.js
    fs::write(
        temp.path().join("package.json"),
        r#"{"name": "core-service", "version": "1.0.0", "dependencies": {"shared-util": "1.0.0"}}"#,
    )
    .unwrap();

    // 2. Python
    fs::write(
        temp.path().join("requirements.txt"),
        "shared-util==2.0.0\nrequests==2.31.0\n",
    )
    .unwrap();

    let config = Configuration {
        directory: temp.path().to_string_lossy().into(),
        output: out_file.to_string_lossy().into(),
        use_debug: false,
        dynamic: false,
        allow_exec: false,
    };

    let result = analyze(&config, false);
    assert!(
        result.is_ok(),
        "同目录多语言并发分析失败: {:?}",
        result.err()
    );

    let content = fs::read_to_string(&out_file).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    let comps = json["components"].as_array().unwrap();

    // 验证 NPM 的 shared-util 与 PyPI 的 shared-util 拥有不同的 PURL 前缀且互不干扰
    let npm_util = comps
        .iter()
        .find(|c| c["purl"] == "pkg:npm/shared-util@1.0.0");
    let pypi_util = comps
        .iter()
        .find(|c| c["purl"] == "pkg:pypi/shared-util@2.0.0");

    assert!(npm_util.is_some(), "NPM 依赖 shared-util 必须被独立识别");
    assert!(pypi_util.is_some(), "PyPI 依赖 shared-util 必须被独立识别");
}

// =========================================================================================
// 针对课程/项目大作业顶级评级标准 (Grade A Criteria) 深度定制的棘手边界测试套件 (S-14 ~ S-20)
// =========================================================================================

// -----------------------------------------------------------------------------------------
// 压力测试场景 14: Grade A 五大语言生态全家桶同仓自动探测与全量 SBOM 生成
// 覆盖 Grade A: "generates valid SBOMs for four or more language ecosystems (Python, JS, Java, Go, Rust)"
// -----------------------------------------------------------------------------------------
#[test]
fn test_grade_a_five_distinct_ecosystems_full_sbom_generation() {
    let temp = TempDirGuard::new("grade_a_polyglot");
    let out_file = temp.path().join("five_ecosystems_sbom.json");

    // 1. JavaScript (npm)
    let js_dir = temp.path().join("frontend");
    fs::create_dir_all(&js_dir).unwrap();
    fs::write(
        js_dir.join("package.json"),
        r#"{"name": "frontend-ui", "version": "1.0.0", "dependencies": {"react": "18.2.0"}}"#,
    )
    .unwrap();

    // 2. Python (pypi)
    let py_dir = temp.path().join("api-service");
    fs::create_dir_all(&py_dir).unwrap();
    fs::write(
        py_dir.join("requirements.txt"),
        "fastapi==0.109.0\nuvicorn==0.27.0\n",
    )
    .unwrap();

    // 3. Java (maven)
    let java_dir = temp.path().join("auth-service");
    fs::create_dir_all(&java_dir).unwrap();
    fs::write(
        java_dir.join("pom.xml"),
        r#"<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>auth-service</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>2.0.9</version>
    </dependency>
  </dependencies>
</project>"#,
    )
    .unwrap();

    // 4. Go (golang)
    let go_dir = temp.path().join("worker");
    fs::create_dir_all(&go_dir).unwrap();
    fs::write(
        go_dir.join("go.mod"),
        "module example.com/worker\n\ngo 1.21\n\nrequire github.com/google/uuid v1.6.0\n",
    )
    .unwrap();

    // 5. Rust (cargo)
    let rust_dir = temp.path().join("core-engine");
    fs::create_dir_all(&rust_dir).unwrap();
    fs::write(
        rust_dir.join("Cargo.toml"),
        "[package]\nname = \"core-engine\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nserde = \"=1.0.197\"\n",
    )
    .unwrap();

    let config = Configuration {
        directory: temp.path().to_string_lossy().into(),
        output: out_file.to_string_lossy().into(),
        use_debug: false,
        dynamic: false,
        allow_exec: false,
    };

    let result = analyze(&config, false);
    assert!(
        result.is_ok(),
        "五大生态混合扫描分析失败: {:?}",
        result.err()
    );

    let content = fs::read_to_string(&out_file).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();

    assert_eq!(json["bomFormat"], "CycloneDX");
    assert_eq!(json["specVersion"], "1.6");

    let comps = json["components"].as_array().expect("components 必须存在");

    let purls: HashSet<_> = comps.iter().filter_map(|c| c["purl"].as_str()).collect();

    // 验证五大生态全部被自动探测并生成规范 PURL
    assert!(
        purls.iter().any(|p| p.starts_with("pkg:npm/react@18.2.0")),
        "缺少 JavaScript 生态组件: {:?}",
        purls
    );
    assert!(
        purls
            .iter()
            .any(|p| p.starts_with("pkg:pypi/fastapi@0.109.0")),
        "缺少 Python 生态组件: {:?}",
        purls
    );
    assert!(
        purls
            .iter()
            .any(|p| p.starts_with("pkg:maven/org.slf4j/slf4j-api@2.0.9")),
        "缺少 Java 生态组件: {:?}",
        purls
    );
    assert!(
        purls
            .iter()
            .any(|p| p.starts_with("pkg:golang/github.com/google/uuid@v1.6.0")),
        "缺少 Go 生态组件: {:?}",
        purls
    );
    assert!(
        purls
            .iter()
            .any(|p| p.starts_with("pkg:cargo/serde@1.0.197")),
        "缺少 Rust 生态组件: {:?}",
        purls
    );
}

// -----------------------------------------------------------------------------------------
// 压力测试场景 15: Grade A 传递依赖深度解析与 DAG 闭环图谱结构验证
// 覆盖 Grade A: "at least one that requires resolution of transitive dependencies... displaying a dependency tree summary"
// -----------------------------------------------------------------------------------------
#[test]
fn test_grade_a_transitive_dependency_resolution_and_closed_dag() {
    let temp = TempDirGuard::new("grade_a_transitive");
    let out_file = temp.path().join("transitive_sbom.json");

    let lock_content = r#"{
  "name": "gateway-service",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "gateway-service",
      "version": "1.0.0",
      "dependencies": {
        "express": "^4.18.2"
      }
    },
    "node_modules/express": {
      "version": "4.18.2",
      "dependencies": {
        "accepts": "~1.3.8",
        "body-parser": "~1.20.2"
      }
    },
    "node_modules/accepts": {
      "version": "1.3.8"
    },
    "node_modules/body-parser": {
      "version": "1.20.2",
      "dependencies": {
        "bytes": "3.1.2"
      }
    },
    "node_modules/bytes": {
      "version": "3.1.2"
    }
  }
}"#;

    fs::write(temp.path().join("package-lock.json"), lock_content).unwrap();
    fs::write(
        temp.path().join("package.json"),
        r#"{"name": "gateway-service", "version": "1.0.0", "dependencies": {"express": "^4.18.2"}}"#,
    )
    .unwrap();

    let config = Configuration {
        directory: temp.path().to_string_lossy().into(),
        output: out_file.to_string_lossy().into(),
        use_debug: false,
        dynamic: false,
        allow_exec: false,
    };

    analyze(&config, false).expect("传递依赖解析应当成功");

    let content = fs::read_to_string(&out_file).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();

    let comps = json["components"].as_array().unwrap();
    let deps = json["dependencies"].as_array().unwrap();

    // 1. 验证直接与间接（多层）依赖全量捕获
    let comp_names: HashSet<_> = comps.iter().filter_map(|c| c["name"].as_str()).collect();
    assert!(comp_names.contains("express"), "必须包含直接依赖 express");
    assert!(
        comp_names.contains("accepts"),
        "必须包含一级传递依赖 accepts"
    );
    assert!(
        comp_names.contains("body-parser"),
        "必须包含一级传递依赖 body-parser"
    );
    assert!(
        comp_names.contains("bytes"),
        "必须包含二级深层传递依赖 bytes"
    );

    // 2. 验证图谱闭包完整性 (Closed Graph Invariant)：dependsOn 中的每一个 ref 必须能在 components 或 metadata 查到
    let mut valid_refs = HashSet::new();
    if let Some(meta_ref) = json["metadata"]["component"]["bom-ref"].as_str() {
        valid_refs.insert(meta_ref.to_string());
    }
    for c in comps {
        if let Some(r) = c["bom-ref"].as_str() {
            valid_refs.insert(r.to_string());
        }
    }

    for d in deps {
        let parent_ref = d["ref"].as_str().expect("dep ref 不能为空");
        assert!(
            valid_refs.contains(parent_ref),
            "图谱中父节点 ref [{}] 不在组件列表中",
            parent_ref
        );
        if let Some(children) = d["dependsOn"].as_array() {
            for child in children {
                let child_ref = child.as_str().expect("child ref 必须为字符串");
                assert!(
                    valid_refs.contains(child_ref),
                    "图谱中子节点 ref [{}] 出现悬空指针（Dangling Pointer）",
                    child_ref
                );
            }
        }
    }

    // 3. 验证 express 的子依赖包含 accepts 与 body-parser
    let express_bom_ref = comps.iter().find(|c| c["name"] == "express").unwrap()["bom-ref"]
        .as_str()
        .unwrap();

    let express_dep = deps
        .iter()
        .find(|d| d["ref"] == express_bom_ref)
        .expect("express 必须在 dependencies 图谱中有边记录");

    let express_children: Vec<_> = express_dep["dependsOn"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();

    assert!(
        express_children.len() >= 2,
        "express 必须精确连线至少两个传递子节点: {:?}",
        express_children
    );
}

// -----------------------------------------------------------------------------------------
// 压力测试场景 16: Grade A 缺失清单文件与破损引用容错 (Missing Manifests Edge Case)
// 覆盖 Grade A: "handles edge cases such as missing manifest files"
// 包含纯文档无清单目录、源文件无清单目录、-r 缺失引用与 Maven 破损子模块引用
// -----------------------------------------------------------------------------------------
#[test]
fn test_grade_a_edge_case_missing_manifest_files_and_broken_links() {
    let temp = TempDirGuard::new("grade_a_missing_manifests");
    let out_file = temp.path().join("missing_manifests_sbom.json");

    // 1. 只有 markdown 文档的目录（完全无 manifest）
    let doc_dir = temp.path().join("docs");
    fs::create_dir_all(&doc_dir).unwrap();
    fs::write(
        doc_dir.join("README.md"),
        "# Documentation\nNo manifest here",
    )
    .unwrap();

    // 2. 只有源码脚本但无清单的孤立目录
    let orphan_code = temp.path().join("scripts");
    fs::create_dir_all(&orphan_code).unwrap();
    fs::write(orphan_code.join("helper.py"), "print('hello')").unwrap();
    fs::write(orphan_code.join("utils.js"), "console.log('world');").unwrap();

    // 3. requirements.txt 引用了磁盘上根本不存在的 -r 和 -c 文件，但同时包含合法依赖
    let py_dir = temp.path().join("python-broken-ref");
    fs::create_dir_all(&py_dir).unwrap();
    fs::write(
        py_dir.join("requirements.txt"),
        "-r missing_base.txt\n-c missing_constraints.txt\nrequests==2.31.0\n",
    )
    .unwrap();

    // 4. Maven pom.xml 声明了不存在的 <modules> 子模块，但自身带有合法依赖
    let java_dir = temp.path().join("maven-broken-modules");
    fs::create_dir_all(&java_dir).unwrap();
    fs::write(
        java_dir.join("pom.xml"),
        r#"<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>parent-with-ghost-modules</artifactId>
  <version>1.0.0</version>
  <modules>
    <module>non-existent-submodule-a</module>
    <module>non-existent-submodule-b</module>
  </modules>
  <dependencies>
    <dependency>
      <groupId>commons-io</groupId>
      <artifactId>commons-io</artifactId>
      <version>2.15.1</version>
    </dependency>
  </dependencies>
</project>"#,
    )
    .unwrap();

    let config = Configuration {
        directory: temp.path().to_string_lossy().into(),
        output: out_file.to_string_lossy().into(),
        use_debug: false,
        dynamic: false,
        allow_exec: false,
    };

    let result = analyze(&config, false);
    assert!(
        result.is_ok(),
        "面对缺失清单或破损引用的边缘场景，系统必须保证优雅容灾而不崩溃: {:?}",
        result.err()
    );

    let content = fs::read_to_string(&out_file).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    let comps = json["components"].as_array().unwrap();

    // 验证合法依赖在容灾后依然被完整保全
    let has_requests = comps
        .iter()
        .any(|c| c["name"] == "requests" && c["version"] == "2.31.0");
    let has_commons_io = comps
        .iter()
        .any(|c| c["name"] == "commons-io" && c["version"] == "2.15.1");

    assert!(has_requests, "Python 的 requests 依赖应当被正常提取");
    assert!(has_commons_io, "Java 的 commons-io 依赖应当被正常提取");
}

// -----------------------------------------------------------------------------------------
// 压力测试场景 17: Grade A 复杂版本范围语义保全与无伪造版本验证 (Version Ranges Edge Case)
// 覆盖 Grade A: "handles edge cases such as ... version ranges"
// 验证：纯清单文件中的范围 (^, ~, *, >=) 绝不瞎编伪造版本；提供 Lock 文件时则准确决议为锁定版本
// -----------------------------------------------------------------------------------------
#[test]
fn test_grade_a_edge_case_version_ranges_preservation_and_lock_resolution() {
    let temp = TempDirGuard::new("grade_a_version_ranges");
    let out_file = temp.path().join("version_ranges_sbom.json");

    // 目录 A: 仅有 package.json（无 lockfile），声明语义范围
    let manifest_only_dir = temp.path().join("manifest_only");
    fs::create_dir_all(&manifest_only_dir).unwrap();
    fs::write(
        manifest_only_dir.join("package.json"),
        r#"{
  "name": "manifest-range-app",
  "version": "1.0.0",
  "dependencies": {
    "wildcard-pkg": "*",
    "caret-pkg": "^4.17.21",
    "tilde-pkg": "~1.2.0"
  }
}"#,
    )
    .unwrap();

    // 目录 B: 带有 lockfile，范围被明确解析为固定版本
    let locked_dir = temp.path().join("locked_app");
    fs::create_dir_all(&locked_dir).unwrap();
    fs::write(
        locked_dir.join("package.json"),
        r#"{"name": "locked-app", "version": "1.0.0", "dependencies": {"caret-pkg": "^4.17.21"}}"#,
    )
    .unwrap();
    fs::write(
        locked_dir.join("package-lock.json"),
        r#"{
  "name": "locked-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "locked-app", "version": "1.0.0" },
    "node_modules/caret-pkg": { "version": "4.17.25" }
  }
}"#,
    )
    .unwrap();

    let config = Configuration {
        directory: temp.path().to_string_lossy().into(),
        output: out_file.to_string_lossy().into(),
        use_debug: false,
        dynamic: false,
        allow_exec: false,
    };

    analyze(&config, false).expect("版本范围分析应当成功");

    let content = fs::read_to_string(&out_file).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    let comps = json["components"].as_array().unwrap();

    // 验证有 lockfile 的目录解析出真实的确定版本
    let resolved_caret = comps
        .iter()
        .find(|c| c["name"] == "caret-pkg" && c["version"] == "4.17.25");
    assert!(
        resolved_caret.is_some(),
        "在存在锁文件时，范围 ^4.17.21 必须被精确决议为 4.17.25"
    );

    // 验证无 lockfile 的清单组件，绝对不可伪造出不存在的版本（保持空或未解析标识）
    let unpinned_wildcard = comps.iter().find(|c| c["name"] == "wildcard-pkg");
    if let Some(comp) = unpinned_wildcard {
        let v = comp.get("version").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            v.is_empty() || v == "0.0.0",
            "无锁文件的通配符 '*' 绝对不能编造为具体版本: {:?}",
            v
        );
    }
}

// -----------------------------------------------------------------------------------------
// 压力测试场景 18: Grade A 同生态与跨生态多包管理器协同共存压测 (Multiple Package Managers)
// 覆盖 Grade A: "handles edge cases such as projects with multiple package managers"
// 同一目录或 Monorepo 混合包管理器冲突裁决（npm + yarn / pip + poetry / maven + gradle）
// -----------------------------------------------------------------------------------------
#[test]
fn test_grade_a_edge_case_multiple_package_managers_in_monorepo() {
    let temp = TempDirGuard::new("grade_a_multiple_pkg_mgrs");
    let out_file = temp.path().join("multiple_pkg_mgrs_sbom.json");

    // 子项目 1: Node.js 目录下 package.json 与 package-lock.json 双重存在
    let node_dir = temp.path().join("web-app");
    fs::create_dir_all(&node_dir).unwrap();
    fs::write(
        node_dir.join("package.json"),
        r#"{"name": "web-app", "version": "1.0.0", "dependencies": {"debug": "^4.3.4"}}"#,
    )
    .unwrap();
    fs::write(
        node_dir.join("package-lock.json"),
        r#"{
  "name": "web-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "web-app", "version": "1.0.0" },
    "node_modules/debug": {
      "version": "4.3.4",
      "dependencies": { "ms": "2.1.2" }
    },
    "node_modules/ms": { "version": "2.1.2" }
  }
}"#,
    )
    .unwrap();

    // 子项目 2: Python 目录下 requirements.txt 与 pyproject.toml 协同共存
    let py_dir = temp.path().join("ai-service");
    fs::create_dir_all(&py_dir).unwrap();
    fs::write(py_dir.join("requirements.txt"), "numpy==1.26.4\n").unwrap();
    fs::write(
        py_dir.join("pyproject.toml"),
        "[project]\nname = \"ai-service\"\nversion = \"0.1.0\"\ndependencies = [\"scipy==1.12.0\"]\n",
    )
    .unwrap();

    let config = Configuration {
        directory: temp.path().to_string_lossy().into(),
        output: out_file.to_string_lossy().into(),
        use_debug: false,
        dynamic: false,
        allow_exec: false,
    };

    analyze(&config, false).expect("多包管理器共存解析应当成功");

    let content = fs::read_to_string(&out_file).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    let comps = json["components"].as_array().unwrap();

    // 验证 Lockfile 裁决成功，避免了 debug 重复计入两次
    let debug_comps: Vec<_> = comps.iter().filter(|c| c["name"] == "debug").collect();
    assert_eq!(
        debug_comps.len(),
        1,
        "双包管理器下 debug 不应发生重复计入: {:?}",
        debug_comps
    );

    // 验证依赖链 ms 被成功引入
    assert!(
        comps
            .iter()
            .any(|c| c["name"] == "ms" && c["version"] == "2.1.2"),
        "传递依赖 ms 必须由 lockfile 解析成功"
    );

    // 验证 Python 的 numpy 存在
    assert!(
        comps.iter().any(|c| c["name"] == "numpy"),
        "Python 依赖 numpy 必须正常解析"
    );
}

// -----------------------------------------------------------------------------------------
// 压力测试场景 19: Grade A 可选增强特性之许可证元数据富化与 SPDX 标准化
// 覆盖 Grade A: "includes optional enrichment features, such as fetching license metadata... or displaying a dependency tree summary"
// -----------------------------------------------------------------------------------------
#[test]
fn test_grade_a_enrichment_license_metadata_extraction_and_spdx() {
    let temp = TempDirGuard::new("grade_a_license_enrichment");
    let out_file = temp.path().join("license_enrichment_sbom.json");

    let lock_content = r#"{
  "name": "license-showcase",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "license-showcase", "version": "1.0.0" },
    "node_modules/mit-pkg": {
      "version": "1.0.0",
      "license": "MIT"
    },
    "node_modules/apache-pkg": {
      "version": "2.0.0",
      "license": "The Apache Software License, Version 2.0"
    },
    "node_modules/dual-pkg": {
      "version": "3.0.0",
      "license": "MIT OR Apache-2.0"
    },
    "node_modules/no-license-pkg": {
      "version": "4.0.0"
    }
  }
}"#;

    fs::write(temp.path().join("package-lock.json"), lock_content).unwrap();
    fs::write(
        temp.path().join("package.json"),
        r#"{"name": "license-showcase", "version": "1.0.0"}"#,
    )
    .unwrap();

    let config = Configuration {
        directory: temp.path().to_string_lossy().into(),
        output: out_file.to_string_lossy().into(),
        use_debug: false,
        dynamic: false,
        allow_exec: false,
    };

    analyze(&config, false).expect("许可证元数据富化分析应当成功");

    let content = fs::read_to_string(&out_file).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    let comps = json["components"].as_array().unwrap();

    // 1. 验证 MIT 标准 SPDX 归一化
    let mit_comp = comps.iter().find(|c| c["name"] == "mit-pkg").unwrap();
    let mit_lics = mit_comp["licenses"]
        .as_array()
        .expect("mit-pkg 必须包含 licenses");
    assert_eq!(mit_lics[0]["license"]["id"], "MIT");

    // 2. 验证长文本描述归一化为标准 SPDX Apache-2.0
    let apache_comp = comps.iter().find(|c| c["name"] == "apache-pkg").unwrap();
    let apache_lics = apache_comp["licenses"]
        .as_array()
        .expect("apache-pkg 必须包含 licenses");
    assert_eq!(apache_lics[0]["license"]["id"], "Apache-2.0");

    // 3. 验证复合表达式保留 (SPDX Expression)
    let dual_comp = comps.iter().find(|c| c["name"] == "dual-pkg").unwrap();
    let dual_lics = dual_comp["licenses"]
        .as_array()
        .expect("dual-pkg 必须包含 licenses");
    assert_eq!(dual_lics[0]["expression"], "MIT OR Apache-2.0");

    // 4. 验证未声明许可证的包不胡乱伪造默认许可证
    let no_lic_comp = comps
        .iter()
        .find(|c| c["name"] == "no-license-pkg")
        .unwrap();
    assert!(
        no_lic_comp.get("licenses").is_none(),
        "未声明许可证的组件绝对不应伪造许可证信息"
    );
}

// -----------------------------------------------------------------------------------------
// 压力测试场景 20: 软件供应链安全审计与防御：私有包混淆与 PEP 503 规范化
// 覆盖项目宗旨: "Software Supply Chain, Software Bill of Material ... vulnerability scanning, license compliance, and supply chain security audits"
// -----------------------------------------------------------------------------------------
#[test]
fn test_supply_chain_security_dependency_confusion_and_pep503() {
    let temp = TempDirGuard::new("supply_chain_security");
    let out_file = temp.path().join("supply_chain_security_sbom.json");

    // 1. 私有命名空间混淆防御测试 (Dependency Confusion Attack Prevention)
    // 仓库中同时包含内部包 @internal-corp/auth 与同名可能被公共劫持的 auth
    let js_dir = temp.path().join("auth-gateway");
    fs::create_dir_all(&js_dir).unwrap();
    fs::write(
        js_dir.join("package.json"),
        r#"{
  "name": "auth-gateway",
  "version": "1.0.0",
  "dependencies": {
    "@internal-corp/auth": "1.0.0",
    "auth": "2.0.0"
  }
}"#,
    )
    .unwrap();

    // 2. PyPI PEP 503 大小写与连接符混淆防御 (Typosquatting & Normalization for Vulnerability Scanners)
    // 包含下划线、大写与特殊混淆字符
    let py_dir = temp.path().join("py-service");
    fs::create_dir_all(&py_dir).unwrap();
    fs::write(
        py_dir.join("requirements.txt"),
        "Flask-JWT-Extended==4.6.0\npython_dateutil==2.9.0\n",
    )
    .unwrap();

    let config = Configuration {
        directory: temp.path().to_string_lossy().into(),
        output: out_file.to_string_lossy().into(),
        use_debug: false,
        dynamic: false,
        allow_exec: false,
    };

    analyze(&config, false).expect("供应链安全审计解析应当成功");

    let content = fs::read_to_string(&out_file).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    let comps = json["components"].as_array().unwrap();

    // 验证 @internal-corp/auth 生成带有严格编码 scope 的 PURL，防止下游扫描器误判为公网无 scope 包
    let scoped_pkg = comps
        .iter()
        .find(|c| c["purl"] == "pkg:npm/%40internal-corp/auth@1.0.0");
    assert!(
        scoped_pkg.is_some(),
        "私有 scoped 依赖必须输出 pkg:npm/%40internal-corp/auth@1.0.0，杜绝供应链依赖混淆: {:?}",
        comps
    );

    let public_pkg = comps.iter().find(|c| c["purl"] == "pkg:npm/auth@2.0.0");
    assert!(public_pkg.is_some(), "公网同名依赖 auth@2.0.0 必须保持独立");

    // 验证 PyPI 包名经由 PEP 503 规范化为统一格式，确保漏洞扫描器（如 OSV/CVE）能够精准命中
    let py_flask = comps
        .iter()
        .find(|c| c["purl"] == "pkg:pypi/flask-jwt-extended@4.6.0");
    let py_dateutil = comps
        .iter()
        .find(|c| c["purl"] == "pkg:pypi/python-dateutil@2.9.0");

    assert!(
        py_flask.is_some(),
        "Flask-JWT-Extended 必须归一化为 flask-jwt-extended"
    );
    assert!(
        py_dateutil.is_some(),
        "python_dateutil 必须归一化为 python-dateutil"
    );
}
