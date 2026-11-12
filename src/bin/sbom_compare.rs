use getopts::Options;
use sbom_generator::compare::{compare, ecosystem, CompareOptions, Comparison, Metrics, Summary};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    env, fs,
    path::{Path, PathBuf},
};

fn ratio(n: usize, d: usize) -> String {
    if d == 0 {
        "N/A".into()
    } else {
        format!("{:.2}% ({n}/{d})", n as f64 / d as f64 * 100.0)
    }
}
fn md(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('`', "\\`")
        .replace(['\n', '\r'], " ")
}
fn listing<'a>(items: impl IntoIterator<Item = &'a String>) -> String {
    let rows = items
        .into_iter()
        .map(|v| format!("- {}\n", md(v)))
        .collect::<String>();
    if rows.is_empty() {
        "无。\n".into()
    } else {
        rows
    }
}
fn metric_row(label: &str, metric: &Metrics) -> String {
    format!(
        "| {} | {} | {} | {} | {} | {} |\n",
        md(label),
        metric.a,
        metric.b,
        metric.common,
        ratio(metric.common, metric.b),
        ratio(metric.common, metric.a)
    )
}
fn counts(summary: &Summary) -> String {
    summary
        .excluded
        .iter()
        .map(|(reason, n)| format!("{reason}={n}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn output_path(path: &str) -> anyhow::Result<PathBuf> {
    let path = Path::new(path);
    if path.exists() {
        return Ok(path.canonicalize()?);
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok(parent.canonicalize()?.join(
        path.file_name()
            .ok_or_else(|| anyhow::anyhow!("输出路径没有文件名"))?,
    ))
}

fn validate_outputs(a: &str, b: &str, output: &str, json: Option<&str>) -> anyhow::Result<()> {
    let inputs = [Path::new(a).canonicalize()?, Path::new(b).canonicalize()?];
    let mut outputs = vec![output_path(output)?];
    if let Some(json) = json {
        outputs.push(output_path(json)?);
    }
    let same = |a: &Path, b: &Path| {
        if cfg!(windows) {
            a.to_string_lossy()
                .eq_ignore_ascii_case(&b.to_string_lossy())
        } else {
            a == b
        }
    };
    anyhow::ensure!(
        !outputs
            .iter()
            .any(|out| inputs.iter().any(|input| same(out, input))),
        "报告输出路径不能覆盖输入 SBOM"
    );
    anyhow::ensure!(
        outputs.len() < 2 || !same(&outputs[0], &outputs[1]),
        "Markdown 与 JSON 报告必须使用不同路径"
    );
    Ok(())
}
fn graph_details(label: &str, summary: &Summary) -> String {
    format!("### {} 图诊断\n\n- dependencies 是否提供：{}\n- 被过滤的边：{}\n- 涉及未知版本的边：{}\n- 悬空引用：{}\n- 重复引用：{}\n\n{}{}\n", label, summary.graph_available, summary.filtered_edges, summary.unresolved_edges, summary.dangling_refs.len(), summary.duplicate_refs.len(), listing(&summary.dangling_refs), listing(&summary.duplicate_refs))
}
fn report(result: &Comparison, path_a: &str, path_b: &str, reference: &str) -> String {
    let a = &result.a;
    let b = &result.b;
    let mut out = format!("# SBOM 组件与依赖图对比报告\n\n参照 SBOM 不是独立真值；相对重合率不等于准确率或召回率，独有项不自动代表误报或漏检。\n\n- A：{} ({})\n- B：{} ({})\n- 参照工具版本：{}\n\n## 统计规则\n\n目标生态：{}。应用节点{}；合法 0.0.0 版本{}。PURL 去掉 qualifier/subpath 后按包名和版本比较，来源路径另行比较。版本范围、占位符、version 与 PURL 版本冲突不进入精确匹配；只有 PURL 提供版本时可使用其版本。嵌套 components 一并读取。\n\n", md(&a.tool_name), md(path_a), md(&b.tool_name), md(path_b), md(reference), result.policy.ecosystems.iter().cloned().collect::<Vec<_>>().join(", "), if result.policy.include_applications { "纳入" } else { "排除" }, if result.policy.exclude_zero_versions { "显式排除" } else { "保留" });
    out.push_str(&format!("## 汇总\n\n| 指标 | 本工具 | 参照 SBOM |\n| --- | ---: | ---: |\n| CycloneDX 版本 | {} | {} |\n| 组件记录数 | {} | {} |\n| 版本未解析记录数 | {} | {} |\n| 其中版本冲突记录数 | {} | {} |\n| 去重 PURL（全部生态） | {} | {} |\n| 目标生态相对重合率（交集 / 参照集合） | {} | — |\n| 全部生态相对重合率 | {} | — |\n| 目标生态 Jaccard（交集 / 并集） | {} | — |\n| 仅 A 出现的包身份 | {} | — |\n| 仅 B 出现的包身份 | — | {} |\n| 同包版本集合差异组数 | {} | — |\n| 同包版本未知组数 | {} | — |\n\n", md(&a.spec_version), md(&b.spec_version), a.total_components, b.total_components, a.unresolved_components, b.unresolved_components, a.inconsistent_components, b.inconsistent_components, a.keys.len(), b.keys.len(), ratio(result.exact.common,result.exact.b), ratio(result.all_exact.common,result.all_exact.b), ratio(result.exact.common,result.exact.a + result.exact.b - result.exact.common), result.only_identities_a.len(), result.only_identities_b.len(), result.version_differences.len(), result.unknown_versions.len()));
    out.push_str("## 目标生态匹配层次\n\n| 层次 | A | B | 交集 | 相对 B 重合率 | 相对 A 重合率 |\n| --- | ---: | ---: | ---: | --- | --- |\n");
    out.push_str(&metric_row("包名＋版本", &result.exact));
    out.push_str(&metric_row("包身份（忽略版本）", &result.identity));
    out.push_str(&metric_row(
        "记录重数（逐包取两侧较小计数）",
        &result.occurrences,
    ));
    out.push_str(&metric_row(
        "包名＋版本＋来源路径记录重数",
        &result.located_occurrences,
    ));
    out.push_str(&format!("\n缺少路径的已解析目标记录：A={}，B={}。记录重数不代表已核实的物理实例。路径只统一分隔符和前导 ./，不猜测不同绝对扫描根目录的对应关系。\n\n", a.missing_locations, b.missing_locations));
    out.push_str("## 各生态\n\n| 生态 | A 唯一 PURL | B 唯一 PURL | 交集 | 相对 B 重合率 | 范围 |\n| --- | ---: | ---: | ---: | --- | --- |\n");
    let ecosystems: BTreeSet<_> = a
        .identities
        .iter()
        .chain(&b.identities)
        .map(|p| ecosystem(p).to_string())
        .collect();
    for eco in ecosystems {
        let sa: BTreeSet<_> = a.keys.iter().filter(|p| ecosystem(p) == eco).collect();
        let sb: BTreeSet<_> = b.keys.iter().filter(|p| ecosystem(p) == eco).collect();
        let common = sa.intersection(&sb).count();
        out.push_str(&format!(
            "| **{}** | {} | {} | {} | {} | {} |\n",
            md(&eco.to_uppercase()),
            sa.len(),
            sb.len(),
            common,
            ratio(common, sb.len()),
            if result.policy.ecosystems.contains(&eco) {
                "目标生态"
            } else {
                "范围外，未计入目标指标"
            }
        ));
    }
    out.push_str("\n## 差异分类\n\n### 同包版本集合差异\n\n| 包身份 | A 版本 | B 版本 | 仅 A 的版本 | 仅 B 的版本 |\n| --- | --- | --- | --- | --- |\n");
    for row in &result.version_differences {
        let join = |v: &BTreeSet<String>| md(&v.iter().cloned().collect::<Vec<_>>().join(", "));
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            md(&row.identity),
            join(&row.versions_a),
            join(&row.versions_b),
            join(&row.only_a),
            join(&row.only_b)
        ));
    }
    out.push_str(&format!("\n### 同包版本未知\n\n{}\n### 仅 A 出现的包身份\n\n{}\n### 仅 B 出现的包身份\n\n{}\n### 精确 PURL 差集（包含版本差异）\n\nA − B：\n\n{}\nB − A：\n\n{}\n", listing(&result.unknown_versions), listing(&result.only_identities_a), listing(&result.only_identities_b), listing(&result.only_keys_a), listing(&result.only_keys_b)));
    out.push_str("## 依赖边独立比较\n\n只比较目标生态内两端均有确定版本的有向包级依赖边；应用根边、同包自边和未知版本边另行过滤。重复边去重，bom-ref 仅在各自文件内寻址，不跨工具直接比较。\n\n");
    if let Some(graph) = &result.graph {
        out.push_str(&format!(
            "A={}，B={}，共有={}；相对 B 重合率={}，Jaccard={}。\n\n",
            graph.a,
            graph.b,
            graph.common,
            ratio(graph.common, graph.b),
            ratio(graph.common, graph.a + graph.b - graph.common)
        ));
    } else {
        out.push_str("依赖边重合率：N/A（缺少图或关系口径不同）。\n\n");
    }
    out.push_str(&format!(
        "仅 A 的边：\n\n{}\n仅 B 的边：\n\n{}\n",
        listing(&result.only_edges_a),
        listing(&result.only_edges_b)
    ));
    out.push_str(&graph_details("A", a));
    out.push_str(&graph_details("B", b));
    out.push_str(&format!(
        "## 输入诊断\n\n- A 排除记录：{}\n- B 排除记录：{}\n\n{}{}\n",
        md(&counts(a)),
        md(&counts(b)),
        listing(&a.diagnostics),
        listing(&b.diagnostics)
    ));
    out.push_str("## 解读限制\n\n");
    out.push_str(&listing(result.warnings.iter()));
    out.push_str("\n未自动验证源码 commit、目标平台和依赖分组一致；许可证、漏洞和运行时加载证据不计入组件重合率。图指标只衡量已报告且可解析的边，缺少 dependencies 与显式空数组分别处理。不同版本集合可能同时含共有版本，版本差异与精确共有并不互斥。\n");
    out
}

fn main() -> anyhow::Result<()> {
    let args: Vec<_> = env::args().collect();
    let mut options = Options::new();
    options.optflag("h", "help", "显示帮助");
    options.optopt("a", "our-sbom", "A CycloneDX JSON", "PATH");
    options.optopt("b", "competitor-sbom", "B CycloneDX JSON", "PATH");
    options.optopt("o", "output", "Markdown 报告", "PATH");
    options.optopt(
        "",
        "json-output",
        "结构化比较报告（含差异与图诊断）",
        "PATH",
    );
    options.optopt("", "reference-version", "参照工具实际版本", "VERSION");
    options.optopt(
        "",
        "ecosystems",
        "目标生态，逗号分隔；默认 cargo,golang,maven,npm,pypi",
        "LIST",
    );
    options.optflag(
        "",
        "include-applications",
        "纳入明确标记为 application 的组件",
    );
    options.optflag(
        "",
        "exclude-zero-versions",
        "显式排除 0.0.0/v0.0.0；默认保留合法版本",
    );
    let args = options.parse(&args[1..])?;
    anyhow::ensure!(args.free.is_empty(), "不支持位置参数: {:?}", args.free);
    if args.opt_present("help") {
        print!("{}", options.usage("用法: sbom_compare [选项]"));
        return Ok(());
    }
    let path_a = args
        .opt_str("a")
        .unwrap_or_else(|| "test/mircoservices/microservices-demo_sbom.json".into());
    let path_b = args
        .opt_str("b")
        .unwrap_or_else(|| "test/mircoservices/sbom-cyclonedx.json".into());
    let output = args
        .opt_str("o")
        .unwrap_or_else(|| "test/benchmark_report.md".into());
    let mut policy = CompareOptions {
        include_applications: args.opt_present("include-applications"),
        exclude_zero_versions: args.opt_present("exclude-zero-versions"),
        ..Default::default()
    };
    if let Some(ecos) = args.opt_str("ecosystems") {
        policy.ecosystems = ecos
            .split(',')
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_ascii_lowercase)
            .collect();
        anyhow::ensure!(
            policy.ecosystems.iter().all(|e| e
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-'))),
            "目标生态名称无效"
        );
    }
    let a: Value = serde_json::from_str(&fs::read_to_string(&path_a)?)?;
    let b: Value = serde_json::from_str(&fs::read_to_string(&path_b)?)?;
    let result = compare(&a, &b, policy)?;
    let markdown = report(
        &result,
        &path_a,
        &path_b,
        &args.opt_str("reference-version").unwrap_or_else(|| {
            result
                .b
                .tool_version
                .clone()
                .unwrap_or_else(|| "未提供".into())
        }),
    );
    // Finish validation and serialization before touching existing reports.
    let json = args
        .opt_str("json-output")
        .map(|path| serde_json::to_string_pretty(&result).map(|json| (path, json)))
        .transpose()?;
    validate_outputs(
        &path_a,
        &path_b,
        &output,
        args.opt_str("json-output").as_deref(),
    )?;
    fs::write(&output, markdown)?;
    if let Some((path, json)) = json {
        fs::write(path, json)?;
    }
    println!(
        "精确版本相对 B 重合率: {}；Jaccard: {}",
        ratio(result.exact.common, result.exact.b),
        ratio(
            result.exact.common,
            result.exact.a + result.exact.b - result.exact.common
        )
    );
    println!(
        "包身份相对 B 重合率: {}；版本集合差异 {} 组；版本未知 {} 组",
        ratio(result.identity.common, result.identity.b),
        result.version_differences.len(),
        result.unknown_versions.len()
    );
    println!("报告: {output}");
    Ok(())
}
