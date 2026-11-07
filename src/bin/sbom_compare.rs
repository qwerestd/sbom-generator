use getopts::Options;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::Path;

struct SbomSummary {
    tool_name: String,
    spec_version: String,
    total_components: usize,
    unique_purls: HashSet<String>,
    ecosystems: HashMap<String, usize>,
    ecosystem_unique_purls: HashMap<String, HashSet<String>>,
}

/// 判定是否为真实的第三方依赖库组件（剔除 type == "application" 的本地工程根模块及 @0.0.0 合成虚拟根节点）
fn is_valid_third_party_lib(comp: &Value) -> bool {
    let Some(purl) = comp["purl"].as_str() else {
        return false;
    };
    let purl = purl.trim();
    if purl.is_empty() {
        return false;
    }
    if comp["type"].as_str() == Some("application") {
        return false;
    }
    let version = comp["version"].as_str().unwrap_or("").trim();
    if version.is_empty()
        || version == "0.0.0"
        || version.eq_ignore_ascii_case("runtime")
        || purl.ends_with("@0.0.0")
    {
        return false;
    }
    true
}

/// 仅规范已知的编码与 PyPI 包名差异；版本大小写可能有意义，不能整体转小写。
fn normalize_purl(raw: &str) -> String {
    let base = raw
        .trim()
        .split('?')
        .next()
        .unwrap_or("")
        .split('#')
        .next()
        .unwrap_or("");
    let mut s = base
        .replace("%2B", "+")
        .replace("%2b", "+")
        .replace("%40", "@");
    if let Some(rest) = s.strip_prefix("pkg:pypi/") {
        if let Some(at_pos) = rest.find('@') {
            let pkg_name = rest[..at_pos]
                .to_ascii_lowercase()
                .split(['-', '_', '.'])
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join("-");
            let ver_part = &rest[at_pos..];
            s = format!("pkg:pypi/{}{}", pkg_name, ver_part);
        }
    }
    s
}

fn is_supported_ecosystem(eco: &str) -> bool {
    matches!(eco, "cargo" | "golang" | "maven" | "npm" | "pypi")
}

fn ratio_text(numerator: usize, denominator: usize) -> String {
    if denominator == 0 {
        "N/A".to_string()
    } else {
        format!(
            "{:.2}% ({}/{})",
            numerator as f64 / denominator as f64 * 100.0,
            numerator,
            denominator
        )
    }
}

fn analyze_sbom(path: &str) -> anyhow::Result<SbomSummary> {
    let content =
        fs::read_to_string(path).map_err(|e| anyhow::anyhow!("无法读取文件 {}: {}", path, e))?;
    let json: Value = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("JSON 解析失败 {}: {}", path, e))?;

    if json["bomFormat"].as_str() != Some("CycloneDX") {
        anyhow::bail!("{} 不是 CycloneDX SBOM", path);
    }
    let components = json["components"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("{} 缺少 components 数组", path))?;

    let spec_version = json["specVersion"].as_str().unwrap_or("未知").to_string();

    // 提取工具名称
    let mut tool_name = "Unknown".to_string();
    if let Some(tools) = json["metadata"]["tools"].as_array() {
        if let Some(first) = tools.first() {
            if let Some(n) = first["name"].as_str() {
                tool_name = n.to_string();
            }
        }
    } else if let Some(components) = json["metadata"]["tools"]["components"].as_array() {
        if let Some(first) = components.first() {
            if let Some(n) = first["name"].as_str() {
                let v = first["version"].as_str().unwrap_or("");
                tool_name = format!("{} (v{})", n, v);
            }
        }
    }

    let mut total_components = 0;
    let mut unique_purls = HashSet::new();
    let mut ecosystems: HashMap<String, usize> = HashMap::new();
    let mut ecosystem_unique_purls: HashMap<String, HashSet<String>> = HashMap::new();

    for comp in components {
        if !is_valid_third_party_lib(comp) {
            continue;
        }
        total_components += 1;

        if let Some(raw_purl) = comp["purl"].as_str() {
            let norm_purl = normalize_purl(raw_purl);
            if !norm_purl.is_empty() {
                let eco = extract_eco(&norm_purl);
                unique_purls.insert(norm_purl.clone());
                *ecosystems.entry(eco.clone()).or_insert(0) += 1;
                ecosystem_unique_purls
                    .entry(eco)
                    .or_default()
                    .insert(norm_purl);
            }
        }
    }

    Ok(SbomSummary {
        tool_name,
        spec_version,
        total_components,
        unique_purls,
        ecosystems,
        ecosystem_unique_purls,
    })
}

fn extract_eco(purl: &str) -> String {
    if let Some(stripped) = purl.strip_prefix("pkg:") {
        if let Some(slash_pos) = stripped.find('/') {
            return stripped[..slash_pos].to_string();
        }
    }
    "unknown".to_string()
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("用法: {} [选项]", program);
    print!("{}", opts.usage(&brief));
}

pub fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optflag("h", "help", "显示帮助信息");
    opts.optopt("", "reference-version", "参照工具的实际版本", "VERSION");
    opts.optopt(
        "a",
        "our-sbom",
        "本平台生成的 SBOM JSON 路径 (默认: test/mircoservices/microservices-demo_sbom.json)",
        "PATH",
    );
    opts.optopt(
        "b",
        "competitor-sbom",
        "行业头部工具 (如 Trivy/Syft) 生成的 SBOM JSON 路径 (默认: test/mircoservices/sbom-cyclonedx.json)",
        "PATH",
    );
    opts.optopt(
        "o",
        "output",
        "导出的 Markdown 评测报告路径 (默认: test/benchmark_report.md)",
        "PATH",
    );

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => anyhow::bail!("解析参数失败: {}", f),
    };

    if matches.opt_present("h") {
        print_usage(&program, opts);
        return Ok(());
    }

    let our_path = matches
        .opt_str("a")
        .unwrap_or_else(|| "test/mircoservices/microservices-demo_sbom.json".to_string());
    let comp_path = matches
        .opt_str("b")
        .unwrap_or_else(|| "test/mircoservices/sbom-cyclonedx.json".to_string());
    let output_md = matches
        .opt_str("o")
        .unwrap_or_else(|| "test/benchmark_report.md".to_string());
    let reference_version = matches
        .opt_str("reference-version")
        .unwrap_or_else(|| "未提供".to_string());

    println!(
        "\n🔍 正在解析待对比的 SBOM 文件 (已自动剥离本地 application 根模块并完成 PURL 规范化)..."
    );
    println!("  - 本平台 SBOM [A]: {}", our_path);
    println!("  - 参照工具 SBOM [B]: {}", comp_path);

    let summary_a = analyze_sbom(&our_path)?;
    let summary_b = analyze_sbom(&comp_path)?;

    // 计算集合交集与独有集
    let purls_a = &summary_a.unique_purls;
    let purls_b = &summary_b.unique_purls;

    let common_purls: HashSet<_> = purls_a.intersection(purls_b).cloned().collect();
    let only_in_a: HashSet<_> = purls_a.difference(purls_b).cloned().collect();
    let only_in_b: HashSet<_> = purls_b.difference(purls_a).cloned().collect();

    // 计算目标核心生态（Top 5: Cargo/Go/Maven/NPM/PyPI）在参照工具 B 中的唯一包集合
    let supported_purls_b: HashSet<_> = purls_b
        .iter()
        .filter(|p| is_supported_ecosystem(&extract_eco(p)))
        .cloned()
        .collect();
    let supported_common: HashSet<_> = common_purls
        .iter()
        .filter(|p| is_supported_ecosystem(&extract_eco(p)))
        .cloned()
        .collect();

    let overlap_supported = ratio_text(supported_common.len(), supported_purls_b.len());
    let overlap_total = ratio_text(common_purls.len(), purls_b.len());
    let supported_purls_a: HashSet<_> = purls_a
        .iter()
        .filter(|p| is_supported_ecosystem(&extract_eco(p)))
        .collect();
    let union_len = supported_purls_a.len() + supported_purls_b.len() - supported_common.len();
    let jaccard = ratio_text(supported_common.len(), union_len);

    // 格式化输出终端报表
    println!(
        "\n{:=^92}",
        " 📊 软件物料清单 (SBOM) 第三方依赖库横向对比评测结果 "
    );
    println!(
        "{:<34} | {:<26} | {:<26}",
        "对比评测指标项 (Metrics)",
        format!("本平台 ({})", summary_a.tool_name),
        format!("参照基准 ({})", summary_b.tool_name)
    );
    println!("{:-<92}", "");
    println!(
        "{:<34} | {:<26} | {:<26}",
        "CycloneDX 规范版本",
        format!("v{}", summary_a.spec_version),
        format!("v{}", summary_b.spec_version)
    );
    println!(
        "{:<34} | {:<26} | {:<26}",
        "第三方组件记录数",
        format!("{} 个", summary_a.total_components),
        format!("{} 个", summary_b.total_components)
    );
    println!(
        "{:<34} | {:<26} | {:<26}",
        "去重唯一依赖包数 (Unique PURLs)",
        format!("{} 个", summary_a.unique_purls.len()),
        format!(
            "{} 个 (核心生态 {} 个)",
            summary_b.unique_purls.len(),
            supported_purls_b.len()
        )
    );
    println!(
        "{:<34} | {:<26} | {:<26}",
        "目标生态相对重合率", overlap_supported, "参照集合"
    );
    println!(
        "{:<34} | {:<26} | {:<26}",
        "全仓库相对重合率", overlap_total, "参照集合"
    );
    println!(
        "{:<34} | {:<26} | {:<26}",
        "仅一侧出现的 PURL",
        format!("{} 个 (待逐项核验)", only_in_a.len()),
        format!("{} 个 (待逐项核验)", only_in_b.len())
    );

    println!("{:-<92}", "");
    println!("🌐 各语言生态第三方组件记录对比:");
    let mut all_ecos: Vec<_> = summary_a
        .ecosystems
        .keys()
        .chain(summary_b.ecosystems.keys())
        .cloned()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    all_ecos.sort();

    for eco in &all_ecos {
        let inst_a = summary_a.ecosystems.get(eco).copied().unwrap_or(0);
        let inst_b = summary_b.ecosystems.get(eco).copied().unwrap_or(0);
        let uniq_a = summary_a
            .ecosystem_unique_purls
            .get(eco)
            .map(|s| s.len())
            .unwrap_or(0);
        let uniq_b = summary_b
            .ecosystem_unique_purls
            .get(eco)
            .map(|s| s.len())
            .unwrap_or(0);
        let com_cnt = common_purls
            .iter()
            .filter(|p| &extract_eco(p) == eco)
            .count();
        let cov_str = if !is_supported_ecosystem(eco) {
            "非目标生态".to_string()
        } else if uniq_b > 0 {
            format!(
                "{:.1}% ({}/{})",
                (com_cnt as f64 / uniq_b as f64) * 100.0,
                com_cnt,
                uniq_b
            )
        } else {
            "N/A (参照集合为空)".to_string()
        };

        println!(
            "  • [{:<7}] 本系统: {:>4} 记录 ({:>4} 唯一) | 参照: {:>4} 记录 ({:>4} 唯一) | 相对重合率: {}",
            eco.to_uppercase(),
            inst_a,
            uniq_a,
            inst_b,
            uniq_b,
            cov_str
        );
    }
    println!("{:=^92}", "");

    // 生成适用于毕业论文的严谨 Markdown 报告
    let inst_diff = summary_a.total_components as i64 - summary_b.total_components as i64;

    let mut eco_rows_md = String::new();
    for eco in &all_ecos {
        let inst_a = summary_a.ecosystems.get(eco).copied().unwrap_or(0);
        let inst_b = summary_b.ecosystems.get(eco).copied().unwrap_or(0);
        let uniq_a = summary_a
            .ecosystem_unique_purls
            .get(eco)
            .map(|s| s.len())
            .unwrap_or(0);
        let uniq_b = summary_b
            .ecosystem_unique_purls
            .get(eco)
            .map(|s| s.len())
            .unwrap_or(0);
        let com_cnt = common_purls
            .iter()
            .filter(|p| &extract_eco(p) == eco)
            .count();
        let cov_str = if !is_supported_ecosystem(eco) {
            "非目标生态".to_string()
        } else if uniq_b > 0 {
            format!(
                "**{:.1}%** ({}/{})",
                (com_cnt as f64 / uniq_b as f64) * 100.0,
                com_cnt,
                uniq_b
            )
        } else {
            "N/A (参照集合为空)".to_string()
        };
        let note = "差异需核对清单、锁文件、依赖作用域和版本";
        eco_rows_md.push_str(&format!(
            "| **{}** | **{}** ({}) | {} ({}) | {} | {} | {} |\n",
            eco.to_uppercase(),
            inst_a,
            uniq_a,
            inst_b,
            uniq_b,
            com_cnt,
            cov_str,
            note
        ));
    }

    let mut only_a_list: Vec<_> = only_in_a.iter().cloned().collect();
    let mut only_b_list: Vec<_> = only_in_b.iter().cloned().collect();
    only_a_list.sort();
    only_b_list.sort();
    let only_a_rows = only_a_list
        .iter()
        .map(|p| format!("- `{p}`\n"))
        .collect::<String>();
    let only_b_rows = only_b_list
        .iter()
        .map(|p| format!("- `{p}`\n"))
        .collect::<String>();

    let markdown_content = format!(
        r#"# SBOM 组件集合对比报告

本报告比较两份 CycloneDX SBOM 的组件集合。参照 SBOM 不是独立真值；相对重合率不等于准确率或召回率，独有项不自动代表漏检。

- 本工具：`{our_file}`
- 参照文件：`{comp_file}`
- 参照工具版本：{reference_version}

## 统计规则

排除 `type=application`、空版本、`0.0.0` 及明显误作版本的 `runtime`；按 PURL 去重。PURL 比较去除 qualifier/subpath，并仅统一已知编码及 PyPI 包名写法。实例数是过滤后的组件记录数，未核实物理部署路径。过滤可能误排合法的 `0.0.0` 组件。

## 汇总

| 指标 | 本工具 | 参照 SBOM |
| --- | ---: | ---: |
| CycloneDX 版本 | {spec_a} | {spec_b} |
| 组件记录数 | {total_a} | {total_b} |
| 去重 PURL | {unique_a} | {unique_b} |
| 记录数差值 | {inst_diff:+} | — |
| 目标生态相对重合率（交集 / 参照集合） | {overlap_supported} | 目标生态 {supp_b} 个 |
| 全部生态相对重合率 | {overlap_total} | 全部 {unique_b} 个 |
| 目标生态 Jaccard（交集 / 并集） | {jaccard} | — |
| 仅本工具出现 | {only_a_count} | 待核验 |
| 仅参照工具出现 | {only_b_count} | 待核验 |

## 各生态

| 生态 | 本工具记录数（唯一 PURL） | 参照记录数（唯一 PURL） | 交集 | 相对重合率 | 备注 |
| --- | ---: | ---: | ---: | ---: | --- |
{eco_rows}
## 待核验的差异 PURL

### 仅本工具出现

{only_a_rows}
### 仅参照工具出现

{only_b_rows}
## 解读限制

双方扫描模式、锁文件、依赖作用域和版本解析可能不同。对独有项需回查项目清单、锁文件和原始 SBOM，不能直接认定为真实依赖、误报或漏检。
"#,
        our_file = our_path,
        comp_file = comp_path,
        spec_a = summary_a.spec_version,
        spec_b = summary_b.spec_version,
        total_a = summary_a.total_components,
        total_b = summary_b.total_components,
        inst_diff = inst_diff,
        unique_a = summary_a.unique_purls.len(),
        unique_b = summary_b.unique_purls.len(),
        supp_b = supported_purls_b.len(),
        only_b_count = only_in_b.len(),
        reference_version = reference_version,
        only_a_count = only_in_a.len(),
        jaccard = jaccard,
        overlap_supported = overlap_supported,
        overlap_total = overlap_total,
        eco_rows = eco_rows_md,
        only_a_rows = only_a_rows,
        only_b_rows = only_b_rows,
    );

    fs::write(&output_md, markdown_content)?;
    println!("\n📝 严谨版评测实验报告已自动生成！");
    println!("   文件保存至: {}", Path::new(&output_md).display());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization_preserves_version_case_and_aligns_pypi_name() {
        assert_eq!(
            normalize_purl("pkg:golang/example.com/Module@v1.0.0-RC1?type=module"),
            "pkg:golang/example.com/Module@v1.0.0-RC1"
        );
        assert_eq!(
            normalize_purl("pkg:pypi/My_Package@1.0"),
            "pkg:pypi/my-package@1.0"
        );
        assert_eq!(
            normalize_purl("pkg:pypi/My__..Package@1.0-RC1"),
            "pkg:pypi/my-package@1.0-RC1"
        );
    }

    #[test]
    fn invalid_versions_and_empty_reference_are_not_successes() {
        assert!(!is_valid_third_party_lib(
            &serde_json::json!({"type":"library","version":"runtime","purl":"pkg:maven/org.postgresql/postgresql@runtime"})
        ));
        assert_eq!(ratio_text(0, 0), "N/A");
    }
}
