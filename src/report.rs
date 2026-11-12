use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;

// 逻辑聚合模型
#[derive(Serialize, Deserialize, Debug)]
pub struct LogicalReport {
    pub total_logical_components: usize,
    pub total_physical_instances: usize,
    pub components: Vec<LogicalComponent>,
    #[serde(default)]
    pub vulnerabilities: Vec<VulnerabilitySummary>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LogicalComponent {
    pub name: String,
    pub version: Option<String>,
    pub license: Option<String>,
    pub instance_count: usize,
    pub instances: Vec<String>, // 存储所有对应的 bom-ref
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VulnerabilitySummary {
    pub id: String,
    pub severity: String,
    pub score: f64,
    pub description: String,
    pub recommendation: String,
    pub affected_components: Vec<String>,
}

/// 从 CycloneDX 组件 JSON 节点提取 SPDX 许可证标识
fn extract_component_license(comp: &serde_json::Value) -> Option<String> {
    let choice = comp.get("licenses")?.as_array()?.first()?;
    choice
        .get("expression")
        .or_else(|| choice.get("license")?.get("id"))
        .or_else(|| choice.get("license")?.get("name"))?
        .as_str()
        .map(|s| s.to_string())
}

/// 根据 PURL 识别简短生态标签
fn detect_eco_badge(purl: &str) -> &'static str {
    if purl.starts_with("pkg:cargo/") {
        "Cargo"
    } else if purl.starts_with("pkg:golang/") {
        "Go"
    } else if purl.starts_with("pkg:npm/") {
        "NPM"
    } else if purl.starts_with("pkg:maven/") {
        "Maven"
    } else if purl.starts_with("pkg:pypi/") {
        "PyPI"
    } else {
        "Pkg"
    }
}

/// 读取 SBOM 文件并生成聚合报表
pub fn generate_report(sbom_path: &str) -> anyhow::Result<LogicalReport> {
    let content = fs::read_to_string(sbom_path)?;
    let v: serde_json::Value = serde_json::from_str(&content)?;

    let components = v["components"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("No components found"))?;

    let mut map: HashMap<(String, Option<String>), LogicalComponent> = HashMap::new();
    let mut ref_to_display: HashMap<String, String> = HashMap::new();

    for comp in components {
        let name = comp["name"].as_str().unwrap_or("unknown").to_string();
        let version = comp["version"].as_str().map(|s| s.to_string());
        let bom_ref = comp["bom-ref"].as_str().unwrap_or("").to_string();
        let license = extract_component_license(comp);

        let display_label = match &version {
            Some(ver) => format!("{}@{}", name, ver),
            None => name.clone(),
        };
        ref_to_display.insert(bom_ref.clone(), display_label);

        let entry = map
            .entry((name.clone(), version.clone()))
            .or_insert(LogicalComponent {
                name,
                version,
                license: license.clone(),
                instance_count: 0,
                instances: Vec::new(),
            });

        if entry.license.is_none() && license.is_some() {
            entry.license = license;
        }
        entry.instances.push(bom_ref);
        entry.instance_count += 1;
    }

    let mut components_list: Vec<LogicalComponent> = map.into_values().collect();
    // 按实例数量降序、组件名称升序稳定排序
    components_list.sort_by(|a, b| {
        b.instance_count
            .cmp(&a.instance_count)
            .then_with(|| a.name.cmp(&b.name))
    });

    // 解析 CycloneDX 1.6 `vulnerabilities` 区块
    let mut vulnerabilities = Vec::new();
    if let Some(vulns_arr) = v.get("vulnerabilities").and_then(|val| val.as_array()) {
        for vuln in vulns_arr {
            let id = vuln["id"].as_str().unwrap_or("UNKNOWN").to_string();
            let description = vuln["description"].as_str().unwrap_or("").to_string();
            let recommendation = vuln["recommendation"].as_str().unwrap_or("").to_string();
            let (severity, score) = vuln
                .get("ratings")
                .and_then(|r| r.as_array())
                .and_then(|arr| arr.first())
                .map(|rating| {
                    let sev = rating["severity"].as_str().unwrap_or("high").to_uppercase();
                    let sc = rating["score"].as_f64().unwrap_or(0.0);
                    (sev, sc)
                })
                .unwrap_or_else(|| ("HIGH".to_string(), 0.0));

            let mut affected_components = Vec::new();
            if let Some(affects) = vuln.get("affects").and_then(|a| a.as_array()) {
                for aff in affects {
                    if let Some(r) = aff["ref"].as_str() {
                        let label = ref_to_display
                            .get(r)
                            .cloned()
                            .unwrap_or_else(|| r.split('?').next().unwrap_or(r).to_string());
                        if !affected_components.contains(&label) {
                            affected_components.push(label);
                        }
                    }
                }
            }

            vulnerabilities.push(VulnerabilitySummary {
                id,
                severity,
                score,
                description,
                recommendation,
                affected_components,
            });
        }
    }

    Ok(LogicalReport {
        total_logical_components: components_list.len(),
        total_physical_instances: components.len(),
        components: components_list,
        vulnerabilities,
    })
}

/// 在控制台优雅展示报表（包含逻辑组件聚合、SPDX 许可证与 OSV 漏洞安全告警）
/// Print a concise summary; detailed inventory remains in the SBOM file.
pub fn print_report(report: &LogicalReport) {
    println!(
        "扫描完成：{} 个逻辑组件，{} 条组件记录，{} 条漏洞记录。",
        report.total_logical_components,
        report.total_physical_instances,
        report.vulnerabilities.len()
    );
}

struct TreeNodeMeta {
    name: String,
    version: String,
    eco_badge: &'static str,
    license: String,
    vulns: Vec<String>,
    runtime_status: String,
}

/// 在命令行终端输出直观的 ASCII 多语言依赖树层级摘要 (Dependency Tree Summary)
pub fn print_dependency_tree(sbom_path: &str) -> anyhow::Result<()> {
    let content = fs::read_to_string(sbom_path)?;
    let v: serde_json::Value = serde_json::from_str(&content)?;

    let Some(components) = v.get("components").and_then(|c| c.as_array()) else {
        return Ok(());
    };
    if components.is_empty() {
        return Ok(());
    }

    // 1. 建立 ref -> 漏洞编号列表 索引
    let mut ref_vulns: HashMap<String, Vec<String>> = HashMap::new();
    if let Some(vulns_arr) = v.get("vulnerabilities").and_then(|val| val.as_array()) {
        for vuln in vulns_arr {
            let id = vuln["id"].as_str().unwrap_or("VULN").to_string();
            if let Some(affects) = vuln.get("affects").and_then(|a| a.as_array()) {
                for aff in affects {
                    if let Some(r) = aff["ref"].as_str() {
                        ref_vulns.entry(r.to_string()).or_default().push(id.clone());
                    }
                }
            }
        }
    }

    // 2. 建立 ref -> 节点元数据 索引
    let mut node_map: HashMap<String, TreeNodeMeta> = HashMap::new();
    let mut all_refs: Vec<String> = Vec::new();
    for comp in components {
        let bom_ref = comp["bom-ref"].as_str().unwrap_or("").to_string();
        if bom_ref.is_empty() {
            continue;
        }
        let name = comp["name"].as_str().unwrap_or("unknown").to_string();
        let version = comp["version"].as_str().unwrap_or("n/a").to_string();
        let purl = comp["purl"].as_str().unwrap_or("");
        let eco_badge = detect_eco_badge(purl);
        let license = extract_component_license(comp).unwrap_or_else(|| "UNKNOWN".to_string());
        let vulns = ref_vulns.remove(&bom_ref).unwrap_or_default();

        let mut runtime_status = String::new();
        if let Some(props) = comp.get("properties").and_then(|p| p.as_array()) {
            for p in props {
                if p["name"] == "sbom:runtime:status" {
                    if let Some(val) = p["value"].as_str() {
                        runtime_status = val.to_string();
                    }
                }
            }
        }

        node_map.insert(
            bom_ref.clone(),
            TreeNodeMeta {
                name,
                version,
                eco_badge,
                license,
                vulns,
                runtime_status,
            },
        );
        all_refs.push(bom_ref);
    }

    // 3. 建立有向邻接表与入度统计
    let mut adj: HashMap<String, Vec<String>> = HashMap::new();
    let mut in_degree: HashMap<String, usize> = HashMap::new();
    if let Some(deps_arr) = v.get("dependencies").and_then(|d| d.as_array()) {
        for dep in deps_arr {
            let parent = dep["ref"].as_str().unwrap_or("").to_string();
            if parent.is_empty() {
                continue;
            }
            if let Some(children) = dep.get("dependsOn").and_then(|c| c.as_array()) {
                let mut child_list = Vec::new();
                for ch in children {
                    if let Some(ch_ref) = ch.as_str() {
                        if node_map.contains_key(ch_ref) {
                            *in_degree.entry(ch_ref.to_string()).or_insert(0) += 1;
                            child_list.push(ch_ref.to_string());
                        }
                    }
                }
                adj.insert(parent, child_list);
            }
        }
    }

    // 4. 筛选入度为 0 的顶层根依赖节点
    let mut roots: Vec<String> = all_refs
        .iter()
        .filter(|r| *in_degree.get(*r).unwrap_or(&0) == 0)
        .cloned()
        .collect();
    if roots.is_empty() {
        roots = all_refs;
    }

    // 优先将拥有子依赖的节点排在前面，使树形展示更具层次感
    roots.sort_by(|a, b| {
        let a_children = adj.get(a).map(|v| v.len()).unwrap_or(0);
        let b_children = adj.get(b).map(|v| v.len()).unwrap_or(0);
        b_children.cmp(&a_children).then_with(|| a.cmp(b))
    });

    println!(
        "\n{:=^86}",
        " 🌳 多语言依赖拓扑树摘要 (Dependency Tree Summary) "
    );
    println!("📦 项目顶层依赖视图 (共 {} 个顶层入口节点)", roots.len());

    let max_roots_to_display = 25;
    let display_count = roots.len().min(max_roots_to_display);
    for (idx, root_ref) in roots.iter().take(display_count).enumerate() {
        let is_last_root = idx + 1 == display_count && roots.len() <= max_roots_to_display;
        let mut visited = HashSet::new();
        print_tree_recursive(root_ref, "", is_last_root, 0, &node_map, &adj, &mut visited);
    }

    if roots.len() > max_roots_to_display {
        println!(
            "└── ... (其余 {} 个顶层直接依赖节点已折叠，完整清单见 SBOM JSON)",
            roots.len() - max_roots_to_display
        );
    }
    println!("{:=^86}", "");

    Ok(())
}

fn print_tree_recursive(
    current_ref: &str,
    prefix: &str,
    is_last: bool,
    depth: usize,
    node_map: &HashMap<String, TreeNodeMeta>,
    adj: &HashMap<String, Vec<String>>,
    visited: &mut HashSet<String>,
) {
    let Some(meta) = node_map.get(current_ref) else {
        return;
    };

    let connector = if is_last { "└── " } else { "├── " };
    let vuln_tag = if meta.vulns.is_empty() {
        String::new()
    } else {
        format!(" 🚨 [{}]", meta.vulns.join(", "))
    };

    let status_tag = match meta.runtime_status.as_str() {
        "loaded" => " <🟢 LOADED>",
        "dormant" => " <⚪ DORMANT>",
        _ => "",
    };

    println!(
        "{}{}{}[{}] {}@{}{}[{}]{}",
        prefix,
        connector,
        if !meta.vulns.is_empty() {
            "⚠️ "
        } else {
            ""
        },
        meta.eco_badge,
        meta.name,
        meta.version,
        status_tag,
        meta.license,
        vuln_tag
    );

    if depth >= 4 || !visited.insert(current_ref.to_string()) {
        return;
    }

    if let Some(children) = adj.get(current_ref) {
        if children.is_empty() {
            return;
        }
        let child_prefix = format!("{}{}", prefix, if is_last { "    " } else { "│   " });
        let max_children = 12;
        let show_len = children.len().min(max_children);
        for (i, ch_ref) in children.iter().take(show_len).enumerate() {
            let last_child = i + 1 == show_len && children.len() <= max_children;
            print_tree_recursive(
                ch_ref,
                &child_prefix,
                last_child,
                depth + 1,
                node_map,
                adj,
                visited,
            );
        }
        if children.len() > max_children {
            println!(
                "{}└── ... (其余 {} 个子依赖已折叠)",
                child_prefix,
                children.len() - max_children
            );
        }
    }
}
