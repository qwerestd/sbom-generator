use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
                instance_count: 0,
                instances: Vec::new(),
            });

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

/// 在控制台优雅展示报表（包含逻辑组件聚合与 OSV 漏洞安全告警）
pub fn print_report(report: &LogicalReport) {
    println!("{:=^68}", " SBOM 逻辑聚合报表 ");
    println!("{:<32} | {:<16} | {:<10}", "组件名称", "版本", "物理实例数");
    println!("{:-<68}", "");

    for comp in &report.components {
        let ver = comp.version.as_deref().unwrap_or("n/a");
        println!(
            "{:<32} | {:<16} | {:<10}",
            comp.name, ver, comp.instance_count
        );
    }

    println!("{:-<68}", "");
    println!(
        "总结：识别到 {} 个逻辑组件，共映射 {} 个物理隔离实例。",
        report.total_logical_components, report.total_physical_instances
    );

    if !report.vulnerabilities.is_empty() {
        println!("\n{:=^68}", " 🚨 OSV 开源漏洞联动审计告警 ");
        for vuln in &report.vulnerabilities {
            println!(
                "[{}] {:.1} | {} -> 命中组件: {}",
                vuln.severity,
                vuln.score,
                vuln.id,
                vuln.affected_components.join(", ")
            );
            println!("  ├─ 风险描述: {}", vuln.description);
            println!("  └─ 修复建议: {}", vuln.recommendation);
        }
        println!("{:=^68}", "");
    }
}
