// src/report.rs

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

// 逻辑聚合模型
#[derive(Serialize, Deserialize, Debug)]
pub struct LogicalReport {
    pub total_logical_components: usize,
    pub total_physical_instances: usize,
    pub components: Vec<LogicalComponent>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LogicalComponent {
    pub name: String,
    pub version: Option<String>,
    pub instance_count: usize,
    pub instances: Vec<String>, // 存储所有对应的 bom-ref
}

/// 读取 SBOM 文件并生成聚合报表
pub fn generate_report(sbom_path: &str) -> anyhow::Result<LogicalReport> {
    let content = fs::read_to_string(sbom_path)?;
    let v: serde_json::Value = serde_json::from_str(&content)?;

    let components = v["components"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("No components found"))?;

    let mut map: HashMap<(String, Option<String>), LogicalComponent> = HashMap::new();

    for comp in components {
        let name = comp["name"].as_str().unwrap_or("unknown").to_string();
        let version = comp["version"].as_str().map(|s| s.to_string());
        let bom_ref = comp["bom-ref"].as_str().unwrap_or("").to_string();
        if comp["name"].as_str().unwrap_or("").contains("macro")
            || comp["name"].as_str().unwrap_or("").contains("windows")
        {
            continue;
        }
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

    let components_list: Vec<LogicalComponent> = map.into_values().collect();

    Ok(LogicalReport {
        total_logical_components: components_list.len(),
        total_physical_instances: components.len(),
        components: components_list,
    })
}

/// 在控制台优雅展示报表
pub fn print_report(report: &LogicalReport) {
    println!("{:=^60}", " SBOM 逻辑聚合报表 ");
    println!("{:<20} | {:<15} | {:<10}", "组件名称", "版本", "物理实例数");
    println!("{:-<60}", "");

    for comp in &report.components {
        let ver = comp.version.as_deref().unwrap_or("n/a");
        println!(
            "{:<20} | {:<15} | {:<10}",
            comp.name, ver, comp.instance_count
        );
    }

    println!("{:-<60}", "");
    println!(
        "总结：识别到 {} 个逻辑组件，共映射 {} 个物理隔离实例。",
        report.total_logical_components, report.total_physical_instances
    );
}
