use derive_builder::Builder;
// 1. 引入 serde 序列化支持
use serde::{Deserialize, Serialize};

use crate::model::location::Location;

// 2. 修复点：直接使用 rename_all = "lowercase"，
// 这样即使未来增加 Application, Framework 等变体，也会自动格式化为 CycloneDX 强制要求的小写
#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DependencyType {
    #[default]
    Library,
    // Application, // 未来扩展时，它会自动变成 "application"
}

#[derive(Builder, Clone, Default, Debug)]
pub struct DependencyLocation {
    #[allow(dead_code)]
    #[builder(default)] // 修复点：让 Builder 能真正使用 Location 的默认值，防止 build() 报错
    pub block: Location,

    #[allow(dead_code)]
    #[builder(default)] // 修复点：同上
    pub name: Location,

    #[allow(dead_code)]
    #[builder(default)]
    pub version: Option<Location>,
}

#[derive(Builder, Clone, Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")] // 可选：保持 JSON 输出的一致性
pub struct Dependency {
    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    pub r#type: DependencyType,

    #[allow(dead_code)]
    pub name: String,

    #[allow(dead_code)]
    #[builder(default)]
    // 修复点：核心 Bug！如果不加这行，None 会被序列化为 "version": null，
    // 这会导致 CycloneDX 标准校验直接崩溃（Schema 不允许 null）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    #[allow(dead_code)]
    pub purl: String,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)] // 这个没问题，因为 CycloneDX SBOM 里不需要你的代码扫描物理行号位置
    pub location: Option<DependencyLocation>,
}
