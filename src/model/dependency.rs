use derive_builder::Builder;
// 1. 引入 serde 序列化支持
use serde::{Deserialize, Serialize};

use crate::model::location::Location;

// 2. 增加 Serialize, Deserialize，并将输出名称格式化为 CycloneDX 需要的小写 "library"
#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize)]
pub enum DependencyType {
    #[default]
    #[serde(rename = "library")]
    Library,
}

#[derive(Builder, Clone, Default, Debug)]
pub struct DependencyLocation {
    #[allow(dead_code)]
    pub block: Location,
    #[allow(dead_code)]
    pub name: Location,
    #[allow(dead_code)]
    pub version: Option<Location>,
}

#[derive(Builder, Clone, Default, Debug, Serialize, Deserialize)]
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
    pub version: Option<String>,

    #[allow(dead_code)]
    pub purl: String,
    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub location: Option<DependencyLocation>,
}
