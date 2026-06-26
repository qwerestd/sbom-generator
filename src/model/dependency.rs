// src/model/dependency.rs

use derive_builder::Builder;
use packageurl::PackageUrl;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::model::location::Location;

#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DependencyType {
    #[default]
    Library,
}

#[derive(Builder, Clone, Default, Debug)]
pub struct DependencyLocation {
    #[allow(dead_code)]
    #[builder(default)]
    pub block: Location,

    #[allow(dead_code)]
    #[builder(default)]
    pub name: Location,

    #[allow(dead_code)]
    #[builder(default)]
    pub version: Option<Location>,
}

#[derive(Builder, Clone, Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[builder(build_fn(skip))]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    pub purl: String,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub location: Option<DependencyLocation>,
}

impl Dependency {
    /// 自动检测并修正有问题的 PURL（保持原本完美的清洗逻辑）
    pub fn auto_fix_and_validate_purl(raw_purl: &str) -> String {
        match PackageUrl::from_str(raw_purl) {
            Ok(parsed_purl) => parsed_purl.to_string(),
            Err(_) => {
                eprintln!("[自动修复拦截器] 发现不合规的 PURL: {}", raw_purl);

                let fixed_purl = raw_purl.replace(['^', '~', '='], "");

                if PackageUrl::from_str(&fixed_purl).is_ok() {
                    fixed_purl
                } else {
                    raw_purl.split('@').next().unwrap_or(raw_purl).to_string()
                }
            }
        }
    }
}

// =====================================================================
// 【全套接管】：手动为 Builder 实现 build 方法，在这将所有权、可变性清洗一网打尽
// =====================================================================
impl DependencyBuilder {
    pub fn build(&self) -> Result<Dependency, String> {
        // 1. 提取必要字段（如果没填则抛出规范的 Builder 错误）
        let name = self
            .name
            .clone()
            .ok_or_else(|| "field 'name' is required but not initialized".to_string())?;

        let raw_purl = self
            .purl
            .clone()
            .ok_or_else(|| "field 'purl' is required but not initialized".to_string())?;

        // 2. 【在这里触发拦截器】：在这里，我们拥有完全可控的变量，彻底规避宏生成的隐式借用冲突
        let clean_purl = Dependency::auto_fix_and_validate_purl(&raw_purl);

        // 3. 安全组装还原最终的对象模型
        Ok(Dependency {
            group: self.group.clone().unwrap_or_default(),
            r#type: self.r#type.unwrap_or_default(),
            name,
            version: self.version.clone().unwrap_or_default(),
            purl: clean_purl, // 👈 干净合规的 PURL 优雅入库
            dependencies: self.dependencies.clone().unwrap_or_default(),
            location: self.location.clone().unwrap_or_default(),
        })
    }
}
