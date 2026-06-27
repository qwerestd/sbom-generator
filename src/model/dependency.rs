use derive_builder::Builder;
use packageurl::PackageUrl;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
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

    // ===============================================================
    // 【核心新增】：物理唯一的全局身份证实例字段
    // ===============================================================
    #[allow(dead_code)]
    #[builder(default)]
    pub instance_id: String,

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
    /// 自动检测并修正有问题的 PURL
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

    /// 兜底派生唯一 ID 算法
    pub fn derive_fallback_id(clean_purl: &str, location: &Option<DependencyLocation>) -> String {
        let mut hasher = DefaultHasher::new();
        clean_purl.hash(&mut hasher);
        if let Some(loc) = location {
            format!("{:?}", loc.block).hash(&mut hasher);
        }
        format!("{}?package-id={:016x}", clean_purl, hasher.finish())
    }
}

// =====================================================================
// 【全套接管】：手动为 Builder 实现 build 方法
// =====================================================================
impl DependencyBuilder {
    pub fn build(&self) -> Result<Dependency, String> {
        let name = self
            .name
            .clone()
            .ok_or_else(|| "field 'name' is required but not initialized".to_string())?;

        let raw_purl = self
            .purl
            .clone()
            .ok_or_else(|| "field 'purl' is required but not initialized".to_string())?;

        let clean_purl = Dependency::auto_fix_and_validate_purl(&raw_purl);

        // 智能解开 derive_builder 宏带来的双重 Option 嵌套
        let final_location = self.location.clone().unwrap_or_default();

        // 智能判定：如果探针没传 instance_id，则利用物理行号位置自动保底计算
        let final_id = match &self.instance_id {
            Some(explicit_id) if !explicit_id.is_empty() => explicit_id.clone(),
            _ => Dependency::derive_fallback_id(&clean_purl, &final_location),
        };

        Ok(Dependency {
            group: self.group.clone().unwrap_or_default(),
            r#type: self.r#type.unwrap_or_default(),
            name,
            version: self.version.clone().unwrap_or_default(),
            purl: clean_purl,
            instance_id: final_id, // 👈 干净合规的唯一身份证号优雅入库
            dependencies: self.dependencies.clone().unwrap_or_default(),
            location: final_location,
        })
    }
}
