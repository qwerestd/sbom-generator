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

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub declared_version: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub rust_dependency_scope: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub rust_dependency_relationship: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub rust_is_direct: Option<bool>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub rust_target_conditions: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub rust_activation: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub rust_is_proc_macro: Option<bool>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub rust_project_root: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub rust_source_cargo_lock: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub rust_resolved_graph_confirmed: Option<bool>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub rust_all_target_present: Option<bool>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub rust_host_active: Option<bool>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub python_dependency_scope: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub python_source_type: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub python_manifest_path: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub python_project_root: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub python_confidence: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub python_is_project_package: Option<bool>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub python_dependency_relationship: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub python_is_direct: Option<bool>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub python_marker: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub python_activation: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub go_module_path: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub go_project_root: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub go_manifest_path: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub go_workspace_root: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub go_go_work_path: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub go_scope: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub go_relationship: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub go_direct: Option<bool>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub go_indirect: Option<bool>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub go_main_module: Option<bool>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub go_local: Option<bool>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub go_workspace_member: Option<bool>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub go_replacement_original: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub go_replacement_path: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub go_replacement_version: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub go_replacement_type: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub go_evidence_source: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub go_confidence: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub go_parsing_mode: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub go_version: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub go_toolchain_version: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub go_goos: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub go_goarch: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub go_cgo_enabled: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub go_host_active: Option<bool>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub go_excluded_versions: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip)]
    pub go_retractions: Option<String>,

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
                eprintln!("[PURL校验] 保留不合规的原始 PURL: {}", raw_purl);
                raw_purl.to_string()
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
            declared_version: self.declared_version.clone().unwrap_or_default(),
            rust_dependency_scope: self.rust_dependency_scope.clone().unwrap_or_default(),
            rust_dependency_relationship: self
                .rust_dependency_relationship
                .clone()
                .unwrap_or_default(),
            rust_is_direct: self.rust_is_direct.unwrap_or_default(),
            rust_target_conditions: self.rust_target_conditions.clone().unwrap_or_default(),
            rust_activation: self.rust_activation.clone().unwrap_or_default(),
            rust_is_proc_macro: self.rust_is_proc_macro.unwrap_or_default(),
            rust_project_root: self.rust_project_root.clone().unwrap_or_default(),
            rust_source_cargo_lock: self.rust_source_cargo_lock.clone().unwrap_or_default(),
            rust_resolved_graph_confirmed: self.rust_resolved_graph_confirmed.unwrap_or_default(),
            rust_all_target_present: self.rust_all_target_present.unwrap_or_default(),
            rust_host_active: self.rust_host_active.unwrap_or_default(),
            python_dependency_scope: self.python_dependency_scope.clone().unwrap_or_default(),
            python_source_type: self.python_source_type.clone().unwrap_or_default(),
            python_manifest_path: self.python_manifest_path.clone().unwrap_or_default(),
            python_project_root: self.python_project_root.clone().unwrap_or_default(),
            python_confidence: self.python_confidence.clone().unwrap_or_default(),
            python_is_project_package: self.python_is_project_package.unwrap_or_default(),
            python_dependency_relationship: self
                .python_dependency_relationship
                .clone()
                .unwrap_or_default(),
            python_is_direct: self.python_is_direct.unwrap_or_default(),
            python_marker: self.python_marker.clone().unwrap_or_default(),
            python_activation: self.python_activation.clone().unwrap_or_default(),
            go_module_path: self.go_module_path.clone().unwrap_or_default(),
            go_project_root: self.go_project_root.clone().unwrap_or_default(),
            go_manifest_path: self.go_manifest_path.clone().unwrap_or_default(),
            go_workspace_root: self.go_workspace_root.clone().unwrap_or_default(),
            go_go_work_path: self.go_go_work_path.clone().unwrap_or_default(),
            go_scope: self.go_scope.clone().unwrap_or_default(),
            go_relationship: self.go_relationship.clone().unwrap_or_default(),
            go_direct: self.go_direct.unwrap_or_default(),
            go_indirect: self.go_indirect.unwrap_or_default(),
            go_main_module: self.go_main_module.unwrap_or_default(),
            go_local: self.go_local.unwrap_or_default(),
            go_workspace_member: self.go_workspace_member.unwrap_or_default(),
            go_replacement_original: self.go_replacement_original.clone().unwrap_or_default(),
            go_replacement_path: self.go_replacement_path.clone().unwrap_or_default(),
            go_replacement_version: self.go_replacement_version.clone().unwrap_or_default(),
            go_replacement_type: self.go_replacement_type.clone().unwrap_or_default(),
            go_evidence_source: self.go_evidence_source.clone().unwrap_or_default(),
            go_confidence: self.go_confidence.clone().unwrap_or_default(),
            go_parsing_mode: self.go_parsing_mode.clone().unwrap_or_default(),
            go_version: self.go_version.clone().unwrap_or_default(),
            go_toolchain_version: self.go_toolchain_version.clone().unwrap_or_default(),
            go_goos: self.go_goos.clone().unwrap_or_default(),
            go_goarch: self.go_goarch.clone().unwrap_or_default(),
            go_cgo_enabled: self.go_cgo_enabled.clone().unwrap_or_default(),
            go_host_active: self.go_host_active.unwrap_or_default(),
            go_excluded_versions: self.go_excluded_versions.clone().unwrap_or_default(),
            go_retractions: self.go_retractions.clone().unwrap_or_default(),
            purl: clean_purl,
            instance_id: final_id, // 👈 干净合规的唯一身份证号优雅入库
            dependencies: self.dependencies.clone().unwrap_or_default(),
            location: final_location,
        })
    }
}
