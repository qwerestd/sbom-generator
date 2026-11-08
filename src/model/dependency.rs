use derive_builder::Builder;
use packageurl::PackageUrl;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::str::FromStr;

use crate::model::location::Location;
use crate::model::position::Position;

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DependencyType {
    Application,
    #[default]
    Library,
}

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DynamicLoadStatus {
    Referenced, // 静态源码引用，不代表运行时已加载
    Loaded,     // 🟢 运行时成功监测到实际加载进内存
    Dormant,    // ⚪ 项目已监测执行，但该依赖未被调用 (冷依赖)
    #[default]
    NotTraced, // 🔘 纯静态解析 / 未试跑 / 缺少运行时环境
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

impl DependencyLocation {
    /// 从清单文件路径快速构建位置元数据（用于注入 syft:location:0:path）
    pub fn from_file(path: &Path) -> Self {
        let file_str = path.display().to_string();
        let loc = Location {
            file: file_str,
            start: Position::default(),
            end: Position::default(),
        };
        Self {
            block: loc.clone(),
            name: loc,
            version: None,
        }
    }
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

    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_requirement: Option<String>,

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,

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

    #[allow(dead_code)]
    #[builder(default)]
    #[serde(default)]
    pub dynamic_status: DynamicLoadStatus,
}

impl Dependency {
    /// 遵循各生态官方规范的深度 PURL 规范化与自愈器：
    /// 1. PyPI (PEP 503): 包名小写化，并将连续的 .、_、- 统一折叠为单个 -
    /// 2. NPM: scope 与 name 统一小写，规范 %40scope/name 格式
    /// 3. Cargo (crates.io): 包名统一小写
    /// 4. Golang: 保留模块路径大小写与主版本后缀
    /// 5. Maven: groupId/artifactId 严格按规范切分
    /// 6. Version: 彻底清洗版本中的语义范围符 (^, ~, =) 与前导 'v' 干扰
    pub fn auto_fix_and_validate_purl(raw_purl: &str) -> String {
        let trimmed = raw_purl.trim();
        if trimmed.is_empty() {
            return String::new();
        }

        // 预清洗常见的非法字符与范围符
        let pre_cleaned = trimmed
            .replace(['^', '~', '='], "")
            .replace("+incompatible", "");

        // Encode the npm scope before parsing: its @ is not a version delimiter.
        let encoded = trimmed.replacen("pkg:npm/@", "pkg:npm/%40", 1);
        let pre_cleaned = pre_cleaned.replacen("pkg:npm/@", "pkg:npm/%40", 1);
        let parsed =
            match PackageUrl::from_str(&encoded).or_else(|_| PackageUrl::from_str(&pre_cleaned)) {
                Ok(p) => p,
                Err(_) => {
                    eprintln!("[自动修复拦截器] 发现无法解析的 PURL: {}", raw_purl);
                    // Strip only a version delimiter after the final path separator.
                    let base = encoded.split(['?', '#']).next().unwrap_or(&encoded);
                    let identity = match (base.rfind('@'), base.rfind('/')) {
                        (Some(at), Some(slash)) if at > slash => &base[..at],
                        _ => base,
                    };
                    return PackageUrl::from_str(identity)
                        .map(|p| p.to_string())
                        .unwrap_or_else(|_| identity.to_string());
                }
            };

        let pkg_type = parsed.ty().to_ascii_lowercase();
        let mut name = parsed.name().to_string();
        let mut namespace = parsed.namespace().map(|s| s.to_string());
        let mut version = parsed.version().map(|s| s.to_string());

        // 1. 版本号通用清洗：去除语义范围符 (^, ~, =, %5E)
        if let Some(ref ver) = version {
            let v_unescaped = ver
                .replace("%5E", "")
                .replace("%5e", "")
                .replace(['^', '~', '=', ' '], "");
            let v_trimmed = v_unescaped.trim();
            // 关键准则：Golang 官方规范规定其 module 版本必须以 'v' 开头 (如 v1.2.3)，绝不可去除！
            // 仅对非 golang 生态（如 npm, pypi, cargo）清洗误带的前导 'v' 或 'V'
            let v_clean = if pkg_type == "golang" {
                if !v_trimmed.starts_with('v')
                    && v_trimmed.chars().next().is_some_and(|c| c.is_ascii_digit())
                {
                    format!("v{}", v_trimmed)
                } else {
                    v_trimmed.to_string()
                }
            } else if v_trimmed.len() > 1
                && (v_trimmed.starts_with('v') || v_trimmed.starts_with('V'))
                && v_trimmed.chars().nth(1).is_some_and(|c| c.is_ascii_digit())
            {
                v_trimmed[1..].to_string()
            } else {
                v_trimmed.to_string()
            };
            version = Some(v_clean);
        }

        // 2. 生态专属规范化
        match pkg_type.as_str() {
            "pypi" => {
                name = Self::pep503_normalize_str(&name);
            }
            "npm" => {
                name = name.to_ascii_lowercase();
                if let Some(ref ns) = namespace {
                    let mut clean_ns = ns.to_ascii_lowercase();
                    if clean_ns.starts_with('@') || clean_ns.starts_with("%40") {
                        clean_ns = clean_ns
                            .trim_start_matches('@')
                            .trim_start_matches("%40")
                            .to_string();
                    }
                    namespace = Some(clean_ns);
                }
            }
            "cargo" => {
                name = name.to_ascii_lowercase();
            }
            "golang" => {
                // Module paths are case-sensitive; preserve their declared spelling.
            }
            "maven" => {
                name = name.trim().to_string();
                if let Some(ref ns) = namespace {
                    namespace = Some(ns.trim().to_string());
                }
            }
            _ => {}
        }

        // 组装标准的 PURL 字符串
        let mut purl_str = format!("pkg:{}", pkg_type);
        if let Some(ref ns) = namespace {
            if !ns.is_empty() {
                if pkg_type == "npm" {
                    purl_str.push_str(&format!("/%40{}", ns));
                } else {
                    purl_str.push_str(&format!("/{}", ns));
                }
            }
        }
        purl_str.push_str(&format!("/{}", name));
        if let Some(ref ver) = version {
            if !ver.is_empty() {
                purl_str.push_str(&format!("@{}", ver));
            }
        }

        if let Ok(std_purl) = PackageUrl::from_str(&purl_str) {
            std_purl.to_string()
        } else {
            purl_str
        }
    }

    fn pep503_normalize_str(name: &str) -> String {
        let mut result = String::with_capacity(name.len());
        let mut last_was_dash = false;
        for c in name.chars() {
            if c == '.' || c == '_' || c == '-' {
                if !last_was_dash {
                    result.push('-');
                    last_was_dash = true;
                }
            } else {
                result.push(c.to_ascii_lowercase());
                last_was_dash = false;
            }
        }
        result
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
            version_requirement: self.version_requirement.clone().unwrap_or_default(),
            license: self.license.clone().unwrap_or_default(),
            purl: clean_purl,
            instance_id: final_id, // 👈 干净合规的唯一身份证号优雅入库
            dependencies: self.dependencies.clone().unwrap_or_default(),
            location: final_location,
            dynamic_status: self.dynamic_status.unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versionless_scoped_npm_preserves_identity() {
        for raw in [
            "pkg:npm/@angular/animations",
            "pkg:npm/%40angular/animations",
        ] {
            let purl = Dependency::auto_fix_and_validate_purl(raw);
            assert_eq!(purl, "pkg:npm/%40angular/animations");
        }
    }

    #[test]
    fn test_auto_fix_and_validate_purl_ecosystem_normalization() {
        // 1. PyPI PEP 503 规范化
        let py_purl = Dependency::auto_fix_and_validate_purl("pkg:pypi/Flask_SQLAlchemy@v3.0.0");
        assert_eq!(py_purl, "pkg:pypi/flask-sqlalchemy@3.0.0");

        // 2. NPM 作用域与小写化
        let npm_purl = Dependency::auto_fix_and_validate_purl("pkg:npm/@Angular/Core@^16.0.0");
        assert_eq!(npm_purl, "pkg:npm/%40angular/core@16.0.0");

        // 3. Go 模块路径保留大小写，保留/补齐 v 前缀
        let go_purl =
            Dependency::auto_fix_and_validate_purl("pkg:golang/github.com/gin-gonic/Gin@v1.9.1");
        assert_eq!(go_purl, "pkg:golang/github.com/gin-gonic/Gin@v1.9.1");

        let go_purl_missing_v =
            Dependency::auto_fix_and_validate_purl("pkg:golang/github.com/gin-gonic/Gin@1.9.1");
        assert_eq!(
            go_purl_missing_v,
            "pkg:golang/github.com/gin-gonic/Gin@v1.9.1"
        );

        // 4. Cargo 包名小写化
        let cargo_purl = Dependency::auto_fix_and_validate_purl("pkg:cargo/Serde@~1.0.100");
        assert_eq!(cargo_purl, "pkg:cargo/serde@1.0.100");
    }
}
