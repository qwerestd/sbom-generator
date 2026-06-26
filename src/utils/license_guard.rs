use crate::model::cyclonedx::{LicenseChoice, LicenseDetail};

pub fn build_license_node(raw_license: &Option<String>) -> Option<Vec<LicenseChoice>> {
    let lic_str = raw_license.as_ref()?.trim();
    if lic_str.is_empty() || lic_str.eq_ignore_ascii_case("UNKNOWN") {
        return None;
    }

    // 1. 如果是标准的 Rust / NPM 表达式 (例如 "MIT OR Apache-2.0")
    if lic_str.contains(" OR ") || lic_str.contains(" AND ") {
        return Some(vec![LicenseChoice::Expression {
            expression: lic_str.to_string(),
        }]);
    }

    // 2. 常见 Java/Maven 自由小作文 -> 强行映射为标准 SPDX ID
    let spdx_id = match lic_str.to_lowercase().as_str() {
        s if s.contains("apache") && s.contains("2") => Some("Apache-2.0"),
        s if s.contains("mit") => Some("MIT"),
        s if s.contains("bsd") && s.contains("3") => Some("BSD-3-Clause"),
        s if s.contains("bsd") && s.contains("2") => Some("BSD-2-Clause"),
        s if s.contains("eclipse") || s.contains("epl") => Some("EPL-2.0"),
        s if s.contains("mozilla") || s.contains("mpl") => Some("MPL-2.0"),
        _ => None,
    };

    if let Some(id) = spdx_id {
        Some(vec![LicenseChoice::Detail {
            license: LicenseDetail {
                id: Some(id.to_string()),
                name: None,
            },
        }])
    } else {
        // 3. 实在认不出来的野生协议，放入 name 字段，保命不报 Schema 错误
        Some(vec![LicenseChoice::Detail {
            license: LicenseDetail {
                id: None,
                name: Some(lic_str.to_string()),
            },
        }])
    }
}