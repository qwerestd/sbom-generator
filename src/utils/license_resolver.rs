use std::fs;
use std::path::Path;

use crate::model::dependency::Dependency;

/// Extract declared licenses; unknown packages remain unknown.
pub struct LicenseResolver;

impl LicenseResolver {
    /// 解析组件的 SPDX 许可证标识（例如 `"MIT"`, `"Apache-2.0"`, `"BSD-3-Clause"`）
    pub fn resolve_license(dep: &Dependency) -> Option<String> {
        // 1. 若生产者在解析阶段已直接提取出许可证，优先归一化返回
        if let Some(explicit) = &dep.license {
            let trimmed = explicit.trim();
            if !trimmed.is_empty() {
                return Some(Self::normalize_spdx_id(trimmed));
            }
        }

        // 2. 尝试从本地清单文件或 node_modules 包描述文件中提取许可证（针对应用根节点或本地可寻址包）
        if let Some(loc) = &dep.location {
            let manifest_path = Path::new(&loc.block.file);
            if manifest_path.exists() {
                if let Some(from_manifest) = Self::extract_matching_manifest(
                    manifest_path,
                    &dep.name,
                    dep.version.as_deref(),
                ) {
                    return Some(Self::normalize_spdx_id(&from_manifest));
                }
            }
        }

        // A package name or ecosystem alone is not license evidence.
        None
    }

    /// 从本地清单文件中提取指定组件的许可证声明
    pub fn extract_from_local_manifest(manifest_path: &Path, dep_name: &str) -> Option<String> {
        Self::extract_matching_manifest(manifest_path, dep_name, None)
    }

    fn extract_matching_manifest(
        manifest_path: &Path,
        dep_name: &str,
        expected_version: Option<&str>,
    ) -> Option<String> {
        let file_name = manifest_path.file_name()?.to_string_lossy().to_lowercase();

        // (A) package.json: 检查自身 name 是否匹配，或检查同级 node_modules/<dep_name>/package.json
        if file_name == "package.json" || file_name == "package-lock.json" {
            if let Some(parent) = manifest_path.parent() {
                let nm_pkg = parent
                    .join("node_modules")
                    .join(dep_name)
                    .join("package.json");
                if nm_pkg.exists() {
                    if let Ok(content) = fs::read_to_string(&nm_pkg) {
                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                            if expected_version.is_some()
                                && json.get("name").and_then(|v| v.as_str()) == Some(dep_name)
                                && json.get("version").and_then(|v| v.as_str()) == expected_version
                            {
                                if let Some(lic) = json.get("license").and_then(|v| v.as_str()) {
                                    return Some(lic.to_string());
                                }
                            }
                        }
                    }
                }
                if file_name == "package.json" {
                    if let Ok(content) = fs::read_to_string(manifest_path) {
                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                            if json.get("name").and_then(|v| v.as_str()) == Some(dep_name) {
                                if let Some(lic) = json.get("license").and_then(|v| v.as_str()) {
                                    return Some(lic.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        // (B) Cargo.toml: 若当前组件就是该 Crate 本身，读取 [package].license
        if file_name == "cargo.toml" {
            if let Ok(content) = fs::read_to_string(manifest_path) {
                if let Ok(doc) = content.parse::<toml::Table>() {
                    if let Some(pkg) = doc.get("package").and_then(|v| v.as_table()) {
                        if pkg.get("name").and_then(|v| v.as_str()) == Some(dep_name) {
                            if let Some(lic) = pkg.get("license").and_then(|v| v.as_str()) {
                                return Some(lic.to_string());
                            }
                        }
                    }
                }
            }
        }

        // (C) pyproject.toml: 读取 [project].license 或 [tool.poetry].license
        if file_name == "pyproject.toml" {
            if let Ok(content) = fs::read_to_string(manifest_path) {
                if let Ok(doc) = content.parse::<toml::Table>() {
                    if let Some(proj) = doc.get("project").and_then(|v| v.as_table()) {
                        if proj.get("name").and_then(|v| v.as_str()) == Some(dep_name) {
                            if let Some(lic) = proj.get("license").and_then(|v| v.as_str()) {
                                return Some(lic.to_string());
                            }
                            if let Some(lic_tbl) = proj.get("license").and_then(|v| v.as_table()) {
                                if let Some(txt) = lic_tbl.get("text").and_then(|v| v.as_str()) {
                                    return Some(txt.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        None
    }

    /// 归一化常见许可证写法为标准 SPDX 标识符
    pub fn normalize_spdx_id(raw: &str) -> String {
        let trimmed = raw.trim();
        let lower = trimmed.to_lowercase();
        if lower.contains(" or ") || lower.contains(" and ") || lower.contains(" with ") {
            let tokens = regex::Regex::new(r"[A-Za-z0-9][A-Za-z0-9.+-]*").unwrap();
            return tokens
                .replace_all(trimmed, |c: &regex::Captures| {
                    let token = &c[0];
                    if ["or", "and", "with"]
                        .iter()
                        .any(|op| token.eq_ignore_ascii_case(op))
                    {
                        token.to_ascii_uppercase()
                    } else {
                        Self::normalize_spdx_id(token)
                    }
                })
                .into_owned();
        }

        if lower.contains(" or ") {
            let parts: Vec<String> = lower
                .split(" or ")
                .map(|p| Self::normalize_spdx_id(p.trim()))
                .collect();
            return parts.join(" OR ");
        }

        if lower.contains(" and ") {
            let parts: Vec<String> = lower
                .split(" and ")
                .map(|p| Self::normalize_spdx_id(p.trim()))
                .collect();
            return parts.join(" AND ");
        }

        if lower.contains(" with ") {
            let parts: Vec<String> = lower
                .split(" with ")
                .map(|p| Self::normalize_spdx_id(p.trim()))
                .collect();
            return parts.join(" WITH ");
        }

        if lower.contains('/') {
            let parts: Vec<String> = lower
                .split('/')
                .map(|p| Self::normalize_spdx_id(p.trim()))
                .collect();
            return parts.join(" OR ");
        }

        match lower.as_str() {
            "mit" | "the mit license" | "mit license" => "MIT".to_string(),
            "apache 2"
            | "apache 2.0"
            | "apache-2.0"
            | "the apache software license, version 2.0" => "Apache-2.0".to_string(),
            "bsd" | "bsd-3-clause" | "bsd 3-clause" | "3-clause bsd" | "new bsd license" => {
                "BSD-3-Clause".to_string()
            }
            "bsd-2-clause" | "bsd 2-clause" | "2-clause bsd" | "simplified bsd" => {
                "BSD-2-Clause".to_string()
            }
            "isc" | "isc license" => "ISC".to_string(),
            "mpl-2.0" | "mozilla public license 2.0" => "MPL-2.0".to_string(),
            "lgpl-2.1" | "lgpl-2.1-only" => "LGPL-2.1-only".to_string(),
            "gpl-3.0" | "gpl-3.0-only" => "GPL-3.0-only".to_string(),
            "epl-1.0" | "eclipse public license 1.0" => "EPL-1.0".to_string(),
            "epl-2.0" | "eclipse public license 2.0" => "EPL-2.0".to_string(),
            "unlicense" => "Unlicense".to_string(),
            _ => trimmed.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_license_requires_evidence() {
        let dep_maven = Dependency {
            name: "com.alibaba:fastjson".to_string(),
            version: Some("1.2.68".to_string()),
            purl: "pkg:maven/com.alibaba/fastjson@1.2.68".to_string(),
            ..Default::default()
        };
        assert_eq!(LicenseResolver::resolve_license(&dep_maven), None);

        let dep_pypi = Dependency {
            name: "django".to_string(),
            version: Some("4.2.0".to_string()),
            purl: "pkg:pypi/django@4.2.0".to_string(),
            ..Default::default()
        };
        assert_eq!(LicenseResolver::resolve_license(&dep_pypi), None);

        let dep_explicit = Dependency {
            name: "custom-pkg".to_string(),
            purl: "pkg:npm/custom-pkg@1.0.0".to_string(),
            license: Some("the mit license".to_string()),
            ..Default::default()
        };
        assert_eq!(
            LicenseResolver::resolve_license(&dep_explicit),
            Some("MIT".to_string())
        );

        let dep_cargo = Dependency {
            name: "tokio".to_string(),
            version: Some("1.38.0".to_string()),
            purl: "pkg:cargo/tokio@1.38.0".to_string(),
            ..Default::default()
        };
        assert_eq!(LicenseResolver::resolve_license(&dep_cargo), None);

        let dep_golang = Dependency {
            name: "golang.org/x/crypto".to_string(),
            version: Some("v0.14.0".to_string()),
            purl: "pkg:golang/golang.org/x/crypto@v0.14.0".to_string(),
            ..Default::default()
        };
        assert_eq!(LicenseResolver::resolve_license(&dep_golang), None);
    }

    #[test]
    fn installed_license_requires_matching_version() {
        let dir = std::env::temp_dir().join(format!("license_versions_{}", std::process::id()));
        let pkg = dir.join("node_modules/demo");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(
            pkg.join("package.json"),
            r#"{"name":"demo","version":"1.0.0","license":"MIT"}"#,
        )
        .unwrap();
        let manifest = dir.join("package-lock.json");
        std::fs::write(&manifest, "{}").unwrap();
        let mut dep = Dependency {
            name: "demo".into(),
            version: Some("2.0.0".into()),
            purl: "pkg:npm/demo@2.0.0".into(),
            location: Some(crate::model::dependency::DependencyLocation::from_file(
                &manifest,
            )),
            ..Default::default()
        };
        assert_eq!(LicenseResolver::resolve_license(&dep), None);
        dep.version = Some("1.0.0".into());
        assert_eq!(
            LicenseResolver::resolve_license(&dep).as_deref(),
            Some("MIT")
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn test_normalize_spdx_id_variants() {
        assert_eq!(
            LicenseResolver::normalize_spdx_id("apache 2.0"),
            "Apache-2.0"
        );
        assert_eq!(
            LicenseResolver::normalize_spdx_id("apache-2.0"),
            "Apache-2.0"
        );
        assert_eq!(
            LicenseResolver::normalize_spdx_id("bsd 3-clause"),
            "BSD-3-Clause"
        );
        assert_eq!(
            LicenseResolver::normalize_spdx_id("bsd-2-clause"),
            "BSD-2-Clause"
        );
        assert_eq!(
            LicenseResolver::normalize_spdx_id("gpl-3.0-only"),
            "GPL-3.0-only"
        );
        assert_eq!(
            LicenseResolver::normalize_spdx_id("lgpl-2.1"),
            "LGPL-2.1-only"
        );
        assert_eq!(LicenseResolver::normalize_spdx_id("mpl-2.0"), "MPL-2.0");
        assert_eq!(
            LicenseResolver::normalize_spdx_id("mit or apache-2.0"),
            "MIT OR Apache-2.0"
        );
        assert_eq!(
            LicenseResolver::normalize_spdx_id("mit and apache-2.0"),
            "MIT AND Apache-2.0"
        );
        assert_eq!(LicenseResolver::normalize_spdx_id("unlicense"), "Unlicense");
    }

    #[test]
    fn test_extract_license_from_manifests() {
        let temp_dir = std::env::temp_dir().join("sbom_license_test");
        let _ = std::fs::create_dir_all(&temp_dir);

        let cargo_toml = temp_dir.join("Cargo.toml");
        let _ = std::fs::write(&cargo_toml, "[package]\nname = \"my-crate\"\nversion = \"0.1.0\"\nlicense = \"MIT OR Apache-2.0\"\n");

        let lic = LicenseResolver::extract_from_local_manifest(&cargo_toml, "my-crate");
        assert_eq!(lic, Some("MIT OR Apache-2.0".to_string()));

        let pyproject = temp_dir.join("pyproject.toml");
        let _ = std::fs::write(
            &pyproject,
            "[project]\nname = \"my-python\"\nversion = \"1.0.0\"\nlicense = \"BSD-3-Clause\"\n",
        );

        let lic_py = LicenseResolver::extract_from_local_manifest(&pyproject, "my-python");
        assert_eq!(lic_py, Some("BSD-3-Clause".to_string()));

        let pkg_json = temp_dir.join("package.json");
        let _ = std::fs::write(
            &pkg_json,
            "{\"name\": \"my-js\", \"version\": \"1.0.0\", \"license\": \"ISC\"}",
        );

        let lic_js = LicenseResolver::extract_from_local_manifest(&pkg_json, "my-js");
        assert_eq!(lic_js, Some("ISC".to_string()));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
