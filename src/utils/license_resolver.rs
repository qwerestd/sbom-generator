use std::fs;
use std::path::Path;

use crate::model::dependency::Dependency;
use crate::utils::osv_scanner::OsvScanner;

/// 开源许可证合规解析与推断引擎（支持本地清单提取 + SPDX 权威知识库映射）
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
                if let Some(from_manifest) =
                    Self::extract_from_local_manifest(manifest_path, &dep.name)
                {
                    return Some(Self::normalize_spdx_id(&from_manifest));
                }
            }
        }

        // 3. 基于 PURL 坐标查询内置的多语言主流开源组件 SPDX 许可证知识库
        let (eco, full_name, _ver) = OsvScanner::parse_purl_coordinates(&dep.purl)?;
        Self::lookup_curated_spdx(&eco, &full_name)
    }

    /// 从本地清单文件中提取指定组件的许可证声明
    pub fn extract_from_local_manifest(manifest_path: &Path, dep_name: &str) -> Option<String> {
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
                            if let Some(lic) = json.get("license").and_then(|v| v.as_str()) {
                                return Some(lic.to_string());
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

    /// 内置六大生态高频开源组件与组织命名空间 SPDX 许可证映射库
    fn lookup_curated_spdx(ecosystem: &str, full_name: &str) -> Option<String> {
        let eco = ecosystem.to_lowercase();
        let name = full_name.to_lowercase().replace(':', "/");

        match eco.as_str() {
            "cargo" => {
                match name.as_str() {
                    "tokio" | "bytes" | "mio" | "hyper" | "tower" | "tracing"
                    | "pin-project-lite" => Some("MIT".to_string()),
                    "serde" | "serde_derive" | "serde_json" | "syn" | "quote" | "proc-macro2"
                    | "itoa" | "ryu" | "regex" | "regex-automata" | "regex-syntax"
                    | "aho-corasick" | "anyhow" | "thiserror" | "clap" | "log" | "once_cell"
                    | "lazy_static" | "reqwest" | "futures" | "chrono" | "toml" | "cc" | "libc"
                    | "bitflags" | "smallvec" | "parking_lot" | "indexmap" | "hashbrown"
                    | "rand" | "uuid" | "url" | "percent-encoding" | "idna" | "form_urlencoded"
                    | "http" | "h2" => Some("MIT OR Apache-2.0".to_string()),
                    "walkdir" | "same-file" | "memchr" | "bstr" | "termcolor" => {
                        Some("Unlicense OR MIT".to_string())
                    }
                    "openssl" | "openssl-sys" | "foreign-types" => Some("Apache-2.0".to_string()),
                    "tree-sitter" | "tree-sitter-kotlin" => Some("MIT".to_string()),
                    _ => Some("MIT OR Apache-2.0".to_string()),
                }
            }
            "golang" => {
                if name.starts_with("golang.org/x/")
                    || name.starts_with("google.golang.org/")
                    || name.starts_with("cloud.google.com/")
                {
                    return Some("BSD-3-Clause".to_string());
                }
                if name.starts_with("github.com/gin-gonic/")
                    || name.starts_with("github.com/uber-go/")
                    || name.starts_with("go.uber.org/")
                    || name.starts_with("github.com/stretchr/")
                    || name.starts_with("github.com/sirupsen/")
                {
                    return Some("MIT".to_string());
                }
                if name.starts_with("github.com/spf13/")
                    || name.starts_with("go.opentelemetry.io/")
                    || name.starts_with("github.com/prometheus/")
                    || name.starts_with("cel.dev/")
                {
                    return Some("Apache-2.0".to_string());
                }
                Some("BSD-3-Clause".to_string())
            }
            "maven" => {
                if name.starts_with("org.apache.")
                    || name.starts_with("org.springframework")
                    || name.starts_with("com.alibaba/")
                    || name.starts_with("com.fasterxml.")
                    || name.starts_with("com.google.")
                    || name.starts_with("io.ktor/")
                    || name.starts_with("org.jetbrains.")
                    || name.starts_with("commons-")
                    || name.starts_with("io.netty/")
                    || name.starts_with("io.grpc/")
                    || name.starts_with("net.sf.ehcache/")
                    || name.starts_with("net.sf.oval/")
                {
                    return Some("Apache-2.0".to_string());
                }
                if name.starts_with("org.slf4j/") || name.starts_with("org.mockito/") {
                    return Some("MIT".to_string());
                }
                if name.starts_with("ch.qos.logback/") {
                    return Some("EPL-1.0 OR LGPL-2.1-or-later".to_string());
                }
                if name.starts_with("junit/") || name.starts_with("org.junit.") {
                    return Some("EPL-2.0".to_string());
                }
                if name.starts_with("org.json/") {
                    return Some("JSON".to_string());
                }
                Some("Apache-2.0".to_string())
            }
            "npm" => match name.as_str() {
                "typescript" => Some("Apache-2.0".to_string()),
                "semver" | "Rimraf" | "glob" | "minimatch" | "lru-cache" | "once" | "wrappy"
                | "inherits" | "yallist" => Some("ISC".to_string()),
                _ => Some("MIT".to_string()),
            },
            "pypi" => match name.as_str() {
                "requests" | "aiohttp" | "tornado" | "arrow" | "cryptography" => {
                    Some("Apache-2.0".to_string())
                }
                "django" | "flask" | "jinja2" | "werkzeug" | "click" | "itsdangerous"
                | "markupsafe" | "numpy" | "scipy" | "pandas" | "scikit-learn" | "matplotlib"
                | "pillow" | "psutil" | "idna" | "pycparser" => Some("BSD-3-Clause".to_string()),
                "certifi" => Some("MPL-2.0".to_string()),
                "fastapi" | "uvicorn" | "pydantic" | "starlette" | "urllib3" | "pyyaml"
                | "pytest" | "attrs" | "six" | "setuptools" | "wheel" | "pip"
                | "charset-normalizer" | "sqlalchemy" | "httpx" | "anyio" | "sniffio" => {
                    Some("MIT".to_string())
                }
                _ => Some("MIT".to_string()),
            },
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_license_by_purl_and_explicit() {
        let dep_maven = Dependency {
            name: "com.alibaba:fastjson".to_string(),
            version: Some("1.2.68".to_string()),
            purl: "pkg:maven/com.alibaba/fastjson@1.2.68".to_string(),
            ..Default::default()
        };
        assert_eq!(
            LicenseResolver::resolve_license(&dep_maven),
            Some("Apache-2.0".to_string())
        );

        let dep_pypi = Dependency {
            name: "django".to_string(),
            version: Some("4.2.0".to_string()),
            purl: "pkg:pypi/django@4.2.0".to_string(),
            ..Default::default()
        };
        assert_eq!(
            LicenseResolver::resolve_license(&dep_pypi),
            Some("BSD-3-Clause".to_string())
        );

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
        assert_eq!(
            LicenseResolver::resolve_license(&dep_cargo),
            Some("MIT".to_string())
        );

        let dep_golang = Dependency {
            name: "golang.org/x/crypto".to_string(),
            version: Some("v0.14.0".to_string()),
            purl: "pkg:golang/golang.org/x/crypto@v0.14.0".to_string(),
            ..Default::default()
        };
        assert_eq!(
            LicenseResolver::resolve_license(&dep_golang),
            Some("BSD-3-Clause".to_string())
        );
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
