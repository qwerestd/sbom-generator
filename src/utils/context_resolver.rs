use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashMap;

lazy_static! {
    /// 匹配 `${var.name}` 形式的属性占位符（适用于 Maven、Gradle、Python、NPM 等）
    static ref BRACED_VAR_RE: Regex = Regex::new(r"\$\{([^}]+)\}").unwrap();
    /// 匹配 `$varName` 形式的简写变量占位符（适用于 Gradle Groovy/Kotlin DSL 等）
    static ref SIMPLE_VAR_RE: Regex = Regex::new(r"\$([a-zA-Z_][a-zA-Z0-9_.]*)").unwrap();
}

/// 源自 Maven `enrich_string_with_properties` 并推广至全工程的通用多级变量插值引擎。
/// 支持最多 5 层嵌套属性引用（例如 `a = "${b}"`, `b = "1.2.3"`），同时兼容 `${var}` 与 `$var` 语法。
pub fn interpolate_variables(input: &str, properties: &HashMap<String, String>) -> String {
    if !input.contains('$') || properties.is_empty() {
        return input.to_string();
    }

    let mut resolved = input.to_string();

    for _ in 0..5 {
        let mut has_replacement = false;
        let current_text = resolved.clone();

        // 1. 优先替换 `${var}`
        for cap in BRACED_VAR_RE.captures_iter(&current_text) {
            let full_placeholder = &cap[0];
            let var_key = cap[1].trim();

            if let Some(target_val) = properties.get(var_key) {
                if target_val != full_placeholder {
                    resolved = resolved.replace(full_placeholder, target_val);
                    has_replacement = true;
                }
            }
        }

        // 2. 替换 `$var`（当不存在花括号包裹时）
        if resolved.contains('$') && !resolved.contains("${") {
            let snapshot = resolved.clone();
            for cap in SIMPLE_VAR_RE.captures_iter(&snapshot) {
                let full_placeholder = &cap[0];
                let var_key = &cap[1];

                if let Some(target_val) = properties.get(var_key) {
                    if target_val != full_placeholder {
                        resolved = resolved.replace(full_placeholder, target_val);
                        has_replacement = true;
                    }
                }
            }
        }

        if !has_replacement {
            break;
        }
    }

    resolved
}

/// 对属性字典内部存在相互引用的变量做自举收敛（源自 Maven `replace_properties`）
pub fn resolve_property_map(raw_properties: &HashMap<String, String>) -> HashMap<String, String> {
    let mut result = HashMap::with_capacity(raw_properties.len());
    for (k, v) in raw_properties {
        result.insert(k.clone(), interpolate_variables(v, raw_properties));
    }
    result
}

/// 通用分层上下文容器（推广自 Maven 的 Parent Properties + `<dependencyManagement>` 机制）
/// 可用于：
/// - Maven 父子 POM 属性与版本锁定继承
/// - Gradle 根工程 `gradle.properties` / `ext` / `libs.versions.toml` 向子模块渗透
/// - Cargo Workspace `[workspace.package]` 与 `[workspace.dependencies]` 向成员 Crate 渗透
/// - Python `-c constraints.txt` 对 `requirements.txt` 的版本锁定渗透
#[derive(Clone, Debug, Default)]
pub struct HierarchicalContext {
    /// 属性键值表（如版本号变量）
    pub properties: HashMap<String, String>,
    /// 受管依赖版本表：Key 为标准化包名（如 `group:artifact` 或 `crate_name` 或 `pep503_name`），Value 为受管版本
    pub managed_versions: HashMap<String, String>,
}

impl HierarchicalContext {
    pub fn new() -> Self {
        Self::default()
    }

    /// 继承父级上下文，子级同名属性与受管版本优先覆盖父级
    pub fn inherit_from(&mut self, parent: &HierarchicalContext) {
        let mut merged_props = parent.properties.clone();
        merged_props.extend(self.properties.drain());
        self.properties = resolve_property_map(&merged_props);

        let mut merged_versions = parent.managed_versions.clone();
        merged_versions.extend(self.managed_versions.drain());
        self.managed_versions = merged_versions;
    }

    /// 插入属性
    pub fn insert_property(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.properties.insert(key.into(), value.into());
    }

    /// 插入受管版本（如 BOM / Version Catalog / Workspace Dependency / Constraints）
    pub fn insert_managed_version(
        &mut self,
        pkg_key: impl Into<String>,
        version: impl Into<String>,
    ) {
        self.managed_versions.insert(pkg_key.into(), version.into());
    }

    /// 对给定字符串执行变量插值
    pub fn interpolate(&self, raw: &str) -> String {
        interpolate_variables(raw, &self.properties)
    }

    /// 决议组件版本：
    /// 1. 若组件自身显式声明了版本，先对其执行 `${var}` / `$var` 插值；
    /// 2. 若插值后版本为空、为 `"*"`、为 `"workspace"` 或仍含未解析的 `$`，则自动回退查询 `managed_versions` 受管版本表！
    pub fn resolve_version(&self, pkg_key: &str, declared_version: Option<&str>) -> Option<String> {
        if let Some(raw_v) = declared_version {
            let trimmed = raw_v.trim();
            if !trimmed.is_empty() && trimmed != "*" && !trimmed.eq_ignore_ascii_case("workspace") {
                let interpolated = self.interpolate(trimmed);
                if !interpolated.contains('$') && !interpolated.is_empty() {
                    return Some(interpolated);
                }
            }
        }

        self.managed_versions
            .get(pkg_key)
            .map(|v| self.interpolate(v))
            .filter(|v| !v.contains('$') && !v.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interpolate_and_hierarchical_context() {
        let mut parent = HierarchicalContext::new();
        parent.insert_property("kotlin.version", "1.9.22");
        parent.insert_property("spring.boot.version", "${base.boot.version}");
        parent.insert_property("base.boot.version", "3.2.1");
        parent.insert_managed_version(
            "org.springframework.boot:spring-boot-starter-web",
            "${spring.boot.version}",
        );

        let mut child = HierarchicalContext::new();
        child.insert_property("custom.ver", "$kotlin.version");
        child.inherit_from(&parent);

        assert_eq!(child.interpolate("${spring.boot.version}"), "3.2.1");
        assert_eq!(child.interpolate("$custom.ver"), "1.9.22");
        assert_eq!(
            child.resolve_version("org.springframework.boot:spring-boot-starter-web", None),
            Some("3.2.1".to_string())
        );
    }
}
