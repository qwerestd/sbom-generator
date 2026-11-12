//! CycloneDX comparison policy. Keep in sync with ui/compare-core.js using shared conformance fixtures.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

type Set = BTreeSet<String>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct CompareOptions {
    pub ecosystems: Set,
    pub include_applications: bool,
    pub exclude_zero_versions: bool,
}
impl Default for CompareOptions {
    fn default() -> Self {
        Self {
            ecosystems: ["cargo", "golang", "maven", "npm", "pypi"]
                .map(str::to_string)
                .into_iter()
                .collect(),
            include_applications: false,
            exclude_zero_versions: false,
        }
    }
}

impl CompareOptions {
    fn normalized(&self) -> anyhow::Result<Self> {
        let result = Self {
            ecosystems: self
                .ecosystems
                .iter()
                .map(|e| e.trim().to_ascii_lowercase())
                .filter(|e| !e.is_empty())
                .collect(),
            ..self.clone()
        };
        anyhow::ensure!(!result.ecosystems.is_empty(), "至少选择一个目标生态");
        anyhow::ensure!(
            result.ecosystems.iter().all(|e| e
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-'))),
            "目标生态名称无效"
        );
        Ok(result)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Record {
    pub identity: String,
    pub key: Option<String>,
    pub version: Option<String>,
    pub status: String,
    pub location: Option<String>,
    pub locations: Set,
    pub component: Value,
}
#[derive(Clone, Debug, Serialize)]
pub struct Summary {
    pub tool_name: String,
    pub tool_version: Option<String>,
    pub timestamp: Option<String>,
    pub spec_version: String,
    pub records: Vec<Record>,
    pub total_components: usize,
    pub unresolved_components: usize,
    pub inconsistent_components: usize,
    pub excluded: BTreeMap<String, usize>,
    pub diagnostics: Set,
    pub keys: Set,
    pub identities: Set,
    pub versions: BTreeMap<String, Set>,
    pub occurrences: BTreeMap<String, usize>,
    pub located_occurrences: BTreeMap<String, usize>,
    pub missing_locations: usize,
    pub graph_available: bool,
    pub edges: Set,
    pub dangling_refs: Set,
    pub duplicate_refs: Set,
    pub filtered_edges: usize,
    pub unresolved_edges: usize,
    pub methods: Set,
}
#[derive(Clone, Debug, Serialize)]
pub struct Metrics {
    pub a: usize,
    pub b: usize,
    pub common: usize,
    pub only_a: usize,
    pub only_b: usize,
    pub coverage_a: Option<f64>,
    pub coverage_b: Option<f64>,
    pub jaccard: Option<f64>,
}
#[derive(Clone, Debug, Serialize)]
pub struct VersionDifference {
    pub identity: String,
    pub versions_a: Set,
    pub versions_b: Set,
    pub only_a: Set,
    pub only_b: Set,
}
#[derive(Clone, Debug, Serialize)]
pub struct Comparison {
    pub policy: CompareOptions,
    pub a: Summary,
    pub b: Summary,
    pub exact: Metrics,
    pub all_exact: Metrics,
    pub identity: Metrics,
    pub occurrences: Metrics,
    pub located_occurrences: Metrics,
    pub graph: Option<Metrics>,
    pub common_keys: Set,
    pub only_keys_a: Set,
    pub only_keys_b: Set,
    pub only_identities_a: Set,
    pub only_identities_b: Set,
    pub version_differences: Vec<VersionDifference>,
    pub unknown_versions: Set,
    pub only_edges_a: Set,
    pub only_edges_b: Set,
    pub warnings: Vec<String>,
}

fn decode(raw: &str) -> Option<String> {
    let mut result = Vec::new();
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let pair = raw.get(i + 1..i + 3)?;
            result.push(u8::from_str_radix(pair, 16).ok()?);
            i += 3;
        } else {
            result.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(result).ok()
}
fn encode_part(raw: &str) -> String {
    raw.replace('%', "%25")
        .replace('?', "%3F")
        .replace('#', "%23")
        .replace('@', "%40")
}
fn normalize_version(eco: &str, version: &str) -> String {
    if eco == "golang" && version.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        format!("v{version}")
    } else {
        version.to_string()
    }
}
fn pep503(raw: &str) -> String {
    raw.to_ascii_lowercase()
        .split(['-', '_', '.'])
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}
pub fn split_purl(raw: &str) -> Option<(String, Option<String>)> {
    let raw = raw.trim().split(['?', '#']).next()?;
    let body = raw.strip_prefix("pkg:")?;
    let (eco, path) = body.split_once('/')?;
    if eco.is_empty()
        || !eco
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-'))
    {
        return None;
    }
    let eco = eco.to_ascii_lowercase();
    let at = path
        .rfind('@')
        .filter(|at| path.rfind('/').is_none_or(|slash| *at > slash));
    let (name, version) = match at {
        Some(at) => (
            &path[..at],
            Some(normalize_version(&eco, &decode(&path[at + 1..])?)),
        ),
        None => (path, None),
    };
    let mut name = decode(name)?;
    if name.is_empty()
        || name.split('/').any(str::is_empty)
        || name.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return None;
    }
    if eco == "pypi" {
        name = pep503(&name);
    }
    if eco == "npm" || eco == "cargo" {
        name.make_ascii_lowercase();
    }
    if name.is_empty() {
        return None;
    }
    name = if eco == "npm" && name.starts_with('@') {
        format!("@{}", encode_part(&name[1..]))
    } else {
        encode_part(&name)
    };
    Some((format!("pkg:{eco}/{name}"), version))
}
pub fn normalize_purl(raw: &str) -> String {
    split_purl(raw)
        .map(|(id, version)| {
            version
                .map(|v| format!("{id}@{}", encode_part(&v)))
                .unwrap_or(id)
        })
        .unwrap_or_default()
}
pub fn ecosystem(identity: &str) -> &str {
    identity
        .strip_prefix("pkg:")
        .and_then(|x| x.split_once('/'))
        .map(|x| x.0)
        .unwrap_or("unknown")
}
fn exact_version(raw: &str) -> bool {
    !raw.is_empty()
        && !raw
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "*^~<>=,|[]()${}/\\".contains(c))
        && ![
            "latest",
            "latest.release",
            "latest.integration",
            "release",
            "runtime",
            "workspace",
            "unknown",
        ]
        .iter()
        .any(|x| raw.eq_ignore_ascii_case(x))
        && !raw.ends_with(".+")
        && !raw.split('.').any(|part| part.eq_ignore_ascii_case("x"))
        && !raw.starts_with("workspace:")
        && !raw.starts_with("file:")
        && !raw.contains("://")
}
fn property<'a>(value: &'a Value, name: &str) -> Option<&'a str> {
    value["properties"]
        .as_array()?
        .iter()
        .find(|p| p["name"].as_str() == Some(name))?["value"]
        .as_str()
}
fn locations(value: &Value) -> Set {
    let mut paths = Set::new();
    let normalize = |path: &str| path.replace('\\', "/").trim_start_matches("./").to_string();
    for p in value["properties"].as_array().into_iter().flatten() {
        let name = p["name"].as_str().unwrap_or("");
        let is_syft = name
            .strip_prefix("syft:location:")
            .and_then(|s| s.strip_suffix(":path"))
            .is_some_and(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()));
        if is_syft || matches!(name, "aquasecurity:trivy:FilePath" | "trivy:FilePath") {
            if let Some(path) = p["value"].as_str() {
                paths.insert(normalize(path));
            }
        }
    }
    for occurrence in value["evidence"]["occurrences"]
        .as_array()
        .into_iter()
        .flatten()
    {
        if let Some(path) = occurrence["location"].as_str() {
            paths.insert(normalize(path));
        }
    }
    paths.remove("");
    paths
}

fn flatten<'a>(components: &'a [Value], output: &mut Vec<&'a Value>) {
    for component in components {
        output.push(component);
        if let Some(nested) = component["components"].as_array() {
            flatten(nested, output);
        }
    }
}
fn ratio(common: usize, total: usize) -> Option<f64> {
    (total > 0).then(|| common as f64 / total as f64 * 100.0)
}
fn metrics(a: usize, b: usize, common: usize) -> Metrics {
    Metrics {
        a,
        b,
        common,
        only_a: a - common,
        only_b: b - common,
        coverage_a: ratio(common, a),
        coverage_b: ratio(common, b),
        jaccard: ratio(common, a + b - common),
    }
}
fn set_metrics(a: &Set, b: &Set) -> Metrics {
    metrics(a.len(), b.len(), a.intersection(b).count())
}
fn multiset_metrics(a: &BTreeMap<String, usize>, b: &BTreeMap<String, usize>) -> Metrics {
    metrics(
        a.values().sum(),
        b.values().sum(),
        a.iter()
            .map(|(key, n)| (*n).min(*b.get(key).unwrap_or(&0)))
            .sum(),
    )
}
fn target(key: &str, policy: &CompareOptions) -> bool {
    policy.ecosystems.contains(ecosystem(key))
}

pub fn summarize(json: &Value, policy: &CompareOptions) -> anyhow::Result<Summary> {
    let normalized = policy.normalized()?;
    let policy = &normalized;
    anyhow::ensure!(json["bomFormat"] == "CycloneDX", "不是 CycloneDX SBOM");
    let components = json["components"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("缺少 components 数组"))?;
    anyhow::ensure!(
        json.get("dependencies").is_none_or(Value::is_array),
        "dependencies 必须是数组"
    );
    let mut all = Vec::new();
    flatten(components, &mut all);
    // Metadata's root is reference evidence, not an extra inventory record unless explicitly requested.
    if json["metadata"]["component"].is_object() {
        if let Some(nested) = json["metadata"]["component"]["components"].as_array() {
            flatten(nested, &mut all);
        }
        all.push(&json["metadata"]["component"]);
    }
    let tool = json["metadata"]["tools"]
        .as_array()
        .or_else(|| json["metadata"]["tools"]["components"].as_array())
        .and_then(|x| x.first());
    let mut result = Summary {
        tool_name: tool
            .and_then(|t| t["name"].as_str())
            .unwrap_or("Unknown")
            .to_string(),
        tool_version: tool.and_then(|t| t["version"].as_str()).map(str::to_string),
        timestamp: json["metadata"]["timestamp"].as_str().map(str::to_string),
        spec_version: json["specVersion"].as_str().unwrap_or("未知").to_string(),
        records: vec![],
        total_components: 0,
        unresolved_components: 0,
        inconsistent_components: 0,
        excluded: BTreeMap::new(),
        diagnostics: Set::new(),
        keys: Set::new(),
        identities: Set::new(),
        versions: BTreeMap::new(),
        occurrences: BTreeMap::new(),
        located_occurrences: BTreeMap::new(),
        missing_locations: 0,
        graph_available: json.get("dependencies").is_some(),
        edges: Set::new(),
        dangling_refs: Set::new(),
        duplicate_refs: Set::new(),
        filtered_edges: 0,
        unresolved_edges: 0,
        methods: Set::new(),
    };
    // Ref -> Option<exact key>. None means an explicitly excluded/unknown-version endpoint.
    let mut refs: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut unresolved_refs = Set::new();
    for component in &all {
        let parsed = component["purl"].as_str().and_then(split_purl);
        let kind = component["type"].as_str().unwrap_or("library");
        let excluded = if std::ptr::eq(*component, &json["metadata"]["component"])
            && !policy.include_applications
        {
            Some("metadata-root")
        } else if kind == "application" && !policy.include_applications {
            Some("application")
        } else if !matches!(kind, "library" | "framework" | "application") {
            Some("component-type")
        } else if parsed.is_none() {
            Some("invalid-purl")
        } else {
            None
        };
        let reference = component["bom-ref"]
            .as_str()
            .or_else(|| component["purl"].as_str())
            .filter(|s| !s.trim().is_empty());
        let mut key = None;
        let mut unresolved = false;
        if let Some(reason) = excluded {
            *result.excluded.entry(reason.into()).or_default() += 1;
        } else if let Some((identity, purl_version)) = parsed {
            let eco = ecosystem(&identity);
            let declared = component["version"]
                .as_str()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(|v| normalize_version(eco, v));
            let version = declared.clone().or_else(|| purl_version.clone());
            if policy.exclude_zero_versions
                && version
                    .as_deref()
                    .is_some_and(|v| matches!(v, "0.0.0" | "v0.0.0"))
            {
                *result.excluded.entry("zero-version".into()).or_default() += 1;
            } else {
                let status = if declared.as_deref().is_some_and(|v| !exact_version(v))
                    || purl_version.as_deref().is_some_and(|v| !exact_version(v))
                    || property(component, "sbom:version:status") == Some("unresolved")
                    || version.is_none()
                {
                    "unresolved"
                } else if declared.is_some() && purl_version.is_some() && declared != purl_version {
                    "inconsistent"
                } else {
                    "exact"
                };
                if status == "exact" {
                    key = version
                        .as_ref()
                        .map(|v| format!("{identity}@{}", encode_part(v)));
                } else {
                    unresolved = true;
                    result.unresolved_components += 1;
                }
                if status == "inconsistent" {
                    result.inconsistent_components += 1;
                    result
                        .diagnostics
                        .insert(format!("version-conflict:{identity}"));
                }
                let paths = locations(component);
                let loc = paths.first().cloned();
                result.identities.insert(identity.clone());
                if let Some(k) = &key {
                    result.keys.insert(k.clone());
                    result
                        .versions
                        .entry(identity.clone())
                        .or_default()
                        .insert(version.clone().unwrap());
                    if target(k, policy) {
                        *result.occurrences.entry(k.clone()).or_default() += 1;
                        if paths.is_empty() {
                            result.missing_locations += 1;
                        }
                        for path in &paths {
                            *result
                                .located_occurrences
                                .entry(serde_json::to_string(&(k, path))?)
                                .or_default() += 1;
                        }
                    }
                }
                if target(&identity, policy) {
                    if let Some(method) = property(component, "sbom:analysis:method") {
                        result.methods.insert(method.into());
                    }
                }
                let mut metadata = (*component).clone();
                if let Some(object) = metadata.as_object_mut() {
                    object.remove("components");
                }
                result.records.push(Record {
                    identity,
                    key: key.clone(),
                    version,
                    status: status.into(),
                    location: loc,
                    locations: paths,
                    component: metadata,
                });
                result.total_components += 1;
            }
        }
        if let Some(reference) = reference {
            let reference = reference.trim().to_string();
            if refs.insert(reference.clone(), key).is_some() {
                result.duplicate_refs.insert(reference.clone());
            }
            if unresolved {
                unresolved_refs.insert(reference);
            }
        }
    }
    // Root may also appear in components; identical repeated root refs are still reported as ambiguous.
    for declaration in json["dependencies"].as_array().into_iter().flatten() {
        let parent = declaration["ref"].as_str().map(str::trim).unwrap_or("");
        anyhow::ensure!(
            declaration.get("dependsOn").is_none_or(Value::is_array),
            "dependsOn 必须是数组"
        );
        if !refs.contains_key(parent) {
            result.dangling_refs.insert(parent.to_string());
        }
        for child in declaration["dependsOn"].as_array().into_iter().flatten() {
            let child = child.as_str().map(str::trim).unwrap_or("");
            if !refs.contains_key(child) {
                result.dangling_refs.insert(child.to_string());
            }
            if result.duplicate_refs.contains(parent)
                || result.duplicate_refs.contains(child)
                || !refs.contains_key(parent)
                || !refs.contains_key(child)
            {
                continue;
            }
            if unresolved_refs.contains(parent) || unresolved_refs.contains(child) {
                result.unresolved_edges += 1;
                continue;
            }
            match (
                refs.get(parent).and_then(Option::as_ref),
                refs.get(child).and_then(Option::as_ref),
            ) {
                (Some(from), Some(to))
                    if from != to && target(from, policy) && target(to, policy) =>
                {
                    result.edges.insert(serde_json::to_string(&(from, to))?);
                }
                _ => result.filtered_edges += 1,
            }
        }
    }
    Ok(result)
}

pub fn compare(a: &Value, b: &Value, policy: CompareOptions) -> anyhow::Result<Comparison> {
    let policy = policy.normalized()?;
    let a = summarize(a, &policy)?;
    let b = summarize(b, &policy)?;
    let keys_a: Set = a
        .keys
        .iter()
        .filter(|k| target(k, &policy))
        .cloned()
        .collect();
    let keys_b: Set = b
        .keys
        .iter()
        .filter(|k| target(k, &policy))
        .cloned()
        .collect();
    let ids_a: Set = a
        .identities
        .iter()
        .filter(|k| target(k, &policy))
        .cloned()
        .collect();
    let ids_b: Set = b
        .identities
        .iter()
        .filter(|k| target(k, &policy))
        .cloned()
        .collect();
    let mut differences = Vec::new();
    let mut unknown = Set::new();
    let unknown_records: Set = a
        .records
        .iter()
        .chain(&b.records)
        .filter(|r| r.key.is_none())
        .map(|r| r.identity.clone())
        .collect();
    for id in ids_a.intersection(&ids_b) {
        let va = a.versions.get(id).cloned().unwrap_or_default();
        let vb = b.versions.get(id).cloned().unwrap_or_default();
        if va.is_empty() || vb.is_empty() || unknown_records.contains(id) {
            unknown.insert(id.clone());
        }
        if !va.is_empty() && !vb.is_empty() && va != vb {
            differences.push(VersionDifference {
                identity: id.clone(),
                only_a: va.difference(&vb).cloned().collect(),
                only_b: vb.difference(&va).cloned().collect(),
                versions_a: va,
                versions_b: vb,
            });
        }
    }
    let mut warnings = Vec::new();
    let incompatible_go = (a.methods.contains("go-package-imports")
        && b.methods.contains("go-module-graph"))
        || (b.methods.contains("go-package-imports") && a.methods.contains("go-module-graph"));
    if incompatible_go {
        warnings.push("Go 导入图与模块要求图口径不同，依赖边重合率为 N/A".into());
    }
    if !a.graph_available || !b.graph_available {
        warnings.push("至少一侧未提供 dependencies，依赖边重合率为 N/A".into());
    }
    if a.missing_locations > 0 || b.missing_locations > 0 {
        warnings.push("部分记录缺少来源路径，路径指标只覆盖有路径的记录；不推断物理实例".into());
    }
    if !a.dangling_refs.is_empty()
        || !b.dangling_refs.is_empty()
        || !a.duplicate_refs.is_empty()
        || !b.duplicate_refs.is_empty()
    {
        warnings.push("依赖图存在悬空或重复引用，相关边已跳过；图指标可能不完整".into());
    }
    if a.methods != b.methods {
        warnings.push(
            "两侧解析方法或依赖作用域可能不同，需要核对源码提交、开发依赖、平台与扫描参数".into(),
        );
    }
    Ok(Comparison {
        exact: set_metrics(&keys_a, &keys_b),
        all_exact: set_metrics(&a.keys, &b.keys),
        identity: set_metrics(&ids_a, &ids_b),
        occurrences: multiset_metrics(&a.occurrences, &b.occurrences),
        located_occurrences: multiset_metrics(&a.located_occurrences, &b.located_occurrences),
        graph: (a.graph_available && b.graph_available && !incompatible_go)
            .then(|| set_metrics(&a.edges, &b.edges)),
        common_keys: keys_a.intersection(&keys_b).cloned().collect(),
        only_keys_a: keys_a.difference(&keys_b).cloned().collect(),
        only_keys_b: keys_b.difference(&keys_a).cloned().collect(),
        only_identities_a: ids_a.difference(&ids_b).cloned().collect(),
        only_identities_b: ids_b.difference(&ids_a).cloned().collect(),
        version_differences: differences,
        unknown_versions: unknown,
        only_edges_a: a.edges.difference(&b.edges).cloned().collect(),
        only_edges_b: b.edges.difference(&a.edges).cloned().collect(),
        policy,
        a,
        b,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn conformance_cases_cover_classification_inventory_and_graphs() {
        let cases: Value =
            serde_json::from_str(include_str!("../tests/fixtures/compare_cases.json")).unwrap();
        for case in cases.as_array().unwrap() {
            let policy = case
                .get("options")
                .map(|v| serde_json::from_value(v.clone()).unwrap())
                .unwrap_or_default();
            let result = compare(&case["a"], &case["b"], policy);
            if case["expect_error"] == true {
                assert!(result.is_err(), "{}", case["name"]);
                continue;
            }
            let value = serde_json::to_value(result.unwrap()).unwrap();
            for (path, expected) in case["expected"].as_object().unwrap() {
                let mut actual = &value;
                let mut length = None;
                for part in path.split('.') {
                    if part == "length" {
                        length = Some(Value::from(actual.as_array().unwrap().len()));
                    } else {
                        actual = &actual[part];
                    }
                }
                let actual = length.as_ref().unwrap_or(actual);
                if let (Some(a), Some(b)) = (actual.as_f64(), expected.as_f64()) {
                    assert!((a - b).abs() < 1e-9, "{}: {path}: {a} != {b}", case["name"]);
                } else {
                    assert_eq!(actual, expected, "{}: {path}", case["name"]);
                }
            }
        }
    }
}
