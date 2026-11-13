//! Offline Maven/Gradle local repository `.pom` resolver for static mode.
//! Reads `~/.m2/repository` and `~/.gradle/caches/modules-2/files-2.1` without spawning external CLIs.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::PathBuf;

use lazy_static::lazy_static;
use regex::Regex;
use tree_sitter::Node;

use crate::utils::tree_sitter::language::get_tree_sitter_xml;
use crate::utils::tree_sitter::tree::get_tree;

lazy_static! {
    static ref POM_PROP_RE: Regex = Regex::new(r"\$\{([^}]+)\}").unwrap();
}

#[derive(Clone, Debug)]
pub struct PomDep {
    pub group_id: String,
    pub artifact_id: String,
    pub version: Option<String>,
    pub scope: Option<String>,
    pub dep_type: Option<String>,
    pub optional: bool,
    pub exclusions: HashSet<(String, String)>,
}

#[derive(Clone, Debug, Default)]
pub struct ParsedPom {
    pub group_id: Option<String>,
    pub artifact_id: Option<String>,
    pub version: Option<String>,
    pub parent: Option<(String, String, String)>,
    pub properties: HashMap<String, String>,
    pub dependency_management: Vec<PomDep>,
    pub dependencies: Vec<PomDep>,
}

#[derive(Clone, Debug)]
pub struct EffectivePom {
    pub properties: HashMap<String, String>,
    pub managed_versions: HashMap<(String, String), String>,
    pub dependencies: Vec<PomDep>,
}

#[derive(Clone, Debug)]
pub struct SeedDep {
    pub group_id: String,
    pub artifact_id: String,
    pub version: String,
    pub exclusions: HashSet<(String, String)>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ResolvedTransitiveDep {
    pub group_id: String,
    pub artifact_id: String,
    pub version: String,
}

pub struct LocalPomRepo {
    m2_root: Option<PathBuf>,
    gradle_root: Option<PathBuf>,
    parsed_cache: HashMap<(String, String, String), Option<ParsedPom>>,
    effective_cache: HashMap<(String, String, String), Option<EffectivePom>>,
}

impl Default for LocalPomRepo {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalPomRepo {
    pub fn new() -> Self {
        Self {
            m2_root: Self::find_m2_repo(),
            gradle_root: Self::find_gradle_cache(),
            parsed_cache: HashMap::new(),
            effective_cache: HashMap::new(),
        }
    }

    pub fn with_roots(m2_root: Option<PathBuf>, gradle_root: Option<PathBuf>) -> Self {
        Self {
            m2_root,
            gradle_root,
            parsed_cache: HashMap::new(),
            effective_cache: HashMap::new(),
        }
    }

    pub fn is_available(&self) -> bool {
        self.m2_root.is_some() || self.gradle_root.is_some()
    }

    fn home_dir() -> Option<PathBuf> {
        std::env::var_os("USERPROFILE")
            .or_else(|| std::env::var_os("HOME"))
            .map(PathBuf::from)
    }

    fn find_m2_repo() -> Option<PathBuf> {
        for var in ["MAVEN_REPO_LOCAL", "M2_REPO"] {
            if let Some(val) = std::env::var_os(var) {
                let p = PathBuf::from(val);
                if p.is_dir() {
                    return Some(p);
                }
            }
        }
        Self::home_dir()
            .map(|h| h.join(".m2").join("repository"))
            .filter(|p| p.is_dir())
    }

    fn find_gradle_cache() -> Option<PathBuf> {
        if let Some(val) = std::env::var_os("GRADLE_USER_HOME") {
            let p = PathBuf::from(val)
                .join("caches")
                .join("modules-2")
                .join("files-2.1");
            if p.is_dir() {
                return Some(p);
            }
        }
        Self::home_dir()
            .map(|h| {
                h.join(".gradle")
                    .join("caches")
                    .join("modules-2")
                    .join("files-2.1")
            })
            .filter(|p| p.is_dir())
    }

    fn locate_pom(&self, group: &str, artifact: &str, version: &str) -> Option<PathBuf> {
        if group.is_empty()
            || artifact.is_empty()
            || version.is_empty()
            || group.contains('$')
            || artifact.contains('$')
            || version.contains('$')
        {
            return None;
        }
        if let Some(m2) = &self.m2_root {
            let mut p = m2.clone();
            for part in group.split('.') {
                p.push(part);
            }
            p.push(artifact);
            p.push(version);
            p.push(format!("{artifact}-{version}.pom"));
            if p.is_file() {
                return Some(p);
            }
        }
        if let Some(gradle) = &self.gradle_root {
            let ver_dir = gradle.join(group).join(artifact).join(version);
            if ver_dir.is_dir() {
                if let Ok(entries) = fs::read_dir(&ver_dir) {
                    let expected = format!("{artifact}-{version}.pom");
                    for entry in entries.flatten() {
                        let hash_dir = entry.path();
                        if !hash_dir.is_dir() {
                            continue;
                        }
                        let candidate = hash_dir.join(&expected);
                        if candidate.is_file() {
                            return Some(candidate);
                        }
                        if let Ok(files) = fs::read_dir(&hash_dir) {
                            for f in files.flatten() {
                                let fp = f.path();
                                if fp.extension().is_some_and(|e| e == "pom") && fp.is_file() {
                                    return Some(fp);
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn get_parsed_pom(&mut self, group: &str, artifact: &str, version: &str) -> Option<ParsedPom> {
        let key = (group.to_string(), artifact.to_string(), version.to_string());
        if let Some(cached) = self.parsed_cache.get(&key) {
            return cached.clone();
        }
        let parsed = self
            .locate_pom(group, artifact, version)
            .and_then(|p| fs::read_to_string(p).ok())
            .and_then(|text| parse_pom_xml(&text));
        self.parsed_cache.insert(key, parsed.clone());
        parsed
    }

    pub fn resolve_effective_pom(
        &mut self,
        group: &str,
        artifact: &str,
        version: &str,
    ) -> Option<EffectivePom> {
        let mut visited_parents = HashSet::new();
        let mut visited_boms = HashSet::new();
        self.resolve_effective_pom_inner(
            group,
            artifact,
            version,
            0,
            &mut visited_parents,
            &mut visited_boms,
        )
    }

    fn resolve_effective_pom_inner(
        &mut self,
        group: &str,
        artifact: &str,
        version: &str,
        depth: usize,
        visited_parents: &mut HashSet<(String, String, String)>,
        visited_boms: &mut HashSet<(String, String, String)>,
    ) -> Option<EffectivePom> {
        if depth > 16 {
            return None;
        }
        let key = (group.to_string(), artifact.to_string(), version.to_string());
        if let Some(cached) = self.effective_cache.get(&key) {
            return cached.clone();
        }
        if !visited_parents.insert(key.clone()) {
            return None;
        }

        let Some(parsed) = self.get_parsed_pom(group, artifact, version) else {
            self.effective_cache.insert(key, None);
            return None;
        };

        let mut props = HashMap::new();
        let mut managed_versions: HashMap<(String, String), String> = HashMap::new();

        if let Some((pg, pa, pv)) = &parsed.parent {
            props.insert("project.parent.groupId".to_string(), pg.clone());
            props.insert("project.parent.artifactId".to_string(), pa.clone());
            props.insert("project.parent.version".to_string(), pv.clone());
            if let Some(parent_eff) = self.resolve_effective_pom_inner(
                pg,
                pa,
                pv,
                depth + 1,
                visited_parents,
                visited_boms,
            ) {
                props.extend(parent_eff.properties);
                managed_versions.extend(parent_eff.managed_versions);
            }
        }

        let eff_group = parsed
            .group_id
            .clone()
            .or_else(|| parsed.parent.as_ref().map(|p| p.0.clone()))
            .unwrap_or_else(|| group.to_string());
        let eff_artifact = parsed
            .artifact_id
            .clone()
            .unwrap_or_else(|| artifact.to_string());
        let eff_version = parsed
            .version
            .clone()
            .or_else(|| parsed.parent.as_ref().map(|p| p.2.clone()))
            .unwrap_or_else(|| version.to_string());

        props.extend(parsed.properties.clone());
        props.insert("project.groupId".to_string(), eff_group.clone());
        props.insert("pom.groupId".to_string(), eff_group);
        props.insert("project.artifactId".to_string(), eff_artifact.clone());
        props.insert("pom.artifactId".to_string(), eff_artifact);
        props.insert("project.version".to_string(), eff_version.clone());
        props.insert("pom.version".to_string(), eff_version);

        // Resolve local dependencyManagement entries & BOM imports
        for dep in &parsed.dependency_management {
            let g = interpolate(&dep.group_id, &props);
            let a = interpolate(&dep.artifact_id, &props);
            let v = dep.version.as_deref().map(|raw| interpolate(raw, &props));
            let is_import = dep
                .scope
                .as_deref()
                .is_some_and(|s| s.eq_ignore_ascii_case("import"));
            let is_pom = dep
                .dep_type
                .as_deref()
                .is_some_and(|t| t.eq_ignore_ascii_case("pom"));
            if is_import && is_pom {
                if let Some(ver) = v {
                    let bom_key = (g.clone(), a.clone(), ver.clone());
                    if visited_boms.insert(bom_key) {
                        if let Some(bom_eff) = self.resolve_effective_pom_inner(
                            &g,
                            &a,
                            &ver,
                            depth + 1,
                            visited_parents,
                            visited_boms,
                        ) {
                            for (mk, mv) in bom_eff.managed_versions {
                                managed_versions.entry(mk).or_insert(mv);
                            }
                        }
                    }
                }
            } else if let Some(ver) = v {
                if !g.is_empty() && !a.is_empty() && !ver.is_empty() && !ver.contains('$') {
                    managed_versions.insert((g, a), ver);
                }
            }
        }

        let mut resolved_deps = Vec::with_capacity(parsed.dependencies.len());
        for dep in &parsed.dependencies {
            let g = interpolate(&dep.group_id, &props);
            let a = interpolate(&dep.artifact_id, &props);
            let mut v = dep.version.as_deref().map(|raw| interpolate(raw, &props));
            if v.as_deref().is_none_or(|s| s.is_empty()) {
                v = managed_versions.get(&(g.clone(), a.clone())).cloned();
            } else if let Some(ver) = v.as_deref() {
                let re_interp = interpolate(ver, &props);
                v = Some(re_interp);
            }
            resolved_deps.push(PomDep {
                group_id: g,
                artifact_id: a,
                version: v,
                scope: dep.scope.clone(),
                dep_type: dep.dep_type.clone(),
                optional: dep.optional,
                exclusions: dep.exclusions.clone(),
            });
        }

        let eff = EffectivePom {
            properties: props,
            managed_versions,
            dependencies: resolved_deps,
        };
        self.effective_cache.insert(key, Some(eff.clone()));
        Some(eff)
    }

    /// Resolve an external `<parent>` and any BOM `<scope>import</scope>` entries into
    /// inherited properties and managed versions for a workspace `pom.xml`.
    pub fn resolve_parent_and_boms(
        &mut self,
        parent: Option<(&str, &str, &str)>,
        bom_imports: &[(&str, &str, &str)],
    ) -> (HashMap<String, String>, HashMap<(String, String), String>) {
        let mut props = HashMap::new();
        let mut managed = HashMap::new();
        if let Some((pg, pa, pv)) = parent {
            if let Some(eff) = self.resolve_effective_pom(pg, pa, pv) {
                props.extend(eff.properties);
                managed.extend(eff.managed_versions);
            }
        }
        for (bg, ba, bv) in bom_imports {
            if let Some(eff) = self.resolve_effective_pom(bg, ba, bv) {
                for (k, v) in eff.managed_versions {
                    managed.entry(k).or_insert(v);
                }
            }
        }
        (props, managed)
    }

    /// BFS ("nearest definition wins") transitive expansion from direct dependencies.
    /// Skips `test`, `provided`, `import`, and `optional=true` transitive edges.
    pub fn expand_transitive_deps(
        &mut self,
        seeds: &[SeedDep],
        managed_overrides: &HashMap<(String, String), String>,
    ) -> Vec<ResolvedTransitiveDep> {
        let mut selected: HashMap<(String, String), String> = HashMap::new();
        let mut queue: VecDeque<SeedDep> = VecDeque::new();
        let mut expanded: HashSet<(String, String, String)> = HashSet::new();
        let mut direct_keys: HashSet<(String, String)> = HashSet::new();

        for seed in seeds {
            if let Some(clean_ver) = normalize_pinned_version(&seed.version) {
                let ga = (seed.group_id.clone(), seed.artifact_id.clone());
                direct_keys.insert(ga.clone());
                selected.entry(ga).or_insert_with(|| clean_ver.clone());
                queue.push_back(SeedDep {
                    group_id: seed.group_id.clone(),
                    artifact_id: seed.artifact_id.clone(),
                    version: clean_ver,
                    exclusions: seed.exclusions.clone(),
                });
            }
        }

        while let Some(cur) = queue.pop_front() {
            let (g, a, v, exclusions) =
                (cur.group_id, cur.artifact_id, cur.version, cur.exclusions);
            if !expanded.insert((g.clone(), a.clone(), v.clone())) {
                continue;
            }
            let Some(eff) = self.resolve_effective_pom(&g, &a, &v) else {
                continue;
            };
            for dep in eff.dependencies {
                if dep.optional {
                    continue;
                }
                if let Some(scope) = dep.scope.as_deref() {
                    if !matches!(scope.to_ascii_lowercase().as_str(), "compile" | "runtime") {
                        continue;
                    }
                }
                if is_excluded(&dep.group_id, &dep.artifact_id, &exclusions) {
                    continue;
                }
                let ga = (dep.group_id.clone(), dep.artifact_id.clone());
                if selected.contains_key(&ga) {
                    continue;
                }
                let raw_ver = managed_overrides
                    .get(&ga)
                    .map(String::as_str)
                    .or(dep.version.as_deref());
                let Some(ver) = raw_ver.and_then(normalize_pinned_version) else {
                    continue;
                };
                selected.insert(ga, ver.clone());
                let mut next_exclusions = exclusions.clone();
                next_exclusions.extend(dep.exclusions);
                queue.push_back(SeedDep {
                    group_id: dep.group_id,
                    artifact_id: dep.artifact_id,
                    version: ver,
                    exclusions: next_exclusions,
                });
            }
        }

        let mut out: Vec<ResolvedTransitiveDep> = selected
            .into_iter()
            .filter(|(ga, _)| !direct_keys.contains(ga))
            .map(|((group_id, artifact_id), version)| ResolvedTransitiveDep {
                group_id,
                artifact_id,
                version,
            })
            .collect();
        out.sort_by(|a, b| {
            (&a.group_id, &a.artifact_id, &a.version).cmp(&(
                &b.group_id,
                &b.artifact_id,
                &b.version,
            ))
        });
        out
    }
}

fn is_excluded(group: &str, artifact: &str, exclusions: &HashSet<(String, String)>) -> bool {
    exclusions.contains(&(group.to_string(), artifact.to_string()))
        || exclusions.contains(&(group.to_string(), "*".to_string()))
        || exclusions.contains(&("*".to_string(), artifact.to_string()))
        || exclusions.contains(&("*".to_string(), "*".to_string()))
}

fn normalize_pinned_version(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.contains('$') {
        return None;
    }
    if trimmed.starts_with('[') && trimmed.ends_with(']') && !trimmed.contains(',') {
        let inner = trimmed[1..trimmed.len() - 1].trim();
        return (!inner.is_empty()).then(|| inner.to_string());
    }
    if trimmed.starts_with('[') || trimmed.starts_with('(') {
        return None;
    }
    Some(trimmed.to_string())
}

fn interpolate(input: &str, props: &HashMap<String, String>) -> String {
    let mut resolved = input.trim().to_string();
    for _ in 0..6 {
        let mut changed = false;
        let snapshot = resolved.clone();
        for cap in POM_PROP_RE.captures_iter(&snapshot) {
            if let Some(val) = props.get(&cap[1]) {
                resolved = resolved.replace(&cap[0], val);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    resolved
}

fn node_tag<'a>(n: Node<'a>, text: &'a str) -> &'a str {
    let mut c = n.walk();
    for child in n.named_children(&mut c) {
        if child.kind() == "STag" {
            let mut sc = child.walk();
            for name in child.named_children(&mut sc) {
                if name.kind() == "Name" {
                    return name.utf8_text(text.as_bytes()).unwrap_or("");
                }
            }
        }
    }
    ""
}

fn child_elements<'a>(n: Node<'a>) -> Vec<Node<'a>> {
    let mut out = Vec::new();
    let mut c = n.walk();
    for content in n.named_children(&mut c).filter(|x| x.kind() == "content") {
        let mut cc = content.walk();
        for elem in content.named_children(&mut cc) {
            if elem.kind() == "element" {
                out.push(elem);
            }
        }
    }
    out
}

fn element_text(n: Node<'_>, text: &str) -> String {
    let mut c = n.walk();
    for content in n.named_children(&mut c).filter(|x| x.kind() == "content") {
        if let Ok(raw) = content.utf8_text(text.as_bytes()) {
            return raw.trim().to_string();
        }
    }
    String::new()
}

fn child_text(n: Node<'_>, key: &str, text: &str) -> Option<String> {
    for child in child_elements(n) {
        if node_tag(child, text) == key {
            let val = element_text(child, text);
            if !val.is_empty() {
                return Some(val);
            }
        }
    }
    None
}

fn parse_dep_node(n: Node<'_>, text: &str) -> Option<PomDep> {
    let group_id = child_text(n, "groupId", text)?;
    let artifact_id = child_text(n, "artifactId", text)?;
    let version = child_text(n, "version", text);
    let scope = child_text(n, "scope", text);
    let dep_type = child_text(n, "type", text);
    let optional = child_text(n, "optional", text).is_some_and(|v| v.eq_ignore_ascii_case("true"));
    let mut exclusions = HashSet::new();
    for child in child_elements(n) {
        if node_tag(child, text) == "exclusions" {
            for ex in child_elements(child) {
                if node_tag(ex, text) == "exclusion" {
                    if let (Some(eg), Some(ea)) = (
                        child_text(ex, "groupId", text),
                        child_text(ex, "artifactId", text),
                    ) {
                        exclusions.insert((eg, ea));
                    }
                }
            }
        }
    }
    Some(PomDep {
        group_id,
        artifact_id,
        version,
        scope,
        dep_type,
        optional,
        exclusions,
    })
}

pub fn parse_pom_xml(text: &str) -> Option<ParsedPom> {
    let tree = get_tree(text, &get_tree_sitter_xml())?;
    let root_doc = tree.root_node();
    let mut c = root_doc.walk();
    let project_node = root_doc
        .named_children(&mut c)
        .find(|n| n.kind() == "element" && node_tag(*n, text) == "project")?;

    let mut pom = ParsedPom::default();
    for child in child_elements(project_node) {
        match node_tag(child, text) {
            "groupId" => pom.group_id = Some(element_text(child, text)),
            "artifactId" => pom.artifact_id = Some(element_text(child, text)),
            "version" => pom.version = Some(element_text(child, text)),
            "parent" => {
                if let (Some(pg), Some(pa), Some(pv)) = (
                    child_text(child, "groupId", text),
                    child_text(child, "artifactId", text),
                    child_text(child, "version", text),
                ) {
                    pom.parent = Some((pg, pa, pv));
                }
            }
            "properties" => {
                for prop in child_elements(child) {
                    let k = node_tag(prop, text);
                    let v = element_text(prop, text);
                    if !k.is_empty() && !v.is_empty() {
                        pom.properties.insert(k.to_string(), v);
                    }
                }
            }
            "dependencyManagement" => {
                for dm_child in child_elements(child) {
                    if node_tag(dm_child, text) == "dependencies" {
                        for dep_node in child_elements(dm_child) {
                            if node_tag(dep_node, text) == "dependency" {
                                if let Some(dep) = parse_dep_node(dep_node, text) {
                                    pom.dependency_management.push(dep);
                                }
                            }
                        }
                    }
                }
            }
            "dependencies" => {
                for dep_node in child_elements(child) {
                    if node_tag(dep_node, text) == "dependency" {
                        if let Some(dep) = parse_dep_node(dep_node, text) {
                            pom.dependencies.push(dep);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Some(pom)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_parent_bom_exclusions_and_transitive_m2_and_gradle_poms() {
        let temp_root = std::env::temp_dir().join(format!(
            "sbom_pom_cache_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let m2 = temp_root.join("m2");
        let gradle = temp_root.join("gradle");

        // Parent POM in .m2
        let parent_dir = m2.join("com/example/parent-pom/1.0.0");
        fs::create_dir_all(&parent_dir).unwrap();
        fs::write(
            parent_dir.join("parent-pom-1.0.0.pom"),
            r#"<project>
                <groupId>com.example</groupId>
                <artifactId>parent-pom</artifactId>
                <version>1.0.0</version>
                <properties><lib.ver>2.1.0</lib.ver></properties>
                <dependencyManagement>
                    <dependencies>
                        <dependency>
                            <groupId>com.example</groupId>
                            <artifactId>bom-lib</artifactId>
                            <version>3.0.0</version>
                            <type>pom</type>
                            <scope>import</scope>
                        </dependency>
                    </dependencies>
                </dependencyManagement>
            </project>"#,
        )
        .unwrap();

        // BOM POM in .m2
        let bom_dir = m2.join("com/example/bom-lib/3.0.0");
        fs::create_dir_all(&bom_dir).unwrap();
        fs::write(
            bom_dir.join("bom-lib-3.0.0.pom"),
            r#"<project>
                <groupId>com.example</groupId>
                <artifactId>bom-lib</artifactId>
                <version>3.0.0</version>
                <dependencyManagement>
                    <dependencies>
                        <dependency>
                            <groupId>org.sample</groupId>
                            <artifactId>trans-a</artifactId>
                            <version>1.2.3</version>
                        </dependency>
                    </dependencies>
                </dependencyManagement>
            </project>"#,
        )
        .unwrap();

        // Direct lib in .m2
        let direct_dir = m2.join("org/sample/direct-lib/2.1.0");
        fs::create_dir_all(&direct_dir).unwrap();
        fs::write(
            direct_dir.join("direct-lib-2.1.0.pom"),
            r#"<project>
                <groupId>org.sample</groupId>
                <artifactId>direct-lib</artifactId>
                <version>2.1.0</version>
                <dependencies>
                    <dependency>
                        <groupId>org.sample</groupId>
                        <artifactId>trans-a</artifactId>
                        <version>1.0.0</version>
                    </dependency>
                    <dependency>
                        <groupId>org.sample</groupId>
                        <artifactId>excluded-lib</artifactId>
                        <version>1.0.0</version>
                    </dependency>
                    <dependency>
                        <groupId>junit</groupId>
                        <artifactId>junit</artifactId>
                        <version>4.13.2</version>
                        <scope>test</scope>
                    </dependency>
                    <dependency>
                        <groupId>org.sample</groupId>
                        <artifactId>opt-lib</artifactId>
                        <version>1.0.0</version>
                        <optional>true</optional>
                    </dependency>
                </dependencies>
            </project>"#,
        )
        .unwrap();

        // Transitive lib in Gradle cache layout
        let grad_trans_dir = gradle.join("org.sample/trans-a/1.2.3/abc123hash");
        fs::create_dir_all(&grad_trans_dir).unwrap();
        fs::write(
            grad_trans_dir.join("trans-a-1.2.3.pom"),
            r#"<project>
                <groupId>org.sample</groupId>
                <artifactId>trans-a</artifactId>
                <version>1.2.3</version>
                <dependencies>
                    <dependency>
                        <groupId>org.sample</groupId>
                        <artifactId>leaf-b</artifactId>
                        <version>0.9.0</version>
                    </dependency>
                </dependencies>
            </project>"#,
        )
        .unwrap();

        let mut repo = LocalPomRepo::with_roots(Some(m2), Some(gradle));
        let (props, managed) =
            repo.resolve_parent_and_boms(Some(("com.example", "parent-pom", "1.0.0")), &[]);
        assert_eq!(props.get("lib.ver").map(String::as_str), Some("2.1.0"));
        assert_eq!(
            managed
                .get(&("org.sample".to_string(), "trans-a".to_string()))
                .map(String::as_str),
            Some("1.2.3")
        );

        let mut exclusions = HashSet::new();
        exclusions.insert(("org.sample".to_string(), "excluded-lib".to_string()));
        let transitive = repo.expand_transitive_deps(
            &[SeedDep {
                group_id: "org.sample".to_string(),
                artifact_id: "direct-lib".to_string(),
                version: "2.1.0".to_string(),
                exclusions,
            }],
            &managed,
        );

        assert!(transitive.contains(&ResolvedTransitiveDep {
            group_id: "org.sample".to_string(),
            artifact_id: "trans-a".to_string(),
            version: "1.2.3".to_string(),
        }));
        assert!(transitive.contains(&ResolvedTransitiveDep {
            group_id: "org.sample".to_string(),
            artifact_id: "leaf-b".to_string(),
            version: "0.9.0".to_string(),
        }));
        assert!(!transitive.iter().any(|d| d.artifact_id == "excluded-lib"
            || d.artifact_id == "junit"
            || d.artifact_id == "opt-lib"));

        let _ = fs::remove_dir_all(&temp_root);
    }
}
