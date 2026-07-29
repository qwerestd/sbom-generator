use std::collections::BTreeSet;
use std::path::PathBuf;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PythonProjectContext {
    Normal,
    Tests,
    Fixtures,
    Examples,
    Vendor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PythonMetadataKind {
    UvLock,
    PyprojectToml,
    RequirementsTxt,
    PoetryLock,
    PipfileLock,
    SetupPy,
    SetupCfg,
    CondaLock,
}

impl PythonMetadataKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            PythonMetadataKind::UvLock => "uv.lock",
            PythonMetadataKind::PyprojectToml => "pyproject.toml",
            PythonMetadataKind::RequirementsTxt => "requirements",
            PythonMetadataKind::PoetryLock => "poetry.lock",
            PythonMetadataKind::PipfileLock => "Pipfile.lock",
            PythonMetadataKind::SetupPy => "setup.py",
            PythonMetadataKind::SetupCfg => "setup.cfg",
            PythonMetadataKind::CondaLock => "conda-lock",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum PythonSourcePriority {
    ResolvedLockfile = 1,
    DynamicEnvironment = 2,
    DeclaredManifest = 3,
    SourceImport = 4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PythonMetadataSource {
    pub kind: PythonMetadataKind,
    pub path: PathBuf,
    pub priority: PythonSourcePriority,
    pub is_lockfile: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PythonProjectRoot {
    pub root_path: PathBuf,
    pub project_name: Option<String>,
    pub context: PythonProjectContext,
    pub sources: Vec<PythonMetadataSource>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum PythonScope {
    Prod,
    Build,
    Optional,
    Dev,
    Test,
    Unknown,
}

impl PythonScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            PythonScope::Prod => "prod",
            PythonScope::Build => "build",
            PythonScope::Optional => "optional",
            PythonScope::Dev => "dev",
            PythonScope::Test => "test",
            PythonScope::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PythonEvidenceKind {
    LockfileExact,
    LockfileDependencyEdge,
    ManifestExact,
    ManifestRange,
    OptionalDependencyGroup,
    RequirementsDirect,
    RequirementsInclude,
    RequirementsConstraint,
    FilenameHeuristic,
    DynamicEnvironment,
    ImportInference,
}

impl PythonEvidenceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            PythonEvidenceKind::LockfileExact => "lockfile-exact",
            PythonEvidenceKind::LockfileDependencyEdge => "lockfile-dependency-edge",
            PythonEvidenceKind::ManifestExact => "manifest-exact",
            PythonEvidenceKind::ManifestRange => "manifest-range",
            PythonEvidenceKind::OptionalDependencyGroup => "optional-dependency-group",
            PythonEvidenceKind::RequirementsDirect => "requirements-direct",
            PythonEvidenceKind::RequirementsInclude => "requirements-include",
            PythonEvidenceKind::RequirementsConstraint => "requirements-constraint",
            PythonEvidenceKind::FilenameHeuristic => "filename-heuristic",
            PythonEvidenceKind::DynamicEnvironment => "dynamic-environment",
            PythonEvidenceKind::ImportInference => "import-inference",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum EvidenceConfidence {
    High,
    Medium,
    Low,
}

impl EvidenceConfidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            EvidenceConfidence::High => "high",
            EvidenceConfidence::Medium => "medium",
            EvidenceConfidence::Low => "low",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PythonEvidence {
    pub kind: PythonEvidenceKind,
    pub source_path: PathBuf,
    pub project_root: PathBuf,
    pub confidence: EvidenceConfidence,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PythonDependencyRef {
    pub canonical_name: String,
    pub version: Option<String>,
}

#[derive(Clone, Debug)]
pub struct PythonDependencyEdge {
    pub target: PythonDependencyRef,
    pub marker: Option<String>,
    pub seed_scope: Option<PythonScope>,
    pub evidence: Vec<PythonEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DependencyRelationship {
    Direct,
    Transitive,
    Unknown,
}

impl DependencyRelationship {
    pub fn as_str(&self) -> &'static str {
        match self {
            DependencyRelationship::Direct => "direct",
            DependencyRelationship::Transitive => "transitive",
            DependencyRelationship::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActivationStatus {
    Unconditional,
    Conditional,
    Unknown,
}

impl ActivationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ActivationStatus::Unconditional => "unconditional",
            ActivationStatus::Conditional => "conditional",
            ActivationStatus::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PythonScopeEvidence {
    pub scope: PythonScope,
    pub project_root: PathBuf,
    pub seed_package: String,
    pub source_path: PathBuf,
    pub source_kind: PythonMetadataKind,
}

#[derive(Clone, Debug)]
pub struct PythonDependency {
    pub canonical_name: String,
    pub display_name: String,
    pub resolved_version: Option<String>,
    pub declared_version: Option<String>,
    pub scopes: BTreeSet<PythonScope>,
    pub source_kind: PythonMetadataKind,
    pub project_root: PathBuf,
    pub source_path: PathBuf,
    pub is_project_package: bool,
    pub is_editable: bool,
    pub is_local_path: bool,
    pub relationship: DependencyRelationship,
    pub activation: ActivationStatus,
    pub markers: BTreeSet<String>,
    pub evidence: Vec<PythonEvidence>,
    pub scope_evidence: Vec<PythonScopeEvidence>,
    pub dependencies: Vec<PythonDependencyEdge>,
}

impl PythonDependency {
    pub fn scopes_string(&self) -> String {
        let values: Vec<_> = self
            .scopes
            .iter()
            .filter(|scope| **scope != PythonScope::Unknown)
            .map(PythonScope::as_str)
            .collect();

        if values.is_empty() {
            PythonScope::Unknown.as_str().to_string()
        } else {
            values.join(",")
        }
    }
}

#[derive(Clone, Debug)]
pub struct PythonResolvedProject {
    pub root: PythonProjectRoot,
    pub dependencies: Vec<PythonDependency>,
    pub warnings: Vec<String>,
}
