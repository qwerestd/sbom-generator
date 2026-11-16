use crate::model::configuration::Configuration;
use crate::model::dependency::Dependency;

pub trait DynamicProducer: Sync {
    /// 检查该探测器是否适用于当前环境
    fn is_applicable(&self, configuration: &Configuration) -> bool;

    /// Query package-manager evidence. Resolution and installed metadata do not
    /// establish that a component was loaded at runtime. Partial results carry
    /// sbom:analysis:status=partial and must retain diagnostics.
    fn detect_dependencies(&self, configuration: &Configuration)
        -> anyhow::Result<Vec<Dependency>>;
}
