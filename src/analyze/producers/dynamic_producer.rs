use crate::model::configuration::Configuration;
use crate::model::dependency::Dependency;

pub trait DynamicProducer {
    /// 检查该探测器是否适用于当前环境
    fn is_applicable(&self, configuration: &Configuration) -> bool;

    /// 执行动态探测，返回真实的运行时依赖
    fn detect_dependencies(&self, configuration: &Configuration)
        -> anyhow::Result<Vec<Dependency>>;
}
