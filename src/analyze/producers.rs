pub mod cargo;
pub mod dynamic_producer;
pub mod go;
pub mod gradle;
pub mod maven;
pub mod npm;
pub mod producer;
pub mod pypi;

// 向下兼容重导出，确保外部或存量调用路径无缝衔接
pub use cargo::cargo_lock_producer as cargo_producer;
pub use go::go_producer;
pub use gradle::gradle_producer;
pub use npm::npm_lock_producer;
pub use npm::npm_producer;
pub use pypi::pypi_producer;

pub mod dynamic {
    pub use super::cargo::cargo_dynamic;
    pub use super::go::go_dynamic;
    pub use super::gradle::gradle_dynamic;
    pub use super::maven::maven_dynamic;
    pub use super::npm::npm_dynamic;
    pub use super::pypi::pypi_dynamic;
}
