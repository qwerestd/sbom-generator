use std::fmt::{Display, Formatter};
use std::str::FromStr;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RustScopeFilter {
    #[default]
    Prod,
    All,
    Test,
}

impl RustScopeFilter {
    pub fn includes(self, scope: &str) -> bool {
        match self {
            RustScopeFilter::Prod => matches!(scope, "normal" | "build" | "unknown"),
            RustScopeFilter::All => true,
            RustScopeFilter::Test => scope == "dev",
        }
    }
}

impl FromStr for RustScopeFilter {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "prod" | "production" => Ok(RustScopeFilter::Prod),
            "all" => Ok(RustScopeFilter::All),
            "test" | "dev" => Ok(RustScopeFilter::Test),
            _ => Err(format!(
                "invalid rust scope '{}'; expected prod, all, or test",
                value
            )),
        }
    }
}

pub struct Configuration {
    pub directory: String,
    pub output: String,
    pub use_debug: bool,
    pub dynamic: bool,
    pub rust_scope: RustScopeFilter,
}

impl Configuration {
    pub fn print_configuration(&self) {
        println!("Configuration");
        println!("=============");
        println!("Directory: {}", self.directory);
        println!("Output:    {}", self.output);
        println!("Debug:     {}", self.use_debug);
        println!("RustScope: {:?}", self.rust_scope);
    }
}

impl Display for Configuration {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "(directory={}, output={}, debug={}, rust_scope={:?})",
            self.directory, self.output, self.use_debug, self.rust_scope
        )
    }
}
