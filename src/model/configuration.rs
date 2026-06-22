use std::fmt::{Display, Formatter};

pub struct Configuration {
    pub directory: String,
    pub output: String,
    pub use_debug: bool,
    pub dynamic: bool,
}

impl Configuration {
    pub fn print_configuration(&self) {
        println!("Configuration");
        println!("=============");
        println!("Directory: {}", self.directory);
        println!("Output:    {}", self.output);
        println!("Debug:     {}", self.use_debug);
    }
}

impl Display for Configuration {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "(directory={}, output={}, debug={})",
            self.directory, self.output, self.use_debug
        )
    }
}
