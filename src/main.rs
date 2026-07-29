use std::env;
use std::path::Path;
use std::process::exit;

use getopts::Options;
use sbom_generator::analyze::sbom_generate::analyze;
use sbom_generator::model::configuration::{Configuration, RustScopeFilter};

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} FILE [options]", program);
    print!("{}", opts.usage(&brief));
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help");
    opts.optopt(
        "i",
        "directory",
        "directory to scan (valid existing directory)",
        "/path/to/code/to/analyze",
    );
    opts.optflag("d", "debug", "use debug mode");

    // 【修改点1】：反转设计逻辑！默认开启动态，新增 -s 供用户强制离线纯静态
    opts.optflag(
        "s",
        "static-only",
        "force static analysis only (disable dynamic detection)",
    );

    opts.optopt(
        "o",
        "output",
        "file to write the results",
        "/path/to/file.sbom",
    );
    opts.optopt(
        "",
        "rust-scope",
        "Rust dependency scope to include: prod, all, or test (default: prod)",
        "prod|all|test",
    );

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            eprintln!("error when parsing arguments: {}", f);
            print_usage(&program, opts);
            exit(1);
        }
    };

    if matches.opt_present("h") {
        print_usage(&program, opts);
        exit(0);
    }

    let directory_to_analyze_option = matches.opt_str("i");
    let output = matches.opt_str("o");

    if directory_to_analyze_option.is_none() {
        eprintln!("missing directory to analyze");
        print_usage(&program, opts);
        exit(1);
    }

    if output.is_none() {
        eprintln!("missing output file");
        print_usage(&program, opts);
        exit(1);
    }

    let directory = directory_to_analyze_option.unwrap();
    let output_path = output.unwrap();
    let rust_scope = match matches
        .opt_str("rust-scope")
        .unwrap_or_else(|| "prod".to_string())
        .parse::<RustScopeFilter>()
    {
        Ok(scope) => scope,
        Err(e) => {
            eprintln!("{}", e);
            print_usage(&program, opts);
            exit(1);
        }
    };

    let directory_path = Path::new(&directory);
    if !directory_path.exists() {
        eprintln!("directory does not exist: {}", directory);
        exit(1);
    }
    if !directory_path.is_dir() {
        eprintln!("path is not a directory: {}", directory);
        exit(1);
    }

    let output_as_path = Path::new(&output_path);
    if output_as_path.is_dir() {
        eprintln!("output path points to a directory: {}", output_path);
        exit(1);
    }

    let enable_dynamic = !matches.opt_present("s");
    let configuration = Configuration {
        directory,
        output: output_path,
        use_debug: matches.opt_present("d"),
        dynamic: enable_dynamic,
        rust_scope,
    };

    if let Err(e) = analyze(&configuration, enable_dynamic) {
        eprintln!("error when generating SBOM: {:#}", e);
        exit(1);
    }
}
