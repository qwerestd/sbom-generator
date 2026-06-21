use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Executes a [`Command`], returning true if the command finished with exit status 0, otherwise false
fn run<F>(name: &str, mut configure: F) -> bool
where
    F: FnMut(&mut Command) -> &mut Command,
{
    let mut command = Command::new(name);
    let configured = configure(&mut command);
    println!("Running {configured:?}");
    configured
        .status()
        .map(|status| status.success())
        .unwrap_or(false) // 优雅返回错误，交由上层 assert 处理
}

fn main() {
    struct TreeSitterProject {
        /// The directory where we clone the project
        name: String,
        /// The name of the unit we compile
        compilation_unit: String,
        /// The git repository to clone
        repository: String,
        /// The git commit hash that will be passed to `git checkout`
        commit_hash: String,
        /// The directory we use to build the tree-sitter project
        build_dir: PathBuf,
        /// The files to pass to the `cc::Build` instance
        files: Vec<String>,
        /// Whether compilation of this project requires C++ support or not
        cpp: bool,
    }

    fn compile_project(tree_sitter_project: &TreeSitterProject) {
        let dir = &tree_sitter_project.build_dir;
        let files: Vec<PathBuf> = tree_sitter_project
            .files
            .iter()
            .map(|x| dir.join(x))
            .collect();
        let cpp = tree_sitter_project.cpp;
        cc::Build::new()
            .include(dir)
            .files(files)
            .warnings(false)
            .cpp(cpp)
            .compile(tree_sitter_project.compilation_unit.as_str());
    }

    let tree_sitter_projects: Vec<TreeSitterProject> = vec![
        TreeSitterProject {
            name: "tree-sitter-xml".to_string(),
            compilation_unit: "tree-sitter-xml".to_string(),
            repository: "https://github.com/tree-sitter-grammars/tree-sitter-xml.git".to_string(),
            build_dir: "xml/src".into(),
            commit_hash: "809266ed1694d64dedc168a18893cc254e3edf7e".to_string(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-json".to_string(),
            compilation_unit: "tree-sitter-json".to_string(),
            repository: "https://github.com/tree-sitter/tree-sitter-json.git".to_string(),
            commit_hash: "3fef30de8aee74600f25ec2e319b62a1a870d51e".to_string(),
            build_dir: "src".into(),
            files: vec!["parser.c".to_string()],
            cpp: false,
        },
        TreeSitterProject {
            name: "tree-sitter-yaml".to_string(),
            compilation_unit: "tree-sitter-yaml-parser".to_string(),
            repository: "https://github.com/tree-sitter-grammars/tree-sitter-yaml.git".to_string(),
            build_dir: "src".into(),
            commit_hash: "ee093118211be521742b9866a8ed8ce6d87c7a94".to_string(),
            files: vec!["parser.c".to_string(), "scanner.c".to_string()],
            cpp: false,
        },
    ];

    let base_dir = env::current_dir().unwrap();
    for proj in &tree_sitter_projects {
        let project_dir = format!(".vendor/{}@{}", &proj.name, &proj.commit_hash);
        let project_path = Path::new(&project_dir);

        if !project_path.exists() {
            // 【修改 1】使用纯 Rust 跨平台创建多级目录，代替过期的 "mkdir" "-p"
            std::fs::create_dir_all(project_path).unwrap_or_else(|e| {
                panic!("failed to create directory {project_dir}: {e}");
            });

            env::set_current_dir(project_path).unwrap();
            assert!(run("git", |cmd| { cmd.args(["init", "-q"]) }));
            assert!(run("git", |cmd| {
                cmd.args(["remote", "add", "origin", &proj.repository])
            }));
            assert!({
                let mut ok = false;
                let mut retry_time = std::time::Duration::from_secs(1);
                for _ in 0..5 {
                    ok = run("git", |cmd| {
                        cmd.args(["fetch", "-q", "--depth", "1", "origin", &proj.commit_hash])
                    });
                    if ok {
                        break;
                    }
                    std::thread::sleep(retry_time);
                    retry_time *= 2; // 指数退避策略
                }
                ok
            });
            assert!(run("git", |cmd| {
                cmd.args(["checkout", "-q", "FETCH_HEAD"])
            }));

            // 【修改 2】使用纯 Rust 跨平台安全清空 .git 缓存文件夹，代替过期的 "rm" "-rf"
            let git_dir = Path::new(".git");
            if git_dir.exists() {
                std::fs::remove_dir_all(git_dir).unwrap_or_else(|e| {
                    panic!("failed to remove .git registry: {e}");
                });
            }

            env::set_current_dir(&base_dir).unwrap();
        }
        env::set_current_dir(&project_dir).unwrap();
        compile_project(proj);
        env::set_current_dir(&base_dir).unwrap();
    }
}
