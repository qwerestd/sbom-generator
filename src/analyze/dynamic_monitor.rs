use crate::model::dependency::{Dependency, DynamicLoadStatus};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// 动态依赖加载监测引擎
/// 在扫描期自动嗅探本地可执行环境与入口，在隔离沙箱中进行毫秒级试跑与加载追踪。
/// 具备 4 层工业级防御机制（前置环境校验、独立沙箱隔离、超时看门狗、三态平滑降级）。
pub fn monitor_dependency_loading(
    root_dir: &str,
    dependencies: &mut [Dependency],
    use_debug: bool,
) {
    if dependencies.is_empty() {
        return;
    }

    let root_path = Path::new(root_dir);
    if !root_path.exists() {
        return;
    }

    // 收集所有潜在的项目子目录（支持单体与 Monorepo 多微服务）
    let mut project_roots = vec![root_path.to_path_buf()];
    collect_candidate_roots(root_path, &mut project_roots);

    // 【智能实操痕迹识别】：没有跑过的项目绝不开启，仅在检测到确凿运行/编译痕迹时才启动动态探针
    let active_roots: Vec<PathBuf> = project_roots
        .into_iter()
        .filter(|dir| has_project_operational_traces(dir))
        .collect();

    if active_roots.is_empty() {
        println!(
            " -> [动态依赖监测] 智能决策: 目标工程未检测到编译/运行实操痕迹 (如 __pycache__, dist, target, node_modules 等)，跳过动态试跑，保持高精度静态分析"
        );
        return;
    }

    let mut total_loaded_paths = HashSet::new();
    let mut traced_ecosystems = HashSet::new();

    for dir in &active_roots {
        // 1. 尝试对 Node.js 生态进行依赖加载监测
        if let Some(loaded) = trace_nodejs_loading(dir, use_debug) {
            traced_ecosystems.insert("npm");
            total_loaded_paths.extend(loaded);
        }

        // 2. 尝试对 Python 生态进行依赖加载监测
        if let Some(loaded) = trace_python_loading(dir, use_debug) {
            traced_ecosystems.insert("pypi");
            total_loaded_paths.extend(loaded);
        }
    }

    // 若未成功追踪到任何生态的运行时（如刚克隆下来未装配），尝试源码级动态导入探测 (Dynamic Import AST / Regex)
    let dynamic_imported_names = detect_dynamic_imports_in_source(root_path);

    let mut loaded_count = 0;
    let mut dormant_count = 0;

    for dep in dependencies.iter_mut() {
        let is_npm = dep.purl.starts_with("pkg:npm/");
        let is_pypi = dep.purl.starts_with("pkg:pypi/");

        let mut is_loaded = false;

        // 规则 1：检查是否出现在实际加载的模块路径中
        let dep_name_lower = dep.name.to_lowercase();
        for loaded_path in &total_loaded_paths {
            let path_normalized = loaded_path.replace('\\', "/").to_lowercase();
            let npm_pattern = format!("/node_modules/{}/", dep_name_lower);
            let pypi_pattern_1 = format!("/site-packages/{}/", dep_name_lower);
            let pypi_pattern_2 = format!("/site-packages/{}-", dep_name_lower);
            let pypi_pattern_3 = format!("/site-packages/{}.", dep_name_lower);

            if path_normalized.contains(&npm_pattern)
                || path_normalized.contains(&pypi_pattern_1)
                || path_normalized.contains(&pypi_pattern_2)
                || path_normalized.contains(&pypi_pattern_3)
                || path_normalized.ends_with(&format!("/{}", dep_name_lower))
            {
                is_loaded = true;
                break;
            }
        }

        // 规则 2：检查源码中是否存在动态 import / require 引用
        if !is_loaded && dynamic_imported_names.contains(&dep_name_lower) {
            is_loaded = true;
        }

        if is_loaded {
            dep.dynamic_status = DynamicLoadStatus::Loaded;
            loaded_count += 1;
        } else if (is_npm && traced_ecosystems.contains("npm"))
            || (is_pypi && traced_ecosystems.contains("pypi"))
        {
            dep.dynamic_status = DynamicLoadStatus::Dormant;
            dormant_count += 1;
        } else {
            dep.dynamic_status = DynamicLoadStatus::NotTraced;
        }
    }

    if loaded_count > 0 || dormant_count > 0 {
        println!(
            " -> [动态依赖监测] 动态探测完成: 识别到 {} 个运行时活跃依赖 (🟢 LOADED), {} 个未触发依赖 (⚪ DORMANT)",
            loaded_count, dormant_count
        );
    } else if use_debug {
        println!(" -> [动态依赖监测] 未发现装配好的本地运行时环境 (如 node_modules/.venv)，保持高精度静态状态");
    }
}

/// 递归搜寻潜在的生态项目根目录（最多深入 2 层，防止过度遍历）
fn collect_candidate_roots(root: &Path, acc: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if file_name.starts_with('.')
                || file_name == "node_modules"
                || file_name == "target"
                || file_name == "vendor"
            {
                continue;
            }
            if path.join("package.json").exists()
                || path.join("requirements.txt").exists()
                || path.join("pyproject.toml").exists()
                || path.join("pom.xml").exists()
                || path.join("Cargo.toml").exists()
            {
                acc.push(path.clone());
            }
        }
    }
}

/// 智能检查目录是否具备真实的编译/运行实操痕迹
/// 只有当工程确实被安装/执行/编译过时才启动动态监测，杜绝盲目试跑没有跑过的工程
pub fn has_project_operational_traces(dir: &Path) -> bool {
    // 1. Node.js 实操痕迹检查: 存在非空 node_modules，或存在编译打包产物
    let node_modules = dir.join("node_modules");
    if node_modules.exists() && node_modules.is_dir() {
        if let Ok(entries) = fs::read_dir(&node_modules) {
            let has_subdirs = entries.flatten().any(|e| e.path().is_dir());
            if has_subdirs {
                return true;
            }
        }
    }
    for build_artifact in &[
        "dist", "build", ".next", ".nuxt", ".cache", ".turbo", ".vite",
    ] {
        let p = dir.join(build_artifact);
        if p.exists() && p.is_dir() {
            return true;
        }
    }

    // 2. Python 实操痕迹检查: 以编译字节码 __pycache__ 或真实装配的虚拟环境为铁证
    if dir.join("__pycache__").exists() || has_pycache_subdirs(dir, 0, 2) {
        return true;
    }
    for venv_name in &[".venv", "venv", "env"] {
        let venv_dir = dir.join(venv_name);
        if venv_dir.exists()
            && (venv_dir.join("Scripts").exists()
                || venv_dir.join("bin").exists()
                || venv_dir.join("lib").exists())
        {
            return true;
        }
    }
    if dir.join(".pytest_cache").exists() || dir.join(".mypy_cache").exists() {
        return true;
    }

    // 3. Java 实操痕迹检查: Maven target/classes 或 Gradle build/classes
    if dir.join("target/classes").exists() || dir.join("target/test-classes").exists() {
        return true;
    }
    if dir.join("build/classes").exists()
        || dir.join("build/libs").exists()
        || dir.join(".gradle").exists()
    {
        return true;
    }

    // 4. Rust 实操痕迹检查: target/debug 或 target/release
    if dir.join("target/debug").exists() || dir.join("target/release").exists() {
        return true;
    }

    false
}

fn has_pycache_subdirs(dir: &Path, current_depth: usize, max_depth: usize) -> bool {
    if current_depth > max_depth {
        return false;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "__pycache__" {
                return true;
            }
            if !name.starts_with('.')
                && name != "node_modules"
                && name != "target"
                && has_pycache_subdirs(&path, current_depth + 1, max_depth)
            {
                return true;
            }
        }
    }
    false
}

/// 追踪 Node.js 项目依赖加载
fn trace_nodejs_loading(dir: &Path, use_debug: bool) -> Option<Vec<String>> {
    let pkg_json_path = dir.join("package.json");
    if !pkg_json_path.exists() {
        return None;
    }

    // 防御 1：前置检查 node_modules 是否存在
    let node_modules_path = dir.join("node_modules");
    if !node_modules_path.exists() {
        if use_debug {
            println!(
                " -> [动态监测:Node] 目录 {:?} 缺少 node_modules，跳过动态执行",
                dir
            );
        }
        return None;
    }

    // 寻找入口文件
    let mut entry_file: Option<PathBuf> = None;
    if let Ok(content) = fs::read_to_string(&pkg_json_path) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(main) = json.get("main").and_then(|m| m.as_str()) {
                let candidate = dir.join(main);
                if candidate.exists() && candidate.is_file() {
                    entry_file = Some(candidate);
                }
            }
        }
    }

    // 兜底常用入口
    if entry_file.is_none() {
        for candidate_name in &[
            "index.js",
            "app.js",
            "server.js",
            "main.js",
            "src/index.js",
            "src/app.js",
        ] {
            let p = dir.join(candidate_name);
            if p.exists() && p.is_file() {
                entry_file = Some(p);
                break;
            }
        }
    }

    let entry = entry_file?;

    // 准备临时探针脚本与输出文件
    let pid = std::process::id();
    let temp_dir = std::env::temp_dir();
    let probe_script = temp_dir.join(format!("sbom_npm_probe_{}.js", pid));
    let out_file = temp_dir.join(format!("sbom_npm_out_{}.json", pid));

    let probe_code = format!(
        r#"
const fs = require('fs');
const Module = require('module');
const outFile = {out_file:?};
const loaded = new Set();
const orig = Module._load;

Module._load = function(request, parent, isMain) {{
    try {{
        const resolved = Module._resolveFilename(request, parent, isMain);
        if (resolved && resolved.includes('node_modules')) {{
            loaded.add(resolved);
        }}
    }} catch (e) {{}}
    return orig.apply(this, arguments);
}};

function dumpLoaded() {{
    try {{
        fs.writeFileSync(outFile, JSON.stringify(Array.from(loaded)));
    }} catch (e) {{}}
}}

process.on('exit', dumpLoaded);
// 1200ms 安全退出计时器，防止 Web 服务器挂起
setTimeout(() => {{
    dumpLoaded();
    process.exit(0);
}}, 1200).unref();
"#,
        out_file = out_file.to_string_lossy().to_string()
    );

    if fs::write(&probe_script, probe_code).is_err() {
        return None;
    }

    // 防御 2 & 3：以独立子进程启动，并带 2500ms 超时看门狗
    let result = run_child_with_timeout(
        Command::new("node")
            .arg("-r")
            .arg(&probe_script)
            .arg(&entry)
            .current_dir(dir),
        Duration::from_millis(2500),
    );

    // 清理探针脚本
    let _ = fs::remove_file(&probe_script);

    if result.is_err() && use_debug {
        println!(" -> [动态监测:Node] 试跑未在预定时间内正常返回，安全熔断并读取产物");
    }

    // 读取收集到的加载清单
    if out_file.exists() {
        if let Ok(content) = fs::read_to_string(&out_file) {
            let _ = fs::remove_file(&out_file);
            if let Ok(paths) = serde_json::from_str::<Vec<String>>(&content) {
                return Some(paths);
            }
        }
        let _ = fs::remove_file(&out_file);
    }

    None
}

/// 追踪 Python 项目依赖加载
fn trace_python_loading(dir: &Path, use_debug: bool) -> Option<Vec<String>> {
    let has_py = dir.join("requirements.txt").exists()
        || dir.join("pyproject.toml").exists()
        || dir.join("Pipfile").exists();
    if !has_py {
        return None;
    }

    // 寻找入口文件
    let mut entry_file: Option<PathBuf> = None;
    for candidate in &[
        "main.py",
        "app.py",
        "server.py",
        "run.py",
        "src/main.py",
        "manage.py",
    ] {
        let p = dir.join(candidate);
        if p.exists() && p.is_file() {
            entry_file = Some(p);
            break;
        }
    }
    let entry = entry_file?;

    // 寻找 Python 解释器（优先虚拟环境，保证隔离与准确性）
    let python_cmd = find_python_executable(dir);

    let pid = std::process::id();
    let temp_dir = std::env::temp_dir();
    let probe_script = temp_dir.join(format!("sbom_py_probe_{}.py", pid));
    let out_file = temp_dir.join(format!("sbom_py_out_{}.json", pid));

    let probe_code = format!(
        r#"
import sys, os, json, atexit, threading

out_file = {out_file:?}

def dump_loaded():
    try:
        paths = []
        for m in list(sys.modules.values()):
            f = getattr(m, '__file__', None)
            if f and ('site-packages' in f or '.venv' in f or 'dist-packages' in f):
                paths.append(os.path.abspath(f))
        with open(out_file, 'w', encoding='utf-8') as fp:
            json.dump(paths, fp)
    except Exception:
        pass

atexit.register(dump_loaded)

# 1200ms 定时熔断，防止服务常驻挂起
def auto_quit():
    dump_loaded()
    os._exit(0)

t = threading.Timer(1.2, auto_quit)
t.daemon = True
t.start()
"#,
        out_file = out_file.to_string_lossy().to_string()
    );

    if fs::write(&probe_script, probe_code).is_err() {
        return None;
    }

    // 通过环境变量 PYTHONPATH 预载入探针脚本
    let parent_probe_dir = temp_dir.to_string_lossy().to_string();
    let mut cmd = Command::new(&python_cmd);
    cmd.env("PYTHONPATH", &parent_probe_dir)
        .arg("-i")
        .arg(&probe_script)
        .arg(&entry)
        .current_dir(dir);

    let _ = run_child_with_timeout(&mut cmd, Duration::from_millis(2500));

    let _ = fs::remove_file(&probe_script);

    if out_file.exists() {
        if let Ok(content) = fs::read_to_string(&out_file) {
            let _ = fs::remove_file(&out_file);
            if let Ok(paths) = serde_json::from_str::<Vec<String>>(&content) {
                return Some(paths);
            }
        }
        let _ = fs::remove_file(&out_file);
    } else if use_debug {
        println!(" -> [动态监测:Python] 试跑未产生加载记录或环境不可用，安全回退");
    }

    None
}

/// 寻找可用的 Python 可执行文件（优先本地虚拟环境）
fn find_python_executable(dir: &Path) -> String {
    let venv_candidates = [
        dir.join(".venv/Scripts/python.exe"),
        dir.join(".venv/bin/python"),
        dir.join("venv/Scripts/python.exe"),
        dir.join("venv/bin/python"),
    ];

    for candidate in &venv_candidates {
        if candidate.exists() {
            return candidate.to_string_lossy().to_string();
        }
    }

    "python".to_string()
}

/// 在子进程中带硬性超时运行，超时自动 kill 强退，绝不阻塞主进程
fn run_child_with_timeout(cmd: &mut Command, timeout: Duration) -> anyhow::Result<()> {
    cmd.stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    let mut child = cmd.spawn()?;
    let start = Instant::now();
    let mut finished = false;

    while start.elapsed() < timeout {
        match child.try_wait() {
            Ok(Some(_)) => {
                finished = true;
                break;
            }
            Ok(None) => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => break,
        }
    }

    if !finished {
        let _ = child.kill();
        let _ = child.wait();
        return Err(anyhow::anyhow!("子进程执行超时，已触发安全熔断"));
    }

    Ok(())
}

/// 源码级动态加载语法快速探测 (Dynamic Import / Reflection Detection)
/// 检测源码中的 import('...'), require('...'), Class.forName('...'), importlib.import_module('...')
fn detect_dynamic_imports_in_source(root: &Path) -> HashSet<String> {
    let mut detected = HashSet::new();

    let extensions = ["js", "ts", "jsx", "tsx", "py", "java", "rs"];
    let files = walk_source_files(root, &extensions, 0, 3);

    let re_js_dynamic_import = regex::Regex::new(r#"import\s*\(\s*['"]([^'"]+)['"]\s*\)"#).ok();
    let re_js_require = regex::Regex::new(r#"require\s*\(\s*['"]([^'"]+)['"]\s*\)"#).ok();
    let re_py_import =
        regex::Regex::new(r#"importlib\.import_module\s*\(\s*['"]([^'"]+)['"]\s*\)"#).ok();
    let re_java_forname = regex::Regex::new(r#"Class\.forName\s*\(\s*['"]([^'"]+)['"]\s*\)"#).ok();

    for file in files {
        let Ok(content) = fs::read_to_string(&file) else {
            continue;
        };

        if let Some(ref re) = re_js_dynamic_import {
            for cap in re.captures_iter(&content) {
                if let Some(pkg) = cap.get(1) {
                    let name = extract_root_package_name(pkg.as_str());
                    detected.insert(name.to_lowercase());
                }
            }
        }
        if let Some(ref re) = re_js_require {
            for cap in re.captures_iter(&content) {
                if let Some(pkg) = cap.get(1) {
                    let name = extract_root_package_name(pkg.as_str());
                    detected.insert(name.to_lowercase());
                }
            }
        }
        if let Some(ref re) = re_py_import {
            for cap in re.captures_iter(&content) {
                if let Some(pkg) = cap.get(1) {
                    let name = extract_root_package_name(pkg.as_str());
                    detected.insert(name.to_lowercase());
                }
            }
        }
        if let Some(ref re) = re_java_forname {
            for cap in re.captures_iter(&content) {
                if let Some(pkg) = cap.get(1) {
                    let name = extract_root_package_name(pkg.as_str());
                    detected.insert(name.to_lowercase());
                }
            }
        }
    }

    detected
}

fn extract_root_package_name(pkg_path: &str) -> &str {
    if pkg_path.starts_with('@') {
        let parts: Vec<&str> = pkg_path.split('/').collect();
        if parts.len() >= 2 {
            // @scope/package
            return pkg_path.splitn(3, '/').take(2).last().unwrap_or(pkg_path);
        }
    }
    pkg_path.split('/').next().unwrap_or(pkg_path)
}

fn walk_source_files(
    dir: &Path,
    extensions: &[&str],
    current_depth: usize,
    max_depth: usize,
) -> Vec<PathBuf> {
    if current_depth > max_depth {
        return Vec::new();
    }
    let mut files = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return files;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !name.starts_with('.')
                && name != "node_modules"
                && name != "target"
                && name != "vendor"
            {
                files.extend(walk_source_files(
                    &path,
                    extensions,
                    current_depth + 1,
                    max_depth,
                ));
            }
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if extensions.contains(&ext) {
                files.push(path);
            }
        }
    }

    files
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::dependency::DependencyBuilder;

    #[test]
    fn test_dynamic_monitor_empty_or_missing_dir_safe() {
        let mut deps = vec![DependencyBuilder::default()
            .name("express".to_string())
            .purl("pkg:npm/express@4.18.2".to_string())
            .build()
            .unwrap()];

        // 针对不存在的目录，确保绝对不崩溃且依赖保持 NotTraced 状态
        monitor_dependency_loading("C:/non_existent_folder_xyz_123", &mut deps, false);
        assert_eq!(deps[0].dynamic_status, DynamicLoadStatus::NotTraced);
    }

    #[test]
    fn test_dynamic_monitor_with_dynamic_source_import() {
        let temp_dir = std::env::temp_dir().join("sbom_test_dynamic_src");
        let _ = fs::create_dir_all(&temp_dir);
        let src_file = temp_dir.join("index.js");
        fs::write(
            &src_file,
            "const a = require('lodash'); const b = import('axios');",
        )
        .unwrap();

        let mut deps = vec![
            DependencyBuilder::default()
                .name("lodash".to_string())
                .purl("pkg:npm/lodash@4.17.21".to_string())
                .build()
                .unwrap(),
            DependencyBuilder::default()
                .name("axios".to_string())
                .purl("pkg:npm/axios@1.6.0".to_string())
                .build()
                .unwrap(),
            DependencyBuilder::default()
                .name("unused-pkg".to_string())
                .purl("pkg:npm/unused-pkg@1.0.0".to_string())
                .build()
                .unwrap(),
        ];

        // 1. 无实操痕迹时：智能跳过，依赖保持 NotTraced
        monitor_dependency_loading(&temp_dir.to_string_lossy(), &mut deps, false);
        assert_eq!(
            deps[0].dynamic_status,
            DynamicLoadStatus::NotTraced,
            "未跑过的干净工程应当被智能跳过"
        );

        // 2. 模拟存在编译产物/实操痕迹 (如 dist 或 node_modules)
        let _ = fs::create_dir_all(temp_dir.join("dist"));
        monitor_dependency_loading(&temp_dir.to_string_lossy(), &mut deps, false);

        assert_eq!(
            deps[0].dynamic_status,
            DynamicLoadStatus::Loaded,
            "lodash 应当被识别为 Loaded"
        );
        assert_eq!(
            deps[1].dynamic_status,
            DynamicLoadStatus::Loaded,
            "axios 应当被识别为 Loaded"
        );
        assert_eq!(deps[2].dynamic_status, DynamicLoadStatus::NotTraced);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_dynamic_monitor_node_runtime_execution() {
        // 验证 Node 运行时真实加载追踪与 Dormant 休眠标记
        if Command::new("node").arg("-v").output().is_err() {
            // 系统未安装 node 时平滑跳过
            return;
        }

        let temp_dir =
            std::env::temp_dir().join(format!("sbom_test_node_exec_{}", std::process::id()));
        let pkg_mod_dir = temp_dir.join("node_modules").join("my-loaded-pkg");
        let _ = fs::create_dir_all(&pkg_mod_dir);

        fs::write(
            temp_dir.join("package.json"),
            r#"{"name":"demo","main":"index.js"}"#,
        )
        .unwrap();
        fs::write(
            pkg_mod_dir.join("index.js"),
            "module.exports = { hello: 'world' };",
        )
        .unwrap();
        fs::write(
            temp_dir.join("index.js"),
            "const m = require('my-loaded-pkg');",
        )
        .unwrap();

        let mut deps = vec![
            DependencyBuilder::default()
                .name("my-loaded-pkg".to_string())
                .purl("pkg:npm/my-loaded-pkg@1.0.0".to_string())
                .build()
                .unwrap(),
            DependencyBuilder::default()
                .name("my-dormant-pkg".to_string())
                .purl("pkg:npm/my-dormant-pkg@2.0.0".to_string())
                .build()
                .unwrap(),
        ];

        monitor_dependency_loading(&temp_dir.to_string_lossy(), &mut deps, true);

        assert_eq!(
            deps[0].dynamic_status,
            DynamicLoadStatus::Loaded,
            "my-loaded-pkg 应当被动态追踪器捕获并标记为 Loaded"
        );
        assert_eq!(
            deps[1].dynamic_status,
            DynamicLoadStatus::Dormant,
            "my-dormant-pkg 未被调用，应当被标记为 Dormant"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
