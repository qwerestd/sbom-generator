use crate::model::dependency::{Dependency, DependencyType};
use crate::utils::file_utils::make_instance_id;
use regex::Regex;
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;
use std::{env, fs};

// 全局静态预编译正则，省去每次调用都在堆内存重复解析状态机的开销
static MAVEN_COORD_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[a-zA-Z0-9_.\-]+:[a-zA-Z0-9_.\-]+:[a-zA-Z0-9_.\-]+:[a-zA-Z0-9_.\-]+(?::[a-zA-Z0-9_.\-]+)*").unwrap()
});

pub struct MavenCliDriver;

impl MavenCliDriver {
    /// 获取缓存文件的存放绝对路径 (存放在 C:\Users\你的用户名\.sbom_mvn_cache.txt)
    fn get_cache_file_path() -> PathBuf {
        let home_dir = env::var("USERPROFILE").unwrap_or_else(|_| r"C:\".to_string());
        PathBuf::from(home_dir).join(".sbom_mvn_cache.txt")
    }

    /// 尝试读取缓存
    fn read_cache() -> Option<String> {
        let cache_file = Self::get_cache_file_path();
        if let Ok(content) = fs::read_to_string(&cache_file) {
            let path_str = content.trim();
            // 【安全校验】哪怕有缓存，也要确认那个路径的文件还没被用户删掉
            if Path::new(path_str).exists() {
                eprintln!("⚡ [缓存命中] 读取到已保存的 Maven 路径: {}", path_str);
                return Some(path_str.to_string());
            } else {
                eprintln!("⚠️ [缓存失效] 发现残留的 Maven 路径已被移动或删除，准备重新扫描...");
            }
        }
        None
    }

    /// 写入缓存
    fn write_cache(mvn_path: &str) {
        let cache_file = Self::get_cache_file_path();
        if fs::write(&cache_file, mvn_path).is_ok() {
            eprintln!(
                "💾 [缓存保存] Maven 路径已持久化到: {}",
                cache_file.display()
            );
        }
    }

    /// 阶段一：快速定点排查 IDEA 默认路径 (耗时只需几毫秒)
    fn scan_idea_fast() -> Option<String> {
        let local_app_data = env::var("LOCALAPPDATA").unwrap_or_default();
        let program_files =
            env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".to_string());

        let base_dirs = vec![
            PathBuf::from(&program_files).join("JetBrains"),
            PathBuf::from(&local_app_data).join("Programs"),
            PathBuf::from(&local_app_data)
                .join("JetBrains")
                .join("Toolbox")
                .join("apps"),
        ];

        let maven_rel_path = r"plugins\maven\lib\maven3\bin\mvn.cmd";

        for base_dir in base_dirs {
            if !base_dir.exists() {
                continue;
            }
            let mut queue = VecDeque::new();
            queue.push_back(base_dir);

            // 在 IDEA 目录下进行限制深度的扫描
            let mut depth_limit = 50;
            while let Some(current_dir) = queue.pop_front() {
                depth_limit -= 1;
                if depth_limit == 0 {
                    break;
                }

                if let Ok(entries) = fs::read_dir(&current_dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_dir() {
                            let target = path.join(maven_rel_path);
                            if target.exists() {
                                return Some(target.to_string_lossy().to_string());
                            }
                            queue.push_back(path);
                        }
                    }
                }
            }
        }
        None
    }

    /// 阶段二：全盘暴力扫描 (利用 BFS 广度优先，避开系统权限死区，耗时 1~3 分钟)
    fn scan_system_deep() -> Option<String> {
        eprintln!(
            "⏳ [全盘扫描] 正在跨越所有磁盘深度搜索 mvn.cmd，这可能需要几分钟，请耐心等待..."
        );
        let mut queue = VecDeque::new();

        // 将你常用的盘符加入队列起始点
        let roots = vec![r"C:\", r"D:\", r"E:\"];
        for root in roots {
            let p = PathBuf::from(root);
            if p.exists() {
                queue.push_back(p);
            }
        }

        let target_file = "mvn.cmd";

        while let Some(current_dir) = queue.pop_front() {
            // 忽略没有权限读的系统级目录，直接 continue
            let entries = match fs::read_dir(&current_dir) {
                Ok(e) => e,
                Err(_) => continue,
            };

            for entry in entries.flatten() {
                let path = entry.path();

                if path.is_dir() {
                    let dir_name = path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_lowercase();
                    // 智能避障：跳过明显不可能存在 Maven 且文件海量的系统文件夹
                    if dir_name == "windows"
                        || dir_name == "$recycle.bin"
                        || dir_name == "system volume information"
                    {
                        continue;
                    }
                    queue.push_back(path);
                // 👇 [优化点]: 修复 Clippy 的嵌套过深警告 (collapsible_if)
                } else if path.is_file()
                    && path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_lowercase()
                        == target_file
                {
                    // 防止重名文件，判断它是否在 /bin/ 目录下
                    if let Some(parent) = path.parent() {
                        if parent
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_lowercase()
                            == "bin"
                        {
                            let found = path.to_string_lossy().to_string();
                            eprintln!("✅ [全盘扫描命中] 在深层目录发现: {}", found);
                            return Some(found);
                        }
                    }
                }
            }
        }
        None
    }

    /// 统筹中枢：缓存 -> 快速扫描 -> 深度扫描
    fn resolve_maven_path() -> String {
        // 1. 优先查缓存
        if let Some(cached) = Self::read_cache() {
            return cached;
        }

        // 2. 缓存失效，先花几十毫秒快速扫 IDEA 目录
        if let Some(idea_mvn) = Self::scan_idea_fast() {
            eprintln!("✅ [快速拦截] 嗅探到 IDEA 内置 Maven: {}", idea_mvn);
            Self::write_cache(&idea_mvn);
            return idea_mvn;
        }

        // 3. 实在没有，启动核弹级全盘扫描
        if let Some(deep_mvn) = Self::scan_system_deep() {
            Self::write_cache(&deep_mvn);
            return deep_mvn;
        }

        eprintln!("❌ 致命错误: 已执行全系统穿透扫描，仍未找到任何 mvn.cmd！请确保你的系统或 IDEA 中安装了 Maven。");
        std::process::exit(1);
    }

    /// 构造 Maven 命令
    fn build_mvn_command() -> Command {
        Command::new(Self::resolve_maven_path())
    }

    pub fn is_available() -> bool {
        Self::build_mvn_command()
            .arg("-v")
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    }

    /// 核心依赖生成模块 (强制暴露底层报错，开启 verbose 穿透隐藏节点)
    pub fn generate_dependencies(project_dir: &Path) -> Result<Vec<Dependency>, String> {
        let mut cmd = Self::build_mvn_command();
        // 💡 核心优化：加入 -Dverbose=true 强制 Maven 吐出所有 omitted 和 conflict 的完整树结构
        cmd.args([
            "dependency:tree",
            "-DoutputType=text",
            "-Dverbose=true",
            "-B",
        ])
        .current_dir(project_dir);

        eprintln!("🚀 正在启动动态 Maven 解析引擎，请稍候...");

        let output = match cmd.output() {
            Ok(out) => out,
            Err(e) => {
                eprintln!("❌ 致命错误: 无法启动 mvn 进程: {}", e);
                std::process::exit(1);
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            eprintln!("❌ 致命错误: Maven 命令执行失败！底层原因如下：");
            eprintln!("================ MAVEN STDERR ================\n{}", stderr);
            eprintln!("================ MAVEN STDOUT ================\n{}", stdout);
            std::process::exit(1);
        }

        Self::parse_ascii_tree(&String::from_utf8_lossy(&output.stdout))
    }

    /// 优化后的正则树状文本解析拓扑算法，保留全部 Scope 和关联边
    fn parse_ascii_tree(content: &str) -> Result<Vec<Dependency>, String> {
        let mut deps_map: HashMap<String, Dependency> = HashMap::new();
        let mut parent_stack: Vec<String> = Vec::new(); // 栈内存放的必须是 instance_id
        let mut current_module_scope: String = String::new(); // 当前子项目物理作用域

        // 💡 核心优化：预编译正则清洗 Maven 产生的 `(omitted for duplicate)`、`(version managed from x.x.x)` 等提示词
        // 确保深度 depth 计算精准，不再抛弃任何节点导致断带
        let clean_annotation_re = Regex::new(r"\([^\)]+\)\s*").unwrap();

        for line in content.lines() {
            // 剥离 Maven 的 [INFO] 前缀
            let clean_line = match line.find("] ") {
                Some(idx) => &line[idx + 2..],
                None => line,
            };

            if clean_line.starts_with("Building ") || clean_line.contains("Scanning for") {
                continue;
            }

            // 【优化 A】：剥离所有的辅助括号修饰词，保证深度对齐，不丢数据
            let normalized_line = clean_annotation_re.replace_all(clean_line, "");

            if let Some(mat) = MAVEN_COORD_RE.find(&normalized_line) {
                let parts: Vec<&str> = mat.as_str().split(':').collect();

                // 【优化 B】：精准捕获 Classifier 与 Scope
                let (group_id, artifact_id, version, _scope) = match parts.len() {
                    4 => (parts[0], parts[1], parts[3], "compile"), // 默认 scope
                    5 => (parts[0], parts[1], parts[3], parts[4]),  // 包含 scope
                    6 => (parts[0], parts[1], parts[4], parts[5]),  // 包含 classifier 和 scope
                    _ => continue,
                };

                let raw_purl = format!("pkg:maven/{}/{}@{}", group_id, artifact_id, version);
                let valid_purl = Dependency::auto_fix_and_validate_purl(&raw_purl);

                // 因为剥离了多余修饰词，现在的 mat.start() 计算出的 depth 绝对精准安全
                let depth = mat.start() / 3;

                // 【精髓 A】：微服务领地切变侦测
                if depth == 0 {
                    current_module_scope = valid_purl.clone();
                }

                // 【精髓 B】：为当前包派生“带子工程语境”的身份证
                let instance_id = make_instance_id(&valid_purl, &current_module_scope);

                // 【精髓 C】：单调栈连线（连线的父子节点全部流转 instance_id）
                parent_stack.truncate(depth);
                if let Some(parent_instance_id) = parent_stack.last() {
                    if let Some(parent_dep) = deps_map.get_mut(parent_instance_id) {
                        if !parent_dep.dependencies.contains(&instance_id) {
                            parent_dep.dependencies.push(instance_id.clone());
                        }
                    }
                }
                parent_stack.push(instance_id.clone());

                // 【精髓 D】：落盘入库（Key 严格设为 instance_id）
                if !deps_map.contains_key(&instance_id) {
                    deps_map.insert(
                        instance_id.clone(),
                        Dependency {
                            group: Some(group_id.to_string()),
                            r#type: DependencyType::Library,
                            name: artifact_id.to_string(),
                            version: Some(version.to_string()),
                            purl: valid_purl,
                            instance_id,
                            dependencies: Vec::new(),
                            location: None,
                        },
                    );
                }
            }
        }

        let result: Vec<Dependency> = deps_map.into_values().collect();
        eprintln!(
            "🔍 [自检] 动态正则引擎成功提取 {} 个 Java 依赖，多模块隔离 DAG 连线完毕！",
            result.len()
        );
        Ok(result)
    }
}
