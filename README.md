# SBOM Generator (安全软件物料清单生成器)

<p align="center">
  <img src="src-tauri/icons/icon.png" width="128" height="128" alt="SBOM Generator Logo" />
</p>

<p align="center">
  <strong>基于 Rust 构建的高性能、工业级多语言多生态 SBOM (Software Bill of Materials) 生成与拓扑依赖分析工具</strong>
</p>

<p align="center">
  <a href="#-核心特性"><img src="https://img.shields.io/badge/CycloneDX-v1.6-blue.svg" alt="CycloneDX v1.6" /></a>
  <a href="#-支持的语言与生态"><img src="https://img.shields.io/badge/Ecosystems-Rust%20%7C%20Go%20%7C%20Java%20%7C%20Node.js%20%7C%20Python-brightgreen.svg" alt="Ecosystems" /></a>
  <a href="#-架构设计"><img src="https://img.shields.io/badge/Parser-Tree--sitter%20%2B%20Dynamic%20Probe-orange.svg" alt="Parser" /></a>
  <a href="#-桌面可视化客户端-tauri-20"><img src="https://img.shields.io/badge/GUI-Tauri%202.0%20%2B%20ECharts-purple.svg" alt="GUI" /></a>
</p>

---

## 📖 目录

- [✨ 核心特性](#-核心特性)
- [🌐 支持的语言与生态](#-支持的语言与生态)
- [🏗️ 架构设计与技术创新](#️-架构设计与技术创新)
- [🚀 快速开始](#-快速开始)
  - [环境准备](#环境准备)
  - [编译构建](#编译构建)
  - [命令行 CLI 使用](#命令行-cli-使用)
  - [桌面客户端 GUI (Tauri 2.0)](#桌面客户端-gui-tauri-20)
- [📊 输出样例与报表](#-输出样例与报表)
  - [控制台逻辑聚合报表](#1-控制台逻辑聚合报表)
  - [CycloneDX 1.6 依赖图谱格式](#2-cyclonedx-16-依赖图谱格式)
- [📁 模块目录结构](#-模块目录结构)
- [💡 项目进阶与开源生态推荐](#-项目进阶与开源生态推荐)
- [📄 开源协议](#-开源协议)

---

## ✨ 核心特性

- **双轨检测引擎 (Dual-Track Detection)**：首创「运行时动态探针 + 静态 AST / 锁文件责任链」双轨设计，动态优先还原真实运行时完整 DAG 图，断网或无环境时自动平滑降级至纯静态语法分析。
- **物理唯一身份证隔离 (`instance_id`)**：基于 `PURL + 作用域物理路径盐` 哈希计算全局唯一主键，杜绝大型微服务群 / Monorepo 仓库中不同子模块引用同名不同版本包时的冲突。
- **CycloneDX 1.6 规范全合规**：完整输出符合规范的 `metadata`、`components`、`dependencies`（有向依赖边）、`properties` 源码位置锚点（`syft:location:0:path`）与组件性质细分（`application` / `library`）。
- **Maven 高级特性全生态推广**：将 Maven 模块成熟的双趟解析、`${VAR}` / `$var` 多级变量插值与受管依赖版本继承（`HierarchicalContext`）推广至 Gradle、Cargo、Go、NPM 与 Python 全生态。
- **Tree-sitter 毫秒级语法分析**：内置 C 语言级高性能解析器（XML、JSON、YAML、Kotlin），快速定位代码精确行列位置（`Line` / `Col`）。
- **OSV 漏洞联动匹配器 (`sbom-vuln-scanner`)**：利用已生成的组件 PURL，实时请求 [Google OSV.dev Batch API](https://osv.dev/) 并结合内置离线高危 CVE/GHSA 漏洞知识库（支持自定义挂载 `osv-offline-db.json`），在 SBOM 生成后一秒内输出 CycloneDX 1.6 `vulnerabilities` 安全审计结果。
- **交互式桌面可视化与红点告警气泡**：集成 Tauri 2.0 + Apache ECharts，一键生成带力导向图布局、被依赖热度分析、单向拓扑箭头与多语言分类图例的依赖网络图谱；**命中 CVE/GHSA 的风险节点自动高亮染成刺目红并弹出详细漏洞告警气泡（含 CVSS 评分与升级修复建议）**。

---

## 🌐 支持的语言与生态

| 语言 / 生态 | 动态探针轨道 (Dynamic) | 静态分析轨道 (Static Fallback) | 关键特性支持 |
| :--- | :--- | :--- | :--- |
| **Rust** (Cargo) | `cargo metadata` (全特性拓扑) | `Cargo.lock` + `Cargo.toml` | Workspace 跨 Crate 受管版本穿透、4-Pass DAG 构建 |
| **Go** (Golang) | `go mod graph` + `go list -m all` | `go.work` + `go.mod` + `go.sum` | MVS 最小版本收敛、`replace` (支持本地路径过滤)、`exclude`、`// indirect` |
| **Java** (Maven) | `mvn dependency:tree -Dverbose=true` | 多模块双趟 `pom.xml` AST | 父子 POM `<parent>` 继承、`<dependencyManagement>` 穿透、多级变量插值 |
| **Java / Kotlin** (Gradle) | `gradlew dependencies` (ASCII 树解析) | `build.gradle` (Groovy), `build.gradle.kts` (Kotlin), `libs.versions.toml`, `gradle.lockfile` | `gradle.properties` 上下文继承、Version Catalog、变量插值 |
| **Node.js** (NPM) | `npm ls --json --all` | `package-lock.json` + `package.json` | 向上递归 `node_modules` 寻址、Monorepo `catalog:` 继承、Tree-sitter JSON 源码定位 |
| **Python** (PyPI) | 本地虚拟环境优先嗅探 + `pip inspect` | `poetry.lock`, `uv.lock`, `Pipfile.lock`, `requirements.txt`, `pyproject.toml`, `Pipfile` | 根依赖 BFS 可达性剪枝（杜绝全局包污染）、`-r` 递归、`-c` constraints、PEP 621 |

---

## 🏗️ 架构设计与技术创新

```
                   [ 待分析工程目录 / Repository ]
                                  │
                 ┌────────────────┴────────────────┐
                 ▼                                 ▼
      [ 轨道一：动态探针引擎 ]           [ 轨道二：静态责任链队列 ]
      • CliLocator 多级缓存嗅探          • 目录遍历与构建产物剪枝过滤
      • 本地 Wrapper / 虚拟环境优先       • 单子项目作用域目录聚类
      • 真实命令图谱提取 (MVS/BFS)        • 多级回退 (Lock -> Manifest)
                 │                                 │
                 └────────────────┬────────────────┘
                                  ▼
               [ 通用上下文解析中枢 HierarchicalContext ]
               • 多级变量插值引擎 (${VAR} / $var)
               • 工作区受管依赖继承 (BOM / Workspace / Catalog)
                                  │
                                  ▼
                 [ 4-Pass 拓扑图处理与融合引擎 ]
                 Pass 1: 双索引映射构建与 instance_id 分配
                 Pass 2: 有向边连线与 In-Degree 入度计算
                 Pass 3: 根应用节点识别与 BFS 可达性剪枝
                 Pass 4: 拓扑去重与边集合并 (dependsOn 并集)
                                  │
                 ┌────────────────┴────────────────┐
                 ▼                                 ▼
       [ CycloneDX 1.6 JSON ]           [ 控制台逻辑聚合报表 ]
       • 定序顶级输出 (Metadata/Deps)      • 逻辑组件 vs 物理隔离实例汇总
       • syft 物理位置属性注入
```

### 1. 通用技术底座 (`src/utils/`)
- **`HierarchicalContext`**：统一处理变量多层递归替换与 BOM/版本表继承。
- **`AsciiTreeStackBuilder`**：单调栈状态机，无损将 Maven / Gradle 的 CLI 缩进树转化为带多模块领地划分的 DAG 图谱。
- **`CliLocator`**：解决静态分析工具在不同机器上寻找 `mvn`、`gradle`、`go`、`python` 慢或进程崩溃的问题。内置内存 `OnceLock`、磁盘缓存 `~/.sbom_cli_cache.json` 及常见 IDE（IDEA、PyCharm、GoLand）内置可执行文件嗅探。
- **`build_reachable_dag`**：通用 4-Pass 依赖图构建器，自动过滤未引用的孤岛组件。

---

## 🚀 快速开始

### 环境准备

- [Rust 编译器](https://rustup.rs/) (建议 1.80+ 稳定版)
- C/C++ 编译器 (用于编译 Tree-sitter 语法运行时，如 GCC / Clang / MSVC)
- （可选）Node.js / npm、Go、Maven、Python、Gradle（用于动态检测模式）

### 编译构建

```bash
# 克隆仓库
git clone https://github.com/your-username/sbom-generator.git
cd sbom-generator

# 编译命令行 Release 版本
cargo build --release

# 编译二进制位于:
# target/release/sbom-generator (Linux/macOS)
# target/release/sbom-generator.exe (Windows)
```

### 命令行 CLI 使用

```bash
# 默认模式：自动尝试动态探测，失败自动降级到静态解析
./target/release/sbom-generator -i /path/to/project -o output.sbom.json

# 强制纯静态分析（适用于离线安全审计、无语言环境的 CI/CD 流水线）
./target/release/sbom-generator -i /path/to/project -o output.sbom.json -s

# 开启 Debug 调试日志输出（打印各组件实例及清单物理路径）
./target/release/sbom-generator -i /path/to/project -o output.sbom.json -d
```

#### CLI 参数选项：
| 参数 | 长参数 | 说明 |
| :--- | :--- | :--- |
| `-i` | `--directory` | 必填，待扫描分析的工程根目录 |
| `-o` | `--output` | 必填，生成的 SBOM JSON 保存文件路径 |
| `-s` | `--static-only` | 可选，强制仅使用纯静态解析（禁用任何动态探针） |
| `-d` | `--debug` | 可选，开启详细调试日志 |
| `-h` | `--help` | 查看帮助说明信息 |

---

### 桌面客户端 GUI (Tauri 2.0)

本项目内置基于 **Tauri 2.0 + 原生前端 + Apache ECharts** 开发的交互式图谱客户端：

```bash
# 进入桌面端目录并启动开发调试
cargo tauri dev

# 打包发布全平台原生安装包 (.msi / .exe / .dmg / .deb)
cargo tauri build
```

**GUI 功能亮点**：
- 📂 **可视化路径选择**：支持一键输入源码路径与保存位置。
- 🎨 **多语言生态配色**：按 Rust (Cargo)、Go、Node.js、Java/Kotlin (Maven/Gradle)、Python (PyPI) 自动分类赋予专业配色。
- 🔍 **依赖热度高亮**：根据各节点入度动态调整节点体积与发光阴影，核心基础库一目了然。
- 🔗 **关系悬浮溯源**：鼠标悬停任意边高亮显示 `A 依赖于 B` 的指向关系与 PURL 全称。

---

## 📊 输出样例与报表

### 1. 控制台逻辑聚合报表

每次生成 SBOM 时，控制台将自动打印结构化的分析聚合报表：

```text
======================= SBOM 逻辑聚合报表 ========================
组件名称                             | 版本               | 物理实例数     
--------------------------------------------------------------------
github.com/gin-gonic/gin         | v1.9.1           | 1         
github.com/redis/go-redis/v9     | v9.5.1           | 1         
org.springframework.boot:spring-boot-starter-web | 3.2.2 | 2         
serde                            | 1.0.210          | 1         
requests                         | 2.31.0           | 1         
--------------------------------------------------------------------
总结：识别到 5 个逻辑组件，共映射 6 个物理隔离实例。
```

### 2. CycloneDX 1.6 依赖图谱格式

输出文件严格保证根级属性顺序（`bomFormat` -> `specVersion` -> `version` -> `metadata` -> `components` -> `dependencies`）：

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "timestamp": "2026-10-31T01:00:00Z",
    "tools": [
      {
        "vendor": "BNBU_DS",
        "name": "sbom-generator",
        "version": "0.1.0"
      }
    ]
  },
  "components": [
    {
      "type": "application",
      "name": "cloud-gateway",
      "version": "1.22",
      "purl": "pkg:golang/github.com/bnbu/cloud-gateway@1.22",
      "bom-ref": "pkg:golang/github.com/bnbu/cloud-gateway@1.22?package-id=a2c4a309ce9d9d38",
      "properties": [
        {
          "name": "syft:location:0:path",
          "value": "go.mod"
        }
      ]
    },
    {
      "type": "library",
      "name": "github.com/gin-gonic/gin",
      "version": "v1.9.1",
      "purl": "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
      "bom-ref": "pkg:golang/github.com/gin-gonic/gin@v1.9.1?package-id=ea25656338117b41"
    }
  ],
  "dependencies": [
    {
      "ref": "pkg:golang/github.com/bnbu/cloud-gateway@1.22?package-id=a2c4a309ce9d9d38",
      "dependsOn": [
        "pkg:golang/github.com/gin-gonic/gin@v1.9.1?package-id=ea25656338117b41"
      ]
    },
    {
      "ref": "pkg:golang/github.com/gin-gonic/gin@v1.9.1?package-id=ea25656338117b41",
      "dependsOn": []
    }
  ]
}
```

---

## 📁 模块目录结构

```text
sbom-generator/
├── Cargo.toml                    # 主工程配置与依赖
├── build.rs                      # Tree-sitter C/C++ 语法构建脚本
├── ui/
│   └── index.html                # ECharts 拓扑可视化前端
├── src-tauri/                    # Tauri 2.0 跨平台桌面壳工程
└── src/
    ├── main.rs                   # CLI 命令行入口与参数解析
    ├── lib.rs                    # 核心库导出
    ├── report.rs                 # 控制台逻辑聚合报表引擎
    ├── model/                    # 数据模型层 (Dependency, Location, Configuration)
    ├── sbom/                     # CycloneDX 1.6 生成与序列化
    ├── utils/                    # 通用底座
    │   ├── cli_driver.rs         # 跨平台 CLI 探测与缓存中枢 (CliLocator)
    │   ├── context_resolver.rs   # 变量插值与受管版本继承 (HierarchicalContext)
    │   ├── file_utils.rs         # 智能目录遍历与剪枝
    │   ├── graph_utils.rs        # 4-Pass DAG 图引擎与单调栈树解析
    │   └── tree_sitter/          # Tree-sitter 运行时绑定与源码行列计算
    └── analyze/
        ├── sbom_generate.rs      # 多生态编排主入口
        └── producers/            # 语言生态解析模块
            ├── cargo/            # Rust Cargo 生态 (Dynamic + Lock + Toml Workspace)
            ├── go/               # Go Modules 生态 (Dynamic Graph + go.work/mod/sum)
            ├── gradle/           # Gradle 生态 (Dynamic Tree + Groovy/Kotlin/TOML)
            ├── maven/            # Maven 生态 (Dynamic Tree + 双趟 POM AST)
            ├── npm/              # Node.js NPM 生态 (Dynamic + Lock + AST Json)
            └── pypi/             # Python PyPI 生态 (Dynamic + Locks + Req + Pyproject)
```

---

## 💡 项目进阶与开源生态推荐

如果您希望将本项目进一步扩展为企业级安全平台，或对软件供应链安全（Supply Chain Security）感兴趣，推荐以下演进方向与优质开源参考项目：

### 1. 本项目可落地的后续扩展方向 (Project Roadmap)
1. **漏洞匹配引擎 (Vulnerability Scanner)**：
   - 基于生成的组件 PURL，对接 [OSV.dev (Open Source Vulnerabilities)](https://osv.dev/) 或 GitHub Advisory Database 的离线/在线 API，快速标记存在 CVE/GHSA 漏洞的组件。
2. **开源合规与 License 探测 (License & Compliance)**：
   - 解析各生态包的 SPDX 许可证表达式（如 `MIT`, `Apache-2.0`, `GPL-3.0`），建立企业合规风险阻断策略（如商业闭源项目中阻断传染型 GPL 依赖）。
3. **SBOM Diff 依赖对比器 (SBOM Diffing)**：
   - 对比两次 CI 构建产出的 SBOM 文件，输出组件的新增、升级、降级或移除差异，防止供应链投毒（如检测意外引入的恶意深层依赖）。
4. **VEX (Vulnerability Exploitability eXchange) 生成**：
   - 依据 CycloneDX 1.6 VEX 标准，输出组件受影响状态（`not_affected` / `affected`），提供企业级漏洞可利用性状态声明。

### 2. 业界优质开源项目推荐 (Inspiration & Benchmarks)
- [anchore/syft](https://github.com/anchore/syft)：Go 语言编写的顶级 CLI 工具，支持容器镜像与文件系统的 SBOM 生成（本项目的 `syft:location:0:path` 即与其命名标准兼容）。
- [aquasecurity/trivy](https://github.com/aquasecurity/trivy)：全球广受欢迎的全能安全扫描器，支持漏洞扫描、配置审计与 SBOM 生成。
- [google/osv-scanner](https://github.com/google/osv-scanner)：Google 官方出品的漏洞扫描器，直接以 SBOM 文件或锁文件作为输入匹配 OSV 漏洞库。
- [guacsec/guac](https://github.com/guacsec/guac)：Graph for Understanding Artifact Composition，基于图数据库将企业所有 SBOM 与安全元数据编织为可查询的安全知识图谱。

---

## 📄 开源协议

本项目采用 [Apache-2.0 / MIT](LICENSE) 双重开源协议，欢迎提交 Issue 与 Pull Request 共同完善！
