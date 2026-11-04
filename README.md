# 基于 Rust 的多语言软件物料清单 (SBOM) 生成与供应链安全审计系统

<p align="center">
  <img src="src-tauri/icons/icon.png" width="120" height="120" alt="SBOM Generator Logo" />
</p>

<p align="center">
  <strong>计算机科学与技术 / 软件工程专业 本科毕业设计 (Graduation Project)</strong>
</p>

<p align="center">
  <a href="#-支持的语言与生态"><img src="https://img.shields.io/badge/Language-Rust%202021-DEA584.svg" alt="Rust 2021" /></a>
  <a href="#-输出规范与合规标准"><img src="https://img.shields.io/badge/Standard-CycloneDX%20v1.6-007ACC.svg" alt="CycloneDX v1.6" /></a>
  <a href="#-支持的语言与生态"><img src="https://img.shields.io/badge/Ecosystems-Rust%20%7C%20Go%20%7C%20Java%20%7C%20Kotlin%20%7C%20Node.js%20%7C%20Python-2ea44f.svg" alt="Ecosystems" /></a>
  <a href="#-安全审计与开源合规"><img src="https://img.shields.io/badge/Security-OSV.dev%20%7C%20SPDX-d73a49.svg" alt="Security" /></a>
  <a href="#-实测对比实验与基准分析-test-数据集"><img src="https://img.shields.io/badge/Benchmark-vs%20Trivy%20v0.76.1-blueviolet.svg" alt="Benchmark" /></a>
  <a href="#-自动化测试与质量保证"><img src="https://img.shields.io/badge/Tests-47%20Passed%20(100%25)-success.svg" alt="Tests" /></a>
  <a href="#-开源协议"><img src="https://img.shields.io/badge/License-MIT%20%2F%20Apache--2.0-blue.svg" alt="License" /></a>
</p>

---

## 📖 目录

- [📌 课题背景与研究意义](#-课题背景与研究意义)
- [✨ 系统核心功能与设计亮点](#-系统核心功能与设计亮点)
- [🌐 支持的语言与生态矩阵](#-支持的语言与生态矩阵)
- [🏗️ 系统总体架构与解析流程](#️-系统总体架构与解析流程)
- [📊 实测对比实验与基准分析 (`test/` 数据集)](#-实测对比实验与基准分析-test-数据集)
  - [实验 1：大型多语言微服务架构对齐评测 (`test/opentelemetry/`)](#实验-1大型多语言微服务架构对齐评测-testopentelemetry)
  - [实验 2：云原生分布式微服务基准与实例隔离 (`test/mircoservices/`)](#实验-2云原生分布式微服务基准与实例隔离-testmircoservices)
  - [实验 3：缺失锁定文件时的语法树容错解析 (`test/juice-shop/`)](#实验-3缺失锁定文件时的语法树容错解析-testjuice-shop)
- [🛡️ 安全审计与开源许可证合规](#️-安全审计与开源许可证合规)
  - [1. 基于 Google OSV 的已知脆弱性匹配](#1-基于-google-osv-的已知脆弱性匹配)
  - [2. SPDX 开源许可证多级提取与规范化](#2-spdx-开源许可证多级提取与规范化)
- [⚡ 动态系统资源与吞吐量监控](#-动态系统资源与吞吐量监控)
- [🚀 快速开始与实验复现](#-快速开始与实验复现)
  - [环境准备](#环境准备)
  - [编译构建](#编译构建)
  - [命令行 CLI 使用说明](#命令行-cli-使用说明)
  - [SBOM 对比评测工具使用 (`sbom_compare`)](#sbom-对比评测工具使用-sbom_compare)
- [🖥️ 桌面可视化客户端 (Tauri 2.0 GUI)](#️-桌面可视化客户端-tauri-20-gui)
- [📋 标准 CycloneDX 1.6 输出样例](#-标准-cyclonedx-16-输出样例)
- [🧪 自动化测试与质量保证](#-自动化测试与质量保证)
- [📁 代码目录与模块结构](#-代码目录与模块结构)
- [💡 总结与后续演进展望](#-总结与后续演进展望)
- [📄 开源协议](#-开源协议)

---

## 📌 课题背景与研究意义

随着开源软件与现代微服务架构的普及，第三方依赖组件在现代软件开发中占据了 80% 以上的代码量。近年来，Log4Shell、SolarWinds、Event-Stream 等软件供应链安全事件频发，促使国际社会与工业界加速推进软件物料清单（Software Bill of Materials, SBOM）的标准化建设。

然而，现存的主流扫描工具在应对复杂工程时仍面临以下挑战：
1. **缺乏运行时与静态分析的协同**：多数工具仅依赖单点 Lock 文件，若工程未锁定依赖或缺少环境工具链则直接报错漏检；
2. **大仓多微服务多实例冲突**：在 Monorepo（单体大仓）或微服务协同项目中，不同子模块引入同一依赖的不同版本时，传统工具常进行简单粗暴的全局合并，丢失了物理部署路径与拓扑上下文；
3. **脆弱性告警疲劳**：传统清单仅列出静态包名，无法区分组件是运行时被真正调用的活跃依赖还是未使用的休眠组件。

针对上述问题，本课题选用兼具高性能与内存安全特性的 **Rust 语言**，设计并实现了一套具备**双轨混合检测机制、物理实例隔离、依赖拓扑还原与基准比对评测**的多语言 SBOM 自动化生成与供应链安全审计平台。

---

## ✨ 系统核心功能与设计亮点

- **「运行时动态探针 + 静态 AST 责任链」双轨容错引擎**：
  - **动态探针优先**：优先嗅探开发机或构建容器中的语言环境（如 `cargo metadata`、`go mod graph`、`mvn dependency:tree` 等），获取官方权威解析器导出的 100% 精确运行时图谱；
  - **静态 AST 平滑降级**：在无网络、缺失本地编译器或安全沙箱环境中，自动回退至静态解析责任链。基于 **Tree-sitter** 与流式语法解析器遍历 `Lockfile` 与构建清单（`pom.xml`、`build.gradle.kts`、`pyproject.toml` 等），支持在**无 Lock 锁文件**的情况下自适应恢复依赖。
- **基于物理路径盐的实例隔离 (`instance_id` & `bom-ref`)**：
  - 针对微服务 Monorepo 场景，采用 `PURL + 相对工程路径 Hash 盐` 算法生成唯一物理身份标识，杜绝不同子服务间同名但不同版本的依赖拓扑覆盖与短路。
- **多生态高级构建语义深度穿透**：
  - 实现了 Maven 双趟解析、`<parent>` 继承、`<dependencyManagement>` 跨模块穿透与 `${VAR}` 多级属性插值；
  - 支持 Gradle Version Catalog、Cargo Workspace 跨 Crate 属性继承、Go MVS 最小版本选择与 Python PEP 621 规范。
- **自动化横向评测对比引擎 (`sbom_compare`)**：
  - 内置跨工具基准评测算法，可载入两个 CycloneDX 标准文件，精确计算**去重唯一组件数、交集匹配率、参照工具召回率 (Recall)、Jaccard 相似度**与 **DAG 拓扑边差异**，并能一键导出用于实验汇报与学术论文的 Markdown 报告。
- **全流程安全审计与合规富化**：
  - 集成 Google OSV 在线 Batch API 与内置离线知识库，秒级关联 CVE / GHSA 漏洞；结合包名与清单抽取自动化标准化 SPDX 许可证。
- **Tauri 2.0 桌面交互工作台**：
  - 采用 Rust 原生轻量化桌面方案，提供力导向有向图交互、高危风险红点呼吸显示、抽屉式属性详情审查，以及直观的双 SBOM 差异对比图表。

---

## 🌐 支持的语言与生态矩阵

本系统针对现代互联网与云原生架构最主流的 **5 大核心语言、6 大包管理器生态**进行了深度适配：

| 编程语言 | 包管理 / 构建生态 | 动态探针轨道 (Dynamic) | 静态语法分析轨道 (Static Fallback) | 关键技术实现 |
| :--- | :--- | :--- | :--- | :--- |
| **Rust** | `Cargo` | `cargo metadata` | `Cargo.lock` + `Cargo.toml` | Workspace 跨 Crate 受管属性穿透、4-Pass DAG 环路处理 |
| **Go** | `Go Modules` | `go mod graph` + `go list` | `go.work` + `go.mod` + `go.sum` | 最小版本选择 (MVS)、`replace` 替换、`exclude` 规则 |
| **Java** | `Maven` | `mvn dependency:tree` | 双趟 `pom.xml` AST | `<parent>` 继承、`<dependencyManagement>` 穿透、`${VAR}` 插值 |
| **Java / Kotlin** | `Gradle` | `gradlew dependencies` | `build.gradle(.kts)`, `libs.versions.toml` | Tree-sitter Kotlin 语法树解析、Version Catalog 声明提取 |
| **Node.js** | `NPM` | `npm ls --json --all` | `package-lock.json` + `package.json` | 向上递归寻址、`catalog:` 语法、Lockfile v1/v2/v3 兼容 |
| **Python** | `PyPI` | 本地虚拟环境 + `pip inspect` | `poetry.lock`, `uv.lock`, `requirements.txt` | BFS 可达性剪枝、`-r` 级联包含、PEP 621 与 Poetry 规范 |

---

## 🏗️ 系统总体架构与解析流程

```text
               待分析目标工程根目录 (Target Project Path)
                                 │
                ┌────────────────┴────────────────┐
                ▼                                 ▼
     [ 动态探针分析引擎 ]               [ 静态语法分析责任链 ]
     • 宿主编译器/环境探测               • 目录遍历与构建产物剪枝过滤
     • 本地 Wrapper / 虚拟环境优先       • 单子项目领地作用域聚类 (Scope Cluster)
     • 权威运行时拓扑图提取 (MVS/BFS)    • 智能降级回退 (Lockfile -> Manifest AST)
                │                                 │
                └────────────────┬────────────────┘
                                 ▼
             [ 通用上下文解析中枢 (HierarchicalContext) ]
             • 多级变量插值引擎 (${VAR} / 属性继承)
             • 工作区受管依赖解析 (BOM / Workspace / Catalog)
                                 │
                                 ▼
             [ 4-Pass 依赖图构建与拓扑网络融合引擎 ]
             Pass 1: 构建双索引字典与 instance_id 分配
             Pass 2: 建立有向边集合与 In-Degree 入度拓扑排序
             Pass 3: 顶层根节点识别与 BFS 可达性剪枝 (剔除孤立包)
             Pass 4: 跨微服务模块图谱融合与 dependsOn 边集合并
                                 │
                ┌────────────────┼────────────────┐
                ▼                ▼                ▼
       [ OSV 漏洞匹配器 ]  [ 许可证标准化引擎 ]  [ 资源监控探针 ]
       • 在线 Batch API    • SPDX ID 标准化     • CPU / RAM 动态采样
       • 内置离线漏洞库    • 本地多级清单提取   • 分析耗时与吞吐率统计
                │                │                │
                └────────────────┼────────────────┘
                                 ▼
      ┌──────────────────────────┴──────────────────────────┐
      ▼                                                     ▼
[ CycloneDX 1.6 标准 JSON ]                       [ 交互式终端 / Tauri 2.0 GUI ]
• 规范化顶级定序结构                              • 层次分明的 ASCII 依赖拓扑树
• 物理实例隔离与源码锚点                          • 力导向动力学图谱与漏洞红点审查
• PURL / CVE / SPDX 全量富化                     • 双 SBOM 横向对比实验评测台
```

---

## 📊 实测对比实验与基准分析 (`test/` 数据集)

为验证本系统在真实工业代码环境中的有效性与可靠性，课题选取了 3 个具有不同架构特性的经典开源项目作为测试基准，放置于 [`test/`](test/) 目录下，与当前全球网络安全事实标准 **Aqua Security Trivy (v0.76.1)** 进行同台严格对照实验。

### 实验 1：大型多语言微服务架构对齐评测 (`test/opentelemetry/`)

* **测试对象**：CNCF 旗舰级分布式遥测基准系统 [OpenTelemetry Demo](https://github.com/open-telemetry/opentelemetry-demo)，包含多语言微服务协作。
* **数据源**：
  - 本系统输出：[`test/opentelemetry/opentelemetry-demo_sbom.json`](test/opentelemetry/opentelemetry-demo_sbom.json)
  - Trivy 对照产物：[`test/opentelemetry/opentelemetry-trivy.json`](test/opentelemetry/opentelemetry-trivy.json)

两款工具在各语言生态的组件发现与对齐数据如下：

| 语言生态分类 | 本系统 (sbom-generator) | 参照工具 (Trivy v0.76.1) | 共同交集 | 增量差值 (Delta) | 参照工具召回率 (%) | 实验结果分析 |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **Cargo (Rust)** | **306** | 305 | 302 | **+1** | **99.0%** | **高精度对齐**：基础解析与 PURL 规范化极为扎实，验证了核心算法准确性。 |
| **Maven (Java)** | **20** | **0** | 0 | **+20** | **100.0%** | **发现盲区**：Trivy 因嵌套目录完全漏检 Java 微服务模块，本系统成功捕获。 |
| **NPM (Node.js)** | **1959** | 925 | 801 | **+1034** | **86.6%** | **深度穿透**：覆盖 Trivy 主体依赖的同时，挖掘出两倍以上的深层嵌套依赖。 |
| **Golang (Go)** | **194** | 156 | 97 | **+38** | **62.2%** | **微服务感知**：细粒度保留多微服务独立上下文，总发现量显著领先。 |
| **PyPI (Python)** | **531** | 525 | 254 | **+6** | **48.4%** | **规范适配**：通过 Poetry 与 PEP 621 规范解析，捕获了微服务专有依赖。 |

> **实验讨论**：在评测中，Trivy 识别出的 GEM (Ruby: 135)、HEX (Erlang: 57)、NUGET (.NET: 30) 属于项目中辅助性非核心微服务。本课题在开题与系统设计阶段明确将**研究边界聚焦于 Top 5 核心主流生态（Rust, Go, Java, JS/TS, Python）**，该结果符合预期设计范围。

---

### 实验 2：云原生分布式微服务基准与实例隔离 (`test/mircoservices/`)

* **测试对象**：Google 官方开源的经典 10 语言云原生微服务靶场 [Google Cloud Microservices Demo](https://github.com/GoogleCloudPlatform/microservices-demo)。
* **数据源**：
  - 本系统输出：[`test/mircoservices/microservices-demo_sbom.json`](test/mircoservices/microservices-demo_sbom.json)
  - Trivy 对照产物：[`test/mircoservices/sbom-cyclonedx.json`](test/mircoservices/sbom-cyclonedx.json)
  - 自动生成对比报告：[`test/benchmark_report.md`](test/benchmark_report.md)

运行本系统的 `sbom_compare` 对比引擎生成的综合指标如下：

| 评估指标 (Metric) | 本系统 (sbom-generator) | 参照工具 (Trivy v0.76.1) | 差异与优势说明 |
| :--- | :---: | :---: | :--- |
| **物理组件实例数 (Total Instances)** | **1,024 个** | 860 个 | **提升 19.1%**：基于路径盐精确分离各微服务的实体实例 |
| **去重唯一组件数 (Unique PURLs)** | **556 个** | 480 个 | 多挖掘出 **80 个** 深度传递依赖与受管依赖 |
| **参照工具召回重合率 (Recall Rate)** | **99.17%** | 基准对照 | 证明本系统对工业级主流依赖的捕获覆盖率达到 99%+ |
| **依赖图 DAG 拓扑边数 (Edges)** | **1,462 条** | 1,410 条 | 完整还原深层微服务依赖链路拓扑网络 |
| **依赖集合 Jaccard 相似度** | **85.00%** | 基准对照 | 双方共有 476 个核心依赖，两款工具具有极高拟合度 |
| **多模块大仓实例冲突隔离** | **支持 (`instance_id`)** | 不支持 (扁平合并) | 避免同名不同版本依赖拓扑短路 |
| **运行时动态依赖状态标记** | **支持 (Loaded / Dormant)** | 不支持 | 辨识编译实操痕迹，有效降低 CVE 虚报疲劳 |

---

### 实验 3：缺失锁定文件时的语法树容错解析 (`test/juice-shop/`)

* **测试对象**：OWASP 著名全栈靶场工程 [OWASP Juice Shop](https://github.com/juice-shop/juice-shop)。
* **边界场景**：工程代码仓库默认仅提交声明清单 `package.json`，**未提供 `package-lock.json` 锁定文件**。
* **数据源**：
  - 本系统输出：[`test/juice-shop/juice-shop_sbom.json`](test/juice-shop/juice-shop_sbom.json)
  - Trivy 对照产物：[`test/juice-shop/juice-shop-trivy.json`](test/juice-shop/juice-shop-trivy.json)

**实验结果对照**：
* **Trivy v0.76.1**：由于缺乏 Lock 文件，解析流程直接中断，输出的物料清单组件数组为空（`components: []`，**检出 0 个依赖构件**）。
* **本系统 (sbom-generator)**：自适应触发静态 AST 责任链与模糊版本范围解算引擎，**成功恢复出 1,126 个组件，并重建出 2,013 条依赖关系有向边**！充分证明了本系统在边缘工程场景下的高容错性。

---

## 🛡️ 安全审计与开源许可证合规

### 1. 基于 Google OSV 的已知脆弱性匹配
在完成依赖拓扑梳理后，系统自动启动安全漏洞匹配引擎：
* **双通道协同**：并发请求 Google 开源漏洞库 `https://api.osv.dev/v1/querybatch`（在线模式）；若处于离线环境，无缝切换至内置的 6 大主流生态离线漏洞库；
* **规范化风险注入**：在生成的 CycloneDX 文件中写入标准的 `vulnerabilities` 节点，精确标注 CVE / GHSA 编号、CVSS 评分、受波及组件的 `bom-ref`、危害描述以及安全修复升级版本。

### 2. SPDX 开源许可证多级提取与规范化
* **多源抽取与规范化**：从构建清单提取原生的 `license` 声明；对于未显式声明的构件，结合包名特征与知识库进行推断，并通过 `normalize_spdx_id` 算法标准化为 SPDX 标准格式（如 `MIT`, `Apache-2.0`, `BSD-3-Clause` 等）。
* 在终端展示许可证分布比例，在 CycloneDX JSON 中输出标准化 `"licenses": [{"license": {"id": "..."}}]`。

---

## ⚡ 动态系统资源与吞吐量监控

为便于科学评估平台在大型工程环境中的开销表现，系统实现了动态硬件监控模块（[`src/analyze/dynamic_monitor.rs`](src/analyze/dynamic_monitor.rs)）：
* **性能指标采集**：采样并记录分析生命周期内的 **CPU 使用率峰值** 与 **物理常驻内存 (RSS RAM)**；
* **吞吐与效率统计**：度量各个语言生态处理耗时与构件生成吞吐率，数据可在控制台日志及桌面端面板中统一展示。

---

## 🚀 快速开始与实验复现

### 环境准备
- [Rust 编译器工具链](https://rustup.rs/) (建议 1.80+ 稳定版)
- C/C++ 编译工具链 (用于 Tree-sitter 原生运行时构建，如 MSVC, GCC 或 Clang)

### 编译构建
```bash
# 1. 获取项目源码
git clone https://github.com/bnbu-ds/sbom-generator.git
cd sbom-generator

# 2. 编译主程序与对比评测工具
cargo build --release --bins

# 生成的二进制位于：
# - 核心分析生成程序：target/release/sbom-generator
# - 对比评测实验程序：target/release/sbom_compare
```

### 命令行 CLI 使用说明
```bash
# 1. 扫描 test 目录下的 Juice Shop 工程并生成 CycloneDX 1.6 SBOM
./target/release/sbom-generator -i ./test/juice-shop -o ./test/juice-shop/juice-shop_sbom.json

# 2. 扫描并同步在终端打印彩色多语言依赖拓扑树与 CVE 告警
./target/release/sbom-generator -i ./test/juice-shop -o ./test/juice-shop/juice-shop_sbom.json --tree

# 3. 纯离线/沙箱模式运行（完全跳过外部 CLI 探针，使用静态 AST 责任链）
./target/release/sbom-generator -i ./test/juice-shop -o ./test/juice-shop/juice-shop_sbom.json -s --tree
```

#### CLI 参数表：
| 参数简写 | 参数全称 | 属性 | 说明 |
| :--- | :--- | :--- | :--- |
| `-i` | `--directory` | **必填** | 待扫描分析的目标工程根目录物理路径 |
| `-o` | `--output` | **必填** | 输出的 CycloneDX 1.6 标准 SBOM JSON 路径 |
| `-t` | `--tree` | 可选 | 在终端打印层次依赖拓扑树（带生态、许可证与漏洞内联告警） |
| `-s` | `--static-only` | 可选 | 强制仅使用静态 AST 责任链（纯离线环境或安全沙箱） |
| `-d` | `--debug` | 可选 | 开启详细调试日志，打印各子模块实例、文件路径与变量插值详情 |
| `-h` | `--help` | 可选 | 查看命令行帮助说明 |

---

### SBOM 对比评测工具使用 (`sbom_compare`)

使用独立的对比评测工具，可快速复现 `test/` 目录下的横向对比实验并重新导出报告：

```bash
# 以 Google Microservices Demo 为例进行基准评测对比
./target/release/sbom_compare \
  --file-a ./test/mircoservices/microservices-demo_sbom.json \
  --file-b ./test/mircoservices/sbom-cyclonedx.json \
  --export-markdown ./test/benchmark_report.md
```

---

## 🖥️ 桌面可视化客户端 (Tauri 2.0 GUI)

除 CLI 工具外，本项目还提供了基于 **Tauri 2.0 + 原生前端 + Apache ECharts** 构建的图形化工作台：

```bash
# 启动桌面端本地开发与热重载
cargo tauri dev

# 打包全平台原生独立安装包 (.msi / .exe / .dmg / .deb)
cargo tauri build
```

### 桌面端核心功能：
1. **全景依赖拓扑网络**：基于力导向动力学布局渲染超大依赖网络，支持节点流向箭头引导与滚轮缩放拖拽；
2. **安全风险雷达**：CVE 漏洞节点呈现高危警示红，支持一键切换「仅看风险组件」；
3. **抽屉式组件审查面板**：点击任意节点可在右侧抽屉中查阅 PURL、物理实例 ID、源码物理定位、SPDX 许可证与关联漏洞修复建议；
4. **自定义双 SBOM 横向对比工作台**：在 GUI 中任意选取两个 CycloneDX JSON 文件，实时计算召回率、Jaccard 相似度与生态矩阵分布，并支持一键复制学术论文实验对比报表。

---

## 📋 标准 CycloneDX 1.6 输出样例

生成的物料清单严格遵循国际 CycloneDX 1.6 规范：

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "timestamp": "2026-11-04T12:00:00Z",
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
      "type": "library",
      "name": "fastjson",
      "version": "1.2.68",
      "purl": "pkg:maven/com.alibaba/fastjson@1.2.68",
      "bom-ref": "pkg:maven/com.alibaba/fastjson@1.2.68?package-id=547c1a8e1b626f63",
      "licenses": [
        {
          "license": {
            "id": "Apache-2.0"
          }
        }
      ],
      "properties": [
        {
          "name": "syft:location:0:path",
          "value": "pom.xml"
        }
      ]
    }
  ],
  "dependencies": [
    {
      "ref": "pkg:maven/com.alibaba/fastjson@1.2.68?package-id=547c1a8e1b626f63",
      "dependsOn": []
    }
  ],
  "vulnerabilities": [
    {
      "id": "CVE-2022-25845",
      "source": {
        "name": "OSV.dev",
        "url": "https://osv.dev/vulnerability/CVE-2022-25845"
      },
      "ratings": [
        {
          "score": 9.8,
          "severity": "critical",
          "method": "CVSSv31"
        }
      ],
      "description": "Fastjson AutoType 反序列化远程代码执行漏洞 (RCE)",
      "recommendation": "建议升级至安全版本 >= 1.2.83",
      "affects": [
        {
          "ref": "pkg:maven/com.alibaba/fastjson@1.2.68?package-id=547c1a8e1b626f63"
        }
      ]
    }
  ]
}
```

---

## 🧪 自动化测试与质量保证

项目采用规范的单元测试与集成测试保障代码可靠性，包含 **47 项自动化测试**，覆盖核心解析器、图算法、漏洞匹配与动态探针等模块：

```bash
# 运行全部单元测试与集成测试
cargo test --lib
```

```text
running 47 tests
test analyze::producers::gradle::gradle_producer::tests::test_gradle_producer_use_file ... ok
test analyze::dynamic_monitor::tests::test_dynamic_monitor_empty_or_missing_dir_safe ... ok
test analyze::producers::go::go_producer::tests::test_parse_go_mod_with_replace_and_exclude ... ok
test analyze::producers::cargo::cargo_dynamic::tests::test_parse_cargo_metadata_json ... ok
test analyze::producers::go::go_dynamic::tests::test_parse_go_mod_graph_with_mvs ... ok
test analyze::producers::cargo::cargo_toml_producer::tests::test_cargo_workspace_inheritance ... ok
test analyze::producers::npm::npm_dynamic::tests::test_parse_npm_ls_json ... ok
test analyze::producers::pypi::pypi_lock_producer::tests::test_parse_poetry_lock_dag ... ok
test utils::license_resolver::tests::test_normalize_spdx_id_variants ... ok
test utils::osv_scanner::tests::test_parse_purl_and_offline_matching ... ok
test analyze::producers::maven::maven_file::tests::test_parse_pom_with_dependency_management ... ok
test analyze::sbom_generate::tests::test_analyze_polyglot_showcase_with_osv ... ok
...
test result: ok. 47 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.52s
```

---

## 📁 代码目录与模块结构

```text
sbom-generator/
├── Cargo.toml                    # 项目配置文件与依赖管理
├── build.rs                      # Tree-sitter C 语言原生编译脚本
├── ui/
│   └── index.html                # Tauri 2.0 桌面端单页面界面 (可视化拓扑与对比评测)
├── src-tauri/                    # Tauri 2.0 桌面框架与 Rust IPC 桥接层
├── test/                         # 毕设实测数据集与基准报告
│   ├── opentelemetry/            # CNCF OpenTelemetry Demo 实测数据 (vs Trivy)
│   ├── mircoservices/            # Google Microservices Demo 实测数据 (vs Trivy)
│   ├── juice-shop/               # OWASP Juice Shop 无锁边界实测数据 (vs Trivy)
│   └── benchmark_report.md       # 自动化对比评测实验报告样例
└── src/
    ├── main.rs                   # CLI 命令行入口与参数驱动
    ├── lib.rs                    # 核心库导出与多任务编排
    ├── report.rs                 # 依赖报表整合、SPDX 审计与 ASCII 树渲染
    ├── bin/
    │   └── sbom_compare.rs       # 独立 SBOM 对比评测工具二进制
    ├── model/                    # 数据实体模型 (Dependency, Location, Configuration)
    ├── sbom/                     # CycloneDX 1.6 标准构建与序列化
    ├── utils/                    # 通用工具组件
    │   ├── osv_scanner.rs        # Google OSV.dev 漏洞匹配引擎 (Batch + 离线库)
    │   ├── license_resolver.rs   # SPDX 开源许可证推断与标准化
    │   ├── cli_driver.rs         # 外部工具链动态探测与缓存 (CliLocator)
    │   ├── context_resolver.rs   # 变量插值与工作区上下文继承 (HierarchicalContext)
    │   ├── graph_utils.rs        # 4-Pass DAG 图引擎与拓扑排序
    │   └── tree_sitter/          # Tree-sitter 运行时绑定与源码行列计算
    └── analyze/
        ├── dynamic_monitor.rs    # 运行时 CPU/内存/吞吐量动态监控模块
        ├── sbom_generate.rs      # 多生态编排主入口
        └── producers/            # 语言生态专用解析器
            ├── cargo/            # Rust Cargo 生态 (Dynamic + Lock + Toml Workspace)
            ├── go/               # Go Modules 生态 (Dynamic Graph + go.work/mod/sum)
            ├── gradle/           # Gradle 生态 (Dynamic Tree + Groovy/Kotlin/TOML)
            ├── maven/            # Maven 生态 (Dynamic Tree + 双趟 POM AST)
            ├── npm/              # Node.js NPM 生态 (Dynamic + Lock + AST Json)
            └── pypi/             # Python PyPI 生态 (Dynamic + Locks + Req + Pyproject)
```

---

## 💡 总结与后续演进展望

本课题通过运用 Rust 语言的系统级控制能力与内存安全特性，设计并实现了一套具备工业级鲁棒性的多语言 SBOM 生成系统，通过了包含分布式微服务与无锁极限场景在内的 3 组真实工业数据集验证。

**后续演进方向包括**：
1. **支持 SPDX 2.3 / 3.0 双标准互转**：扩展序列化模块，实现 CycloneDX 与 SPDX 规范间的无损双向转换；
2. **引入 VEX (Vulnerability Exploitability eXchange) 可利用性声明**：细化漏洞状态（`affected` / `not_affected` / `in_triage`），降低供应链审查误报率；
3. **扩展跨服务 RPC 拓扑链路 (Service Call Graph)**：通过 Tree-sitter 进一步分析 gRPC / HTTP 客户端桩代码，将独立的微服务依赖子图串联为分布式业务调用调用网络。

---

## 📄 开源协议

本项目基于 [Apache-2.0 / MIT](LICENSE) 双重开源协议发布。
