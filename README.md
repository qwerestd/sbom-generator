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
  - [实验 3：全生命周期开发依赖覆盖评测 (`test/juice-shop/`)](#实验-3全生命周期开发依赖覆盖评测-testjuice-shop)
- [🛡️ 安全审计与开源许可证合规](#️-安全审计与开源许可证合规)
  - [1. 基于 Google OSV 的已知脆弱性匹配](#1-基于-google-osv-的已知脆弱性匹配)
  - [2. SPDX 开源许可证多级提取与规范化](#2-spdx-开源许可证多级提取与规范化)
- [⚡ 依赖加载可达性监测与安全沙箱策略](#-依赖加载可达性监测与安全沙箱策略)
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
| **Python** | `PyPI` | 宿主机受信任解释器 + `pip inspect` | `poetry.lock`, `uv.lock`, `requirements.txt` | BFS 可达性剪枝、`-r` 级联包含、PEP 621 与 Poetry 规范 |

---

## 🏗️ 系统总体架构与解析流程

```text
               待分析目标工程根目录 (Target Project Path)
                                 │
                ┌────────────────┴────────────────┐
                ▼                                 ▼
     [ 动态探针分析引擎 ]               [ 静态语法分析责任链 ]
     • 宿主机受信任工具链探测            • 目录遍历与构建产物剪枝过滤
     • 禁用被扫仓库内不可信解释器        • 单子项目领地作用域聚类 (Scope Cluster)
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
       [ OSV 漏洞匹配器 ]  [ 许可证标准化引擎 ]  [ 依赖加载可达性监测 ]
       • 在线 Batch API    • SPDX ID 标准化     • 静态源码动态导入扫描
       • 内置离线漏洞库    • 本地多级清单提取   • --allow-exec 沙箱钩子探测
                │                │                │
                └────────────────┼────────────────┘
                                 ▼
      ┌──────────────────────────┴──────────────────────────┐
      ▼                                                     ▼
[ CycloneDX 1.6 标准 JSON ]                       [ 交互式终端 / Tauri 2.0 GUI ]
• 规范化顶级定序结构                              • 层次分明的 ASCII 依赖拓扑树
• 物理实例隔离与相对路径源码锚点                  • 力导向动力学图谱与漏洞红点审查
• PURL / CVE / SPDX 全量富化                     • 双 SBOM 横向对比实验评测台
```

---

## 📊 实测对比实验与基准分析 (`test/` 数据集)

为验证本系统在真实工业代码环境中的有效性与可靠性，课题选取了 3 个具有不同架构特性的经典开源项目作为测试基准，放置于 [`test/`](test/) 目录下，与当前主流安全扫描工具 **Aqua Security Trivy (v0.76.1)** 进行同台严格对照实验。所有报告均同时披露**目标生态基准覆盖率 (Target Eco Coverage)** 与**全仓库跨生态总覆盖率 (Total Repo Coverage)** 两个口径。

### 实验 1：大型多语言微服务架构对齐评测 (`test/opentelemetry/`)

* **测试对象**：CNCF 旗舰级分布式遥测基准系统 [OpenTelemetry Demo](https://github.com/open-telemetry/opentelemetry-demo)，包含多语言微服务协作。
* **数据源**：
  - 本系统输出：[`test/opentelemetry/opentelemetry-demo_sbom.json`](test/opentelemetry/opentelemetry-demo_sbom.json)
  - Trivy 对照产物：[`test/opentelemetry/opentelemetry-trivy.json`](test/opentelemetry/opentelemetry-trivy.json)
  - 对比评测报告：[`test/opentelemetry/benchmark_report.md`](test/opentelemetry/benchmark_report.md)

在严格剔除 `type == "application"` 本地工程虚拟根节点并完成 PURL 规范化对齐后，两款工具在各语言生态的第三方依赖库对比数据如下：

| 语言生态分类 | 本系统：实例数 (唯一包) | 参照工具：实例数 (唯一包) | 共同唯一包 | 实例差值 (Delta) | 参照基准覆盖率 (%) | 差异机制与实验分析 |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **Cargo (Rust)** | **305** (305) | 305 (305) | **305** | 0 (持平) | **100.0%** (305/305) | **完全一致**：解码 `%2B` 与 `+` 编码差异后，305 个第三方 Crate 100% 精确对齐。 |
| **PyPI (Python)** | **525** (254) | 525 (254) | **254** | 0 (持平) | **100.0%** (254/254) | **完全一致**：剥离本地服务目录节点后，物理实例数（525）与唯一包数（254）100% 吻合。 |
| **Golang (Go)** | **151** (95) | 153 (97) | **95** | -2 | **97.9%** (95/97) | **高覆盖率对齐**：剔除 `go.sum` 冗余历史条目后，精确对齐 95/97 个 `go.mod` 核心依赖。 |
| **NPM (Node.js)** | **1959** (1251) | 925 (801) | **801** | **+1034** | **100.0%** (801/801) | **全生命周期覆盖**：100% 覆盖 801 个生产依赖；多出的 450 个唯一包经核查 `package-lock.json` **100% (450/450)** 为 `"dev": true` 开发测试依赖。 |
| **Maven / Gradle** | **18** (17) | **0** (0) | 0 | **+18** | **100.0% (基准漏检)** | **无锁 AST 补盲**：Trivy 因缺失 `gradle.lockfile` 漏检 Java/Kotlin 服务，本系统通过 AST 成功恢复 18 个依赖。 |
| **非目标语言 (Gem/Hex/NuGet)** | 0 (0) | 222 (219) | 0 | -222 | 非目标设计边界 | 属于未适配辅助服务（Ruby 132 / Erlang 57 / .NET 30），归入后续扩展工作。 |
| **合计（双口径汇总）** | **2958** (1922) | 2130 (1676) | **1455** | **+828** | **目标生态: 99.86%** (1455/1457)<br>**全仓总体: 86.81%** (1455/1676) | 目标 5 大核心生态覆盖率达 **99.86%**；计入 3 个未适配语言后的全仓库总体覆盖率为 **86.81%**。 |

> **严谨对比方法学说明（Methodology）**：
> 1. **剔除本地工程虚拟根（`application` 节点过滤）**：严格排除 `type == "application"` 及版本为 `0.0.0` 的本地目录合成节点，仅统计真实第三方开源库（`type == "library"`），避免将本地服务文件夹名或 `go 1.2x` 语言指令计入第三方依赖增量。
> 2. **NPM 扩展依赖的 `"dev": true` 实证核查**：针对本系统在 `opentelemetry-demo` 中额外识别出的 **450 个** 唯一 NPM 包，对仓库内全部 4 个 `package-lock.json`（根目录、`src/frontend`、`src/payment`、`src/react-native-app`）进行字段级比对，证实 **450 个包中有 450 个（100.0%）在锁文件中显式标记为 `"dev": true`**。这是因为 Trivy 默认跳过 `devDependencies`，而本系统保留了开发与测试工具链依赖。
> 3. **双口径覆盖率披露**：同时报告**目标生态基准覆盖率（99.86%，1455/1457）**与包含 Ruby/Erlang/.NET 在内的**全仓库跨生态总覆盖率（86.81%，1455/1676）**，不隐瞒未适配语言边界。

---

### 实验 2：云原生分布式微服务基准与实例隔离 (`test/mircoservices/`)

* **测试对象**：Google 官方开源的经典云原生微服务靶场 [Google Cloud Microservices Demo](https://github.com/GoogleCloudPlatform/microservices-demo)。
* **数据源**：
  - 本系统输出：[`test/mircoservices/microservices-demo_sbom.json`](test/mircoservices/microservices-demo_sbom.json)
  - Trivy 对照产物：[`test/mircoservices/sbom-cyclonedx.json`](test/mircoservices/sbom-cyclonedx.json)
  - 自动生成对比报告：[`test/benchmark_report.md`](test/benchmark_report.md)

在清理测试目录嵌套副本并重新生成后，运行 `sbom_compare` 对比引擎得到的综合指标如下：

| 评估指标 (Metric) | 本系统 (sbom-generator) | 参照工具 (Trivy v0.76.1) | 差异与机制说明 |
| :--- | :---: | :---: | :--- |
| **第三方库物理实例数 (Instances)** | **903 个** | 846 个 | Go (178=178)、PyPI (184=184) 实例数完全一致；NPM 多保留子模块嵌套实例 |
| **去重唯一第三方包数 (Unique PURLs)** | **478 个** | 476 个 | 100% 覆盖全部 476 个基准包，并扩展发现 **+2 个** 无锁 Gradle 依赖 |
| **目标生态基准覆盖率 (Target Eco Coverage)** | **100.00%** (476/476) | 基准对照 (100%) | Go (82/82)、NPM (262/262)、PyPI (132/132) 唯一包实现 100% 精确对齐 |
| **全仓库跨生态总覆盖率 (Total Repo Coverage)** | **100.00%** (476/476) | 基准对照 (100%) | 全仓库所有生态唯一包 100% 覆盖 |
| **无锁 Gradle 模块 AST 补盲** | **2 个** | 0 个 | 通过 AST 静态穿透恢复 `src/adservice/build.gradle` 中的 2 个依赖 |
| **多模块大仓实例冲突隔离** | **支持 (`instance_id`)** | 不支持 (全局扁平合并) | 基于相对路径哈希盐隔离不同微服务的同名依赖实例 |

---

### 实验 3：全生命周期开发依赖覆盖评测 (`test/juice-shop/`)

* **测试对象**：OWASP 著名全栈靶场工程 [OWASP Juice Shop](https://github.com/juice-shop/juice-shop)（包含根目录与 `frontend/` 两个子工程 `package-lock.json`）。
* **数据源**：
  - 本系统输出：[`test/juice-shop/juice-shop_sbom.json`](test/juice-shop/juice-shop_sbom.json)
  - Trivy 对照产物：[`test/juice-shop/juice-shop-trivy.json`](test/juice-shop/juice-shop-trivy.json)
  - 自动生成对比报告：[`test/juice-shop/benchmark_report.md`](test/juice-shop/benchmark_report.md)

| 评估指标 (Metric) | 本系统 (sbom-generator) | 参照工具 (Trivy v0.76.1) | 差异与实证归因分析 |
| :--- | :---: | :---: | :--- |
| **第三方库物理实例数 / 唯一包数** | **1,125 个** | 655 个 | 剔除本地 `application` 根节点后，本系统多检出 +470 个组件 |
| **目标生态基准覆盖率 (Target Eco Coverage)** | **99.85%** (654/655) | 基准对照 (100%) | 精确覆盖参照工具 654/655 个核心生产依赖 |
| **全仓库跨生态总覆盖率 (Total Repo Coverage)** | **99.85%** (654/655) | 基准对照 (100%) | 单一 NPM 生态工程，目标生态口径与全仓口径一致 |
| **扩展依赖发现增量 (`+471` 唯一包) 归因** | **468 个 `dev: true` + 3 个生产包** | 默认忽略 `dev` 依赖 | 经核对 `package-lock.json` 与 `frontend/package-lock.json`，额外检出的 471 个包中有 **468 个 (99.36%)** 为 `"dev": true` 的测试/构建期依赖 |

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

## ⚡ 依赖加载可达性监测与安全沙箱策略

为辅助识别实际被业务代码引用的活跃依赖，同时严格防范扫描不可信仓库时的代码执行风险，系统实现了分层安全设计的依赖加载监测模块（[`src/analyze/dynamic_monitor.rs`](src/analyze/dynamic_monitor.rs)）：
* **默认安全模式（纯静态导入与编译痕迹分析，`allow_exec = false`）**：默认**禁止执行被扫描仓库中的任何入口脚本或测试代码**，仅通过源码静态分析扫描 `require()`、`import()`、`importlib.import_module()`、`__import__` 等动态导入语句以及本地构建产物痕迹（如 `node_modules`、`__pycache__`、`target`）。
* **显式受控运行时探针（`--allow-exec` 显式授权）**：仅当用户在受信任环境下显式传入 `--allow-exec` 参数时，才启动带超时熔断的运行时模块加载钩子（Node.js `Module._load` 拦截与 Python `sys.modules` 快照）；且**严禁调用被扫描仓库目录内自带的 `.venv/venv` 解释器二进制**，强制仅使用宿主机受信任的系统解释器。
* **严谨的可达性状态表述**：对于静态与动态阶段均未观测到加载痕迹的组件，前端与报告统一标记为 **`⚪ 未观测到加载（不代表不可达）`**，避免因分支覆盖不全而误导用户将潜在受影响依赖直接豁免。

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
# 1. 扫描目标工程并生成 CycloneDX 1.6 SBOM（默认关闭入口代码执行，安全扫描）
./target/release/sbom-generator -i /path/to/project -o ./output_sbom.json

# 2. 扫描并同步在终端打印彩色多语言依赖拓扑树与 CVE 告警
./target/release/sbom-generator -i /path/to/project -o ./output_sbom.json --tree

# 3. 纯离线/静态模式运行（完全跳过外部包管理器 CLI 探针，仅使用静态 AST 责任链）
./target/release/sbom-generator -i /path/to/project -o ./output_sbom.json -s --tree

# 4. 在受控沙箱中显式开启运行时入口加载探针（可选）
./target/release/sbom-generator -i /path/to/project -o ./output_sbom.json --allow-exec
```

#### CLI 参数表：
| 参数简写 | 参数全称 | 属性 | 说明 |
| :--- | :--- | :--- | :--- |
| `-i` | `--directory` | **必填** | 待扫描分析的目标工程根目录物理路径 |
| `-o` | `--output` | **必填** | 输出的 CycloneDX 1.6 标准 SBOM JSON 路径 |
| `-t` | `--tree` | 可选 | 在终端打印层次依赖拓扑树（带生态、许可证与漏洞内联告警） |
| `-s` | `--static-only` | 可选 | 强制仅使用静态 AST 责任链（纯离线环境或禁用包管理器 CLI） |
| 无 | `--allow-exec` | 可选 | 显式允许在受控沙箱中启动运行时入口模块加载探针（默认关闭） |
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
│   ├── juice-shop/               # OWASP Juice Shop 全栈靶场实测数据 (vs Trivy)
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
        ├── dynamic_monitor.rs    # 依赖加载可达性静态分析与受控沙箱探测模块
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
