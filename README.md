# SBOM Studio

基于 Rust 的多语言软件物料清单（Software Bill of Materials，SBOM）生成与比较工具。

输入项目目录，收集支持的清单、锁文件及可选的安装包、归档元数据，输出 **CycloneDX 1.6 JSON**。项目提供生成器 CLI、SBOM 对比 CLI，以及基于 Tauri 2 的桌面界面。

工具分别记录依赖身份、可确定版本、版本约束、来源位置及可获得的依赖关系。未知版本声明仍可进入库存，不冒充精确版本，也不用于推断漏洞命中。

## 快速开始

以下命令均在仓库根目录执行，示例使用 PowerShell。

### 扫描自带示例

```powershell
cargo run --bin sbom-generator -- -s -i "examples/polyglot-showcase" -o "sbom.json"
```

`-s` 关闭包管理器动态解析；输出保存在当前目录的 `sbom.json`。`cargo run` 后的 `--` 分隔 Cargo 参数与生成器参数。

### 扩大采集范围

```powershell
cargo run --bin sbom-generator -- -i "C:\projects\sentry-master" -o "sentry-sbom.json" --scan-mode all
```

这会扫描源码输入、支持的安装元数据与归档元数据，并尝试适用的包管理器解析。`all` 表示合并当前支持的采集范围，不代表支持所有生态或能恢复全部依赖。

如果只想读取已有文件，不调用包管理器：

```powershell
cargo run --bin sbom-generator -- -s -i "C:\projects\sentry-master" -o "sentry-static.json" --scan-mode all
```

输出文件的父目录需要已经存在。指定已有文件时会覆盖该输出；需要保留历史结果时，请使用不同文件名。

## 构建与运行

源码构建需要可编译当前依赖的 Rust/Cargo 工具链，以及用于编译 Tree-sitter 原生代码的 C/C++ 工具链。Windows 使用 MSVC 工具链时，需要 Visual Studio C++ Build Tools。

```powershell
cargo build --release --bins
```

| 程序 | Windows 产物 | Linux / macOS 产物 |
| --- | --- | --- |
| SBOM 生成器 | `target/release/sbom-generator.exe` | `target/release/sbom-generator` |
| SBOM 对比器 | `target/release/sbom_compare.exe` | `target/release/sbom_compare` |

编译后直接运行：

```powershell
.\target\release\sbom-generator.exe -i "C:\projects\sentry-master" -o "sentry-sbom.json" --scan-mode all
```

也可以将生成器安装到 Cargo 的可执行文件目录：

```powershell
cargo install --path . --bin sbom-generator
sbom-generator -s -i "examples/fullstack-ecommerce" -o "sbom.json"
```

更新源码后需要重新编译或安装。旧的 `release` 可执行文件不会因修改源码而自动更新。

## 生成器参数

```text
sbom-generator -i DIRECTORY -o OUTPUT [options]
```

| 参数 | 说明 |
| --- | --- |
| `-i, --directory PATH` | 待扫描目录，必填 |
| `-o, --output PATH` | CycloneDX JSON 输出文件，必填 |
| `--scan-mode MODE` | `source`、`installed`、`artifacts` 或 `all`，默认 `source` |
| `--exclude-dir PATH` | 排除目录名或相对扫描根目录的目录路径，可重复指定；不支持 glob |
| `-s, --static-only` | 不调用包管理器，不执行运行时监测；仍可读取扫描模式允许的安装和归档元数据 |
| `-d, --debug` | 输出调试与解析诊断信息 |
| `-t, --tree` | 显式打印依赖树；默认不打印全量依赖明细表 |
| `--allow-exec` | 允许可选的项目入口执行探针，默认关闭；与 `-s` 同用时不执行 |
| `-h, --help` | 显示帮助 |

默认模式可能运行包管理器命令，并由包管理器访问网络、解析依赖或写入缓存。`--allow-exec` 还可能执行项目入口，仅应对可信项目启用。包管理器解析与运行时入口监测是两件不同的事。

### 扫描模式

| 模式 | 源码清单与锁文件 | npm / Python 安装元数据 | 构建目录与支持的归档元数据 |
| --- | --- | --- | --- |
| `source` | 是 | 否 | 否 |
| `installed` | 是 | 是 | 否 |
| `artifacts` | 是 | 否 | 是 |
| `all` | 是 | 是 | 是 |

模式决定文件采集范围，`-s` 决定是否运行包管理器，两者可以组合使用。

默认源码扫描跳过 `node_modules`、`.venv`、`venv`、`build`、`dist`、`target` 等目录，相应扩展模式会开放对应目录。`.git`、`.hg`、`.svn`、`.idea`、`.vscode`、`.gradle`、`.vendor`、`__pycache__`、`bower_components` 等仍默认跳过。目录遍历不跟随符号链接。

例如，扩大采集但排除安装目录与指定子目录：

```powershell
cargo run --bin sbom-generator -- -s -i "C:\projects\demo" -o "demo-sbom.json" --scan-mode all --exclude-dir node_modules --exclude-dir "legacy/generated"
```

## 支持范围

### 源码与包管理器

| 生态 | 主要静态输入 | 可选包管理器解析 |
| --- | --- | --- |
| JavaScript / npm | `package.json`、`package-lock.json` v1/v2/v3、`npm-shrinkwrap.json`、`pnpm-lock.yaml`、Yarn Classic/Berry 的 `yarn.lock`、文本 `bun.lock` | `npm ls --json --all` |
| Python / PyPI | `requirements.txt`、`pyproject.toml`、`Pipfile`、`poetry.lock`、`uv.lock`、`Pipfile.lock` | `pip inspect` |
| Rust / Cargo | `Cargo.toml`、`Cargo.lock` | `cargo metadata --all-features` |
| Go Modules | `go.mod` | 模块图、结构化模块信息与源码包导入图 |
| Java / Maven | `pom.xml`，包括可获得的父子模块上下文、profile 与构建插件声明 | `mvn dependency:tree` |
| Java / Kotlin / Gradle | `build.gradle`、`build.gradle.kts`、`libs.versions.toml`、受支持的 Gradle 锁文件 | `dependencies` 与 `buildEnvironment` |

静态扫描不要求安装上述包管理器。动态解析依赖本机工具、项目环境、缓存和网络条件；探测失败时会尝试静态来源，成功也不会屏蔽静态补充输入。

各生态的边界：

- **npm**：pnpm 支持多 YAML 文档及 snapshots，保留 peer 上下文实例。特殊协议、别名、工作区及依赖边解析仍有格式边界；二进制 `bun.lockb` 尚未支持。
- **Python**：静态清单覆盖可选依赖、Poetry 分组、`dependency-groups` 和构建依赖声明。动态结果对应当前解释器、环境条件和启用的 extras，不等同于锁文件中的跨平台全部分组。
- **Cargo**：保留目标平台依赖声明；锁文件中的组件不会仅因不可达或环形子图而被删除。来源参与锁文件实例区分。
- **Go**：`go.sum` 是校验信息，不单独产生组件；`go.work` 不作为工作区解析依据，动态命令使用 `GOWORK=off`。本地替换可保留无版本组件。
- **Maven**：补充未激活 profile 与构建插件声明，并标注条件；不会自动激活所有 profile，也不保证展开这些条件分支的全部传递依赖。
- **Gradle**：不再只查询 `runtimeClasspath`，实际覆盖仍取决于构建能够报告和解析的配置。任意构建脚本的动态逻辑不能仅靠静态文本完整求值。

### 安装元数据与归档

| 来源 | 当前读取的元数据 |
| --- | --- |
| npm 安装目录 | 包的 `package.json` |
| Python 安装目录 | `METADATA`、`PKG-INFO` |
| JAR / WAR / EAR / ZIP | 内部的 Maven `pom.properties` |
| wheel 及支持的 ZIP 归档 | 内部的 `.dist-info/METADATA` |

这些能力读取元数据，不导入包代码、不解压文件到项目目录。归档读取设有条目数与元数据大小限制。嵌套归档不递归；缺少支持的元数据时，不凭文件名判断依赖，相关情况记录在诊断中。

当前不提供通用的任意二进制依赖识别，也不因使用 `all` 自动支持 NuGet、Composer、RubyGems 等其他生态。

## 输出如何理解

| 字段 | 含义 |
| --- | --- |
| `components` | 组件记录，包括库与明确识别的本地应用 |
| `name`、`version` | 组件名称及能够确定的版本；未知版本不伪造 |
| `purl` | Package URL，表示包身份及可获得的版本信息 |
| `bom-ref` | SBOM 内的组件引用，用于连接依赖关系 |
| `dependencies` | 可解析的有向依赖边，引用组件的 `bom-ref` |
| `licenses` | 可获得的许可证声明 |
| `vulnerabilities` | 可获得的漏洞记录与受影响组件引用 |
| `properties` | 版本约束、来源、解析方法、条件及监测证据等 |

版本无法解析时，组件仍可保留，并通过 `sbom:version:status=unresolved` 标记；版本约束可见于 `sbom:version:requirement`。例如 `foo >=1.0` 不会被当作已确定的 `foo@1.0`。

多路解析只在项目、包版本与实例上下文能够明确对应时融合证据。不同项目、安装位置或 peer 上下文可能保留独立记录。记录数多不等于覆盖更好，也不能仅凭记录数量推断物理安装数量。

组件库存与图关系分开处理：无法确定一条边时，不应把整个包从库存中删除；没有悬空引用也不能证明所有依赖边都已恢复。

### 诊断与证据

| 属性 | 用途 |
| --- | --- |
| `<输出文件>.scan.json` | 独立的扫描诊断文件，保存阶段日志和详细来源证据；不嵌入 SBOM |
| 诊断文件中的组件 `properties` | 解析器、来源文件、融合证据等；具体字段依来源而定 |
| `sbom:analysis:method` | 区分静态、包管理器、安装或归档元数据等解析方法 |
| `syft:location:*:path` | 来源位置 |
| `sbom:dependency:declarations` | 部分解析器保留的依赖声明及条件 |
| `sbom:graph:*`、`sbom:python:*` | 部分解析器提供的图、来源或歧义诊断 |

并非所有解析器都能逐条解释全部跳过项。扫描成功表示生成了输出，不表示所有来源均已完整解析。

### 许可证、漏洞与运行时证据

许可证采用可获得的 SPDX ID、表达式或名称，不按包名猜测。当前输出格式是 CycloneDX JSON，**不是 SPDX SBOM**。

漏洞结果来自可用的 OSV 在线查询或离线匹配规则，覆盖受数据源与版本信息限制。未知版本不用于推断漏洞命中。许可证字段存在不等于完成合规审查，漏洞记录也不等于漏洞已经可以利用。

| 状态或属性 | 含义 |
| --- | --- |
| `sbom:source:referenced=true` | 源码中发现引用，不证明实际执行 |
| `sbom:runtime:status=loaded` | 探针观测到加载并关联到组件 |
| `sbom:runtime:status=dormant` | 对应监测未观测到该组件加载 |
| `sbom:runtime:status=untraced` | 未形成运行时加载判定 |

入口监测主要面向 Node.js 和 Python，需要显式启用 `--allow-exec`。`loaded=0` 不表示没有使用依赖，`dormant` 也不表示依赖不可达或可以安全删除。

## 比较两份 SBOM

对比器读取已有 CycloneDX JSON，不重新扫描源码。

```powershell
cargo run --bin sbom_compare -- -a "ours.json" -b "trivy.json" -o "comparison.md" --json-output "comparison.json"
```

限制比较范围：

```powershell
cargo run --bin sbom_compare -- -a "ours.json" -b "syft.json" -o "comparison.md" --ecosystems npm,pypi
```

| 参数 | 说明 |
| --- | --- |
| `-a, --our-sbom PATH` | A：待测 SBOM |
| `-b, --competitor-sbom PATH` | B：参照 SBOM |
| `-o, --output PATH` | Markdown 比较报告 |
| `--json-output PATH` | 可选的结构化比较报告 |
| `--ecosystems LIST` | 逗号分隔的目标生态，默认 `cargo,golang,maven,npm,pypi` |
| `--include-applications` | 纳入 `application` 组件，默认排除 |
| `--exclude-zero-versions` | 排除 `0.0.0` / `v0.0.0`，默认保留 |
| `--reference-version VERSION` | 记录参照工具版本，不改变匹配计算 |
| `-h, --help` | 显示帮助 |

建议显式指定所有输入、输出路径。输出父目录需存在；报告不能覆盖输入 SBOM，Markdown 与 JSON 报告也不能使用相同路径。

### 指标口径

| 指标 | 比较对象 |
| --- | --- |
| 包身份 | 规范化后的生态与包名，忽略版本 |
| 精确包版本 | 去重后的包身份与确定版本 |
| 记录重数 | 同一包版本的记录次数，交集按两侧较小计数计算 |
| 来源路径记录 | 包版本与来源路径的组合 |
| 依赖边 | 各自解析引用后，目标生态内确定版本组件之间的有向包级关系 |

```text
相对 B 重合率 = 共同精确包版本数 / B 的精确包版本数
相对 A 重合率 = 共同精确包版本数 / A 的精确包版本数
Jaccard       = 共同精确包版本数 / 双方精确包版本并集大小
```

空分母显示 `N/A`。包版本集合键会移除 PURL qualifier/subpath，并规范化部分名称、编码与版本表示；同名同版本的不同来源可能在这一层合并，来源位置应单独比较。

版本范围、未知版本和 `version` / PURL 版本冲突不进入精确匹配。同包不同版本单列版本差异；仅一侧报告的包身份与仅一侧报告的包版本是不同概念。

**重合率不是准确率或召回率，Trivy、Syft 等参照结果也不是独立真值。** 比较前应对齐源码提交、平台、开发/测试依赖范围、环境和工具配置。许可证、漏洞与运行时证据不计入组件重合率。

### 生成 Trivy / Syft 参照文件

已安装相应工具后，针对同一份源码分别生成 CycloneDX JSON：

```powershell
trivy fs --format cyclonedx --include-dev-deps --output "trivy-sbom.json" "C:\projects\sentry-master"
syft scan "dir:C:\projects\sentry-master" -o "cyclonedx-json=syft-sbom.json"
```

Trivy 这里显式包含其支持的开发依赖；两工具的生态、来源和依赖范围仍可能不同。上述命令用于生成 SBOM，不应当作已执行完整漏洞扫描的证明。

## 桌面界面与 compare 页面

安装 Tauri 2 CLI 及对应平台的开发依赖后，在仓库根目录运行：

```powershell
cargo tauri dev
```

主界面提供项目扫描、SBOM 导入、组件与漏洞列表、原始 JSON 和依赖图。桌面扫描入口当前使用默认源码范围；扩展扫描模式通过 CLI 选择，生成后可以导入桌面查看。

compare 页面支持 A、B 及可选 C 三份文件，分别计算 A–B、A–C、B–C：

- KPI 中的目标生态相对重合率以 **B 为参照**，不是三方交集比例。
- 柱状图可切换组件记录数与唯一包版本数，悬停可同时查看两种数量。
- 三方图中绿色表示全部已载入工具共有，蓝/橙/紫表示单工具独有，黄色表示恰好两个工具共有。两份文件时按双方集合展示。
- 网络图按精确包版本合并节点；虚线为布局辅助线，不表示依赖关系，更不是运行时调用证明。
- 未知版本单独展示，不计入精确版本重合率。表格展示行数不一定等于去重包身份数。
- 可复制 Markdown 或导出 JSON；对比页面不执行运行时探测。

图表依赖 ECharts CDN，图表功能需要能够加载该资源。CLI 不依赖前端图表库。内置快捷样本需要对应的 `test/` 文件；打包分发时不能假设所有本地样本都随程序提供。

## 示例与项目结构

| 路径 | 内容 |
| --- | --- |
| [examples/fullstack-ecommerce](examples/fullstack-ecommerce/) | 电商多语言示例 |
| [examples/polyglot-showcase](examples/polyglot-showcase/) | 多生态解析示例 |
| [examples/security-edgecases](examples/security-edgecases/) | 版本与安全边界示例 |
| [test/controlled](test/controlled/) | 受控输入及预期结果 |
| [test](test/) | 真实项目的 SBOM 对照文件与说明 |
| [tests](tests/) | CLI、解析、Schema、压力及前端回归测试 |

```text
src/
  main.rs                     生成器 CLI
  bin/sbom_compare.rs         对比 CLI
  compare.rs                  Rust 比较核心
  analyze/sbom_generate.rs    解析调度与证据采集
  analyze/inventory.rs        来源融合
  analyze/installed.rs        安装与归档元数据
  analyze/producers/          各生态解析器
  analyze/dynamic_monitor.rs  源码引用与可选入口监测
  sbom/generate.rs            CycloneDX 输出
  model/                     组件、配置与位置模型
  utils/                     版本、图、许可证与漏洞工具
ui/                          主页面、compare 页面与 JS 比较核心
src-tauri/                   Tauri 桌面后端
resources/schemas/           本地 JSON Schema
misc/                        辅助评测脚本
```

## 测试与验证

```powershell
cargo test --tests
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```

前端与比较一致性检查需要 Node.js。先构建对比 CLI，才能同时检查 Rust 与 JavaScript 的结果一致性：

```powershell
cargo build --bin sbom_compare
node --test tests/ui_regressions.cjs tests/compare_core.cjs
```

针对采集链运行测试：

```powershell
cargo test --lib
cargo test --test discovery_inventory --test controlled_schema --test scan_failures --test stress_tests
```

`schema_validation`、`sbom_accuracy` 等测试还会读取历史 SBOM 快照。历史文件的源码版本、生成器版本及合法性需要单独核对；快照失败不能用修改统计数字来掩盖。测试状态与覆盖率应以当前代码和实际测试输出为准，本文不承诺固定通过数量。

## 常见问题

**为什么记录少，但重合率很高？** 同一个包版本可以在多个来源出现。记录数统计条目，精确重合率比较去重集合，两者不同。

**为什么扫描后仍有未知版本？** 清单可能只有范围、标签、URL 或本地路径，没有足够证据得到确定版本。工具保留声明，而不是猜测版本。

**为什么 `all` 也会漏依赖？** 它只合并已实现的采集能力。未知格式、无元数据归档、未解析的构建条件、排除目录或缺失环境仍会影响结果，应检查扫描诊断。

**为什么没有许可证或漏洞？** 可能缺少匹配证据或数据源覆盖，不能据此认定没有许可证要求或没有漏洞。

**为什么还看到旧的控制台明细表？** 确认运行的是重新编译后的程序。默认不再自动打印全量明细；`--tree` 是显式的依赖树输出。

**为什么动态探测失败但生成了文件？** 其他静态来源可能仍然有效。检查诊断，区分“生成了库存”和“所有来源均完整解析”。

## 许可证

本项目采用 [Apache License 2.0](LICENSE)。第三方组件遵循各自许可证。
