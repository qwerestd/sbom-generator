# SBOM Studio

使用 Rust 开发的多语言软件物料清单（Software Bill of Materials，SBOM）生成工具。输入项目目录后，工具自动识别支持的包管理器文件，提取组件、版本及可获得的依赖关系，输出 **CycloneDX 1.6 JSON**，用于后续漏洞分析、许可证核查与软件供应链审计。

项目以 CLI 为核心，同时提供 SBOM 对比工具和 Tauri 2 桌面界面。当前不输出 SPDX 格式的 SBOM；SPDX ID 和表达式用于表示许可证。

## 主要功能

- 支持 Python、JavaScript、Java/Kotlin、Go 和 Rust 五类语言生态。
- 遍历子项目，处理同一仓库中的多种包管理器。
- 支持清单、锁文件及可选包管理器动态解析，提取可获得的传递依赖。
- 输出组件名称、确定版本、PURL、实例引用 bom-ref、来源位置和可获得的许可证。
- 提供依赖树、组件集合对比、OSV 漏洞信息和可选入口加载监测。

## 安装与构建

从源码构建需要 Rust/Cargo，以及用于编译 Tree-sitter 原生代码的 C/C++ 工具链。Windows 推荐使用 Rust MSVC 工具链和 Visual Studio C++ Build Tools。

在仓库根目录运行：

~~~bash
cargo build --release --bins
~~~

| 工具 | Windows 产物 | Linux / macOS 产物 |
| --- | --- | --- |
| 生成器 | target/release/sbom-generator.exe | target/release/sbom-generator |
| 对比器 | target/release/sbom_compare.exe | target/release/sbom_compare |

也可以安装生成器到 Cargo 的可执行文件目录：

~~~bash
cargo install --path . --bin sbom-generator
~~~

静态扫描不要求安装各语言包管理器。动态解析需要对应工具及适用的项目环境。源码更新后应重新构建发布版。

## 快速开始

使用仓库自带的示例执行静态扫描：

~~~powershell
# Windows PowerShell，在仓库根目录运行
.\target\release\sbom-generator.exe -i .\examples\fullstack-ecommerce -o .\sbom.json -s
~~~

~~~bash
# Linux / macOS，在仓库根目录运行
./target/release/sbom-generator -i ./examples/fullstack-ecommerce -o ./sbom.json -s
~~~

输出文件的父目录必须已经存在。指定已有输出文件时，扫描结果会覆盖该文件。

已安装到 PATH 后，可直接使用以下命令；否则请替换为构建产物路径：

~~~bash
# 静态扫描并显示依赖树
sbom-generator -i ./examples/polyglot-showcase -o ./sbom.json -s --tree

# 默认模式：尝试适用的包管理器解析，必要时回退到静态解析
sbom-generator -i ./project -o ./sbom.json

# 允许入口执行监测，并输出详细诊断信息
sbom-generator -i ./project -o ./sbom-runtime.json --allow-exec -d
~~~

## CLI 参数

~~~text
sbom-generator -i DIRECTORY -o OUTPUT [options]
~~~

| 参数 | 用途 |
| --- | --- |
| -i, --directory | 待扫描目录，必填 |
| -o, --output | 输出 JSON 文件，必填 |
| -s, --static-only | 仅解析清单和锁文件，跳过包管理器动态探针 |
| -t, --tree | 显示依赖树摘要 |
| -d, --debug | 显示解析及探针诊断信息 |
| --allow-exec | 允许可选的运行时入口执行探针，默认关闭 |
| -h, --help | 显示帮助 |

默认模式可能启动包管理器进程；--allow-exec 还可能执行项目入口，应仅用于可信项目。与 -s 同时使用时，运行时监测不会执行。

同一生态包含多个独立清单目录时，编排器优先使用完整静态解析链，避免根项目探针掩盖子项目。扫描成功不表示每个动态探针均成功。

## 支持的输入

| 生态 | 主要静态输入 | 可选动态解析 |
| --- | --- | --- |
| Python / PyPI | requirements.txt、pyproject.toml、poetry.lock、uv.lock、Pipfile.lock | pip inspect |
| JavaScript / npm | package.json、package-lock.json | npm ls |
| Java / Maven | pom.xml | mvn dependency:tree |
| Java、Kotlin / Gradle | build.gradle、build.gradle.kts、libs.versions.toml、锁文件及属性文件 | Gradle dependencies |
| Go Modules | go.mod、go.sum、go.work | Go 模块图及模块解析结果 |
| Rust / Cargo | Cargo.toml、Cargo.lock | cargo metadata |

扫描跳过 .git、node_modules、target、.venv 等缓存或构建目录；许可证解析在有明确目标时仍可能读取本地安装包元数据。

仅凭直接依赖清单通常无法恢复完整传递依赖。Gradle 的条件、插件和 BOM 管理版本等可能需要构建工具实际求值，工具不保证完整解析任意构建脚本。

## 输出与解释

### 版本和依赖图

版本范围不会当作确定版本输出。例如 npm 的 ^1.2.3、Python 的 >=1.0,<2.0、Cargo 的普通版本要求及 Maven/Gradle 的范围声明，在无法解析时省略组件 version，并保留可获得的需求信息：

~~~json
[
  { "name": "sbom:version:requirement", "value": "^1.2.3" },
  { "name": "sbom:version:status", "value": "unresolved" }
]
~~~

BOM 管理声明等可能只能确定组件身份，尚无可记录的具体版本需求，此时仍保留无版本组件。锁文件或包管理器结果可提供确定版本；清单中的精确声明不等于已验证安装状态。

依赖边引用组件 bom-ref。导出前检查引用唯一性和依赖目标，对可唯一匹配的已知写法差异进行对齐；无法可靠解析的引用会报错。

### 许可证与漏洞

许可证使用 SPDX ID、SPDX 表达式或许可证名称。npm 锁文件条目的许可证随对应组件保留；本地 npm 安装包回退要求名称和版本一致。缺少证据时留空，不按生态或包名猜测。

许可证字段完整率不等于准确率，合规结论仍需结合对应版本的上游声明核查。OSV 结果依赖在线数据或内置离线匹配的覆盖范围，不替代完整漏洞审计；未知版本不用于推断漏洞命中。

### 静态引用与运行时监测

| 属性或状态 | 含义 |
| --- | --- |
| sbom:source:referenced=true | 源码中发现引用，不证明实际执行 |
| sbom:runtime:status=loaded | 探针记录到加载并匹配到组件 |
| sbom:runtime:status=dormant | 当前实现的对应生态探针未观测到该组件加载 |
| sbom:runtime:status=untraced | 未形成该组件的运行时加载判定 |

入口监测目前主要针对 Node.js 和 Python。启用监测不代表入口能启动或覆盖全部执行路径。loaded=0 不表示依赖没有使用，dormant 不表示组件不可达、无漏洞或可以安全删除。

## 示例项目与输出

| 示例 | 包含内容 | SBOM 快照 |
| --- | --- | --- |
| [电商全栈](examples/fullstack-ecommerce/) | Python、npm、Maven | [查看 JSON](examples/fullstack-ecommerce/fullstack-ecommerce_sbom.json) |
| [多语言展示](examples/polyglot-showcase/) | Cargo、Go、Maven/Gradle、npm、Python | [查看 JSON](examples/polyglot-showcase/polyglot-showcase_sbom.json) |
| [安全边界示例](examples/security-edgecases/) | 用于检查版本与漏洞处理的依赖声明 | [查看 JSON](examples/security-edgecases/security-edgecases_sbom.json) |

这些输出是快照。验证当前生成器时，应重新扫描对应示例，并使用独立输出路径。

## 与其他 SBOM 对比

~~~bash
cargo run --bin sbom_compare -- --our-sbom ours.json --competitor-sbom trivy.json --output comparison.md
~~~

可用 --reference-version VERSION 记录参照工具版本。建议始终显式指定输入与输出路径。

[test](test/) 保存 Juice Shop、microservices、OpenTelemetry 和 quickstarts 的对照文件。不同快照的源码提交、开发依赖范围及生成时间可能不同，不能直接视为受控基准。

对比器报告组件记录、未解析版本、去重 PURL、交集、独有项和 Jaccard。精确版本比较排除未解析组件，过滤应用节点和部分合成版本，去除 PURL qualifier/subpath。目标生态固定为当前支持的五类生态；空参照集合显示 N/A。过滤可能排除合法的 0.0.0 组件。

相对重合率不等于准确率或召回率。参照工具不是绝对真值，独有项应回查清单、锁文件、作用域和解析环境。

## 测试与验证

~~~bash
cargo test
node --test tests/ui_regressions.cjs
cargo fmt --all -- --check
~~~

| 测试位置 | 覆盖内容 |
| --- | --- |
| src/ 内的单元测试 | 生态解析器、版本、许可证及图工具 |
| tests/cli_workflows.rs | CLI 生成、对比与错误处理 |
| tests/scan_failures.rs | 无效输入、版本范围、解析回退和子项目覆盖 |
| tests/schema_validation.rs | 使用仓库内 CycloneDX 1.6 及辅助 schema 验证输出 |
| tests/sbom_accuracy.rs | 元数据、PURL 和依赖引用完整性 |
| tests/ui_regressions.cjs | 界面字段转义与对比统计 |

部分测试读取仓库快照，部分涉及本机工具可用性；删除测试引用的输入文件会导致失败。单独执行 Schema 验证：

~~~bash
cargo test --test schema_validation
~~~

安装支持当前平台的 cargo-tarpaulin 后，可测量覆盖率并设置 80% 门槛：

~~~bash
cargo tarpaulin --engine Llvm --output-dir target/coverage --out Json --fail-under 80
~~~

测试通过数量和覆盖率应以提交版本的实际报告为准。历史报告不能证明后续代码仍保持相同覆盖率。

## 可选桌面界面

桌面界面支持项目选择、SBOM 导入、依赖图、组件与漏洞列表、JSON 查看和双 SBOM 对比。安装 Tauri CLI 及平台依赖后运行：

~~~bash
cargo tauri dev
~~~

图表使用 ECharts CDN，相关页面需要网络访问。CLI 可以独立使用。

## 项目结构

~~~text
src/
  main.rs                 生成器 CLI 入口
  analyze/producers/      各生态解析器
  analyze/dynamic_monitor.rs  可选入口加载监测
  model/                  组件、配置与位置模型
  sbom/generate.rs        CycloneDX 输出
  utils/                  版本、许可证、漏洞及图工具
  bin/sbom_compare.rs     SBOM 对比 CLI
src-tauri/                桌面后端
ui/                       桌面前端
examples/                 示例项目与输出
test/                    第三方项目 SBOM 对照文件
tests/                   集成及界面回归测试
resources/                解析资源及 JSON schema
misc/                     辅助脚本
~~~

## 常见问题

- **找不到目录或输出失败**：确认输入路径存在，输出父目录存在且可写；带空格的路径使用引号。
- **包管理器缺失或无法联网**：先使用 -s，版本及传递依赖完整度取决于现有清单和锁文件。
- **动态结果与静态一致**：可能由回退、多项目策略或无有效探针结果造成，使用 -d 查看诊断信息。
- **许可证为空**：表示缺少可采用的声明或匹配证据，不表示没有许可证。
- **Cargo 提示无法创建增量编译硬链接**：若回退为复制且构建成功，可以继续使用产物。

## 许可证

本项目采用 [Apache License 2.0](LICENSE)。第三方组件遵循各自许可证。
