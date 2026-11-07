# SBOM Studio

一个用 Rust 编写的多语言 SBOM 生成器。给定项目目录，它会识别支持的包管理器文件，提取组件及依赖关系，输出 **CycloneDX 1.6 JSON**。仓库同时包含 Tauri 桌面界面和用于比较两份 SBOM 的命令行工具。

> 本项目生成 CycloneDX SBOM；SPDX 用于表示组件许可证，当前不输出 SPDX 格式的 SBOM。

## 快速开始

需要 Rust **1.85 或更新版本**，以及可用于编译 Tree-sitter 原生代码的 C/C++ 工具链。Windows 推荐安装 Visual Studio C++ Build Tools。

```bash
cargo build --release --bins
```

扫描一个项目。建议首次运行使用静态模式，它只读取项目文件，不启动项目内的包管理器探针：

```bash
# Windows
.\target\release\sbom-generator.exe -i C:\path\to\project -o C:\path\to\sbom.json -s

# macOS / Linux
./target/release/sbom-generator -i /path/to/project -o ./sbom.json -s
```

输出目录须已存在。去掉 `-s` 后，工具会在可用时调用包管理器命令来解析依赖；调用失败时回退到静态解析。添加 `--tree` 可在终端显示依赖树。

## 支持范围

| 生态 | 静态输入 | 可选动态解析 |
| --- | --- | --- |
| Python / PyPI | `requirements.txt`、`pyproject.toml`、`poetry.lock`、`uv.lock`、`Pipfile.lock` | `pip inspect` |
| JavaScript / npm | `package.json`、`package-lock.json` | `npm ls` |
| Java / Maven | `pom.xml` | `mvn dependency:tree` |
| Java、Kotlin / Gradle | `build.gradle`、`build.gradle.kts`、版本目录及锁文件 | Gradle `dependencies` |
| Go Modules | `go.mod`、`go.sum`、`go.work` | `go mod graph` |
| Rust / Cargo | `Cargo.toml`、`Cargo.lock` | `cargo metadata` |

扫描器会遍历子项目，因此一个仓库可以包含多个生态。优先使用锁文件获取确定的版本和传递依赖；只有清单文件时，版本范围和传递依赖的完整度取决于清单内容与可用的动态解析工具。

## 命令行

```text
sbom-generator -i DIRECTORY -o OUTPUT [options]
```

| 参数 | 用途 |
| --- | --- |
| `-i, --directory` | 待扫描项目目录，必填 |
| `-o, --output` | CycloneDX JSON 输出文件，必填 |
| `-s, --static-only` | 只使用静态解析，跳过包管理器 CLI 探针 |
| `-t, --tree` | 在终端打印依赖树 |
| `-d, --debug` | 打印详细分析信息 |
| `--allow-exec` | 允许可选的运行时入口加载探针；默认关闭 |
| `-h, --help` | 查看完整帮助 |

默认扫描可能调用本机的包管理器。对未知来源的项目建议使用 `-s`。启用 `--allow-exec` 前应确认被扫描项目可信。工具会跳过 `.git`、`node_modules`、`target`、`.venv` 等目录。

生成的 SBOM 包含组件版本、PURL、唯一的 `bom-ref`、可获得的依赖边和来源位置。许可证使用 SPDX ID、SPDX 表达式或许可证名称。OSV 漏洞信息来自在线查询或内置的离线匹配；其覆盖范围取决于数据源，不能代替完整的漏洞审计。

## 桌面界面

Tauri 2 桌面应用提供项目目录选择、SBOM 导入、依赖图、漏洞和组件列表、JSON 查看以及双 SBOM 对比。安装 Tauri CLI 及目标平台的系统依赖后运行：

```bash
cargo tauri dev
```

界面使用 ECharts CDN；首次打开图谱需要网络连接。桌面应用代码位于 [ui/index.html](ui/index.html)、[ui/theme.css](ui/theme.css) 和 [src-tauri](src-tauri/)。

## 示例输出

仓库提供三份可直接检查的 CycloneDX 1.6 JSON：

- [电商全栈示例](examples/fullstack-ecommerce/fullstack-ecommerce_sbom.json)：Python、npm、Maven。
- [多语言示例](examples/polyglot-showcase/polyglot-showcase_sbom.json)：Cargo、Go、Maven/Gradle、npm、Python。
- [安全边界示例](examples/security-edgecases/security-edgecases_sbom.json)：含有已知风险的依赖声明。

这些文件是示例快照。需要反映当前源码或依赖时，请重新扫描对应的 `examples/` 项目。

## 与 Trivy 对比

推荐使用 [OWASP crAPI 固定提交测试](test/crapi/README.md)：它包含 Python、Go、Java/Gradle 和 npm，规模适合复现实验。Windows PowerShell 中安装 Git、Rust、Trivy 后运行：

```powershell
.\misc\benchmark-crapi.ps1
```

脚本把第三方源码放入 `target/test-fixtures/crapi/`，将本工具和 Trivy 的 SBOM、运行信息及 Markdown 对比报告写入 `target/benchmark-crapi/`。本工具使用静态模式；Trivy 使用 `--offline-scan --scanners license --include-dev-deps`。对比时按 PURL 去重，并排除应用根节点。Trivy 未识别的生态在报告中标记为 `N/A`，不把 0/0 计为 100%。

单独比较任意两份 CycloneDX 文件：

```bash
cargo run --bin sbom_compare -- --our-sbom ours.json --competitor-sbom trivy.json --output comparison.md
```

Trivy 结果是参照数据，不代表绝对真值。不同版本、已安装依赖和扫描参数可能改变组件及许可证数量。更多历史对照数据见 [test](test/)；解释报告时请一并核对原始 SBOM 与扫描配置。

## 测试与格式验证

```bash
cargo test
node --test tests/ui_regressions.cjs
cargo fmt --all -- --check
```

测试覆盖解析器、图构建、CLI 行为和三个示例 SBOM。示例使用仓库内保存的 [CycloneDX 1.6 JSON schema](resources/schemas/bom-1.6.schema.json)、SPDX 与 JSF 辅助 schema 进行验证：

```bash
cargo test --test schema_validation
```

`tests/scan_failures.rs` 验证解析失败、锁文件回退与独立子项目覆盖；前端回归测试使用 Node.js 内置测试运行器，验证导入字段转义、比较统计和报告结论，无需安装 npm 依赖。

同一生态有多个清单目录时使用完整静态解析链，避免根目录动态探测跳过独立子项目。静态解析失败且无法有效回退时返回错误，并保留旧输出；成功回退会输出告警。比较页面与 CLI 按同样的 PURL 规则归一化，空参照集合显示 N/A；重合率不能代替准确率或召回率。

在 2026-11-07 的 Windows 本地运行中，51 项测试通过；`cargo-tarpaulin` 的 LLVM 引擎测得行覆盖率 **81.33%（3471/4268）**。不同环境的覆盖率可能变化。安装 `cargo-tarpaulin` 后可复测并设置 80% 门槛：

```bash
cargo tarpaulin --engine Llvm --output-dir target/coverage --out Json --fail-under 80
```

## 项目结构

```text
src/
  analyze/producers/   各生态的静态与动态解析器
  sbom/generate.rs     CycloneDX 输出
  utils/              文件遍历、许可证、OSV 与图工具
  bin/sbom_compare.rs  SBOM 对比 CLI
src-tauri/             Tauri 桌面后端
ui/                    桌面前端页面与样式
examples/              示例项目与 SBOM 快照
resources/schemas/     CycloneDX schema 测试资源
tests/                 CLI 与 schema 集成测试
misc/                  基准脚本
```

## 常见问题

- **Cargo 提示无法创建增量编译硬链接**：Cargo 会改为复制缓存文件，构建结果不受影响。
- **Trivy 提示缺少 `node_modules` 或 `site-packages`**：这会限制许可证元数据提取；组件清单仍可生成。
- **找不到包管理器或无法联网**：使用 `-s` 运行静态扫描；只有清单文件时，输出可能无法解析完整的传递依赖。
- **无法写入输出文件**：确认 `-o` 指定文件的父目录已存在且可写。

## 许可证

本仓库的 [LICENSE](LICENSE) 为 Apache License 2.0。
