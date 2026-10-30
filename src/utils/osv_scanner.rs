use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::model::dependency::Dependency;

/// 单个漏洞告警详情（兼容 CycloneDX 1.6 `vulnerabilities` 与前端高亮气泡）
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VulnerabilityInfo {
    /// 漏洞编号（例如 `CVE-2022-25845 / GHSA-pv7h-9867-5q6r`）
    pub id: String,
    /// 严重程度：`CRITICAL` | `HIGH` | `MEDIUM` | `LOW`
    pub severity: String,
    /// CVSS 评分（0.0 - 10.0）
    pub score: f64,
    /// 漏洞中文/英文摘要描述
    pub summary: String,
    /// 修复建议版本
    pub fixed_version: Option<String>,
    /// 情报来源（`OSV.dev API` 或 `OSV Offline Advisory DB`）
    pub source: String,
}

/// 离线 OSV 规则条目（支持内置知识库与外部 `osv-offline-db.json` 挂载）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineAdvisoryRule {
    pub ecosystem: String,
    pub package_name: String,
    pub fixed_version: String,
    pub id: String,
    pub severity: String,
    pub score: f64,
    pub summary: String,
}

#[derive(Serialize)]
struct OsvBatchQueryRequest {
    queries: Vec<OsvQueryItem>,
}

#[derive(Serialize)]
struct OsvQueryItem {
    package: OsvPackageQuery,
}

#[derive(Serialize)]
struct OsvPackageQuery {
    purl: String,
}

#[derive(Deserialize, Debug)]
struct OsvBatchQueryResponse {
    #[serde(default)]
    results: Vec<OsvBatchResultItem>,
}

#[derive(Deserialize, Debug)]
struct OsvBatchResultItem {
    #[serde(default)]
    vulns: Vec<OsvVulnStub>,
}

#[derive(Deserialize, Debug)]
struct OsvVulnStub {
    id: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
}

/// OSV 漏洞联动扫描引擎：结合实时 OSV.dev Batch API 与毫秒级离线 OSV 知识库
pub struct OsvScanner;

impl OsvScanner {
    /// 扫描所有 SBOM 依赖组件，返回 `instance_id -> Vec<VulnerabilityInfo>` 映射表
    pub fn scan_dependencies(
        dependencies: &[Dependency],
        project_dir: Option<&str>,
        enable_online_api: bool,
    ) -> HashMap<String, Vec<VulnerabilityInfo>> {
        if dependencies.is_empty() {
            return HashMap::new();
        }

        // 1. 加载内置 + 外部离线 OSV 漏洞规则库
        let mut advisory_rules = Self::builtin_advisory_rules();
        if let Some(dir) = project_dir {
            let custom_db = Path::new(dir).join("osv-offline-db.json");
            if custom_db.exists() {
                if let Ok(content) = fs::read_to_string(&custom_db) {
                    if let Ok(extra_rules) =
                        serde_json::from_str::<Vec<OfflineAdvisoryRule>>(&content)
                    {
                        advisory_rules.extend(extra_rules);
                    }
                }
            }
        }

        // 2. 按唯一基础 PURL 归并查询，避免重复请求相同组件
        let mut unique_purls: Vec<String> = Vec::new();
        let mut seen_purls: HashSet<String> = HashSet::new();
        for dep in dependencies {
            let base_purl = dep.purl.split('?').next().unwrap_or(&dep.purl).to_string();
            if !base_purl.is_empty() && seen_purls.insert(base_purl.clone()) {
                unique_purls.push(base_purl);
            }
        }

        let mut purl_vulns_map: HashMap<String, Vec<VulnerabilityInfo>> = HashMap::new();

        // 3. 轨道一：毫秒级离线 OSV 知识库精准比对（保证断网/沙箱/内网 100% 稳定检出且提供完整 CVSS 与修复建议）
        for purl in &unique_purls {
            let matched = Self::match_offline_rules(purl, &advisory_rules);
            if !matched.is_empty() {
                purl_vulns_map.insert(purl.clone(), matched);
            }
        }

        // 4. 轨道二：在线请求 Google OSV.dev Batch API (`https://api.osv.dev/v1/querybatch`)
        if enable_online_api && !cfg!(test) {
            if let Ok(online_map) = Self::query_osv_batch_api(&unique_purls) {
                for (purl, online_vulns) in online_map {
                    let entry = purl_vulns_map.entry(purl).or_default();
                    for ov in online_vulns {
                        // 若离线库已包含相同 CVE/GHSA 编号，则保留离线库更丰富的详情；否则追加在线实时检出结果
                        let already_present = entry.iter().any(|existing| {
                            existing.id.contains(&ov.id) || ov.id.contains(&existing.id)
                        });
                        if !already_present {
                            entry.push(ov);
                        }
                    }
                }
            }
        }

        // 5. 映射回每个物理隔离实例 (`instance_id`)
        let mut instance_vulns: HashMap<String, Vec<VulnerabilityInfo>> = HashMap::new();
        for dep in dependencies {
            let base_purl = dep.purl.split('?').next().unwrap_or(&dep.purl);
            if let Some(vulns) = purl_vulns_map.get(base_purl) {
                if !vulns.is_empty() {
                    instance_vulns.insert(dep.instance_id.clone(), vulns.clone());
                }
            }
        }

        instance_vulns
    }

    /// 请求 Google OSV.dev `/v1/querybatch` 批量接口（限时 2.5 秒超时，绝不阻塞主流程）
    fn query_osv_batch_api(
        purls: &[String],
    ) -> anyhow::Result<HashMap<String, Vec<VulnerabilityInfo>>> {
        if purls.is_empty() {
            return Ok(HashMap::new());
        }

        let purls_owned = purls.to_vec();
        // 关键防御：reqwest::blocking 内部会启动其独立的单线程 Tokio runtime。
        // 若在 Tauri 等外层异步运行时 (tokio-rt-worker) 的上下文中直接实例化 reqwest::blocking，
        // 会触发 Tokio 经典的 "Cannot drop a runtime in a context where blocking is not allowed" panic。
        // 通过在专有的系统 OS 线程中隔离执行，彻底避免任何运行时重入与死锁。
        let handle = std::thread::Builder::new()
            .name("osv-batch-api".into())
            .spawn(
                move || -> anyhow::Result<HashMap<String, Vec<VulnerabilityInfo>>> {
                    let client = reqwest::blocking::Client::builder()
                        .timeout(Duration::from_millis(2500))
                        .build()?;

                    let queries: Vec<OsvQueryItem> = purls_owned
                        .iter()
                        .map(|p| OsvQueryItem {
                            package: OsvPackageQuery { purl: p.clone() },
                        })
                        .collect();

                    let payload = OsvBatchQueryRequest { queries };
                    let body_str = serde_json::to_string(&payload)?;
                    let resp = client
                        .post("https://api.osv.dev/v1/querybatch")
                        .header("Content-Type", "application/json")
                        .body(body_str)
                        .send()?;

                    if !resp.status().is_success() {
                        anyhow::bail!("OSV API returned status {}", resp.status());
                    }

                    let resp_text = resp.text()?;
                    let batch_resp: OsvBatchQueryResponse = serde_json::from_str(&resp_text)?;
                    let mut result_map: HashMap<String, Vec<VulnerabilityInfo>> = HashMap::new();

                    for (idx, item) in batch_resp.results.into_iter().enumerate() {
                        if idx >= purls_owned.len() || item.vulns.is_empty() {
                            continue;
                        }
                        let purl = &purls_owned[idx];
                        let mut infos = Vec::new();
                        // 每个组件最多取前 5 条核心漏洞展示，防止单个老旧包产生数十条噪音
                        for stub in item.vulns.into_iter().take(5) {
                            let display_id = if let Some(cve) =
                                stub.aliases.iter().find(|a| a.starts_with("CVE-"))
                            {
                                if cve != &stub.id {
                                    format!("{} ({})", cve, stub.id)
                                } else {
                                    stub.id.clone()
                                }
                            } else {
                                stub.id.clone()
                            };

                            infos.push(VulnerabilityInfo {
                                id: display_id,
                                severity: "HIGH".to_string(),
                                score: 7.5,
                                summary: stub.summary.unwrap_or_else(|| {
                                    format!("OSV.dev 实时检出开源组件安全漏洞 ({})", stub.id)
                                }),
                                fixed_version: None,
                                source: "OSV.dev Batch API".to_string(),
                            });
                        }
                        if !infos.is_empty() {
                            result_map.insert(purl.clone(), infos);
                        }
                    }

                    Ok(result_map)
                },
            )
            .map_err(|e| anyhow::anyhow!("无法启动 OSV 扫描线程: {}", e))?;

        handle
            .join()
            .map_err(|_| anyhow::anyhow!("OSV 扫描线程发生 Panic 异常中断"))?
    }

    /// 解析 PURL (`pkg:<eco>/<namespace>/<name>@<version>`) 并与离线规则库比对
    fn match_offline_rules(purl: &str, rules: &[OfflineAdvisoryRule]) -> Vec<VulnerabilityInfo> {
        let Some((eco, pkg_full_name, version)) = Self::parse_purl_coordinates(purl) else {
            return Vec::new();
        };

        if version.is_empty() || version == "unknown" || version == "*" {
            return Vec::new();
        }

        let mut matched = Vec::new();
        for rule in rules {
            if !rule.ecosystem.eq_ignore_ascii_case(&eco) {
                continue;
            }
            let rule_pkg_norm = rule.package_name.to_lowercase().replace(':', "/");
            let pkg_norm = pkg_full_name.to_lowercase().replace(':', "/");

            if pkg_norm == rule_pkg_norm
                && Self::is_version_less_than(&version, &rule.fixed_version)
            {
                matched.push(VulnerabilityInfo {
                    id: rule.id.clone(),
                    severity: rule.severity.clone(),
                    score: rule.score,
                    summary: rule.summary.clone(),
                    fixed_version: Some(rule.fixed_version.clone()),
                    source: "OSV Knowledge Base".to_string(),
                });
            }
        }
        matched
    }

    /// 从标准 PURL 提取 `(ecosystem, full_name, version)`
    pub fn parse_purl_coordinates(purl: &str) -> Option<(String, String, String)> {
        let base = purl.split('?').next()?.strip_prefix("pkg:")?;
        let (left, version) = base.rsplit_once('@')?;
        let (eco, rest) = left.split_once('/')?;
        let decoded_name = rest.replace("%40", "@").replace("%2F", "/");
        Some((
            eco.to_lowercase(),
            decoded_name,
            version.trim_start_matches('v').to_string(),
        ))
    }

    /// 轻量级多语言版本号比较：判断 `current_ver < fixed_ver`
    pub fn is_version_less_than(current_ver: &str, fixed_ver: &str) -> bool {
        let parse_segments = |v: &str| -> Vec<u64> {
            v.trim()
                .trim_start_matches('v')
                .split(['.', '-', '_', '+'])
                .filter_map(|seg| {
                    let digits: String = seg.chars().take_while(|c| c.is_ascii_digit()).collect();
                    if digits.is_empty() {
                        None
                    } else {
                        digits.parse::<u64>().ok()
                    }
                })
                .collect()
        };

        let cur = parse_segments(current_ver);
        let fix = parse_segments(fixed_ver);
        if cur.is_empty() || fix.is_empty() {
            return false;
        }

        let max_len = cur.len().max(fix.len());
        for i in 0..max_len {
            let c = *cur.get(i).unwrap_or(&0);
            let f = *fix.get(i).unwrap_or(&0);
            if c < f {
                return true;
            }
            if c > f {
                return false;
            }
        }
        false
    }

    /// 内置六大生态高危 CVE / GHSA 权威规则库（覆盖真实供应链安全审计高频漏洞）
    fn builtin_advisory_rules() -> Vec<OfflineAdvisoryRule> {
        vec![
            // ==================== Maven / Gradle (Java & Kotlin) ====================
            OfflineAdvisoryRule {
                ecosystem: "maven".to_string(),
                package_name: "com.alibaba/fastjson".to_string(),
                fixed_version: "1.2.83".to_string(),
                id: "CVE-2022-25845 (GHSA-pv7h-9867-5q6r)".to_string(),
                severity: "CRITICAL".to_string(),
                score: 9.8,
                summary: "Fastjson AutoType 反序列化远程代码执行漏洞 (RCE)".to_string(),
            },
            OfflineAdvisoryRule {
                ecosystem: "maven".to_string(),
                package_name: "org.apache.logging.log4j/log4j-core".to_string(),
                fixed_version: "2.17.1".to_string(),
                id: "CVE-2021-44228 (GHSA-jfh8-c2jp-5v3q)".to_string(),
                severity: "CRITICAL".to_string(),
                score: 10.0,
                summary: "Apache Log4j2 JNDI 远程代码执行漏洞 (Log4Shell)".to_string(),
            },
            OfflineAdvisoryRule {
                ecosystem: "maven".to_string(),
                package_name: "ch.qos.logback/logback-classic".to_string(),
                fixed_version: "1.2.9".to_string(),
                id: "CVE-2021-42550 (GHSA-vmq6-5m68-f53m)".to_string(),
                severity: "HIGH".to_string(),
                score: 8.5,
                summary: "Logback 配置加载 JNDI 注入与远程代码执行漏洞".to_string(),
            },
            OfflineAdvisoryRule {
                ecosystem: "maven".to_string(),
                package_name: "org.apache.commons/commons-io".to_string(),
                fixed_version: "2.7.0".to_string(),
                id: "CVE-2021-29425 (GHSA-gwrp-pvrq-jmwv)".to_string(),
                severity: "MEDIUM".to_string(),
                score: 6.5,
                summary: "Apache Commons IO FilenameUtils 路径穿越漏洞".to_string(),
            },
            OfflineAdvisoryRule {
                ecosystem: "maven".to_string(),
                package_name: "org.apache.httpcomponents/httpclient".to_string(),
                fixed_version: "4.5.13".to_string(),
                id: "CVE-2020-13956 (GHSA-7r82-7xv7-xcpj)".to_string(),
                severity: "MEDIUM".to_string(),
                score: 5.3,
                summary: "Apache HttpClient URI Authority 解析绕过与请求伪造漏洞".to_string(),
            },
            OfflineAdvisoryRule {
                ecosystem: "maven".to_string(),
                package_name: "org.springframework.boot/spring-boot-starter-web".to_string(),
                fixed_version: "2.6.6".to_string(),
                id: "CVE-2022-22965 (GHSA-36p3-wjmg-h94x)".to_string(),
                severity: "CRITICAL".to_string(),
                score: 9.8,
                summary: "Spring Framework DataBinder 远程代码执行漏洞 (Spring4Shell)".to_string(),
            },
            OfflineAdvisoryRule {
                ecosystem: "maven".to_string(),
                package_name: "com.fasterxml.jackson.core/jackson-databind".to_string(),
                fixed_version: "2.13.4".to_string(),
                id: "CVE-2022-42003 (GHSA-jjjh-jjxp-wpff)".to_string(),
                severity: "HIGH".to_string(),
                score: 7.5,
                summary: "Jackson-databind 深度嵌套反序列化栈耗尽拒绝服务漏洞 (DoS)".to_string(),
            },
            // ==================== NPM (Node.js / Frontend) ====================
            OfflineAdvisoryRule {
                ecosystem: "npm".to_string(),
                package_name: "lodash".to_string(),
                fixed_version: "4.17.21".to_string(),
                id: "CVE-2021-23337 (GHSA-35jh-r3h4-6jhm)".to_string(),
                severity: "HIGH".to_string(),
                score: 7.2,
                summary: "Lodash template 命令注入与原型链污染漏洞 (Command Injection)".to_string(),
            },
            OfflineAdvisoryRule {
                ecosystem: "npm".to_string(),
                package_name: "express".to_string(),
                fixed_version: "4.19.2".to_string(),
                id: "CVE-2024-29041 (GHSA-rv95-896h-c2vc)".to_string(),
                severity: "MEDIUM".to_string(),
                score: 6.1,
                summary: "Express.js URL 重定向校验绕过漏洞 (Open Redirect)".to_string(),
            },
            OfflineAdvisoryRule {
                ecosystem: "npm".to_string(),
                package_name: "axios".to_string(),
                fixed_version: "1.6.0".to_string(),
                id: "CVE-2023-45857 (GHSA-wf5p-g6vw-rhxx)".to_string(),
                severity: "MEDIUM".to_string(),
                score: 6.5,
                summary: "Axios 跨域请求 XSRF-TOKEN 凭据泄露漏洞".to_string(),
            },
            OfflineAdvisoryRule {
                ecosystem: "npm".to_string(),
                package_name: "minimist".to_string(),
                fixed_version: "1.2.6".to_string(),
                id: "CVE-2021-44906 (GHSA-xvch-5gv4-984h)".to_string(),
                severity: "CRITICAL".to_string(),
                score: 9.8,
                summary: "Minimist 命令行参数解析器原型链污染漏洞".to_string(),
            },
            // ==================== PyPI (Python / AI) ====================
            OfflineAdvisoryRule {
                ecosystem: "pypi".to_string(),
                package_name: "urllib3".to_string(),
                fixed_version: "2.0.7".to_string(),
                id: "CVE-2023-45803 (GHSA-g4mx-q9vg-27p4)".to_string(),
                severity: "MEDIUM".to_string(),
                score: 6.5,
                summary: "urllib3 HTTP 重定向未剥离请求体导致敏感数据泄露".to_string(),
            },
            OfflineAdvisoryRule {
                ecosystem: "pypi".to_string(),
                package_name: "requests".to_string(),
                fixed_version: "2.31.0".to_string(),
                id: "CVE-2023-32681 (GHSA-j8r2-6x86-q33q)".to_string(),
                severity: "MEDIUM".to_string(),
                score: 6.1,
                summary: "Requests 跨源重定向时 Proxy-Authorization 凭据泄露漏洞".to_string(),
            },
            OfflineAdvisoryRule {
                ecosystem: "pypi".to_string(),
                package_name: "aiohttp".to_string(),
                fixed_version: "3.9.2".to_string(),
                id: "CVE-2024-23334 (GHSA-jwhx-xcg6-8xhj)".to_string(),
                severity: "HIGH".to_string(),
                score: 7.5,
                summary: "aiohttp 静态资源路由符号链接目录穿越任意文件读取漏洞".to_string(),
            },
            OfflineAdvisoryRule {
                ecosystem: "pypi".to_string(),
                package_name: "django".to_string(),
                fixed_version: "4.2.11".to_string(),
                id: "CVE-2024-27351 (GHSA-33mw-q7rj-mjwj)".to_string(),
                severity: "HIGH".to_string(),
                score: 7.5,
                summary: "Django Truncator 正则表达式回溯拒绝服务漏洞 (ReDoS)".to_string(),
            },
            OfflineAdvisoryRule {
                ecosystem: "pypi".to_string(),
                package_name: "pyyaml".to_string(),
                fixed_version: "5.4.0".to_string(),
                id: "CVE-2020-14343 (GHSA-8q59-q68h-6hv4)".to_string(),
                severity: "CRITICAL".to_string(),
                score: 9.8,
                summary: "PyYAML full_load 任意 Python 对象反序列化远程代码执行漏洞".to_string(),
            },
            // ==================== Go (Golang) ====================
            OfflineAdvisoryRule {
                ecosystem: "golang".to_string(),
                package_name: "golang.org/x/net".to_string(),
                fixed_version: "0.23.0".to_string(),
                id: "CVE-2023-45288 (GO-2024-2687)".to_string(),
                severity: "HIGH".to_string(),
                score: 7.5,
                summary: "Go x/net HTTP/2 CONTINUATION 帧洪水攻击拒绝服务漏洞".to_string(),
            },
            OfflineAdvisoryRule {
                ecosystem: "golang".to_string(),
                package_name: "golang.org/x/crypto".to_string(),
                fixed_version: "0.17.0".to_string(),
                id: "CVE-2023-48795 (GHSA-45x7-px36-x8w8)".to_string(),
                severity: "MEDIUM".to_string(),
                score: 5.9,
                summary: "Go x/crypto SSH 协议前缀截断攻击漏洞 (Terrapin Attack)".to_string(),
            },
            OfflineAdvisoryRule {
                ecosystem: "golang".to_string(),
                package_name: "github.com/gin-gonic/gin".to_string(),
                fixed_version: "1.9.1".to_string(),
                id: "CVE-2023-29401 (GHSA-2c4m-59x9-fr2g)".to_string(),
                severity: "MEDIUM".to_string(),
                score: 6.5,
                summary: "Gin Web 框架 Context.FileAttachment 文件名头部注入漏洞".to_string(),
            },
            // ==================== Cargo (Rust) ====================
            OfflineAdvisoryRule {
                ecosystem: "cargo".to_string(),
                package_name: "chrono".to_string(),
                fixed_version: "0.4.20".to_string(),
                id: "CVE-2020-26235 (RUSTSEC-2020-0159)".to_string(),
                severity: "MEDIUM".to_string(),
                score: 6.3,
                summary: "Chrono 时区解析在多线程环境下调用 localtime_r 潜在内存不安全漏洞"
                    .to_string(),
            },
            OfflineAdvisoryRule {
                ecosystem: "cargo".to_string(),
                package_name: "regex".to_string(),
                fixed_version: "1.5.5".to_string(),
                id: "CVE-2022-24713 (RUSTSEC-2022-0013)".to_string(),
                severity: "HIGH".to_string(),
                score: 7.5,
                summary: "Rust regex 编译特定大型空匹配正则时导致内存耗尽拒绝服务漏洞".to_string(),
            },
            OfflineAdvisoryRule {
                ecosystem: "cargo".to_string(),
                package_name: "openssl".to_string(),
                fixed_version: "0.10.55".to_string(),
                id: "CVE-2023-0286 (RUSTSEC-2023-0044)".to_string(),
                severity: "HIGH".to_string(),
                score: 7.4,
                summary: "OpenSSL X.400 地址类型混淆可导致任意内存读取漏洞".to_string(),
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_purl_and_offline_matching() {
        let dep = Dependency {
            name: "com.alibaba:fastjson".to_string(),
            version: Some("1.2.12".to_string()),
            purl: "pkg:maven/com.alibaba/fastjson@1.2.12".to_string(),
            instance_id: "pkg:maven/com.alibaba/fastjson@1.2.12?package-id=test1234".to_string(),
            ..Default::default()
        };

        let result = OsvScanner::scan_dependencies(&[dep], None, false);
        let vulns = result
            .get("pkg:maven/com.alibaba/fastjson@1.2.12?package-id=test1234")
            .expect("fastjson 1.2.12 应命中 CVE-2022-25845");
        assert!(!vulns.is_empty());
        assert!(vulns[0].id.contains("CVE-2022-25845"));
        assert_eq!(vulns[0].severity, "CRITICAL");
    }

    #[test]
    fn test_safe_version_not_flagged() {
        let dep = Dependency {
            name: "lodash".to_string(),
            version: Some("4.17.21".to_string()),
            purl: "pkg:npm/lodash@4.17.21".to_string(),
            instance_id: "pkg:npm/lodash@4.17.21?package-id=safe1".to_string(),
            ..Default::default()
        };

        let result = OsvScanner::scan_dependencies(&[dep], None, false);
        assert!(result.is_empty());
    }
}
