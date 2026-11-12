const tauriCore = window.__TAURI__ ? window.__TAURI__.core : null;
        async function tauriInvoke(cmd, args) {
            if (tauriCore && tauriCore.invoke) {
                return await tauriCore.invoke(cmd, args);
            }
            throw new Error("当前处于浏览器环境，Tauri 未连接");
        }

        function showToast(msg, isErr = false) {
            const toast = document.getElementById('toast');
            toast.innerText = msg;
            toast.style.borderColor = isErr ? 'var(--danger-border)' : 'var(--border-strong)';
            toast.style.color = isErr ? '#ff7b72' : 'var(--text-main)';
            toast.classList.add('show');
            setTimeout(() => toast.classList.remove('show'), 2600);
        }

        // 全局对比数据集与图表实例
        let sbomA = null;
        let sbomB = null;
        let sbomC = null;
        let labelA = "SBOM A";
        let labelB = "SBOM B";
        let labelC = "SBOM C";
        let chartSplitLeft = null;
        let chartSplitRight = null;
        let currentTopoView = "diff";
        let lastMapA = new Map();
        let lastMapB = new Map();
        let lastCommonPurls = new Set();
        let lastOnlyPurlsA = new Set();
        let lastOnlyPurlsB = new Set();

        let compareRepulsionMult = 1.8;
        let compareGraphLayout = 'auto';
        let inputRevision = 0;
        let pendingInputLoad = false;
        const slotRevisions = {a:0,b:0,c:0};
        const pendingSlots = new Set();
        let escapeListenerBound = false;

        let lastComparison = null;
        let lastComparisonAC = null;
        let lastComparisonBC = null;
        let currentDiffList = [];
        let filteredDiffList = [];

        // 分页状态
        let currentPage = 1;
        let pageSize = 30;
        let activeDiffTab = 'all';

        // ECharts 核心实例管理
        let chartOverlap = null;
        let chartEco = null;
        let chartTopo = null;

        function graphLayoutFor(count) {
            return compareGraphLayout === 'auto' ? (count > 600 ? 'circular' : 'force') : compareGraphLayout;
        }

        function membershipInfo(mask, hasC) {
            const entries = {
                1: [2, '仅 A 报告', '#38bdf8'], 2: [3, '仅 B 报告', '#fb923c'],
                4: [4, '仅 C 报告', '#c084fc'], 7: [1, 'A、B、C 共同报告', '#10b981'],
                3: hasC ? [5, 'A、B 共有，C 未报告', '#fbbf24'] : [1, 'A、B 共同报告', '#10b981'],
                5: [6, 'A、C 共有，B 未报告', '#fbbf24'], 6: [7, 'B、C 共有，A 未报告', '#fbbf24']
            };
            const [category, label, color] = entries[mask];
            return {category, label, color};
        }

        function updateEcosystemMetric() {
            const metric = document.getElementById('select-eco-metric')?.value || 'records';
            const title = document.getElementById('eco-chart-title');
            if (title) title.innerText = metric === 'unique' ? '🌐 各生态唯一包版本数' : '🌐 各生态组件记录数';
            if (!chartEco) return;
            const series = chartEco.getOption()?.series || [];
            chartEco.setOption({series:series.map(s => ({data:(s.data || []).map(d => typeof d === 'object' ? {...d,value:d[metric]} : d)}))});
        }

        function invalidateComparison() {
            lastComparison = null; lastComparisonAC = null; lastComparisonBC = null;
            currentDiffList = []; filteredDiffList = []; currentPage = 1;
            lastMapA = new Map(); lastMapB = new Map();
            lastCommonPurls = new Set(); lastOnlyPurlsA = new Set(); lastOnlyPurlsB = new Set();
            for (const id of ['comparison-metrics-body','comparison-edge-differences','comparison-input-diagnostics','paginated-diff-tbody','unresolved-tbody']) {
                const element = document.getElementById(id); if (element) element.innerHTML = '';
            }
            for (const id of ['kpi-target-coverage','kpi-total-coverage','kpi-jaccard','kpi-instances-a','kpi-instances-b','kpi-unique-diff','kpi-unique-stats','kpi-instances-diff','kpi-target-coverage-sub','kpi-total-coverage-sub','kpi-runtime-loaded','kpi-runtime-ratio','kpi-tool-b-label','kpi-trivy-inst-val','kpi-vuln-stats','kpi-vuln-active','comparison-warnings']) {
                const element = document.getElementById(id); if (element) element.innerText = '—';
            }
            for (const id of ['tab-cnt-only-a','tab-cnt-only-b','tab-cnt-only-c','tab-cnt-common','tab-cnt-all','tab-cnt-version-mismatch','tab-cnt-version-unknown','legend-common-count','legend-only-a-count','legend-only-b-count','legend-only-c-count']) {
                const element = document.getElementById(id); if (element) element.innerText = '0';
            }
            const classification = document.getElementById('comparison-classification');
            if (classification) classification.innerText = '输入已更新，暂无可导出的对比结果。';
            const hint = document.getElementById('calc-status-hint');
            if (hint) hint.innerText = '请选择有效文件并执行比较';
            [chartOverlap,chartEco,chartTopo,chartSplitLeft,chartSplitRight].forEach(chart => chart?.clear?.());
        }

        function initCharts() {
            const availability = document.getElementById('chart-availability');
            if (typeof echarts === 'undefined') {
                if (availability) availability.innerText = '图表库未加载；表格和统计仍可使用，请检查网络后刷新。';
                return;
            }
            if (availability) availability.innerText = '';
            if (!chartOverlap && document.getElementById('chart-overlap-pie')) chartOverlap = echarts.init(document.getElementById('chart-overlap-pie'));
            if (!chartEco && document.getElementById('chart-eco-bar')) chartEco = echarts.init(document.getElementById('chart-eco-bar'));
            if (!chartTopo && document.getElementById('chart-topo-graph')) chartTopo = echarts.init(document.getElementById('chart-topo-graph'));
        }

        window.addEventListener('resize', () => {
            [chartOverlap, chartEco, chartTopo, chartSplitLeft, chartSplitRight].forEach(c => c && c.resize());
        });

        // 规范化 PURL
        function escapeHtml(value) {
            return String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[c]));
        }

        function normalizePurl(raw) {
            return CompareCore.normalizePurl(raw);
        }

        function readCompareOptions() {
            const field = document.getElementById('compare-ecosystems');
            const ecosystems = typeof field?.value === 'string' ? field.value : CompareCore.DEFAULT_ECOS.join(',');
            return {
                ecosystems: ecosystems.split(',').map(s => s.trim().toLowerCase()).filter(Boolean),
                include_applications: !!document.getElementById('compare-include-applications')?.checked,
                exclude_zero_versions: !!document.getElementById('compare-exclude-zero')?.checked
            };
        }

        function extractEco(purl) {
            if (!purl) return 'other';
            const m = purl.match(/^pkg:([^/]+)/);
            return m ? m[1].toLowerCase() : 'other';
        }

        let activeTargetEcos = new Set(['cargo', 'golang', 'maven', 'npm', 'pypi']);

        function isTargetEco(e) {
            if (activeTargetEcos && activeTargetEcos.size > 0) {
                return activeTargetEcos.has(e);
            }
            return ['cargo', 'golang', 'maven', 'npm', 'pypi'].includes(e);
        }

        function isValidThirdParty(c) {
            return !!c && !!CompareCore.splitPurl(c.purl) && ['library', 'framework'].includes(c.type || 'library');
        }

        function extractMeta(c) {
            let status = 'untraced';
            let location = '-';
            if (Array.isArray(c?.properties)) {
                const st = c.properties.find(p => p?.name === 'sbom:runtime:status');
                if (st && st.value) status = st.value;
                const loc = c.properties.find(p => p?.name === 'syft:location:0:path' || (typeof p?.name === 'string' && p.name.includes('location')));
                if (loc && loc.value) location = loc.value;
            }
            if (Array.isArray(c?.comparisonLocations) && c.comparisonLocations.length) location = c.comparisonLocations.join(', ');
            let license = 'UNKNOWN';
            if (Array.isArray(c?.licenses) && c.licenses[0]) {
                const choice = c.licenses[0];
                license = choice.expression || choice.license?.id || choice.license?.name || 'UNKNOWN';
            }
            return { status, location, license };
        }

        function extractToolName(sbom, fallback) {
            if (!sbom || !sbom.metadata) return fallback;
            if (Array.isArray(sbom.metadata.tools)) {
                const f = sbom.metadata.tools[0];
                if (f && f.name) return `${f.name} ${f.version || ''}`.trim();
            } else if (sbom.metadata.tools?.components?.[0]) {
                const f = sbom.metadata.tools.components[0];
                if (f && f.name) return `${f.name} ${f.version ? 'v' + f.version : ''}`.trim();
            }
            return fallback;
        }

        // 执行深度比对
        function runBenchmarkComparison() {
            if (pendingInputLoad) {showToast('文件仍在加载，请稍候', true); return;}
            if (!sbomA || !sbomB) {
                invalidateComparison();
                showToast("请先选择待比对的 SBOM 文件 A 与文件 B", true);
                return;
            }

            initCharts();

            const toolA = extractToolName(sbomA, labelA);
            const toolB = extractToolName(sbomB, labelB);

            let report, reportAC = null, reportBC = null;
            try {
                const policy = readCompareOptions();
                const comparisons = CompareCore.compareThree(sbomA, sbomB, sbomC, policy);
                report = comparisons.ab; reportAC = comparisons.ac; reportBC = comparisons.bc;
            } catch (error) {
                invalidateComparison();
                document.getElementById('comparison-warnings').innerText = `对比输入无效: ${error.message}`;
                showToast(`对比输入无效: ${error.message}`, true);
                return;
            }
            lastComparison = report;
            lastComparisonAC = reportAC;
            lastComparisonBC = reportBC;
            const componentFor = r => ({ ...r.component, purl: r.key || r.identity, version: r.key ? r.version : undefined, comparisonLocations:r.locations, comparisonStatus:r.status, comparisonDeclaredVersion:r.component.version, comparisonPurl:r.component.purl });
            const recordsA = report.a.records.map(componentFor);
            const compsA = report.a.records.filter(r => r.key).map(componentFor);
            const recordsB = report.b.records.map(componentFor);
            const compsB = report.b.records.filter(r => r.key).map(componentFor);

            const totalA = recordsA.length;
            const totalB = recordsB.length;
            const unresolved = [...recordsA.filter(c => !c.version?.trim()).map(c => ({ side: 'A', c })),
                ...recordsB.filter(c => !c.version?.trim()).map(c => ({ side: 'B', c })),
                ...(reportAC ? reportAC.b.records.filter(r => !r.key).map(r => ({side:'C', c:componentFor(r)})) : [])];
            const unresolvedSummary = document.getElementById('unresolved-summary');
            if (unresolvedSummary) unresolvedSummary.innerText = `共 ${unresolved.length} 条；页面最多展示前 200 条，完整记录包含在导出的比较数据中。`;
            document.getElementById('unresolved-tbody').innerHTML = unresolved.slice(0,200).map(({ side, c }) => {
                const requirement = (Array.isArray(c.properties) ? c.properties : []).find(p => p?.name === 'sbom:version:requirement')?.value || (c.comparisonStatus === 'inconsistent' ? `版本冲突：version=${c.comparisonDeclaredVersion}，PURL=${c.comparisonPurl}` : `未解析：${c.comparisonDeclaredVersion || '未提供版本'}`);
                return `<tr><td>${side}</td><td>${escapeHtml(c.name)}</td><td>${escapeHtml(c.comparisonPurl || c.purl)}</td><td>${escapeHtml(requirement)}</td></tr>`;
            }).join('');

            const mapA = new Map();
            const statusMapA = new Map();
            const loadedRefsA = new Set();
            let loadedA = 0;
            let dormantA = 0;
            let licensedA = 0;
            const ecoLoadedA = {};

            // Scope is the supported ecosystem set, independent of what A found.
            activeTargetEcos = new Set(report.policy.ecosystems);
            const cView = document.querySelector?.('#select-topo-view option[value="syft"]');
            if (cView) cView.disabled = !reportAC;
            if (!reportAC && currentTopoView === 'syft') {currentTopoView = 'diff';const select=document.getElementById('select-topo-view'); if(select)select.value='diff';}

            recordsA.forEach(c => {
                const p = c.comparisonStatus === 'exact' ? normalizePurl(c.purl) : '';
                const e = extractEco(p);
                const meta = extractMeta(c);
                if (meta.status === 'loaded') {
                    loadedA++;
                    ecoLoadedA[e] = (ecoLoadedA[e] || 0) + 1;
                    statusMapA.set(p, 'loaded');
                    if (c['bom-ref']) loadedRefsA.add(c['bom-ref']);
                } else if (meta.status === 'dormant') {
                    dormantA++;
                    if (statusMapA.get(p) !== 'loaded') statusMapA.set(p, 'dormant');
                } else {
                    if (!statusMapA.has(p)) statusMapA.set(p, 'untraced');
                }
                if (meta.license !== 'UNKNOWN') licensedA++;
                if (p && isTargetEco(e) && (!mapA.has(p) || meta.status === 'loaded')) mapA.set(p, c);
            });

            const mapB = new Map();
            let loadedB = 0;
            let licensedB = 0;
            recordsB.forEach(c => {
                const p = c.comparisonStatus === 'exact' ? normalizePurl(c.purl) : '';
                const meta = extractMeta(c);
                if (meta.status === 'loaded') loadedB++;
                if (meta.license !== 'UNKNOWN') licensedB++;
                if (p && isTargetEco(extractEco(p)) && !mapB.has(p)) mapB.set(p, c);
            });

            // 漏洞统计
            const vulnsA = Array.isArray(sbomA.vulnerabilities) ? sbomA.vulnerabilities : [];
            const vulnsB = Array.isArray(sbomB.vulnerabilities) ? sbomB.vulnerabilities : [];
            let activeVulnsA = 0;
            vulnsA.forEach(v => {
                if ((Array.isArray(v?.affects) ? v.affects : []).some(a => loadedRefsA.has(a?.ref))) activeVulnsA++;
            });

            const purlsA = new Set(mapA.keys());
            const purlsB = new Set(mapB.keys());

            const commonPurls = new Set();
            purlsA.forEach(p => { if (purlsB.has(p)) commonPurls.add(p); });

            const onlyPurlsA = new Set();
            purlsA.forEach(p => { if (!commonPurls.has(p)) onlyPurlsA.add(p); });

            const onlyPurlsB = new Set();
            purlsB.forEach(p => { if (!commonPurls.has(p)) onlyPurlsB.add(p); });

            // 目标生态统计
            let targetBCount = 0;
            let targetCommonCount = 0;
            purlsB.forEach(p => {
                if (isTargetEco(extractEco(p))) targetBCount++;
            });
            commonPurls.forEach(p => {
                if (isTargetEco(extractEco(p))) targetCommonCount++;
            });

            const targetCoverage = targetBCount > 0 ? (targetCommonCount / targetBCount * 100) : null;
            const fullRepoCoverage = report.all_exact.coverage_b;
            const targetACount = [...purlsA].filter(p => isTargetEco(extractEco(p))).length;
            const unionCount = targetACount + targetBCount - targetCommonCount;
            const jaccard = unionCount > 0 ? (targetCommonCount / unionCount * 100) : null;

            // 提取工具 C (Syft) 如果存在
            const sbomC_safe = (typeof sbomC !== 'undefined') ? sbomC : null;
            const recordsC = reportAC ? reportAC.b.records.map(componentFor) : [];
            const compsC = reportAC ? reportAC.b.records.filter(r => r.key).map(componentFor) : [];
            const mapC = new Map();
            compsC.forEach(c => {
                const p = normalizePurl(c.purl);
                if (p && isTargetEco(extractEco(p)) && !mapC.has(p)) mapC.set(p, c);
            });
            const purlsC = new Set(mapC.keys());
            const onlyPurlsC = new Set();
            purlsC.forEach(p => {
                if (!purlsA.has(p) && !purlsB.has(p)) onlyPurlsC.add(p);
            });

            const identitiesOnlyA = new Set(report.only_identities_a), identitiesOnlyB = new Set(report.only_identities_b);
            const sampleRecords = new Map();
            for (const record of [...report.a.records,...report.b.records]) if (!sampleRecords.has(record.identity)) sampleRecords.set(record.identity,record);

            // 构造全量差异列表（附带精准差异归因解释）
            currentDiffList = [];
            onlyPurlsA.forEach(p => {
                if (!identitiesOnlyA.has(CompareCore.splitPurl(p).identity)) return;
                const c = mapA.get(p);
                const meta = extractMeta(c);
                const eco = extractEco(p);
                const reason = 'A 报告此包身份，B 未报告；需回查扫描范围与清单';
                currentDiffList.push({
                    type: 'onlyA',
                    name: c?.name || p.split('/')[1]?.split('@')[0] || p,
                    version: c?.version || '-',
                    eco,
                    purl: p,
                    runtimeStatus: statusMapA.get(p) || meta.status,
                    license: meta.license,
                    location: meta.location,
                    desc: reason
                });
            });

            onlyPurlsB.forEach(p => {
                if (!identitiesOnlyB.has(CompareCore.splitPurl(p).identity)) return;
                const c = mapB.get(p);
                const meta = extractMeta(c);
                const eco = extractEco(p);
                const reason = 'B 报告此包身份，A 未报告；需回查扫描范围与清单';
                currentDiffList.push({
                    type: 'onlyB',
                    name: c?.name || p.split('/')[1]?.split('@')[0] || p,
                    version: c?.version || '-',
                    eco,
                    purl: p,
                    runtimeStatus: 'untraced',
                    license: meta.license,
                    location: meta.location,
                    desc: reason
                });
            });

            onlyPurlsC.forEach(p => {
                const c = mapC.get(p);
                const meta = extractMeta(c);
                const eco = extractEco(p);
                currentDiffList.push({
                    type: 'onlyC',
                    name: c?.name || p.split('/')[1]?.split('@')[0] || p,
                    version: c?.version || '-',
                    eco,
                    purl: p,
                    runtimeStatus: 'untraced',
                    license: meta.license,
                    location: meta.location,
                    desc: '仅 C 报告此包版本；需核验扫描范围、依赖来源与版本表示'
                });
            });

            for (const [side, summary, identities] of [['A',report.a,identitiesOnlyA],['B',report.b,identitiesOnlyB]]) {
                for (const identity of identities) {
                    if ((summary.versions[identity] || []).length) continue;
                    const record = sampleRecords.get(identity);
                    currentDiffList.push({type:side === 'A' ? 'onlyA' : 'onlyB', name:record?.component.name || identity,
                        version:'未知', eco:extractEco(identity), purl:identity, runtimeStatus:'untraced', license:'-', location:record?.location || '-',
                        desc:`仅 ${side} 报告此包身份，且无可比较的确定版本；计入身份差集，不计入精确 PURL 差集。`});
                }
            }

            for (const row of report.version_differences) {
                const record = sampleRecords.get(row.identity);
                currentDiffList.push({ type: 'versionMismatch', name: record?.component.name || row.identity,
                    version: `A: ${row.versions_a.join(', ')} / B: ${row.versions_b.join(', ')}`,
                    eco: extractEco(row.identity), purl: row.identity, runtimeStatus: 'untraced', license: '-',
                    location: record?.location || '-', desc: `版本集合不同；仅 A: ${row.only_a.join(', ') || '无'}；仅 B: ${row.only_b.join(', ') || '无'}。共有版本仍单列。` });
            }
            for (const identity of report.unknown_versions) {
                const record = sampleRecords.get(identity);
                currentDiffList.push({ type: 'versionUnknown', name: record?.component.name || identity,
                    version: `A: ${(report.a.versions[identity] || []).join(', ') || '未知'} / B: ${(report.b.versions[identity] || []).join(', ') || '未知'}`,
                    eco: extractEco(identity), purl: identity, runtimeStatus: 'untraced', license: '-', location: record?.location || '-',
                    desc: '两侧均报告包身份，但至少一侧含未知、范围或冲突版本；不当作精确匹配。' });
            }

            commonPurls.forEach(p => {
                const cA = mapA.get(p);
                const cB = mapB.get(p);
                const c = cA || cB;
                const meta = extractMeta(cA || cB);
                currentDiffList.push({
                    type: 'common',
                    name: c?.name || p.split('/')[1]?.split('@')[0] || p,
                    version: c?.version || '-',
                    eco: extractEco(p),
                    purl: p,
                    runtimeStatus: statusMapA.get(p) || meta.status,
                    license: meta.license,
                    location: meta.location,
                    desc: 'A/B 的包身份与版本一致；来源、许可证和依赖关系需独立核验'
                });
            });

            // 更新 KPI 看板
            document.getElementById('kpi-target-desc').innerText = `所选目标生态: ${report.policy.ecosystems.join(', ')}；组件相同不表示依赖关系与来源相同。`;
            document.getElementById('kpi-target-coverage').innerText = targetCoverage === null ? 'N/A' : `${targetCoverage.toFixed(2)}%`;
            document.getElementById('kpi-target-coverage-sub').innerText = `${targetCommonCount} / ${targetBCount} 唯一包`;
            document.getElementById('kpi-total-coverage').innerText = fullRepoCoverage === null ? 'N/A' : `${fullRepoCoverage.toFixed(2)}%`;
            document.getElementById('kpi-total-coverage-sub').innerText = `${report.all_exact.common} / ${report.all_exact.b} 唯一包`;
            document.getElementById('kpi-jaccard').innerText = jaccard === null ? 'N/A' : `${jaccard.toFixed(1)}%`;

            document.getElementById('kpi-instances-a').innerText = `${totalA}`;
            if (reportAC) {
                document.getElementById('kpi-instances-b').innerText = `vs B:${totalB} / C:${recordsC.length} 个`;
                document.getElementById('kpi-unique-stats').innerText = `A:${purlsA.size} vs B:${purlsB.size} vs C:${purlsC.size}`;
            } else {
                document.getElementById('kpi-instances-b').innerText = `vs ${totalB} 个`;
                document.getElementById('kpi-unique-stats').innerText = `A:${purlsA.size} vs B:${purlsB.size}`;
            }
            const deltaInstances = totalA - totalB;
            document.getElementById('kpi-instances-diff').innerText = `版本可比较/未解析 A:${compsA.length}/${totalA - compsA.length}，B:${compsB.length}/${totalB - compsB.length}；记录差值: ${deltaInstances >= 0 ? '+' : ''}${deltaInstances} 个`;

            document.getElementById('kpi-unique-diff').innerText = `+${onlyPurlsA.size}`;

            document.getElementById('kpi-runtime-loaded').innerText = `${loadedA}`;
            const loadedRatio = totalA > 0 ? (loadedA / totalA * 100).toFixed(1) : '0.0';
            document.getElementById('kpi-runtime-ratio').innerText = `(${loadedRatio}%) 活跃`;
            const runtimeEvidence = document.getElementById('runtime-evidence-desc');
            if (runtimeEvidence) runtimeEvidence.innerText = loadedA ? '输入文件记录了已加载组件；本页面不执行运行探测。' : '输入文件未记录已加载组件，不代表没有使用这些依赖。';

            // 提取并填充工具 B (Trivy) 与 C (Syft) 深度技术档案
            const trivyDetails = extractToolBDetails(sbomB);
            if (reportAC && sbomC_safe) {
                const toolCName = extractToolName(sbomC_safe) || 'Syft';
                document.getElementById('kpi-tool-b-label').innerText = `${trivyDetails.toolName} & ${toolCName}`;
                document.getElementById('kpi-trivy-inst-val').innerText = `${totalB} / ${recordsC.length}`;
            } else {
                document.getElementById('kpi-tool-b-label').innerText = `${trivyDetails.toolName} ${trivyDetails.toolVersion}`;
                document.getElementById('kpi-trivy-inst-val').innerText = `${totalB}`;
            }

            document.getElementById('kpi-vuln-stats').innerText = `${vulnsA.length} vs ${vulnsB.length}`;
            document.getElementById('kpi-vuln-active').innerText = `可达活跃: ${activeVulnsA}`;

            // 更新徽标数字
            document.getElementById('tab-cnt-only-a').innerText = `${currentDiffList.filter(r => r.type === 'onlyA').length}`;
            document.getElementById('tab-cnt-only-b').innerText = `${currentDiffList.filter(r => r.type === 'onlyB').length}`;
            if (document.getElementById('tab-cnt-only-c')) {
                document.getElementById('tab-cnt-only-c').innerText = `${onlyPurlsC.size}`;
            }
            document.getElementById('tab-cnt-common').innerText = `${commonPurls.size}`;
            document.getElementById('tab-cnt-all').innerText = `${currentDiffList.length}`;

            const membership = CompareCore.classifySets(purlsA,purlsB,reportAC ? purlsC : null);
            document.getElementById('legend-common-count').innerText = `${membership[reportAC ? 7 : 3].length}`;
            document.getElementById('legend-only-a-count').innerText = `${membership[1].length}`;
            document.getElementById('legend-only-b-count').innerText = `${membership[2].length}`;
            const pairCount = document.getElementById('legend-pair-count');
            if (pairCount) pairCount.innerText = `${reportAC ? membership[3].length + membership[5].length + membership[6].length : 0}`;
            if (document.getElementById('legend-only-c-count')) {
                document.getElementById('legend-only-c-count').innerText = `${onlyPurlsC.size}`;
            }

            renderComparisonDiagnostics(report, reportAC, reportBC);

            // 渲染图表群
            renderChartsGroup({
                toolA, toolB,
                totalA, totalB,
                purlsA, purlsB, purlsC,
                commonPurls, onlyPurlsA, onlyPurlsB, onlyPurlsC,
                targetCoverage, fullRepoCoverage, jaccard,
                compsA, compsB, compsC,
                loadedA, dormantA,
                vulnsA, vulnsB, activeVulnsA,
                licensedA, licensedB,
                mapA, mapB, mapC
            });

            // 渲染差异明细表格并应用分页
            applyFiltersAndRenderPage();

            showToast("SBOM 交叉对比与评测图表渲染完成！");
        }

        function renderComparisonDiagnostics(report, reportAC, reportBC) {
            const percent = value => value === null ? 'N/A' : `${value.toFixed(2)}%`;
            const rows = [
                ['A–B 包名＋版本', report.exact], ['A–B 包身份（忽略版本）', report.identity],
                ['A–B 记录重数（非物理实例）', report.occurrences], ['A–B 包版本＋来源路径记录', report.located_occurrences]
            ];
            if (report.graph) rows.push(['A–B 依赖边', report.graph]);
            if (reportAC) rows.push(['A–C 包名＋版本', reportAC.exact], ['A–C 包身份', reportAC.identity]);
            if (reportBC) rows.push(['B–C 包名＋版本', reportBC.exact], ['B–C 包身份', reportBC.identity]);
            document.getElementById('comparison-metrics-body').innerHTML = rows.map(([label,m]) =>
                `<tr><td>${escapeHtml(label)}</td><td>${m.a}</td><td>${m.b}</td><td>${m.common}</td><td>${percent(m.coverage_b)}</td><td>${percent(m.coverage_a)}</td><td>${percent(m.jaccard)}</td></tr>`).join('');
            document.getElementById('comparison-classification').innerText = `包身份独有 A:${report.only_identities_a.length} / B:${report.only_identities_b.length}；版本集合差异:${report.version_differences.length} 组；版本未知:${report.unknown_versions.length} 组。图边重合率:${report.graph ? percent(report.graph.coverage_b) : 'N/A'}。`;
            document.getElementById('comparison-warnings').innerText = report.warnings.join('；') || '请确认两侧源码提交、平台和依赖分组一致。参照文件不是独立真值。';
            const details = summary => ({排除记录:summary.excluded,版本冲突:summary.diagnostics,悬空引用:summary.dangling_refs,重复引用:summary.duplicate_refs,过滤边:summary.filtered_edges,未知版本边:summary.unresolved_edges,缺少路径记录:summary.missing_locations,解析方法:summary.methods});
            document.getElementById('comparison-input-diagnostics').innerText = JSON.stringify({A:details(report.a),B:details(report.b)}, null, 2);
            const edges = values => values.slice(0,100).map(raw => { const pair = JSON.parse(raw); return `${pair[0]} → ${pair[1]}`; });
            document.getElementById('comparison-edge-differences').innerText = JSON.stringify({onlyA:edges(report.only_edges_a),onlyB:edges(report.only_edges_b),说明:'界面最多显示各100条；JSON导出保留完整差集。缺少图与显式空图分开处理。'}, null, 2);
            document.getElementById('tab-cnt-version-mismatch').innerText = `${report.version_differences.length}`;
            document.getElementById('tab-cnt-version-unknown').innerText = `${report.unknown_versions.length}`;
        }

        function comparisonMarkdown(report, nameA, nameB) {
            const safe = value => String(value ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\|/g, '\\|').replace(/`/g, '\\`').replace(/[\r\n]/g,' ');
            const pct = value => value === null ? 'N/A' : `${value.toFixed(2)}%`;
            const rows = [['包名＋版本',report.exact],['包身份',report.identity],['记录重数（非物理实例）',report.occurrences],['包版本＋路径记录',report.located_occurrences]];
            if (report.graph) rows.push(['依赖边',report.graph]);
            let md = `# SBOM 组件与依赖图对比报告\n\n- A: ${safe(nameA)}\n- B: ${safe(nameB)}\n- 目标生态相对重合率: ${pct(report.exact.coverage_b)}\n- 目标生态 Jaccard: ${pct(report.exact.jaccard)}\n- 仅 A 出现: ${report.only_identities_a.length}；仅 B 出现: ${report.only_identities_b.length}（包身份）\n\n`;
            md += '| 层次 | A | B | 交集 | 相对B重合率 | 相对A重合率 | Jaccard |\n| --- | ---: | ---: | ---: | --- | --- | --- |\n';
            md += rows.map(([label,m]) => `| ${label} | ${m.a} | ${m.b} | ${m.common} | ${pct(m.coverage_b)} | ${pct(m.coverage_a)} | ${pct(m.jaccard)} |`).join('\n');
            md += `\n\n## 版本集合差异\n\n| 包身份 | A版本 | B版本 |\n| --- | --- | --- |\n`;
            md += report.version_differences.map(r => `| ${safe(r.identity)} | ${safe(r.versions_a.join(', '))} | ${safe(r.versions_b.join(', '))} |`).join('\n');
            for (const [label,values] of [['版本未知',report.unknown_versions],['仅A包身份',report.only_identities_a],['仅B包身份',report.only_identities_b],['仅A精确PURL（含版本差异）',report.only_keys_a],['仅B精确PURL（含版本差异）',report.only_keys_b],['仅A依赖边',report.only_edges_a],['仅B依赖边',report.only_edges_b]]) {
                md += `\n\n## ${label}\n\n` + (values.length ? values.map(v => '- '+safe(v)).join('\n') : '无。');
            }
            md += `\n\n## 统计规则与诊断\n\n目标生态：${safe(report.policy.ecosystems.join(', '))}；应用节点${report.policy.include_applications ? '纳入' : '排除'}；0.0.0${report.policy.exclude_zero_versions ? '显式排除' : '保留'}。范围、占位符与冲突版本不进入精确匹配。来源路径独立比较，PURL qualifier/subpath不计入包版本集合键。\n\n`;
            md += `A 未解析/冲突: ${report.a.unresolved_components}/${report.a.inconsistent_components}；B: ${report.b.unresolved_components}/${report.b.inconsistent_components}。\n\n图边重合率：${report.graph ? pct(report.graph.coverage_b) : 'N/A'}；悬空引用 A:${report.a.dangling_refs.length}/B:${report.b.dangling_refs.length}；重复引用 A:${report.a.duplicate_refs.length}/B:${report.b.duplicate_refs.length}。\n\n`;
            md += report.warnings.map(w => '- '+safe(w)).join('\n');
            return md + '\n\n参照 SBOM 不是独立真值；重合率不等于准确率或召回率。需对齐源码提交、开发/测试依赖、平台与扫描参数。记录重数不代表已核实物理实例。许可证、漏洞与运行时证据需独立评估。';
        }

        // 渲染图表群函数
        function renderChartsGroup(data) {
            if (!chartOverlap || !chartEco) return;
            const {
                toolA, toolB,
                commonPurls, onlyPurlsA, onlyPurlsB, onlyPurlsC,
                purlsA, purlsB, purlsC,
                compsA, compsB, compsC,
                mapA, mapB, mapC
            } = data;

            const hasC = !!sbomC;
            const sbomC_ref = (typeof sbomC !== 'undefined') ? sbomC : null;
            const toolC = sbomC_ref ? (extractToolName(sbomC_ref) || 'Syft') : 'Syft';

            // 1. 依赖集合交并全景环形图 (支持双向或三方全景重合)
            let pieData = [];
            let centerRatio = '0.0';
            let centerLabel = '共有重合率';

            if (hasC) {
                const inAll3 = [...purlsA].filter(p => purlsB.has(p) && purlsC.has(p)).length;
                const onlyInA = [...purlsA].filter(p => !purlsB.has(p) && !purlsC.has(p)).length;
                const onlyInB = [...purlsB].filter(p => !purlsA.has(p) && !purlsC.has(p)).length;
                const onlyInC = [...purlsC].filter(p => !purlsA.has(p) && !purlsB.has(p)).length;
                const totalUnionSet = new Set([...purlsA, ...purlsB, ...purlsC]);
                const pairwise = totalUnionSet.size - inAll3 - onlyInA - onlyInB - onlyInC;

                centerRatio = totalUnionSet.size > 0 ? (inAll3 / totalUnionSet.size * 100).toFixed(1) : 'N/A';
                centerLabel = '三方全重合率';

                pieData = [
                    {
                        value: inAll3,
                        name: '🟢 三方共有依赖 (In All 3)',
                        itemStyle: {
                            color: new echarts.graphic.LinearGradient(0, 0, 1, 1, [
                                { offset: 0, color: '#34d399' },
                                { offset: 1, color: '#059669' }
                            ]),
                            shadowBlur: 14,
                            shadowColor: 'rgba(52, 211, 153, 0.4)'
                        }
                    },
                    {
                        value: onlyInA,
                        name: `🔵 ${toolA} 独有增量 (Only A)`,
                        itemStyle: {
                            color: new echarts.graphic.LinearGradient(0, 0, 1, 1, [
                                { offset: 0, color: '#38bdf8' },
                                { offset: 1, color: '#0284c7' }
                            ]),
                            shadowBlur: 14,
                            shadowColor: 'rgba(56, 189, 248, 0.4)'
                        }
                    },
                    {
                        value: onlyInB,
                        name: `🟠 ${toolB} 独有参照 (Only B)`,
                        itemStyle: {
                            color: new echarts.graphic.LinearGradient(0, 0, 1, 1, [
                                { offset: 0, color: '#fb923c' },
                                { offset: 1, color: '#ea580c' }
                            ]),
                            shadowBlur: 14,
                            shadowColor: 'rgba(251, 146, 60, 0.4)'
                        }
                    },
                    {
                        value: onlyInC,
                        name: `🟣 ${toolC} 独有参照 (Only C)`,
                        itemStyle: {
                            color: new echarts.graphic.LinearGradient(0, 0, 1, 1, [
                                { offset: 0, color: '#c084fc' },
                                { offset: 1, color: '#9333ea' }
                            ]),
                            shadowBlur: 14,
                            shadowColor: 'rgba(192, 132, 252, 0.4)'
                        }
                    }
                ];
                if (pairwise > 0) {
                    pieData.push({
                        value: pairwise,
                        name: '🟡 双方局部共有 (Pairwise)',
                        itemStyle: {
                            color: new echarts.graphic.LinearGradient(0, 0, 1, 1, [
                                { offset: 0, color: '#fbbf24' },
                                { offset: 1, color: '#d97706' }
                            ]),
                            shadowBlur: 10,
                            shadowColor: 'rgba(251, 191, 36, 0.4)'
                        }
                    });
                }
            } else {
                const unionCount = commonPurls.size + onlyPurlsA.size + onlyPurlsB.size;
                centerRatio = unionCount > 0 ? (commonPurls.size / unionCount * 100).toFixed(1) : 'N/A';
                centerLabel = '共有重合率';
                pieData = [
                    {
                        value: commonPurls.size,
                        name: '🟢 双方共有依赖 (Common)',
                        itemStyle: {
                            color: new echarts.graphic.LinearGradient(0, 0, 1, 1, [
                                { offset: 0, color: '#34d399' },
                                { offset: 1, color: '#059669' }
                            ]),
                            shadowBlur: 14,
                            shadowColor: 'rgba(52, 211, 153, 0.4)'
                        }
                    },
                    {
                        value: onlyPurlsA.size,
                        name: `🔵 ${toolA} 独有增量 (Only A)`,
                        itemStyle: {
                            color: new echarts.graphic.LinearGradient(0, 0, 1, 1, [
                                { offset: 0, color: '#38bdf8' },
                                { offset: 1, color: '#0284c7' }
                            ]),
                            shadowBlur: 14,
                            shadowColor: 'rgba(56, 189, 248, 0.4)'
                        }
                    },
                    {
                        value: onlyPurlsB.size,
                        name: `🟠 ${toolB} 独有参照 (Only B)`,
                        itemStyle: {
                            color: new echarts.graphic.LinearGradient(0, 0, 1, 1, [
                                { offset: 0, color: '#fb923c' },
                                { offset: 1, color: '#ea580c' }
                            ]),
                            shadowBlur: 14,
                            shadowColor: 'rgba(251, 146, 60, 0.4)'
                        }
                    }
                ];
            }

            chartOverlap.clear();
            chartOverlap.setOption({
                backgroundColor: 'transparent',
                tooltip: {
                    renderMode: 'html',
                    trigger: 'item',
                    backgroundColor: 'rgba(15, 23, 42, 0.95)',
                    borderColor: '#334155',
                    borderWidth: 1,
                    textStyle: { color: '#f8fafc', fontSize: 12 },
                    formatter: params => `${escapeHtml(params.name)}: ${params.value} 个包版本 (${params.percent}%)`
                },
                legend: {
                    bottom: '2%',
                    itemWidth: 12,
                    itemHeight: 12,
                    textStyle: { color: '#cbd5e1', fontSize: 11 }
                },
                graphic: [
                    {
                        type: 'text',
                        left: 'center',
                        top: '41%',
                        style: {
                            text: centerRatio === 'N/A' ? 'N/A' : centerRatio + '%',
                            textAlign: 'center',
                            fill: '#34d399',
                            fontSize: 26,
                            fontWeight: 'bold',
                            fontFamily: 'monospace'
                        }
                    },
                    {
                        type: 'text',
                        left: 'center',
                        top: '49%',
                        style: {
                            text: centerLabel,
                            textAlign: 'center',
                            fill: '#94a3b8',
                            fontSize: 11
                        }
                    }
                ],
                series: [{
                    type: 'pie',
                    radius: ['52%', '76%'],
                    center: ['50%', '46%'],
                    avoidLabelOverlap: false,
                    padAngle: 3,
                    itemStyle: {
                        borderRadius: 8,
                        borderColor: '#0b1322',
                        borderWidth: 3
                    },
                    label: { show: false },
                    emphasis: {
                        scale: true,
                        scaleSize: 8,
                        label: { show: false }
                    },
                    data: pieData
                }]
            });

            // 2. 跨生态双向/三方覆盖柱状图 (仅对比展示本工程实际包含并检测的语言生态)
            const ecoNameMap = {
                cargo: 'Cargo (Rust)',
                golang: 'Go (Golang)',
                maven: 'Maven (Java)',
                npm: 'NPM (JS)',
                pypi: 'PyPI (Python)',
                composer: 'Composer (PHP)',
                nuget: 'NuGet (.NET)',
                rubygems: 'RubyGems (Ruby)'
            };
            const displayEcos = Array.from(activeTargetEcos).sort();
            if (displayEcos.length === 0) {
                displayEcos.push('cargo', 'golang', 'maven', 'npm', 'pypi');
            }

            const ecoCountA = {};
            const ecoCountB = {};
            const ecoCountC = {};
            displayEcos.forEach(e => { ecoCountA[e] = 0; ecoCountB[e] = 0; ecoCountC[e] = 0; });

            compsA.forEach(c => {
                const e = extractEco(normalizePurl(c.purl));
                if (displayEcos.includes(e)) {
                    ecoCountA[e] = (ecoCountA[e] || 0) + 1;
                }
            });
            compsB.forEach(c => {
                const e = extractEco(normalizePurl(c.purl));
                if (displayEcos.includes(e)) {
                    ecoCountB[e] = (ecoCountB[e] || 0) + 1;
                }
            });
            (compsC || []).forEach(c => {
                const e = extractEco(normalizePurl(c.purl));
                if (displayEcos.includes(e)) {
                    ecoCountC[e] = (ecoCountC[e] || 0) + 1;
                }
            });

            const ecoSeries = [
                {
                    name: toolA,
                    type: 'bar',
                    data: displayEcos.map(e => ({value:ecoCountA[e] || 0,records:ecoCountA[e] || 0,unique:new Set(compsA.filter(c => extractEco(c.purl) === e).map(c=>c.purl)).size})),
                    itemStyle: {
                        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                            { offset: 0, color: '#38bdf8' },
                            { offset: 1, color: '#0284c7' }
                        ]),
                        borderRadius: [6, 6, 0, 0],
                        shadowBlur: 8,
                        shadowColor: 'rgba(56, 189, 248, 0.3)'
                    },
                    barMaxWidth: 24,
                    label: {
                        show: true,
                        position: 'top',
                        color: '#7dd3fc',
                        fontSize: 9,
                        fontFamily: 'monospace'
                    }
                },
                {
                    name: toolB,
                    type: 'bar',
                    data: displayEcos.map(e => ({value:ecoCountB[e] || 0,records:ecoCountB[e] || 0,unique:new Set(compsB.filter(c => extractEco(c.purl) === e).map(c=>c.purl)).size})),
                    itemStyle: {
                        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                            { offset: 0, color: '#fb923c' },
                            { offset: 1, color: '#ea580c' }
                        ]),
                        borderRadius: [6, 6, 0, 0],
                        shadowBlur: 8,
                        shadowColor: 'rgba(251, 146, 60, 0.3)'
                    },
                    barMaxWidth: 24,
                    label: {
                        show: true,
                        position: 'top',
                        color: '#fdba74',
                        fontSize: 9,
                        fontFamily: 'monospace'
                    }
                }
            ];

            const legendData = [toolA, toolB];

            if (hasC) {
                legendData.push(toolC);
                ecoSeries.push({
                    name: toolC,
                    type: 'bar',
                    data: displayEcos.map(e => ({value:ecoCountC[e] || 0,records:ecoCountC[e] || 0,unique:new Set((compsC || []).filter(c => extractEco(c.purl) === e).map(c=>c.purl)).size})),
                    itemStyle: {
                        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                            { offset: 0, color: '#c084fc' },
                            { offset: 1, color: '#9333ea' }
                        ]),
                        borderRadius: [6, 6, 0, 0],
                        shadowBlur: 8,
                        shadowColor: 'rgba(192, 132, 252, 0.3)'
                    },
                    barMaxWidth: 24,
                    label: {
                        show: true,
                        position: 'top',
                        color: '#d8b4fe',
                        fontSize: 9,
                        fontFamily: 'monospace'
                    }
                });
            }

            const ecoStats = [compsA,compsB,compsC || []].map(cs => CompareCore.ecosystemStats(cs, displayEcos));
            chartEco.clear();
            chartEco.setOption({
                backgroundColor: 'transparent',
                tooltip: {
                    renderMode: 'html',
                    trigger: 'axis',
                    axisPointer: { type: 'shadow' },
                    backgroundColor: 'rgba(15, 23, 42, 0.95)',
                    borderColor: '#334155',
                    borderWidth: 1,
                    textStyle: { color: '#f8fafc', fontSize: 12 },
                    formatter: params => escapeHtml(params[0]?.axisValue || '') + params.map(row => {const stat = ecoStats[row.seriesIndex]?.[displayEcos[row.dataIndex]] || {records:0,unique:0};return '<br/>' + escapeHtml(row.seriesName) + ': ' + stat.records + ' 条记录 / ' + stat.unique + ' 个唯一包版本';}).join('')
                },
                legend: {
                    data: legendData,
                    textStyle: { color: '#cbd5e1', fontSize: 11 },
                    top: '2%',
                    right: '4%'
                },
                grid: { top: 46, bottom: 28, left: 55, right: 25 },
                xAxis: {
                    type: 'category',
                    data: displayEcos.map(e => ecoNameMap[e] || e.toUpperCase()),
                    axisLabel: { color: '#94a3b8', fontSize: 11, fontWeight: 500 },
                    axisLine: { lineStyle: { color: '#334155' } },
                    axisTick: { show: false }
                },
                yAxis: {
                    type: 'value',
                    axisLabel: { color: '#94a3b8', fontSize: 10, fontFamily: 'monospace' },
                    splitLine: { lineStyle: { color: 'rgba(255,255,255,0.06)', type: 'dashed' } }
                },
                series: ecoSeries
            });

            updateEcosystemMetric();

            // 3. 交互式拓扑差异全景图 (真实依赖调用链构建，杜绝标签挤压)
            lastMapA = mapA;
            lastMapB = mapB;
            lastCommonPurls = commonPurls;
            lastOnlyPurlsA = onlyPurlsA;
            lastOnlyPurlsB = onlyPurlsB;
            renderTopoGraph(mapA, mapB, commonPurls, onlyPurlsA, onlyPurlsB);
        }

        // 提取生态名称
        function extractEcoName(purl) {
            if (!purl) return 'OTHER';
            const m = purl.match(/^pkg:([^/]+)/);
            return m ? m[1].toUpperCase() : 'OTHER';
        }

        // 从 SBOM dependencies 中提取边
        function extractEdgesFromSbom(sbom, rootRef, rootId, nodeIndexMap, linkSet, links) {
            if (!sbom) return;
            const summary = sbom === sbomA ? lastComparison?.a : sbom === sbomB ? lastComparison?.b : lastComparisonAC?.b;
            const edges = (summary || CompareCore.summarize(sbom, readCompareOptions())).edges;
            for (const encoded of edges) {
                const [source, target] = JSON.parse(encoded);
                if (nodeIndexMap.has(source) && nodeIndexMap.has(target) && !linkSet.has(encoded)) {
                    linkSet.add(encoded);
                    links.push({source, target, lineStyle: {color:'rgba(148, 163, 184, 0.35)', width:1.2, curveness:0.08}});
                }
            }
        }

        // 构建单份 SBOM 独立拓扑图数据
        function buildSingleSbomGraphData(sbom, compMap, nodeColor, borderColor) {
            const rootId = '__PROJECT_ROOT__';
            const rootName = sbom?.metadata?.component?.name || 'Project Root';
            const rootVersion = sbom?.metadata?.component?.version || '';
            const rootBomRef = sbom?.metadata?.component?.['bom-ref'] ? sbom.metadata.component['bom-ref'].trim() : null;

            const nodes = [{
                id: rootId,
                name: `📦 ${rootName}${rootVersion ? '@' + rootVersion : ''}`,
                cleanName: rootName,
                version: rootVersion,
                purl: rootId,
                eco: 'ROOT',
                symbolSize: 24,
                itemStyle: {
                    color: '#6366f1',
                    borderColor: '#818cf8',
                    borderWidth: 2,
                    shadowBlur: 12,
                    shadowColor: 'rgba(99, 102, 241, 0.5)'
                }
            }];
            const nodeIndexMap = new Map([[rootId, 0]]);
            const links = [];
            const linkSet = new Set();

            compMap.forEach((c, purl) => {
                if (nodeIndexMap.has(purl)) return;
                const cleanName = c?.name || purl.split('/')[1]?.split('@')[0] || purl.split('@')[0] || purl;
                const version = c?.version || (purl.split('@')[1]?.split('?')[0]) || '';
                const eco = extractEcoName(purl);

                nodeIndexMap.set(purl, nodes.length);
                nodes.push({
                    id: purl,
                    name: `${cleanName}${version ? '@' + version : ''}`,
                    cleanName: cleanName,
                    version: version,
                    purl: purl,
                    eco: eco,
                    symbolSize: 13,
                    itemStyle: {
                        color: nodeColor,
                        borderColor: borderColor,
                        borderWidth: 1.5,
                        shadowBlur: 6,
                        shadowColor: 'rgba(0,0,0,0.3)'
                    }
                });
            });

            extractEdgesFromSbom(sbom, rootBomRef, rootId, nodeIndexMap, linkSet, links);

            // 根节点兜底锚定未连接节点
            const hasIncoming = new Set();
            links.forEach(l => hasIncoming.add(l.target));
            nodes.forEach(n => {
                if (n.id !== rootId && !hasIncoming.has(n.id)) {
                    const key = `${rootId}->${n.id}`;
                    if (!linkSet.has(key)) {
                        linkSet.add(key);
                        links.push({
                            source: rootId,
                            target: n.id,
                            synthetic: true,
                            value: '布局辅助连线，不代表依赖关系',
                            lineStyle: {
                                type: 'dashed',
                                color: 'rgba(99, 102, 241, 0.22)',
                                width: 1,
                                curveness: 0.05
                            }
                        });
                        hasIncoming.add(n.id);
                    }
                }
            });

            return { nodes, links, rootId };
        }

        // 渲染左右双屏分屏对比拓扑图
        function renderSplitDualGraphs(mapA, mapB) {
            const domLeft = document.getElementById('chart-split-left');
            const domRight = document.getElementById('chart-split-right');
            if (!domLeft || !domRight) return;

            // 检查已存实例如果宽度或高度为0则重新init
            if (chartSplitLeft && (domLeft.clientWidth === 0 || chartSplitLeft.getWidth() === 0)) {
                chartSplitLeft.dispose();
                chartSplitLeft = null;
            }
            if (chartSplitRight && (domRight.clientWidth === 0 || chartSplitRight.getWidth() === 0)) {
                chartSplitRight.dispose();
                chartSplitRight = null;
            }

            if (!chartSplitLeft) {
                chartSplitLeft = echarts.init(domLeft, null, { renderer: 'canvas' });
            }
            if (!chartSplitRight) {
                chartSplitRight = echarts.init(domRight, null, { renderer: 'canvas' });
            }

            // 确定右侧对照工具（优先使用 sbomB，若无则使用 sbomC）
            const targetSbomRight = sbomB;
            const targetMapRight = (targetSbomRight === sbomB) ? mapB : (function() {
                const mc = new Map();
                if (sbomC && Array.isArray(sbomC.components)) {
                    lastComparisonAC.b.records.filter(r => r.key && isTargetEco(extractEco(r.identity))).map(r => ({...r.component, purl:r.key, version:r.version})).forEach(c => {
                        const p = normalizePurl(c.purl);
                        if (p && !mc.has(p)) mc.set(p, c);
                    });
                }
                return mc;
            })();

            const toolBName = extractToolName(targetSbomRight) || (targetSbomRight === sbomC ? 'Syft' : 'Trivy');
            const badgeRight = document.getElementById('split-badge-right');
            if (badgeRight) {
                badgeRight.innerText = `🔶 对照工具拓扑图 (${toolBName})`;
            }

            const leftData = buildSingleSbomGraphData(sbomA, mapA, '#38bdf8', '#0284c7');
            const rightData = buildSingleSbomGraphData(targetSbomRight, targetMapRight, '#fb923c', '#ea580c');

            function makeSubOption(data, toolLabel) {
                return {
                    backgroundColor: 'transparent',
                    tooltip: {
                        renderMode: 'html',
                        trigger: 'item',
                        backgroundColor: 'rgba(15, 23, 42, 0.95)',
                        borderColor: '#334155',
                        borderWidth: 1,
                        textStyle: { color: '#f8fafc', fontSize: 12 },
                        formatter: function(params) {
                            if (params.dataType === 'node') {
                                const d = params.data;
                                if (d.id === data.rootId) {
                                    return `<div style="font-weight:bold; font-size:13px; color:#a5b4fc;">📦 工程根节点 (${escapeHtml(d.cleanName)})</div>`;
                                }
                                return `
                                    <div style="font-weight:bold; font-size:13px; color:#fff; margin-bottom:4px;">${escapeHtml(d.cleanName)}</div>
                                    <div>来源工具: <b style="color:#7dd3fc;">${escapeHtml(toolLabel)}</b></div>
                                    <div>版本: <b style="color:#79c0ff;">${escapeHtml(d.version || '-')}</b></div>
                                    <div>语言生态: <span style="color:#38bdf8;">${escapeHtml(d.eco)}</span></div>
                                    <div style="color:#8b949e; font-size:10px; font-family:monospace; margin-top:4px; word-break:break-all;">${escapeHtml(d.purl)}</div>
                                `;
                            } else if (params.dataType === 'edge') {
                                if (params.data.synthetic) return '布局辅助连线，不代表依赖关系，不计入依赖边比较';
                                return `<div style="font-size:11px; color:#cbd5e1;">${escapeHtml(params.data.source)} ➔ ${escapeHtml(params.data.target)}</div>`;
                            }
                            return '';
                        }
                    },
                    series: [{
                        type: 'graph',
                        layout: graphLayoutFor(data.nodes.length),
                        circular: { rotateLabel: true },
                        data: data.nodes,
                        links: data.links,
                        roam: true,
                        draggable: true,
                        label: { show: false },
                        force: {
                            repulsion: Math.round(150 * compareRepulsionMult),
                            edgeLength: [Math.round(40 * compareRepulsionMult), Math.round(120 * compareRepulsionMult)],
                            gravity: 0.12,
                            friction: 0.5
                        },
                        emphasis: {
                            focus: 'adjacency',
                            label: {
                                show: true,
                                fontSize: 11,
                                fontWeight: 'bold',
                                color: '#ffffff',
                                backgroundColor: '#161b22',
                                borderColor: '#38bdf8',
                                borderWidth: 1,
                                padding: [3, 6],
                                borderRadius: 4
                            },
                            lineStyle: { width: 2.5, color: '#38bdf8', opacity: 1 }
                        }
                    }]
                };
            }

            chartSplitLeft.setOption(makeSubOption(leftData, 'sbom-generator'));
            chartSplitRight.setOption(makeSubOption(rightData, toolBName));

            requestAnimationFrame(() => {
                if (chartSplitLeft) chartSplitLeft.resize();
                if (chartSplitRight) chartSplitRight.resize();
            });
            setTimeout(() => {
                if (chartSplitLeft) chartSplitLeft.resize();
                if (chartSplitRight) chartSplitRight.resize();
            }, 60);
        }

        // 绑定拓扑图操作栏控制事件
        function bindTopoControlEvents(currentNodes) {
            const topoViewSelect = document.getElementById('select-topo-view');
            if (topoViewSelect) {
                topoViewSelect.onchange = (e) => {
                    currentTopoView = e.target.value;
                    document.querySelectorAll('.graph-tab-btn').forEach(btn => {
                        btn.classList.toggle('active', btn.getAttribute('data-view') === currentTopoView);
                    });
                    if (lastComparison) {
                        renderTopoGraph(lastMapA, lastMapB, lastCommonPurls, lastOnlyPurlsA, lastOnlyPurlsB);
                    }
                    showToast(`已切换拓扑图视图: ${e.target.options[e.target.selectedIndex].text}`);
                };
            }

            document.querySelectorAll('.graph-tab-btn').forEach(btn => {
                btn.onclick = () => {
                    document.querySelectorAll('.graph-tab-btn').forEach(b => b.classList.remove('active'));
                    btn.classList.add('active');
                    currentTopoView = btn.getAttribute('data-view');
                    if (topoViewSelect) topoViewSelect.value = currentTopoView;
                    if (lastMapA.size > 0 || lastMapB.size > 0) {
                        renderTopoGraph(lastMapA, lastMapB, lastCommonPurls, lastOnlyPurlsA, lastOnlyPurlsB);
                    }
                    showToast(`已切换拓扑图视图: ${btn.innerText.trim()}`);
                };
            });

            const getActiveCharts = () => currentTopoView === 'split' ? [chartSplitLeft, chartSplitRight].filter(Boolean) : [chartTopo].filter(Boolean);

            const layoutSel = document.getElementById('select-topo-layout');
            if (layoutSel) {
                layoutSel.onchange = e => {
                    compareGraphLayout = e.target.value;
                    getActiveCharts().forEach(c => c.setOption({
                        series: [{
                            layout: graphLayoutFor((c.getOption()?.series?.[0]?.data || []).length),
                            circular: { rotateLabel: true }
                        }]
                    }));
                    showToast('已更新拓扑布局');
                };
            }

            const repulsionSlider = document.getElementById('slider-topo-repulsion');
            if (repulsionSlider) {
                repulsionSlider.oninput = e => {
                    compareRepulsionMult = parseFloat(e.target.value);
                    getActiveCharts().forEach(c => c.setOption({
                        series: [{
                            force: {
                                repulsion: Math.round(180 * compareRepulsionMult),
                                edgeLength: [Math.round(50 * compareRepulsionMult), Math.round(140 * compareRepulsionMult)]
                            }
                        }]
                    }));
                };
            }

            const fsBtn = document.getElementById('btn-topo-fullscreen');
            if (fsBtn) {
                fsBtn.onclick = () => {
                    const box = document.getElementById('chart-topo-graph').parentElement;
                    const isFull = box.classList.toggle('fullscreen-canvas-mode');
                    fsBtn.innerText = isFull ? '✕ 还原' : '⛶ 全屏';
                    setTimeout(() => {
                        [chartTopo, chartSplitLeft, chartSplitRight].forEach(c => c && c.resize());
                    }, 100);
                    showToast(isFull ? "已进入拓扑全屏超大视野模式 (可按 Esc 或点击右上角还原)" : "已退出全屏模式");
                };
            }

            if (!escapeListenerBound) {
            escapeListenerBound = true;
            window.addEventListener('keydown', e => {
                if (e.key === 'Escape') {
                    const box = document.getElementById('chart-topo-graph').parentElement;
                    if (box?.classList.contains('fullscreen-canvas-mode')) {
                        box.classList.remove('fullscreen-canvas-mode');
                        const fs = document.getElementById('btn-topo-fullscreen');
                        if (fs) fs.innerText = '⛶ 全屏';
                        setTimeout(() => {
                            [chartTopo, chartSplitLeft, chartSplitRight].forEach(c => c && c.resize());
                        }, 80);
                    }
                }
            });

            }
            const zoomInBtn = document.getElementById('btn-topo-zoom-in');
            if (zoomInBtn) {
                zoomInBtn.onclick = () => {
                    getActiveCharts().forEach(c => {
                        const opt = c.getOption();
                        const zoom = ((opt && opt.series && opt.series[0] && opt.series[0].zoom) || 1) * 1.3;
                        c.setOption({ series: [{ zoom }] });
                    });
                };
            }

            const zoomOutBtn = document.getElementById('btn-topo-zoom-out');
            if (zoomOutBtn) {
                zoomOutBtn.onclick = () => {
                    getActiveCharts().forEach(c => {
                        const opt = c.getOption();
                        const zoom = Math.max(((opt && opt.series && opt.series[0] && opt.series[0].zoom) || 1) * 0.7, 0.2);
                        c.setOption({ series: [{ zoom }] });
                    });
                };
            }

            const resetBtn = document.getElementById('btn-topo-reset');
            if (resetBtn) {
                resetBtn.onclick = () => {
                    getActiveCharts().forEach(c => c.dispatchAction({ type: 'restore' }));
                };
            }

            const searchInput = document.getElementById('topo-search-input');
            if (searchInput) {
                searchInput.onkeydown = e => {
                    if (e.key === 'Enter') {
                        const val = e.target.value.trim().toLowerCase();
                        if (!val) return;
                        if (currentTopoView === 'split') {
                            let found = false;
                            [chartSplitLeft, chartSplitRight].forEach((c) => {
                                if (!c) return;
                                const opt = c.getOption();
                                const sNodes = opt?.series?.[0]?.data || [];
                                const nIdx = sNodes.findIndex(n => (n.name && n.name.toLowerCase().includes(val)) || (n.purl && n.purl.toLowerCase().includes(val)));
                                if (nIdx >= 0) {
                                    c.dispatchAction({ type: 'focusNodeAdjacency', dataIndex: nIdx });
                                    found = true;
                                }
                            });
                            if (found) {
                                showToast(`已在分屏拓扑中定位匹配节点`);
                            } else {
                                showToast("未找到匹配的拓扑节点", true);
                            }
                        } else {
                            const currentNodes = chartTopo?.getOption()?.series?.[0]?.data || [];
                            const idx = currentNodes.findIndex(n => n.name.toLowerCase().includes(val) || (n.purl && n.purl.toLowerCase().includes(val)));
                            if (idx >= 0) {
                                chartTopo.dispatchAction({ type: 'focusNodeAdjacency', dataIndex: idx });
                                showToast(`已在拓扑图中定位节点: ${currentNodes[idx].name}`);
                            } else {
                                showToast("未找到匹配的拓扑节点", true);
                            }
                        }
                    }
                };
            }
        }

        // 拓扑全景图渲染 (真实依赖链路构建与标签防遮挡)
        function renderTopoGraph(mapA, mapB, commonPurls, onlyPurlsA, onlyPurlsB) {
            const singleDom = document.getElementById('chart-topo-graph');
            const splitDom = document.getElementById('chart-split-container');
            if (currentTopoView === 'split') {
                if (singleDom) singleDom.style.display = 'none';
                if (splitDom) splitDom.style.display = 'grid';
                renderSplitDualGraphs(mapA, mapB);
                bindTopoControlEvents();
                return;
            } else {
                if (singleDom) singleDom.style.display = 'block';
                if (splitDom) splitDom.style.display = 'none';
                if (chartTopo) chartTopo.resize();
            }
            const dom = document.getElementById('chart-topo-graph');
            if (!dom) return;
            if (!chartTopo || chartTopo.isDisposed()) chartTopo = echarts.init(dom, null, { renderer: 'canvas' });

            const nodes = [];
            const nodeIndexMap = new Map();

            // 1. 工程根节点（作为一级依赖的锚点基座，彻底解决孤立节点漂移形成外环的问题）
            const rootId = '__PROJECT_ROOT__';
            const selectedSbom = currentTopoView === 'ours' ? sbomA : currentTopoView === 'trivy' ? sbomB : currentTopoView === 'syft' ? sbomC : null;
            const rootName = selectedSbom?.metadata?.component?.name || '合并布局锚点';
            const rootVersion = selectedSbom?.metadata?.component?.version || '';
            const rootBomRefA = sbomA?.metadata?.component?.['bom-ref'] ? sbomA.metadata.component['bom-ref'].trim() : null;
            const rootBomRefB = sbomB?.metadata?.component?.['bom-ref'] ? sbomB.metadata.component['bom-ref'].trim() : null;

            // 提取三方组件映射
            const mapC = new Map();
            if (sbomC && Array.isArray(sbomC.components)) {
                lastComparisonAC.b.records.filter(r => r.key && isTargetEco(extractEco(r.identity))).map(r => ({...r.component, purl:r.key, version:r.version})).forEach(c => {
                    const p = normalizePurl(c.purl);
                    if (p && isTargetEco(extractEco(p)) && !mapC.has(p)) mapC.set(p, c);
                });
            }

            const onlyPurlsC = new Set();
            mapC.forEach((c, p) => {
                if (!mapA.has(p) && !mapB.has(p)) onlyPurlsC.add(p);
            });

            if (document.getElementById('legend-only-c-count')) {
                document.getElementById('legend-only-c-count').innerText = onlyPurlsC.size;
            }

            nodes.push({
                id: rootId,
                name: `📦 ${rootName}${rootVersion ? '@' + rootVersion : ''}`,
                cleanName: rootName,
                version: rootVersion,
                purl: rootId,
                eco: 'ROOT',
                category: 0,
                symbolSize: 28,
                itemStyle: {
                    color: '#6366f1',
                    borderColor: '#818cf8',
                    borderWidth: 2,
                    shadowBlur: 14,
                    shadowColor: 'rgba(99, 102, 241, 0.5)'
                }
            });
            nodeIndexMap.set(rootId, 0);

            function addNode(purl, type) {
                if (nodeIndexMap.has(purl)) return;
                const c = type === 1 ? mapA.get(purl) : (type === 2 ? mapB.get(purl) : (type === 3 ? mapC.get(purl) : (mapA.get(purl) || mapB.get(purl) || mapC.get(purl))));
                const cleanName = c?.name || purl.split('/')[1]?.split('@')[0] || purl.split('@')[0] || purl;
                const version = c?.version || (purl.split('@')[1]?.split('?')[0]) || '';
                const eco = extractEcoName(purl);

                let catIndex = 1;
                let nodeColor = '#38bdf8';
                let borderColor = '#0284c7';

                const mask = (mapA.has(purl) ? 1 : 0) | (mapB.has(purl) ? 2 : 0) | (mapC.has(purl) ? 4 : 0);
                const membership = membershipInfo(mask, !!sbomC);
                if (currentTopoView === 'diff') {
                    catIndex = type + 1; // 1: 共同, 2: 仅A, 3: 仅B, 4: 仅C
                    nodeColor = type === 0 ? '#10b981' : (type === 1 ? '#38bdf8' : (type === 2 ? '#fb923c' : '#c084fc'));
                    borderColor = type === 0 ? '#059669' : (type === 1 ? '#0284c7' : (type === 2 ? '#ea580c' : '#9333ea'));
                } else if (currentTopoView === 'ours') {
                    catIndex = 1;
                    nodeColor = '#38bdf8';
                    borderColor = '#0284c7';
                } else if (currentTopoView === 'trivy') {
                    catIndex = 1;
                    nodeColor = '#fb923c';
                    borderColor = '#ea580c';
                } else if (currentTopoView === 'syft') {
                    catIndex = 1;
                    nodeColor = '#c084fc';
                    borderColor = '#9333ea';
                }

                if (currentTopoView === 'diff') {catIndex = membership.category; nodeColor = membership.color; borderColor = membership.color;}
                const nodeObj = {
                    membership: membership.label,
                    id: purl,
                    name: `${cleanName}${version ? '@' + version : ''}`,
                    cleanName: cleanName,
                    version: version,
                    purl: purl,
                    eco: eco,
                    category: catIndex,
                    symbolSize: type === 0 ? 14 : (type === 1 ? 16 : 14),
                    itemStyle: {
                        color: nodeColor,
                        borderColor: borderColor,
                        borderWidth: 1.5,
                        shadowBlur: 8,
                        shadowColor: nodeColor + '55'
                    }
                };
                nodeIndexMap.set(purl, nodes.length);
                nodes.push(nodeObj);
            }

            // 依据当前选中的视图排布节点
            if (currentTopoView === 'ours') {
                mapA.forEach((c, p) => addNode(p, 1));
            } else if (currentTopoView === 'trivy') {
                mapB.forEach((c, p) => addNode(p, 2));
            } else if (currentTopoView === 'syft') {
                mapC.forEach((c, p) => addNode(p, 3));
            } else {
                // diff 三方差分融合视图
                commonPurls.forEach(p => addNode(p, 0));
                onlyPurlsA.forEach(p => addNode(p, 1));
                onlyPurlsB.forEach(p => addNode(p, 2));
                onlyPurlsC.forEach(p => addNode(p, 3));
            }

            // 构建真实边 (Links) 从两份 SBOM 的 dependencies 关系中提取
            const links = [];
            const linkSet = new Set();

            const rootBomRefC = sbomC?.metadata?.component?.['bom-ref'] ? sbomC.metadata.component['bom-ref'].trim() : null;
            if (currentTopoView === 'ours') {
                extractEdgesFromSbom(sbomA, rootBomRefA, rootId, nodeIndexMap, linkSet, links);
            } else if (currentTopoView === 'trivy') {
                extractEdgesFromSbom(sbomB, rootBomRefB, rootId, nodeIndexMap, linkSet, links);
            } else if (currentTopoView === 'syft') {
                extractEdgesFromSbom(sbomC, rootBomRefC, rootId, nodeIndexMap, linkSet, links);
            } else {
                extractEdgesFromSbom(sbomA, rootBomRefA, rootId, nodeIndexMap, linkSet, links);
                extractEdgesFromSbom(sbomB, rootBomRefB, rootId, nodeIndexMap, linkSet, links);
                if (sbomC) extractEdgesFromSbom(sbomC, rootBomRefC, rootId, nodeIndexMap, linkSet, links);
            }

            // 核心修复：将所有未有入边的顶层直接依赖或孤立节点锚定至工程根节点，消除外环孤岛
            const hasIncoming = new Set();
            links.forEach(l => hasIncoming.add(l.target));

            nodes.forEach(n => {
                if (n.id !== rootId && !hasIncoming.has(n.id)) {
                    const key = `${rootId}->${n.id}`;
                    if (!linkSet.has(key)) {
                        linkSet.add(key);
                        links.push({
                            source: rootId,
                            target: n.id,
                            synthetic: true,
                            value: '布局辅助连线，不代表依赖关系',
                            lineStyle: {
                                type: 'dashed',
                                color: 'rgba(99, 102, 241, 0.22)',
                                width: 1.1,
                                curveness: 0.05
                            }
                        });
                        hasIncoming.add(n.id);
                    }
                }
            });

            let BM_CATEGORIES = [];
            if (currentTopoView === 'ours') {
                BM_CATEGORIES = [
                    { name: '📦 工程根节点', itemStyle: { color: '#6366f1' } },
                    { name: `🔷 本项目依赖组件 (${mapA.size})`, itemStyle: { color: '#38bdf8' } }
                ];
            } else if (currentTopoView === 'trivy') {
                BM_CATEGORIES = [
                    { name: '📦 工程根节点', itemStyle: { color: '#6366f1' } },
                    { name: `🔶 Trivy 依赖组件 (${mapB.size})`, itemStyle: { color: '#fb923c' } }
                ];
            } else if (currentTopoView === 'syft') {
                BM_CATEGORIES = [
                    { name: '📦 工程根节点', itemStyle: { color: '#6366f1' } },
                    { name: `🟣 Syft 依赖组件 (${mapC.size})`, itemStyle: { color: '#c084fc' } }
                ];
            } else {
                const partition = CompareCore.classifySets(new Set(mapA.keys()),new Set(mapB.keys()),sbomC ? new Set(mapC.keys()) : null);
                BM_CATEGORIES = [
                    {name:'布局锚点'},
                    {name:'全部已载入工具共有 (' + partition[sbomC ? 7 : 3].length + ')',itemStyle:{color:'#10b981'}},
                    {name:'仅 A (' + partition[1].length + ')',itemStyle:{color:'#38bdf8'}},
                    {name:'仅 B (' + partition[2].length + ')',itemStyle:{color:'#fb923c'}},
                    {name:'仅 C (' + partition[4].length + ')',itemStyle:{color:'#c084fc'}},
                    {name:'A、B 共有 (' + (sbomC ? partition[3].length : 0) + ')',itemStyle:{color:'#fbbf24'}},
                    {name:'A、C 共有 (' + partition[5].length + ')',itemStyle:{color:'#fbbf24'}},
                    {name:'B、C 共有 (' + partition[6].length + ')',itemStyle:{color:'#fbbf24'}}
                ];
            }

            const option = {
                backgroundColor: 'transparent',
                animation: nodes.length < 600,
                tooltip: {
                    renderMode: 'html',
                    trigger: 'item',
                    backgroundColor: 'rgba(15, 23, 42, 0.95)',
                    borderColor: '#334155',
                    borderWidth: 1,
                    textStyle: { color: '#f8fafc', fontSize: 12 },
                    formatter: function(params) {
                        if (params.dataType === 'node') {
                            const d = params.data;
                            if (d.id === rootId) {
                                return `
                                    <div style="font-weight:bold; font-size:14px; color:#a5b4fc; margin-bottom:4px;">📦 工程根节点 (${escapeHtml(d.cleanName)})</div>
                                    <div style="color:#cbd5e1; font-size:12px; margin-bottom:4px;">布局锚点；虚线只用于排布，不表示项目声明了全部节点。</div>
                                    ${d.version ? `<div>工程版本: <b style="color:#79c0ff;">${escapeHtml(d.version)}</b></div>` : ''}
                                `;
                            }
                            let typeBadge = '';
                            if (currentTopoView === 'diff') {
                                typeBadge = '<span style="font-weight:bold;">' + escapeHtml(d.membership) + '</span>';
                            } else if (currentTopoView === 'ours') {
                                typeBadge = '<span style="color:#38bdf8; font-weight:bold;">🔷 本项目检测组件</span>';
                            } else if (currentTopoView === 'trivy') {
                                typeBadge = '<span style="color:#fb923c; font-weight:bold;">🔶 Trivy 检测组件</span>';
                            } else if (currentTopoView === 'syft') {
                                typeBadge = '<span style="color:#c084fc; font-weight:bold;">🟣 Syft 检测组件</span>';
                            }
                            return `
                                <div style="font-weight:bold; font-size:13px; color:#fff; margin-bottom:4px;">${escapeHtml(d.cleanName)}</div>
                                <div style="margin-bottom:4px;">识别来源: ${typeBadge}</div>
                                <div>版本: <b style="color:#79c0ff;">${escapeHtml(d.version || '-')}</b></div>
                                <div>语言生态: <span style="color:#38bdf8;">${escapeHtml(d.eco)}</span></div>
                                <div style="color:#8b949e; font-size:10px; font-family:var(--font-mono); margin-top:4px; word-break:break-all;">${escapeHtml(d.purl)}</div>
                            `;
                        } else if (params.dataType === 'edge') {
                            const edge = params.data;
                            if (edge.synthetic) return '布局辅助连线，不代表依赖关系，不计入依赖边比较';
                            if (edge.source === rootId) {
                                return `<div style="font-size:12px; color:#cbd5e1;"><b>一级直属依赖关系</b><br/>📦 工程根节点 ➔ ${escapeHtml(edge.target)}</div>`;
                            }
                            return `<div style="font-size:12px; color:#cbd5e1;"><b>已报告的有向依赖边（非运行时调用证明）</b><br/>${escapeHtml(edge.source)} ➔ ${escapeHtml(edge.target)}</div>`;
                        }
                        return '';
                    }
                },
                legend: {
                    data: BM_CATEGORIES.map(c => c.name),
                    top: 12,
                    left: 16,
                    textStyle: { color: '#cbd5e1', fontSize: 11 }
                },
                series: [{
                    type: 'graph',
                    layout: graphLayoutFor(nodes.length),
                    circular: { rotateLabel: true },
                    data: nodes,
                    links: links,
                    categories: BM_CATEGORIES,
                    roam: true,
                    draggable: true,
                    label: {
                        show: false,
                        position: 'right',
                        formatter: '{b}',
                        fontSize: 10,
                        color: '#c9d1d9'
                    },
                    force: {
                        repulsion: Math.round(180 * compareRepulsionMult),
                        edgeLength: [Math.round(40 * compareRepulsionMult), Math.round(130 * compareRepulsionMult)],
                        gravity: 0.1,
                        friction: 0.5
                    },
                    emphasis: {
                        focus: 'adjacency',
                        label: {
                            show: true,
                            fontSize: 11,
                            fontWeight: 'bold',
                            color: '#ffffff',
                            backgroundColor: '#161b22',
                            borderColor: '#38bdf8',
                            borderWidth: 1,
                            padding: [3, 6],
                            borderRadius: 4
                        },
                        lineStyle: { width: 3, color: '#38bdf8', opacity: 1 }
                    },
                    blur: {
                        itemStyle: { opacity: 0.35 },
                        lineStyle: { opacity: 0.15 }
                    }
                }]
            };

            chartTopo.setOption(option, true);
            bindTopoControlEvents(nodes);
        }

        // 提取工具 B (Trivy) 深度技术档案元数据
        function extractToolBDetails(sbom) {
            let toolName = 'Unknown';
            let toolVersion = '未提供版本';
            let toolVendor = '未提供';

            if (sbom?.metadata?.tools) {
                const tools = sbom.metadata.tools;
                if (Array.isArray(tools) && tools.length > 0) {
                    const t = tools[0];
                    if (t.name) toolName = t.name;
                    if (t.version) toolVersion = t.version.startsWith('v') ? t.version : 'v' + t.version;
                    if (t.vendor) toolVendor = t.vendor;
                } else if (tools.components && Array.isArray(tools.components) && tools.components.length > 0) {
                    const t = tools.components[0];
                    if (t.name) toolName = t.name;
                    if (t.version) toolVersion = t.version.startsWith('v') ? t.version : 'v' + t.version;
                    if (t.vendor) toolVendor = t.vendor;
                }
            }

            const timestamp = sbom?.metadata?.timestamp ? new Date(sbom.metadata.timestamp).toLocaleString() : '未提供';
            const specVersion = sbom?.specVersion ? `CycloneDX ${sbom.specVersion}` : '未提供';
            const totalComponents = (sbom?.components || []).length;

            const ecoCounts = {};
            let licenseCount = 0;
            (sbom?.components || []).forEach(c => {
                const eco = extractEco(c.purl || '');
                ecoCounts[eco] = (ecoCounts[eco] || 0) + 1;
                if (Array.isArray(c.licenses) && c.licenses.length > 0) licenseCount++;
            });

            const licenseRatio = totalComponents > 0 ? ((licenseCount / totalComponents) * 100).toFixed(1) : '0.0';

            return {
                toolName,
                toolVersion,
                toolVendor,
                timestamp,
                specVersion,
                totalComponents,
                ecoCounts,
                licenseCount,
                licenseRatio
            };
        }

        // 差异表格多重筛选与分页逻辑
        function applyFiltersAndRenderPage() {
            const searchKeyword = (document.getElementById('diff-search-input').value || '').trim().toLowerCase();
            const ecoFilter = document.getElementById('filter-eco-select').value;
            const runtimeFilter = document.getElementById('filter-runtime-select').value;

            filteredDiffList = currentDiffList.filter(item => {
                // Tab 过滤
                if (activeDiffTab !== 'all' && item.type !== activeDiffTab) return false;
                // 生态过滤
                if (ecoFilter !== 'all' && item.eco !== ecoFilter) return false;
                // 运行时状态过滤
                if (runtimeFilter !== 'all' && item.runtimeStatus !== runtimeFilter) return false;
                // 搜索关键字
                if (searchKeyword) {
                    const matchName = String(item.name || '').toLowerCase().includes(searchKeyword);
                    const matchPurl = String(item.purl || '').toLowerCase().includes(searchKeyword);
                    const matchLoc = String(item.location || '').toLowerCase().includes(searchKeyword);
                    if (!matchName && !matchPurl && !matchLoc) return false;
                }
                return true;
            });

            // 重置或保持页码合法性
            const totalItems = filteredDiffList.length;
            const totalPages = Math.max(Math.ceil(totalItems / pageSize), 1);
            if (currentPage > totalPages) currentPage = totalPages;
            if (currentPage < 1) currentPage = 1;

            renderTableRows();
            renderPaginationControls(totalItems, totalPages);
        }

        function renderTableRows() {
            const tbody = document.getElementById('paginated-diff-tbody');
            if (filteredDiffList.length === 0) {
                tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 40px;">当前筛选条件下暂无组件</td></tr>`;
                return;
            }

            const startIndex = (currentPage - 1) * pageSize;
            const endIndex = Math.min(startIndex + pageSize, filteredDiffList.length);
            const pageData = filteredDiffList.slice(startIndex, endIndex);

            tbody.innerHTML = pageData.map(item => {
                let badgeClass = 'badge-only-a';
                let typeText = 'A独有';
                if (item.type === 'onlyB') {
                    badgeClass = 'badge-only-b';
                    typeText = 'B独有';
                } else if (item.type === 'onlyC') {
                    badgeClass = 'badge-only-c';
                    typeText = 'Syft独有';
                } else if (item.type === 'versionMismatch') {
                    badgeClass = 'badge-only-b'; typeText = '版本差异';
                } else if (item.type === 'versionUnknown') {
                    badgeClass = 'badge-only-c'; typeText = '版本未知';
                } else if (item.type === 'common') {
                    badgeClass = 'badge-common';
                    typeText = '共有';
                }

                let runtimeHtml = '<span style="color: #6e7681;">⚪ 未追踪</span>';
                if (item.runtimeStatus === 'loaded') {
                    runtimeHtml = '<span class="badge-pill badge-active">🟢 运行时活跃 (Loaded)</span>';
                } else if (item.runtimeStatus === 'dormant') {
                    runtimeHtml = '<span class="badge-pill badge-dormant">⚪ 静态休眠 (Dormant)</span>';
                }

                return `
                    <tr>
                        <td>
                            <div style="display:flex; align-items:center; gap:6px;">
                                <span class="badge-pill ${badgeClass}">${typeText}</span>
                                <b style="color: #fff;">${escapeHtml(item.name)}</b>
                            </div>
                        </td>
                        <td><code style="color: #6cdbd4;">${escapeHtml(item.version)}</code></td>
                        <td><span class="badge-pill">${escapeHtml(item.eco.toUpperCase())}</span></td>
                        <td>${runtimeHtml}</td>
                        <td><span style="color: #bdcad8; font-size:11px;">${escapeHtml(item.license)}</span></td>
                        <td>
                            <div style="font-size:11px; color:#8b949e; word-break:break-all;">
                                <div style="color:#bdcad8; font-family:monospace;">${escapeHtml(item.purl)}</div>
                                <div style="color:#6e7681; font-size:10px;">${escapeHtml(item.location || '-')}</div>
                            </div>
                        </td>
                        <td style="color: #bdcad8; font-size: 11px;">${escapeHtml(item.desc)}</td>
                    </tr>
                `;
            }).join('');
        }

        function renderPaginationControls(totalItems, totalPages) {
            const startIndex = totalItems > 0 ? (currentPage - 1) * pageSize + 1 : 0;
            const endIndex = Math.min(currentPage * pageSize, totalItems);

            document.getElementById('page-item-start').innerText = startIndex;
            document.getElementById('page-item-end').innerText = endIndex;
            document.getElementById('page-item-total').innerText = totalItems;
            document.getElementById('page-jump-input').max = totalPages;
            document.getElementById('page-jump-input').value = currentPage;

            document.getElementById('btn-page-first').disabled = currentPage <= 1;
            document.getElementById('btn-page-prev').disabled = currentPage <= 1;
            document.getElementById('btn-page-next').disabled = currentPage >= totalPages;
            document.getElementById('btn-page-last').disabled = currentPage >= totalPages;

            // 动态生成数字页码按钮 (最多展示 5 个页码)
            const btnContainer = document.getElementById('page-number-buttons');
            btnContainer.innerHTML = '';

            let startP = Math.max(1, currentPage - 2);
            let endP = Math.min(totalPages, startP + 4);
            if (endP - startP < 4) startP = Math.max(1, endP - 4);

            for (let p = startP; p <= endP; p++) {
                const btn = document.createElement('button');
                btn.className = `page-btn ${p === currentPage ? 'active' : ''}`;
                btn.innerText = p;
                btn.onclick = () => {
                    currentPage = p;
                    renderTableRows();
                    renderPaginationControls(totalItems, totalPages);
                };
                btnContainer.appendChild(btn);
            }
        }

        // 绑定分页与筛选事件
        document.getElementById('page-size-select').onchange = e => {
            pageSize = parseInt(e.target.value, 10);
            currentPage = 1;
            applyFiltersAndRenderPage();
        };

        document.getElementById('btn-page-first').onclick = () => { currentPage = 1; applyFiltersAndRenderPage(); };
        document.getElementById('btn-page-prev').onclick = () => { if (currentPage > 1) { currentPage--; applyFiltersAndRenderPage(); } };
        document.getElementById('btn-page-next').onclick = () => { currentPage++; applyFiltersAndRenderPage(); };
        document.getElementById('btn-page-last').onclick = () => {
            currentPage = Math.ceil(filteredDiffList.length / pageSize);
            applyFiltersAndRenderPage();
        };

        document.getElementById('btn-page-jump').onclick = () => {
            const val = parseInt(document.getElementById('page-jump-input').value, 10);
            if (val >= 1) {
                currentPage = val;
                applyFiltersAndRenderPage();
            }
        };

        document.querySelectorAll('.diff-filter-btn').forEach(btn => {
            btn.onclick = () => {
                document.querySelectorAll('.diff-filter-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                activeDiffTab = btn.getAttribute('data-type');
                currentPage = 1;
                applyFiltersAndRenderPage();
            };
        });

        document.getElementById('filter-eco-select').onchange = () => { currentPage = 1; applyFiltersAndRenderPage(); };
        document.getElementById('filter-runtime-select').onchange = () => { currentPage = 1; applyFiltersAndRenderPage(); };
        let filterTimer;
        document.getElementById('diff-search-input').oninput = () => { clearTimeout(filterTimer); filterTimer = setTimeout(() => {currentPage = 1; applyFiltersAndRenderPage();}, 120); };

        // 样本载入辅助函数（支持 A vs B 或 A vs B vs C 三方对照）
        async function readComparisonText(path) {
            if (tauriCore?.invoke) return tauriInvoke('read_file_content', {path});
            let response = await fetch(path);
            if (response.status === 404 && path.startsWith('test/') && typeof window !== 'undefined' && /\/ui\/[^/]+$/.test(window.location.pathname)) response = await fetch('../' + path);
            if (!response.ok) throw new Error('读取失败 HTTP ' + response.status + ': ' + path);
            return response.text();
        }
        function parseComparisonInput(content) {
            const json = JSON.parse(String(content).replace(/^\uFEFF/, ''));
            CompareCore.summarize(json);
            return json;
        }
        async function loadPresetSample(pathA, nameA, pathB, nameB, toastDesc, pathC, nameC) {
            const revision = ++inputRevision;
            for (const side of ['a','b','c']) {++slotRevisions[side]; document.getElementById('file-' + side + '-stat').innerText = '加载中…';}
            pendingSlots.clear();
            pendingInputLoad = true;
            invalidateComparison();
            sbomA = null; sbomB = null; sbomC = null;
            showToast('正在加载对比文件…');
            try {
                const texts = await Promise.all([readComparisonText(pathA),readComparisonText(pathB),pathC ? readComparisonText(pathC).catch(() => null) : null]);
                if (revision !== inputRevision) return;
                const docs = texts.map(text => text === null ? null : parseComparisonInput(text));
                [sbomA,sbomB,sbomC] = docs;
                labelA = nameA; labelB = nameB; labelC = nameC || 'SBOM C';
                for (const [side,path,text] of [['a',pathA,texts[0]],['b',pathB,texts[1]],['c',texts[2] === null ? '' : pathC,texts[2]]]) {
                    document.getElementById('input-file-' + side).value = path || '';
                    document.getElementById('file-' + side + '-stat').innerText = text === null ? '未载入（可选）' : '已载入 (' + (text.length/1024).toFixed(0) + ' KB)';
                }
                pendingInputLoad = false;
                runBenchmarkComparison();
                if (lastComparison) showToast(pathC && !sbomC ? 'A、B 已加载；C 读取失败，当前为双工具比较' : toastDesc);
            } catch (error) {
                if (revision !== inputRevision) return;
                pendingInputLoad = false;
                for (const side of ['a','b','c']) document.getElementById('file-' + side + '-stat').innerText = '载入失败';
                document.getElementById('calc-status-hint').innerText = '加载失败：' + error.message;
                showToast('载入失败：' + error.message, true);
            }
        }
        document.getElementById('sample-btn-quickstarts').onclick = () => {
            loadPresetSample(
                "test/quickstarts/quickstarts_sbom.json", "quickstarts_sbom.json",
                "test/quickstarts/quickstarts_trivy.json", "quickstarts_trivy.json (Trivy)",
                "已载入 CNCF Dapr Quickstarts 4语言企业级三方对比样本 (Ours + Trivy + Syft)！",
                "test/quickstarts/quickstarts_syft.json", "quickstarts_syft.json (Syft)"
            );
        };

        document.getElementById('sample-btn-microservices').onclick = () => {
            loadPresetSample(
                "test/mircoservices/microservices-demo_sbom.json", "microservices-demo_sbom.json",
                "test/mircoservices/sbom-cyclonedx.json", "sbom-cyclonedx.json (Trivy)",
                "已载入 Google Microservices Demo 真实三方对比样本 (Ours + Trivy + Syft)！",
                "test/mircoservices/microservices-demo_syft.json", "microservices-demo_syft.json (Syft)"
            );
        };

        document.getElementById('sample-btn-opentelemetry').onclick = () => {
            loadPresetSample(
                "test/opentelemetry/opentelemetry-demo_sbom.json", "opentelemetry-demo_sbom.json",
                "test/opentelemetry/opentelemetry-trivy.json", "opentelemetry-trivy.json (Trivy)",
                "已载入 CNCF OpenTelemetry Demo 真实三方对比样本 (Ours + Trivy + Syft)！",
                "test/opentelemetry/opentelemetry_syft.json", "opentelemetry_syft.json (Syft)"
            );
        };

        document.getElementById('sample-btn-juice').onclick = () => {
            loadPresetSample(
                "test/juice-shop/juice-shop_sbom.json", "juice-shop_sbom.json",
                "test/juice-shop/juice-shop-trivy.json", "juice-shop-trivy.json (Trivy)",
                "已载入 OWASP Juice Shop 真实三方对比样本 (Ours + Trivy + Syft)！",
                "test/juice-shop/juice-shop_syft.json", "juice-shop_syft.json (Syft)"
            );
        };

        function setInputDocument(side, json, name, path) {
            if (side === 'a') {sbomA = json; labelA = name;}
            if (side === 'b') {sbomB = json; labelB = name;}
            if (side === 'c') {sbomC = json; labelC = name;}
            document.getElementById('input-file-' + side).value = path;
            document.getElementById('file-' + side + '-stat').innerText = json ? '已载入 (' + name + ')' : '未载入';
        }
        async function loadInputDocument(side, read, name, path) {
            ++inputRevision;
            const revision = ++slotRevisions[side];
            pendingSlots.add(side);
            pendingInputLoad = true;
            setInputDocument(side, null, name, path);
            invalidateComparison();
            try {
                const content = await read();
                if (revision !== slotRevisions[side]) return;
                const json = parseComparisonInput(content);
                setInputDocument(side, json, name, path);
                pendingSlots.delete(side); pendingInputLoad = pendingSlots.size > 0;
                if (sbomA && sbomB && !pendingInputLoad) runBenchmarkComparison();
                else showToast('已载入文件 ' + side.toUpperCase() + ': ' + name);
            } catch (error) {
                if (revision !== slotRevisions[side]) return;
                pendingSlots.delete(side); pendingInputLoad = pendingSlots.size > 0;
                document.getElementById('file-' + side + '-stat').innerText = '载入失败';
                document.getElementById('calc-status-hint').innerText = '文件 ' + side.toUpperCase() + ' 载入失败：' + error.message;
                showToast('载入失败：' + error.message, true);
            }
        }
        for (const side of ['a','b','c']) {
            document.getElementById('btn-browse-' + side).onclick = async () => {
                if (!tauriCore?.invoke) {document.getElementById('fallback-file-' + side).click(); return;}
                try {
                    const path = await tauriInvoke('pick_open_file');
                    if (path) await loadInputDocument(side, () => readComparisonText(path), path.split(/[\\/]/).pop(), path);
                } catch (error) {showToast('选择文件失败：' + error.message, true);}
            };
            document.getElementById('fallback-file-' + side).onchange = async e => {
                const file = e.target.files[0];
                e.target.value = '';
                if (file) await loadInputDocument(side, () => file.text(), file.name, file.name);
            };
            const input = document.getElementById('input-file-' + side);
            input.oninput = () => {
                ++inputRevision; ++slotRevisions[side]; pendingSlots.delete(side); pendingInputLoad = pendingSlots.size > 0;
                if (side === 'a') sbomA = null;
                if (side === 'b') sbomB = null;
                if (side === 'c') sbomC = null;
                document.getElementById('file-' + side + '-stat').innerText = '路径已修改，失焦或按 Enter 加载';
                invalidateComparison();
            };
            input.onchange = () => {const path = input.value.trim(); if (path) loadInputDocument(side, () => readComparisonText(path), path.split(/[\\/]/).pop(), path);};
            input.onkeydown = e => {if (e.key === 'Enter') {e.preventDefault(); input.onchange();}};
        }
        document.getElementById('btn-clear-c').onclick = () => {
            ++inputRevision; ++slotRevisions.c; pendingSlots.delete('c'); pendingInputLoad = pendingSlots.size > 0;
            setInputDocument('c', null, 'SBOM C', ''); invalidateComparison();
            if (sbomA && sbomB && !pendingInputLoad) runBenchmarkComparison();
        };

        document.getElementById('btn-trigger-compare').onclick = runBenchmarkComparison;
        document.getElementById('btn-re-run').onclick = runBenchmarkComparison;

        // 与主窗口同步当前活跃 SBOM
        function syncActiveSbomFromParent() {
            try {
                const cached = localStorage.getItem('sbom_compare_active_a');
                if (cached) {
                    ++inputRevision; pendingInputLoad = false; invalidateComparison();
                    sbomA = parseComparisonInput(cached);
                    const name = localStorage.getItem('sbom_compare_active_a_name') || '主窗口当前 SBOM';
                    labelA = name;
                    document.getElementById('input-file-a').value = name;
                    document.getElementById('file-a-stat').innerText = `已同步主窗口数据`;
                    showToast(`已从主窗口自动同步当前 SBOM (${name})！`);
                    return true;
                }
            } catch (_) {}
            return false;
        }

        document.getElementById('btn-sync-active').onclick = () => {
            if (!syncActiveSbomFromParent()) {
                showToast("主窗口暂无活跃生成的 SBOM，可直接选取或载入内置样本", true);
            } else if (sbomB) {
                runBenchmarkComparison();
            }
        };

        // 导出报告
        document.getElementById('btn-export-markdown').onclick = () => {
            if (!sbomA || !sbomB) {
                showToast("请先执行对比评测再导出报告", true);
                return;
            }
            if (!lastComparison) runBenchmarkComparison();
            if (!lastComparison) return;
            let md = comparisonMarkdown(lastComparison, labelA, labelB);
            if (lastComparisonAC) md += '\n\n---\n\n' + comparisonMarkdown(lastComparisonAC, labelA, labelC);
            if (lastComparisonBC) md += '\n\n---\n\n' + comparisonMarkdown(lastComparisonBC, labelB, labelC);

            if (!navigator.clipboard?.writeText) {showToast('当前环境不支持剪贴板，请使用 JSON 导出', true);return;}
            navigator.clipboard.writeText(md).then(() => {
                showToast("评测实验报告已复制到剪贴板！");
            }).catch(() => {
                showToast("复制失败，请检查浏览器剪贴板权限", true);
            });
        };

        document.getElementById('btn-export-json').onclick = () => {
            if (!sbomA || !sbomB) {
                showToast("暂无可导出的比对数据", true);
                return;
            }
            if (!lastComparison) runBenchmarkComparison();
            if (!lastComparison) return;
            const blob = new Blob([JSON.stringify({
                generatedAt: new Date().toISOString(),
                labels: {A:labelA, B:labelB, C:labelC},
                comparisonAB: lastComparison, comparisonAC: lastComparisonAC, comparisonBC: lastComparisonBC,
                differences: currentDiffList
            }, null, 2)], {type: 'application/json;charset=utf-8'});
            const dataStr = URL.createObjectURL(blob);
            const dlAnchor = document.createElement('a');
            dlAnchor.setAttribute("href", dataStr);
            dlAnchor.setAttribute("download", "sbom_comparison_report.json");
            document.body.appendChild(dlAnchor);dlAnchor.click();dlAnchor.remove();
            setTimeout(() => URL.revokeObjectURL(dataStr), 1000);
            showToast("已触发对比 JSON 文件下载！");
        };

        document.getElementById('btn-recompare').onclick = () => runBenchmarkComparison();
        document.getElementById('select-eco-metric').onchange = updateEcosystemMetric;
        for (const id of ['compare-ecosystems','compare-include-applications','compare-exclude-zero']) {
            document.getElementById(id).onchange = () => { if (sbomA && sbomB) runBenchmarkComparison(); };
        }

        // 页面初始化自动触发检查
        window.addEventListener('DOMContentLoaded', () => {
            initCharts();
            const synced = syncActiveSbomFromParent();
            // 若主窗口同步成功且自带了样本，或默认载入 Microservices 样本
            if (!synced) {
                document.getElementById('sample-btn-microservices').click();
            }
        });
