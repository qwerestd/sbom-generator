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
        let labelA = "SBOM A";
        let labelB = "SBOM B";

        let compareRepulsionMult = 1.8;
        let compareGraphLayout = 'force';

        let currentDiffList = [];
        let filteredDiffList = [];

        // 分页状态
        let currentPage = 1;
        let pageSize = 30;
        let activeDiffTab = 'onlyA';

        // ECharts 核心实例管理
        let chartOverlap = null;
        let chartEco = null;
        let chartTopo = null;

        function initCharts() {
            if (!chartOverlap && document.getElementById('chart-overlap-pie')) chartOverlap = echarts.init(document.getElementById('chart-overlap-pie'));
            if (!chartEco && document.getElementById('chart-eco-bar')) chartEco = echarts.init(document.getElementById('chart-eco-bar'));
            if (!chartTopo && document.getElementById('chart-topo-graph')) chartTopo = echarts.init(document.getElementById('chart-topo-graph'));
        }

        window.addEventListener('resize', () => {
            [chartOverlap, chartEco, chartTopo].forEach(c => c && c.resize());
        });

        // 规范化 PURL
        function escapeHtml(value) {
            return String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[c]));
        }

        function normalizePurl(raw) {
            if (typeof raw !== 'string') return '';
            let s = raw.trim().split('?')[0].split('#')[0];
            s = s.replace(/%2B/gi, '+').replace(/%40/gi, '@');
            if (s.startsWith('pkg:pypi/')) {
                const at = s.indexOf('@', 9);
                if (at > 9) s = 'pkg:pypi/' + s.slice(9, at).toLowerCase().replace(/[-_.]+/g, '-') + s.slice(at);
            }
            return s;
        }

        function extractEco(purl) {
            if (!purl) return 'other';
            const m = purl.match(/^pkg:([^/]+)/);
            return m ? m[1].toLowerCase() : 'other';
        }

        function isTargetEco(e) {
            return ['cargo', 'golang', 'maven', 'npm', 'pypi'].includes(e);
        }

        function isValidThirdParty(c) {
            if (!c || !c.purl || typeof c.purl !== 'string' || !c.purl.trim()) return false;
            if (c.type === 'application') return false;
            const ver = typeof c.version === 'string' ? c.version.trim() : '';
            if (!ver || ver.toLowerCase() === 'runtime' || ver === '0.0.0' || c.purl.trim().endsWith('@0.0.0')) return false;
            return true;
        }

        function extractMeta(c) {
            let status = 'untraced';
            let location = '-';
            if (Array.isArray(c?.properties)) {
                const st = c.properties.find(p => p.name === 'sbom:runtime:status');
                if (st && st.value) status = st.value;
                const loc = c.properties.find(p => p.name === 'syft:location:0:path' || (p.name && p.name.includes('location')));
                if (loc && loc.value) location = loc.value;
            }
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
            if (!sbomA || !sbomB) {
                showToast("请先选择待比对的 SBOM 文件 A 与文件 B", true);
                return;
            }

            initCharts();

            const toolA = extractToolName(sbomA, labelA);
            const toolB = extractToolName(sbomB, labelB);

            const compsA = (sbomA.components || []).filter(isValidThirdParty);
            const compsB = (sbomB.components || []).filter(isValidThirdParty);

            const totalA = compsA.length;
            const totalB = compsB.length;

            const mapA = new Map();
            const statusMapA = new Map();
            const loadedRefsA = new Set();
            let loadedA = 0;
            let dormantA = 0;
            let licensedA = 0;
            const ecoLoadedA = {};

            compsA.forEach(c => {
                const p = normalizePurl(c.purl);
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
                if (p && (!mapA.has(p) || meta.status === 'loaded')) mapA.set(p, c);
            });

            const mapB = new Map();
            let loadedB = 0;
            let licensedB = 0;
            compsB.forEach(c => {
                const p = normalizePurl(c.purl);
                const meta = extractMeta(c);
                if (meta.status === 'loaded') loadedB++;
                if (meta.license !== 'UNKNOWN') licensedB++;
                if (p && !mapB.has(p)) mapB.set(p, c);
            });

            // 漏洞统计
            const vulnsA = Array.isArray(sbomA.vulnerabilities) ? sbomA.vulnerabilities : [];
            const vulnsB = Array.isArray(sbomB.vulnerabilities) ? sbomB.vulnerabilities : [];
            let activeVulnsA = 0;
            vulnsA.forEach(v => {
                if ((v.affects || []).some(a => loadedRefsA.has(a.ref))) activeVulnsA++;
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
            const fullRepoCoverage = purlsB.size > 0 ? (commonPurls.size / purlsB.size * 100) : null;
            const targetACount = [...purlsA].filter(p => isTargetEco(extractEco(p))).length;
            const unionCount = targetACount + targetBCount - targetCommonCount;
            const jaccard = unionCount > 0 ? (targetCommonCount / unionCount * 100) : null;

            // 构造全量差异列表
            currentDiffList = [];
            onlyPurlsA.forEach(p => {
                const c = mapA.get(p);
                const meta = extractMeta(c);
                const eco = extractEco(p);
                const reason = '仅 A 出现；需核对清单、锁文件、版本和依赖作用域';
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
                const c = mapB.get(p);
                const meta = extractMeta(c);
                const eco = extractEco(p);
                const reason = '仅 B 出现；需核对清单、锁文件、版本和依赖作用域';
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
                    desc: '两款工具在相同工程下完全一致识别的核心第三方构件'
                });
            });

            // 更新 KPI 看板
            document.getElementById('kpi-target-coverage').innerText = targetCoverage === null ? 'N/A' : `${targetCoverage.toFixed(2)}%`;
            document.getElementById('kpi-target-coverage-sub').innerText = `${targetCommonCount} / ${targetBCount} 唯一包`;
            document.getElementById('kpi-total-coverage').innerText = fullRepoCoverage === null ? 'N/A' : `${fullRepoCoverage.toFixed(2)}%`;
            document.getElementById('kpi-total-coverage-sub').innerText = `${commonPurls.size} / ${purlsB.size} 唯一包`;
            document.getElementById('kpi-jaccard').innerText = jaccard === null ? 'N/A' : `${jaccard.toFixed(1)}%`;

            document.getElementById('kpi-instances-a').innerText = `${totalA}`;
            document.getElementById('kpi-instances-b').innerText = `vs ${totalB} 个`;
            const deltaInstances = totalA - totalB;
            document.getElementById('kpi-instances-diff').innerText = `组件记录差值: ${deltaInstances >= 0 ? '+' : ''}${deltaInstances} 个`;

            document.getElementById('kpi-unique-diff').innerText = `+${onlyPurlsA.size}`;
            document.getElementById('kpi-unique-stats').innerText = `A:${purlsA.size} vs B:${purlsB.size}`;

            document.getElementById('kpi-runtime-loaded').innerText = `${loadedA}`;
            const loadedRatio = totalA > 0 ? (loadedA / totalA * 100).toFixed(1) : '0.0';
            document.getElementById('kpi-runtime-ratio').innerText = `(${loadedRatio}%) 活跃`;

            // 提取并填充工具 B (Trivy) 深度技术档案
            const trivyDetails = extractToolBDetails(sbomB);
            document.getElementById('kpi-tool-b-label').innerText = `${trivyDetails.toolName} ${trivyDetails.toolVersion}`;
            document.getElementById('kpi-trivy-inst-val').innerText = `${trivyDetails.totalComponents}`;

            document.getElementById('kpi-vuln-stats').innerText = `${vulnsA.length} vs ${vulnsB.length}`;
            document.getElementById('kpi-vuln-active').innerText = `可达活跃: ${activeVulnsA}`;

            // 更新徽标数字
            document.getElementById('tab-cnt-only-a').innerText = `${onlyPurlsA.size}`;
            document.getElementById('tab-cnt-only-b').innerText = `${onlyPurlsB.size}`;
            document.getElementById('tab-cnt-common').innerText = `${commonPurls.size}`;
            document.getElementById('tab-cnt-all').innerText = `${currentDiffList.length}`;

            document.getElementById('legend-common-count').innerText = `${commonPurls.size}`;
            document.getElementById('legend-only-a-count').innerText = `${onlyPurlsA.size}`;
            document.getElementById('legend-only-b-count').innerText = `${onlyPurlsB.size}`;

            // 渲染图表群
            renderChartsGroup({
                toolA, toolB,
                totalA, totalB,
                purlsA, purlsB,
                commonPurls, onlyPurlsA, onlyPurlsB,
                targetCoverage, fullRepoCoverage, jaccard,
                compsA, compsB,
                loadedA, dormantA,
                vulnsA, vulnsB, activeVulnsA,
                licensedA, licensedB,
                mapA, mapB
            });

            // 渲染差异明细表格并应用分页
            applyFiltersAndRenderPage();

            showToast("SBOM 交叉对比与评测图表渲染完成！");
        }

        // 渲染图表群函数
        function renderChartsGroup(data) {
            const {
                toolA, toolB,
                commonPurls, onlyPurlsA, onlyPurlsB,
                compsA, compsB,
                mapA, mapB
            } = data;

            // 1. 依赖集合交并全景环形图 (高透亮发光渐变 + 居中核心指标)
            const unionCount = commonPurls.size + onlyPurlsA.size + onlyPurlsB.size;
            const commonRatio = unionCount > 0 ? (commonPurls.size / unionCount * 100).toFixed(1) : '0.0';

            chartOverlap.setOption({
                backgroundColor: 'transparent',
                tooltip: { renderMode: 'html',
                    trigger: 'item',
                    backgroundColor: 'rgba(15, 23, 42, 0.95)',
                    borderColor: '#334155',
                    borderWidth: 1,
                    textStyle: { color: '#f8fafc', fontSize: 12 },
                    formatter: '{b}: {c} 个依赖包 ({d}%)'
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
                            text: commonRatio + '%',
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
                            text: '共有重合率',
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
                    data: [
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
                    ]
                }]
            });

            // 2. 跨生态双向覆盖柱状图 (圆角渐变柱 + 顶部数据标签)
            const allEcos = ['cargo', 'golang', 'maven', 'npm', 'pypi', 'other'];
            const ecoCountA = {};
            const ecoCountB = {};
            allEcos.forEach(e => { ecoCountA[e] = 0; ecoCountB[e] = 0; });

            compsA.forEach(c => {
                const e = extractEco(normalizePurl(c.purl));
                ecoCountA[e] = (ecoCountA[e] || 0) + 1;
            });
            compsB.forEach(c => {
                const e = extractEco(normalizePurl(c.purl));
                ecoCountB[e] = (ecoCountB[e] || 0) + 1;
            });

            chartEco.setOption({
                backgroundColor: 'transparent',
                tooltip: { renderMode: 'richText',
                    trigger: 'axis',
                    axisPointer: { type: 'shadow' },
                    backgroundColor: 'rgba(15, 23, 42, 0.95)',
                    borderColor: '#334155',
                    borderWidth: 1,
                    textStyle: { color: '#f8fafc', fontSize: 12 }
                },
                legend: {
                    data: [toolA, toolB],
                    textStyle: { color: '#cbd5e1', fontSize: 11 },
                    top: '2%',
                    right: '4%'
                },
                grid: { top: 46, bottom: 28, left: 55, right: 25 },
                xAxis: {
                    type: 'category',
                    data: ['Cargo (Rust)', 'Go (Golang)', 'Maven (Java)', 'NPM (JS)', 'PyPI (Python)', '其他生态'],
                    axisLabel: { color: '#94a3b8', fontSize: 11, fontWeight: 500 },
                    axisLine: { lineStyle: { color: '#334155' } },
                    axisTick: { show: false }
                },
                yAxis: {
                    type: 'value',
                    axisLabel: { color: '#94a3b8', fontSize: 10, fontFamily: 'monospace' },
                    splitLine: { lineStyle: { color: 'rgba(255,255,255,0.06)', type: 'dashed' } }
                },
                series: [
                    {
                        name: toolA,
                        type: 'bar',
                        data: allEcos.map(e => ecoCountA[e] || 0),
                        itemStyle: {
                            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                                { offset: 0, color: '#38bdf8' },
                                { offset: 1, color: '#0284c7' }
                            ]),
                            borderRadius: [6, 6, 0, 0],
                            shadowBlur: 8,
                            shadowColor: 'rgba(56, 189, 248, 0.3)'
                        },
                        barMaxWidth: 26,
                        label: {
                            show: true,
                            position: 'top',
                            color: '#7dd3fc',
                            fontSize: 10,
                            fontFamily: 'monospace'
                        }
                    },
                    {
                        name: toolB,
                        type: 'bar',
                        data: allEcos.map(e => ecoCountB[e] || 0),
                        itemStyle: {
                            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                                { offset: 0, color: '#fb923c' },
                                { offset: 1, color: '#ea580c' }
                            ]),
                            borderRadius: [6, 6, 0, 0],
                            shadowBlur: 8,
                            shadowColor: 'rgba(251, 146, 60, 0.3)'
                        },
                        barMaxWidth: 26,
                        label: {
                            show: true,
                            position: 'top',
                            color: '#fdba74',
                            fontSize: 10,
                            fontFamily: 'monospace'
                        }
                    }
                ]
            });

            // 3. 交互式拓扑差异全景图 (真实依赖调用链构建，杜绝标签挤压)
            renderTopoGraph(mapA, mapB, commonPurls, onlyPurlsA, onlyPurlsB);
        }

        // 拓扑全景图渲染 (真实依赖链路构建与标签防遮挡)
        function renderTopoGraph(mapA, mapB, commonPurls, onlyPurlsA, onlyPurlsB) {
            const dom = document.getElementById('chart-topo-graph');
            if (!dom) return;
            if (chartTopo) chartTopo.dispose();
            chartTopo = echarts.init(dom, null, { renderer: 'canvas' });

            const nodes = [];
            const nodeIndexMap = new Map();

            function extractEcoName(purl) {
                if (!purl) return 'OTHER';
                const m = purl.match(/^pkg:([^/]+)/);
                return m ? m[1].toUpperCase() : 'OTHER';
            }

            // 1. 工程根节点（作为一级依赖的锚点基座，彻底解决孤立节点漂移形成外环的问题）
            const rootId = '__PROJECT_ROOT__';
            const rootName = sbomA?.metadata?.component?.name || sbomB?.metadata?.component?.name || 'Project Root';
            const rootVersion = sbomA?.metadata?.component?.version || sbomB?.metadata?.component?.version || '';
            const rootBomRefA = sbomA?.metadata?.component?.['bom-ref'] ? sbomA.metadata.component['bom-ref'].trim() : null;
            const rootBomRefB = sbomB?.metadata?.component?.['bom-ref'] ? sbomB.metadata.component['bom-ref'].trim() : null;

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
                const c = type === 1 ? mapA.get(purl) : (type === 2 ? mapB.get(purl) : (mapA.get(purl) || mapB.get(purl)));
                const cleanName = c?.name || purl.split('/')[1]?.split('@')[0] || purl.split('@')[0] || purl;
                const version = c?.version || (purl.split('@')[1]?.split('?')[0]) || '';
                const eco = extractEcoName(purl);

                const nodeObj = {
                    id: purl,
                    name: `${cleanName}${version ? '@' + version : ''}`,
                    cleanName: cleanName,
                    version: version,
                    purl: purl,
                    eco: eco,
                    category: type + 1, // 0: 根节点, 1: 共有, 2: 仅A, 3: 仅B
                    symbolSize: type === 0 ? 14 : (type === 1 ? 16 : 14),
                    itemStyle: {
                        color: type === 0 ? '#10b981' : (type === 1 ? '#38bdf8' : '#fb923c'),
                        borderColor: type === 0 ? '#059669' : (type === 1 ? '#0284c7' : '#ea580c'),
                        borderWidth: 1.5,
                        shadowBlur: 8,
                        shadowColor: type === 0 ? 'rgba(16,185,129,0.35)' : (type === 1 ? 'rgba(56,189,248,0.35)' : 'rgba(251,146,60,0.35)')
                    }
                };
                nodeIndexMap.set(purl, nodes.length);
                nodes.push(nodeObj);
            }

            commonPurls.forEach(p => addNode(p, 0));
            onlyPurlsA.forEach(p => addNode(p, 1));
            onlyPurlsB.forEach(p => addNode(p, 2));

            // 构建真实边 (Links) 从两份 SBOM 的 dependencies 关系中提取
            const links = [];
            const linkSet = new Set();

            function extractEdgesFromSbom(sbom, rootRef) {
                const refToNormPurl = new Map();
                if (rootRef) refToNormPurl.set(rootRef, rootId);
                const metaName = sbom?.metadata?.component?.name;
                if (metaName) refToNormPurl.set(metaName, rootId);

                (sbom?.components || []).forEach(c => {
                    const normP = normalizePurl(c.purl);
                    if (normP) {
                        if (c['bom-ref']) refToNormPurl.set(c['bom-ref'].trim(), normP);
                        refToNormPurl.set(normP, normP);
                    }
                });

                (sbom?.dependencies || []).forEach(dep => {
                    const rawParent = (dep.ref || '').trim();
                    let parentPurl = refToNormPurl.get(rawParent) || normalizePurl(rawParent);
                    if (rawParent === rootRef || rawParent === metaName) parentPurl = rootId;

                    (dep.dependsOn || []).forEach(childRef => {
                        const rawChild = (childRef || '').trim();
                        let childPurl = refToNormPurl.get(rawChild) || normalizePurl(rawChild);
                        if (rawChild === rootRef || rawChild === metaName) childPurl = rootId;

                        if (parentPurl && childPurl && parentPurl !== childPurl) {
                            if (nodeIndexMap.has(parentPurl) && nodeIndexMap.has(childPurl)) {
                                const key = `${parentPurl}->${childPurl}`;
                                if (!linkSet.has(key)) {
                                    linkSet.add(key);
                                    links.push({
                                        source: parentPurl,
                                        target: childPurl,
                                        lineStyle: {
                                            color: 'rgba(148, 163, 184, 0.35)',
                                            width: 1.2,
                                            curveness: 0.08
                                        }
                                    });
                                }
                            }
                        }
                    });
                });
            }

            extractEdgesFromSbom(sbomA, rootBomRefA);
            extractEdgesFromSbom(sbomB, rootBomRefB);

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
                            lineStyle: {
                                color: 'rgba(99, 102, 241, 0.22)',
                                width: 1.1,
                                curveness: 0.05
                            }
                        });
                        hasIncoming.add(n.id);
                    }
                }
            });

            const BM_CATEGORIES = [
                { name: '📦 工程根节点', itemStyle: { color: '#6366f1' } },
                { name: `🟢 共同识别 (${commonPurls.size})`, itemStyle: { color: '#10b981' } },
                { name: `🔵 工具 A 独有增量 (${onlyPurlsA.size})`, itemStyle: { color: '#38bdf8' } },
                { name: `🟠 工具 B 独有参照 (${onlyPurlsB.size})`, itemStyle: { color: '#fb923c' } }
            ];

            const option = {
                backgroundColor: 'transparent',
                tooltip: { renderMode: 'richText',
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
                                    <div style="color:#cbd5e1; font-size:12px; margin-bottom:4px;">项目顶级入口基座，所有一级依赖组件由其直接声明并向下级联。</div>
                                    ${d.version ? `<div>工程版本: <b style="color:#79c0ff;">${escapeHtml(d.version)}</b></div>` : ''}
                                `;
                            }
                            const typeBadge = d.category === 1
                                ? '<span style="color:#10b981; font-weight:bold;">🟢 双方共同识别 (In Both)</span>'
                                : (d.category === 2
                                    ? '<span style="color:#38bdf8; font-weight:bold;">🔵 工具 A 独有增量 (Only in A)</span>'
                                    : '<span style="color:#fb923c; font-weight:bold;">🟠 工具 B 独有参照 (Only in B)</span>');
                            return `
                                <div style="font-weight:bold; font-size:13px; color:#fff; margin-bottom:4px;">${escapeHtml(d.cleanName)}</div>
                                <div style="margin-bottom:4px;">对比状态: ${typeBadge}</div>
                                <div>版本: <b style="color:#79c0ff;">${escapeHtml(d.version || '-')}</b></div>
                                <div>语言生态: <span style="color:#38bdf8;">${escapeHtml(d.eco)}</span></div>
                                <div style="color:#8b949e; font-size:10px; font-family:var(--font-mono); margin-top:4px; word-break:break-all;">${escapeHtml(d.purl)}</div>
                            `;
                        } else if (params.dataType === 'edge') {
                            const edge = params.data;
                            if (edge.source === rootId) {
                                return `<div style="font-size:12px; color:#cbd5e1;"><b>一级直属依赖关系</b><br/>📦 工程根节点 ➔ ${escapeHtml(edge.target)}</div>`;
                            }
                            return `<div style="font-size:12px; color:#cbd5e1;"><b>传递性调用依赖</b><br/>${escapeHtml(edge.source)} ➔ ${escapeHtml(edge.target)}</div>`;
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
                    layout: compareGraphLayout,
                    circular: { rotateLabel: true },
                    data: nodes,
                    links: links,
                    categories: BM_CATEGORIES,
                    roam: true,
                    draggable: true,
                    label: {
                        show: false, // 彻底消除标签文字拥挤重叠！
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

            chartTopo.setOption(option);

            // 拓扑控制按钮与疏密调节
            document.getElementById('select-topo-layout').onchange = e => {
                compareGraphLayout = e.target.value;
                chartTopo.setOption({
                    series: [{
                        layout: compareGraphLayout,
                        circular: { rotateLabel: true }
                    }]
                });
                showToast(`已切换拓扑布局模式: ${compareGraphLayout === 'force' ? '大空间力导向' : '环形分层拓扑'}`);
            };

            document.getElementById('slider-topo-repulsion').oninput = e => {
                compareRepulsionMult = parseFloat(e.target.value);
                chartTopo.setOption({
                    series: [{
                        force: {
                            repulsion: Math.round(180 * compareRepulsionMult),
                            edgeLength: [Math.round(50 * compareRepulsionMult), Math.round(140 * compareRepulsionMult)]
                        }
                    }]
                });
            };

            document.getElementById('btn-topo-fullscreen').onclick = () => {
                const box = document.getElementById('chart-topo-graph').parentElement;
                const isFull = box.classList.toggle('fullscreen-canvas-mode');
                document.getElementById('btn-topo-fullscreen').innerText = isFull ? '✕ 还原' : '⛶ 全屏';
                setTimeout(() => chartTopo && chartTopo.resize(), 100);
                showToast(isFull ? "已进入拓扑全屏超大视野模式 (可按 Esc 或点击右上角还原)" : "已退出全屏模式");
            };

            window.addEventListener('keydown', e => {
                if (e.key === 'Escape') {
                    const box = document.getElementById('chart-topo-graph').parentElement;
                    if (box?.classList.contains('fullscreen-canvas-mode')) {
                        box.classList.remove('fullscreen-canvas-mode');
                        document.getElementById('btn-topo-fullscreen').innerText = '⛶ 全屏';
                        setTimeout(() => chartTopo && chartTopo.resize(), 80);
                    }
                }
            });

            document.getElementById('btn-topo-zoom-in').onclick = () => {
                const opt = chartTopo.getOption();
                const zoom = (opt.series[0].zoom || 1) * 1.3;
                chartTopo.setOption({ series: [{ zoom }] });
            };
            document.getElementById('btn-topo-zoom-out').onclick = () => {
                const opt = chartTopo.getOption();
                const zoom = Math.max((opt.series[0].zoom || 1) * 0.7, 0.2);
                chartTopo.setOption({ series: [{ zoom }] });
            };
            document.getElementById('btn-topo-reset').onclick = () => {
                chartTopo.dispatchAction({ type: 'restore' });
            };
            document.getElementById('topo-search-input').onkeydown = e => {
                if (e.key === 'Enter') {
                    const val = e.target.value.trim().toLowerCase();
                    if (!val) return;
                    const idx = nodes.findIndex(n => n.name.toLowerCase().includes(val) || (n.purl && n.purl.toLowerCase().includes(val)));
                    if (idx >= 0) {
                        chartTopo.dispatchAction({ type: 'focusNodeAdjacency', dataIndex: idx });
                        showToast(`已在拓扑图中定位节点: ${nodes[idx].name}`);
                    } else {
                        showToast("未找到匹配的拓扑节点", true);
                    }
                }
            };
        }

        // 提取工具 B (Trivy) 深度技术档案元数据
        function extractToolBDetails(sbom) {
            let toolName = 'Trivy';
            let toolVersion = 'v0.76.1';
            let toolVendor = 'Aqua Security';

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

            const timestamp = sbom?.metadata?.timestamp ? new Date(sbom.metadata.timestamp).toLocaleString() : new Date().toLocaleString();
            const specVersion = sbom?.specVersion ? `CycloneDX ${sbom.specVersion}` : 'CycloneDX 1.5';
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
            const searchKeyword = document.getElementById('diff-search-input').value.trim().toLowerCase();
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
                    const matchName = item.name.toLowerCase().includes(searchKeyword);
                    const matchPurl = item.purl.toLowerCase().includes(searchKeyword);
                    const matchLoc = (item.location || '').toLowerCase().includes(searchKeyword);
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
                if (item.type === 'onlyB') badgeClass = 'badge-only-b';
                else if (item.type === 'common') badgeClass = 'badge-common';

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
                                <span class="badge-pill ${badgeClass}">${item.type === 'onlyA' ? 'A独有' : (item.type === 'onlyB' ? 'B独有' : '共有')}</span>
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
        document.getElementById('diff-search-input').oninput = () => { currentPage = 1; applyFiltersAndRenderPage(); };

        // 样本载入辅助函数
        async function loadPresetSample(pathA, nameA, pathB, nameB, toastDesc) {
            try {
                showToast("正在载入对照样本数据...");
                let contentA = null;
                let contentB = null;

                if (tauriCore && tauriCore.invoke) {
                    contentA = await tauriInvoke('read_file_content', { path: pathA });
                    contentB = await tauriInvoke('read_file_content', { path: pathB });
                } else {
                    const [resA, resB] = await Promise.all([fetch(pathA), fetch(pathB)]);
                    if (resA.ok && resB.ok) {
                        contentA = await resA.text();
                        contentB = await resB.text();
                    }
                }

                if (contentA && contentB) {
                    sbomA = JSON.parse(contentA);
                    labelA = nameA;
                    document.getElementById('input-file-a').value = pathA;
                    document.getElementById('file-a-stat').innerText = `已载入 (${(contentA.length/1024).toFixed(0)} KB)`;

                    sbomB = JSON.parse(contentB);
                    labelB = nameB;
                    document.getElementById('input-file-b').value = pathB;
                    document.getElementById('file-b-stat').innerText = `已载入 (${(contentB.length/1024).toFixed(0)} KB)`;

                    document.getElementById('calc-status-hint').innerText = `已成功载入: ${nameA} vs ${nameB}`;
                    runBenchmarkComparison();
                    showToast(toastDesc);
                } else {
                    showToast("无法读取样本文件，请点击「浏览」手动选择本地 JSON", true);
                }
            } catch (e) {
                showToast("载入样本失败: " + e, true);
            }
        }

        document.getElementById('sample-btn-microservices').onclick = () => {
            loadPresetSample(
                "test/mircoservices/microservices-demo_sbom.json", "microservices-demo_sbom.json",
                "test/mircoservices/sbom-cyclonedx.json", "sbom-cyclonedx.json (Trivy)",
                "已载入 Google Microservices Demo 真实对比样本！"
            );
        };

        document.getElementById('sample-btn-opentelemetry').onclick = () => {
            loadPresetSample(
                "test/opentelemetry/opentelemetry-demo_sbom.json", "opentelemetry-demo_sbom.json",
                "test/opentelemetry/opentelemetry-trivy.json", "opentelemetry-trivy.json (Trivy)",
                "已载入 CNCF OpenTelemetry Demo 真实对比样本！"
            );
        };

        document.getElementById('sample-btn-juice').onclick = () => {
            loadPresetSample(
                "test/juice-shop/juice-shop_sbom.json", "juice-shop_sbom.json",
                "test/juice-shop/juice-shop-trivy.json", "juice-shop-trivy.json (Trivy)",
                "已载入 OWASP Juice Shop 真实对比样本！"
            );
        };

        // 文件浏览按钮绑定
        document.getElementById('btn-browse-a').onclick = async () => {
            try {
                const path = await tauriInvoke('pick_open_file');
                if (path) {
                    const content = await tauriInvoke('read_file_content', { path });
                    sbomA = JSON.parse(content);
                    labelA = path.split(/[\/\\]/).pop();
                    document.getElementById('input-file-a').value = path;
                    document.getElementById('file-a-stat').innerText = `已载入 (${labelA})`;
                    showToast(`已成功载入文件 A: ${labelA}`);
                }
            } catch (_) {
                document.getElementById('fallback-file-a').click();
            }
        };

        document.getElementById('fallback-file-a').onchange = e => {
            const f = e.target.files[0];
            if (!f) return;
            const reader = new FileReader();
            reader.onload = ev => {
                sbomA = JSON.parse(ev.target.result);
                labelA = f.name;
                document.getElementById('input-file-a').value = f.name;
                document.getElementById('file-a-stat').innerText = `已载入 (${f.name})`;
                showToast(`已成功载入文件 A: ${f.name}`);
            };
            reader.readAsText(f);
        };

        document.getElementById('btn-browse-b').onclick = async () => {
            try {
                const path = await tauriInvoke('pick_open_file');
                if (path) {
                    const content = await tauriInvoke('read_file_content', { path });
                    sbomB = JSON.parse(content);
                    labelB = path.split(/[\/\\]/).pop();
                    document.getElementById('input-file-b').value = path;
                    document.getElementById('file-b-stat').innerText = `已载入 (${labelB})`;
                    showToast(`已成功载入文件 B: ${labelB}`);
                }
            } catch (_) {
                document.getElementById('fallback-file-b').click();
            }
        };

        document.getElementById('fallback-file-b').onchange = e => {
            const f = e.target.files[0];
            if (!f) return;
            const reader = new FileReader();
            reader.onload = ev => {
                sbomB = JSON.parse(ev.target.result);
                labelB = f.name;
                document.getElementById('input-file-b').value = f.name;
                document.getElementById('file-b-stat').innerText = `已载入 (${f.name})`;
                showToast(`已成功载入文件 B: ${f.name}`);
            };
            reader.readAsText(f);
        };

        document.getElementById('btn-trigger-compare').onclick = runBenchmarkComparison;
        document.getElementById('btn-re-run').onclick = runBenchmarkComparison;

        // 与主窗口同步当前活跃 SBOM
        function syncActiveSbomFromParent() {
            try {
                const cached = localStorage.getItem('sbom_compare_active_a');
                if (cached) {
                    sbomA = JSON.parse(cached);
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
            runBenchmarkComparison();
            const toolA = extractToolName(sbomA, labelA);
            const toolB = extractToolName(sbomB, labelB);
            const targetCov = document.getElementById('kpi-target-coverage').innerText;
            const totalCov = document.getElementById('kpi-total-coverage').innerText;
            const instA = document.getElementById('kpi-instances-a').innerText;
            const instB = document.getElementById('kpi-instances-b').innerText;

            const md = `# SBOM 组件集合对比报告\n\n` +
                `- 工具 A: ${toolA} (${labelA})\n- 参照工具 B: ${toolB} (${labelB})\n` +
                `- 目标生态相对重合率: ${targetCov}\n- 全部生态相对重合率: ${totalCov}\n` +
                `- 目标生态 Jaccard: ${document.getElementById('kpi-jaccard').innerText}\n` +
                `- A 组件记录数: ${instA}；B: ${instB}\n` +
                `- 仅 A 出现: ${currentDiffList.filter(c => c.type === 'onlyA').length}；仅 B 出现: ${currentDiffList.filter(c => c.type === 'onlyB').length}\n\n` +
                `## 统计规则与解读限制\n\n排除 application、空版本、0.0.0 和 runtime；去除 PURL qualifier/subpath，归一化已知编码与 PyPI 包名后去重。0.0.0 过滤可能排除合法组件。记录数不等于已核实的物理部署实例数。空参照集合的相对重合率为 N/A。\n\n` +
                `参照 SBOM 不是独立真值；重合率不等于准确率或召回率。独有项需回查清单、锁文件、依赖作用域及版本。仅凭这两份文件不能认定误报、漏报、达标或工具能力优劣。运行时未观测到加载不代表不可达。`;

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
            runBenchmarkComparison();
            const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify({
                generatedAt: new Date().toISOString(),
                toolA: extractToolName(sbomA, labelA),
                toolB: extractToolName(sbomB, labelB),
                benchmarkProfile: extractToolBDetails(sbomB),
                differences: currentDiffList
            }, null, 2));
            const dlAnchor = document.createElement('a');
            dlAnchor.setAttribute("href", dataStr);
            dlAnchor.setAttribute("download", "sbom_comparison_report.json");
            dlAnchor.click();
            showToast("已触发对比 JSON 文件下载！");
        };

        // 页面初始化自动触发检查
        window.addEventListener('DOMContentLoaded', () => {
            initCharts();
            const synced = syncActiveSbomFromParent();
            // 若主窗口同步成功且自带了样本，或默认载入 Microservices 样本
            if (!synced) {
                document.getElementById('sample-btn-microservices').click();
            }
        });
