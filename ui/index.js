const tauriCore = window.__TAURI__ ? window.__TAURI__.core : null;
        async function tauriInvoke(cmd, args) {
            if (tauriCore && tauriCore.invoke) {
                return await tauriCore.invoke(cmd, args);
            }
            throw new Error("当前处于浏览器预览环境，Tauri 后端未连接。");
        }

        let currentSbomData = null;
        let currentGraphData = null;
        let currentGraphLayout = 'force';
        let currentRepulsionMult = 1.8;

        // 规范化 PURL 辅助计算
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

        const chartDom = document.getElementById('chart-container');
        const myChart = echarts.init(chartDom, null, { renderer: 'canvas' });

        // 高对比度高饱和度分类色标 (暗黑工业风画布上高透亮)
        const CATEGORIES = [
            { name: '📦 项目根节点', itemStyle: { color: '#38bdf8' } },
            { name: '🚨 漏洞告警 (CVE/GHSA)', itemStyle: { color: '#f85149' } },
            { name: 'Rust (Cargo)', itemStyle: { color: '#fb923c' } },
            { name: 'Go (Golang)', itemStyle: { color: '#22d3ee' } },
            { name: 'Node.js (NPM)', itemStyle: { color: '#facc15' } },
            { name: 'Java/Kotlin (Maven/Gradle)', itemStyle: { color: '#fb7185' } },
            { name: 'Python (PyPI)', itemStyle: { color: '#60a5fa' } },
            { name: '其他语言生态', itemStyle: { color: '#2dd4bf' } }
        ];

        function detectCategoryIndex(purl) {
            if (!purl) return 7;
            if (purl.startsWith('pkg:cargo/')) return 2;
            if (purl.startsWith('pkg:golang/')) return 3;
            if (purl.startsWith('pkg:npm/')) return 4;
            if (purl.startsWith('pkg:maven/')) return 5;
            if (purl.startsWith('pkg:pypi/')) return 6;
            return 7;
        }

        function showToast(msg, isErr = false) {
            const toast = document.getElementById('toast');
            toast.innerText = msg;
            toast.style.borderColor = isErr ? 'var(--danger-border)' : 'var(--border-strong)';
            toast.style.color = isErr ? '#ff7b72' : 'var(--text-main)';
            toast.classList.add('show');
            setTimeout(() => toast.classList.remove('show'), 2600);
        }

        // 1. 文件夹与文件路径选择器绑定
        document.getElementById('btn-browse-dir').addEventListener('click', async () => {
            try {
                const dir = await tauriInvoke('pick_directory');
                if (dir) {
                    document.getElementById('input-dir').value = dir;
                    const curSave = document.getElementById('input-save').value.trim();
                    if (!curSave) {
                        const sep = dir.includes('/') ? '/' : '\\';
                        document.getElementById('input-save').value = `${dir.replace(/[\\/]$/, '')}${sep}sbom_result.json`;
                    }
                    showToast(`已选择目录: ${dir}`);
                }
            } catch (e) {
                showToast("打开文件夹失败: " + e, true);
            }
        });

        document.getElementById('btn-browse-save').addEventListener('click', async () => {
            try {
                const dir = document.getElementById('input-dir').value.trim();
                let defaultName = "sbom_result.json";
                if (dir) {
                    const parts = dir.replace(/[\\/]$/, '').split(/[\\/]/);
                    const last = parts[parts.length - 1];
                    if (last) defaultName = `${last}_sbom.json`;
                }
                const file = await tauriInvoke('pick_save_file', { defaultName });
                if (file) {
                    document.getElementById('input-save').value = file;
                    showToast(`已指定输出: ${file}`);
                }
            } catch (e) {
                showToast("指定输出失败: " + e, true);
            }
        });

        document.getElementById('btn-open-explorer').addEventListener('click', async () => {
            const path = document.getElementById('input-save').value.trim() || document.getElementById('input-dir').value.trim();
            if (!path) {
                showToast("请先指定工程目录或输出文件", true);
                return;
            }
            try {
                await tauriInvoke('open_in_explorer', { path });
                showToast(`已在 Windows 资源管理器中打开`);
            } catch (e) {
                showToast("打开失败: " + e, true);
            }
        });

        // 2. 导入已有本地 SBOM JSON
        document.getElementById('btn-import-sbom').addEventListener('click', async () => {
            try {
                if (tauriCore) {
                    const path = await tauriInvoke('pick_open_file');
                    if (path) {
                        const content = await tauriInvoke('read_file_content', { path });
                        const json = JSON.parse(content);
                        loadSbomData(json, path);
                        showToast(`成功导入: ${path.split(/[\\/]/).pop()}`);
                    }
                } else {
                    document.getElementById('file-import-fallback').click();
                }
            } catch (e) {
                showToast("导入失败: " + e, true);
            }
        });

        document.getElementById('file-import-fallback').addEventListener('change', (e) => {
            const file = e.target.files && e.target.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = function(evt) {
                try {
                    const json = JSON.parse(evt.target.result);
                    loadSbomData(json, file.name);
                    showToast(`成功导入文件: ${file.name}`);
                } catch (err) {
                    showToast("解析 JSON 失败: " + err, true);
                }
            };
            reader.readAsText(file);
        });

        // 3. 标签页切换
        document.querySelectorAll('.view-tab-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.view-tab-btn').forEach(b => b.classList.remove('active'));
                document.querySelectorAll('.tab-panel-container').forEach(p => p.classList.remove('active'));
                btn.classList.add('active');
                const targetId = btn.getAttribute('data-tab');
                const target = document.getElementById(targetId);
                if (target) target.classList.add('active');
                if (targetId === 'tab-graph') {
                    setTimeout(() => myChart && myChart.resize(), 50);
                }
            });
        });

        // 收起/展开顶部控制栏以最大化图谱空间
        document.getElementById('btn-toggle-topbar')?.addEventListener('click', () => {
            const bar = document.getElementById('app-control-bar');
            const btn = document.getElementById('btn-toggle-topbar');
            if (bar) {
                const isCollapsed = bar.classList.toggle('collapsed');
                btn.innerHTML = isCollapsed ? '<span>🔽 展开配置栏</span>' : '<span>🔼 收起配置栏</span>';
                setTimeout(() => myChart && myChart.resize(), 60);
            }
        });

        // 4. 数据转换：CycloneDX 1.6 -> ECharts 图谱模型
        function convertCycloneDXToGraph(sbom, filterVulnOnly = false, filterLoadedOnly = false) {
            if (!sbom || !Array.isArray(sbom.components)) {
                return { nodes: [], links: [], vulnerableNodeCount: 0, totalCves: 0, loadedCount: 0, dormantCount: 0, ecosystemsCount: 0 };
            }

            const vulnMap = new HashMapList();
            const allVulns = [];
            if (Array.isArray(sbom.vulnerabilities)) {
                sbom.vulnerabilities.forEach(v => {
                    const rating = (v.ratings && v.ratings[0]) || {};
                    const sev = (rating.severity || 'HIGH').toUpperCase();
                    const score = rating.score !== undefined ? Number(rating.score).toFixed(1) : '';
                    allVulns.push({
                        id: v.id,
                        severity: sev,
                        score: score,
                        description: v.description || '无详细描述',
                        recommendation: v.recommendation || '关注官方安全通报',
                        affects: (v.affects || []).map(a => a.ref)
                    });
                    (v.affects || []).forEach(a => {
                        if (a.ref) {
                            vulnMap.add(a.ref, {
                                id: v.id,
                                severity: sev,
                                score: score,
                                description: v.description || '无详细描述',
                                recommendation: v.recommendation || '关注官方安全通报'
                            });
                        }
                    });
                });
            }

            const nodes = [];
            const links = [];
            const dependedCountMap = new Map();
            const childToParentsMap = new Map();
            const parentToChildrenMap = new Map();

            (sbom.dependencies || []).forEach(dep => {
                const parentRef = dep.ref;
                if (dep.dependsOn) {
                    parentToChildrenMap.set(parentRef, dep.dependsOn);
                    dep.dependsOn.forEach(childRef => {
                        dependedCountMap.set(childRef, (dependedCountMap.get(childRef) || 0) + 1);
                        if (!childToParentsMap.has(childRef)) childToParentsMap.set(childRef, []);
                        childToParentsMap.get(childRef).push(parentRef);

                        const isTargetVuln = vulnMap.has(childRef);
                        links.push({
                            source: parentRef,
                            target: childRef,
                            lineStyle: isTargetVuln
                                ? { curveness: 0.15, width: 2.4, opacity: 0.95, color: '#f85149' }
                                : { curveness: 0.15, width: 1.6, opacity: 0.65, color: '#718096' }
                        });
                    });
                }
            });

            const componentRefs = new Set();
            const ecosystemsFound = new Set();
            let vulnerableNodeCount = 0;
            let loadedCount = 0;
            let dormantCount = 0;

            sbom.components.forEach(c => {
                const ref = c['bom-ref'];
                componentRefs.add(ref);
                const count = dependedCountMap.get(ref) || 0;
                const vulns = vulnMap.get(ref) || [];
                const isVulnerable = vulns.length > 0;
                if (isVulnerable) vulnerableNodeCount++;

                let locationPath = 'runtime/manifest';
                let runtimeStatus = 'untraced';
                if (Array.isArray(c.properties)) {
                    const loc = c.properties.find(p => p.name === 'syft:location:0:path');
                    if (loc) locationPath = loc.value;
                    const rStatus = c.properties.find(p => p.name === 'sbom:runtime:status');
                    if (rStatus) runtimeStatus = rStatus.value;
                }

                if (runtimeStatus === 'loaded') loadedCount++;
                else if (runtimeStatus === 'dormant') dormantCount++;

                let license = 'UNKNOWN';
                if (Array.isArray(c.licenses) && c.licenses[0]) {
                    const choice = c.licenses[0];
                    license = choice.expression || choice.license?.id || choice.license?.name || 'UNKNOWN';
                }

                const ecoIdx = detectCategoryIndex(c.purl);
                if (ecoIdx >= 2 && ecoIdx <= 6) {
                    ecosystemsFound.add(CATEGORIES[ecoIdx].name);
                }

                if (filterVulnOnly && !isVulnerable) return;
                if (filterLoadedOnly && runtimeStatus !== 'loaded') return;

                const baseSize = Math.min(34 + count * 4.5, 74);
                const nodeSize = isVulnerable ? Math.max(baseSize + 10, 44) : baseSize;
                const verLabel = c.version ? (c.version.startsWith('v') ? c.version : `v${c.version}`) : '';

                let prefix = '';
                if (isVulnerable) prefix = '🚨 ';
                else if (runtimeStatus === 'loaded') prefix = '🟢 ';

                nodes.push({
                    id: ref,
                    rawComponent: c,
                    name: `${prefix}${escapeHtml(c.name)}\n${verLabel}`,
                    cleanName: c.name,
                    version: c.version || '',
                    license,
                    purl: c.purl || '',
                    locationPath,
                    runtimeStatus,
                    ecoName: CATEGORIES[ecoIdx]?.name || '其他组件',
                    category: isVulnerable ? 1 : ecoIdx,
                    symbolSize: nodeSize,
                    value: count,
                    vulns: vulns,
                    callers: childToParentsMap.get(ref) || [],
                    dependencies: parentToChildrenMap.get(ref) || [],
                    label: {
                        show: true,
                        position: 'bottom',
                        color: isVulnerable ? '#ff7b72' : (runtimeStatus === 'loaded' ? '#afffed' : '#f1f5f9'),
                        fontSize: 11,
                        fontWeight: (isVulnerable || runtimeStatus === 'loaded') ? 'bold' : 'normal',
                        backgroundColor: 'rgba(10, 18, 30, 0.85)',
                        borderColor: isVulnerable ? '#f85149' : (runtimeStatus === 'loaded' ? '#2ea043' : 'rgba(148, 163, 184, 0.45)'),
                        borderWidth: 1,
                        borderRadius: 4,
                        padding: [2, 6]
                    },
                    itemStyle: isVulnerable ? {
                        color: '#da3633',
                        borderColor: '#ffeb3b',
                        borderWidth: 3.5,
                        shadowBlur: 22,
                        shadowColor: 'rgba(248, 81, 73, 0.85)'
                    } : (runtimeStatus === 'loaded' ? {
                        borderColor: '#34d399',
                        borderWidth: 3,
                        shadowBlur: 16,
                        shadowColor: 'rgba(52, 211, 153, 0.8)'
                    } : {
                        borderColor: 'rgba(148, 163, 184, 0.65)',
                        borderWidth: 2,
                        shadowBlur: 8,
                        shadowColor: 'rgba(56, 189, 248, 0.25)'
                    })
                });
            });

            // 虚拟项目根节点
            const VIRTUAL_ROOT_ID = '__VIRTUAL_PROJECT_ROOT__';
            if (!filterVulnOnly && !filterLoadedOnly) {
                nodes.push({
                    id: VIRTUAL_ROOT_ID,
                    name: '📦 项目根节点\n(Root)',
                    cleanName: '项目根节点',
                    category: 0,
                    symbolSize: 85,
                    vulns: [],
                    label: {
                        show: true,
                        position: 'inside',
                        color: '#ffffff',
                        fontSize: 13,
                        fontWeight: 'bold'
                    },
                    itemStyle: {
                        color: '#1f6feb',
                        borderColor: '#58a6ff',
                        borderWidth: 3,
                        shadowBlur: 25,
                        shadowColor: 'rgba(31, 111, 235, 0.5)'
                    }
                });

                componentRefs.forEach(ref => {
                    if (!dependedCountMap.has(ref)) {
                        const isTargetVuln = vulnMap.has(ref);
                        links.push({
                            source: VIRTUAL_ROOT_ID,
                            target: ref,
                            lineStyle: {
                                curveness: 0.1,
                                width: isTargetVuln ? 2.5 : 1.8,
                                type: 'dashed',
                                opacity: 0.8,
                                color: isTargetVuln ? '#f85149' : '#38bdf8'
                            }
                        });
                    }
                });
            }

            return {
                nodes,
                links,
                vulnerableNodeCount,
                totalCves: Array.isArray(sbom.vulnerabilities) ? sbom.vulnerabilities.length : 0,
                loadedCount,
                dormantCount,
                ecosystemsCount: ecosystemsFound.size,
                ecosystemsList: Array.from(ecosystemsFound),
                allVulns
            };
        }

        class HashMapList {
            constructor() { this.map = new Map(); }
            add(key, val) {
                if (!this.map.has(key)) this.map.set(key, []);
                this.map.get(key).push(val);
            }
            get(key) { return this.map.get(key) || []; }
            has(key) { return this.map.has(key); }
        }

        // 5. 渲染力导向网络图
        function renderGraph(graphData) {
            myChart.setOption({
                backgroundColor: '#0d1117',
                legend: [{
                    data: CATEGORIES.map(a => a.name),
                    top: 10,
                    textStyle: { color: '#8b949e', fontSize: 12 },
                    itemGap: 16,
                    icon: 'roundRect'
                }],
                tooltip: { renderMode: 'html',
                    trigger: 'item',
                    backgroundColor: '#161b22',
                    borderColor: '#30363d',
                    borderWidth: 1,
                    textStyle: { color: '#f0f6fc', fontSize: 12 },
                    extraCssText: 'box-shadow: 0 8px 24px rgba(0,0,0,0.7); border-radius: 4px; max-width: 460px; white-space: normal;',
                    formatter: function (params) {
                        if (params.dataType === 'node') {
                            if (params.data.id === '__VIRTUAL_PROJECT_ROOT__') {
                                return `<b>📦 项目根节点</b><br/><span style="color:#8b949e;">统一统辖各个多语言模块的直接顶层依赖</span>`;
                            }
                            const vulns = params.data.vulns || [];
                            let vulnSection = '';
                            if (vulns.length > 0) {
                                vulnSection = `<div style="margin-top:8px; border-top:1px solid #30363d; padding-top:6px;">
                                                <div style="color:#f85149; font-weight:bold; font-size:12px;">🚨 命中 ${vulns.length} 项 OSV 漏洞告警:</div>
                                                ${vulns.map(v => `
                                                    <div style="margin-top:4px; padding:4px 6px; background:rgba(248,81,73,0.1); border-left:3px solid #f85149;">
                                                        <div style="font-weight:bold; color:#ff7b72; font-size:11px;">[${escapeHtml(v.severity)} ${escapeHtml(v.score || '')}] ${escapeHtml(v.id)}</div>
                                                        <div style="color:#c9d1d9; font-size:11px;">${escapeHtml(v.description)}</div>
                                                        <div style="color:#3fb950; font-size:11px;">修复建议: ${escapeHtml(v.recommendation)}</div>
                                                    </div>
                                                `).join('')}
                                               </div>`;
                            }
                            const statusStr = params.data.runtimeStatus === 'loaded'
                                ? '<span style="color:#3fb950;font-weight:bold;">🟢 活跃运行 (LOADED)</span>'
                                : (params.data.runtimeStatus === 'dormant' ? '<span style="color:#8b949e;">⚪ 静态休眠 (DORMANT)</span>' : '<span style="color:#58a6ff;">🔘 静态责任链</span>');

                            return `<div style="padding:2px;">
                                        <b style="font-size:14px; color:#58a6ff;">${escapeHtml(params.data.cleanName)}</b>
                                        <span style="color:#8b949e; font-size:12px;">(${escapeHtml(params.data.version || '未知')})</span><br/>
                                        <span style="color:#8b949e; font-size:11px;">生态: ${escapeHtml(params.data.ecoName)} | 状态: ${statusStr} | 许可证: <b style="color:#3fb950;">${escapeHtml(params.data.license || 'UNKNOWN')}</b></span><br/>
                                        <span style="color:#6e7681; font-size:10px; font-family:var(--font-mono); word-break:break-all;">${escapeHtml(params.data.purl)}</span>
                                        <div style="margin-top:4px; color:#c9d1d9; font-size:11px;">被下游依赖: <strong style="color:#f0883e;">${params.data.value}</strong> 次</div>
                                        ${vulnSection}
                                    </div>`;
                        }
                        return `<b>依赖链路调用</b><br/>${escapeHtml(params.data.source.split('?')[0])}<br/>⬇<br/>${escapeHtml(params.data.target.split('?')[0])}`;
                    }
                },
                series: [
                    {
                        type: 'graph',
                        layout: currentGraphLayout,
                        circular: { rotateLabel: true },
                        data: graphData.nodes,
                        links: graphData.links,
                        categories: CATEGORIES,
                        roam: true,
                        draggable: true,
                        edgeSymbol: ['none', 'arrow'],
                        edgeSymbolSize: [0, 9],
                        labelLayout: {
                            hideOverlap: true,
                            moveOverlap: 'shiftY'
                        },
                        force: {
                            repulsion: Math.round(1900 * currentRepulsionMult),
                            edgeLength: [Math.round(190 * currentRepulsionMult), Math.round(340 * currentRepulsionMult)],
                            gravity: 0.016, // 降到极低重力，彻底避免向中心团聚挤压
                            friction: 0.35
                        },
                        emphasis: {
                            focus: 'adjacency',
                            lineStyle: { width: 3.5, opacity: 1 },
                            label: {
                                show: true,
                                fontSize: 12,
                                fontWeight: 'bold',
                                color: '#ffffff',
                                backgroundColor: '#161b22',
                                borderColor: '#58a6ff',
                                borderWidth: 1,
                                padding: [3, 6]
                            }
                        },
                        blur: {
                            itemStyle: { opacity: 0.45 },
                            lineStyle: { opacity: 0.25 }
                        }
                    }
                ]
            });
        }

        // 分页与独立窗口全局状态管理
        let currentVulnList = [];
        let vulnPage = 1;
        let vulnPageSize = 30;

        let currentCompList = [];
        let compPage = 1;
        let compPageSize = 50;

        let bmDiffPage = 1;
        let bmDiffPageSize = 30;

        async function openCompareWindow() {
            if (currentSbomData) {
                try {
                    localStorage.setItem('sbom_compare_active_a', JSON.stringify(currentSbomData));
                    const curPath = document.getElementById('input-save')?.value || document.getElementById('input-dir')?.value || '当前分析项目';
                    localStorage.setItem('sbom_compare_active_a_name', curPath.split(/[\/\\]/).pop() || '当前项目 SBOM');
                } catch (_) {}
            }
            try {
                await tauriInvoke('open_compare_window');
                showToast("已唤起独立对比大窗口！");
            } catch (e) {
                window.open('compare.html', '_blank', 'width=1440,height=920');
                showToast("已在独立新窗口打开对比中心！");
            }
        }
        document.getElementById('btn-open-compare-window')?.addEventListener('click', openCompareWindow);
        document.getElementById('btn-popout-compare-top')?.addEventListener('click', openCompareWindow);

        // 6. 渲染表格数据 (附带真分页导航)
        function renderVulnTable(sbom) {
            const tbody = document.getElementById('vuln-table-body');
            const paginationBar = document.getElementById('vuln-pagination-bar');
            currentVulnList = sbom.vulnerabilities || [];
            if (currentVulnList.length === 0) {
                tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; color:#3fb950; padding:40px; font-weight:600;">
                                    ✅ 安全审计通过：当前项目全部组件未发现已知 CVE / GHSA 漏洞！
                                   </td></tr>`;
                if (paginationBar) paginationBar.style.display = 'none';
                return;
            }

            if (paginationBar) paginationBar.style.display = 'flex';
            vulnPage = 1;
            renderVulnPageRows(sbom);
        }

        function renderVulnPageRows(sbom) {
            const tbody = document.getElementById('vuln-table-body');
            const totalItems = currentVulnList.length;
            const totalPages = Math.max(Math.ceil(totalItems / vulnPageSize), 1);
            if (vulnPage > totalPages) vulnPage = totalPages;
            if (vulnPage < 1) vulnPage = 1;

            const startIndex = (vulnPage - 1) * vulnPageSize;
            const endIndex = Math.min(startIndex + vulnPageSize, totalItems);
            const pageData = currentVulnList.slice(startIndex, endIndex);

            // 检查每个组件的动态加载状态
            const compStatusMap = new Map();
            (sbom?.components || currentSbomData?.components || []).forEach(c => {
                let status = 'untraced';
                if (Array.isArray(c.properties)) {
                    const st = c.properties.find(p => p.name === 'sbom:runtime:status');
                    if (st) status = st.value;
                }
                compStatusMap.set(c['bom-ref'], status);
            });

            let html = '';
            pageData.forEach(v => {
                const rating = (v.ratings && v.ratings[0]) || {};
                const sev = (rating.severity || 'HIGH').toUpperCase();
                const score = rating.score !== undefined ? Number(rating.score).toFixed(1) : '-';
                const sevClass = sev === 'CRITICAL' ? 'critical' : (sev === 'HIGH' ? 'high' : (sev === 'MEDIUM' ? 'medium' : 'low'));
                const affectedRefs = (v.affects || []).map(a => a.ref.split('?')[0]).join(', ');

                let hasLoaded = false;
                (v.affects || []).forEach(a => {
                    if (compStatusMap.get(a.ref) === 'loaded') hasLoaded = true;
                });

                const reachabilityTag = hasLoaded
                    ? `<span class="badge-sev critical">🚨 已观测到加载(高危)</span>`
                    : `<span class="badge-sev" style="background:#30363d;color:#8b949e;">⚪ 未观测到加载（不代表不可达）</span>`;

                html += `<tr>
                            <td><b style="color:#ffffff; font-family:var(--font-mono);">${escapeHtml(v.id)}</b></td>
                            <td><span class="badge-sev ${sevClass}">${escapeHtml(sev)}</span></td>
                            <td><b style="font-family:var(--font-mono); color:#ff7b72;">${escapeHtml(score)}</b></td>
                            <td style="font-family:var(--font-mono); color:#79c0ff; word-break:break-all;">${escapeHtml(affectedRefs)}</td>
                            <td>${reachabilityTag}</td>
                            <td>${escapeHtml(v.description || '无详细描述')}</td>
                            <td style="color:#3fb950;">${escapeHtml(v.recommendation || '关注官方安全通报')}</td>
                            <td style="text-align:center;">
                                <button class="tool-btn-sm" data-locate-ref="${escapeHtml(affectedRefs)}">定位</button>
                            </td>
                         </tr>`;
            });
            tbody.innerHTML = html;
            tbody.querySelectorAll('[data-locate-ref]').forEach(button => {
                button.addEventListener('click', () => locateNode(button.dataset.locateRef));
            });

            // 更新漏洞分页器
            document.getElementById('vuln-page-start').innerText = totalItems > 0 ? startIndex + 1 : 0;
            document.getElementById('vuln-page-end').innerText = endIndex;
            document.getElementById('vuln-page-total').innerText = totalItems;

            document.getElementById('btn-vuln-page-first').disabled = vulnPage <= 1;
            document.getElementById('btn-vuln-page-prev').disabled = vulnPage <= 1;
            document.getElementById('btn-vuln-page-next').disabled = vulnPage >= totalPages;
            document.getElementById('btn-vuln-page-last').disabled = vulnPage >= totalPages;

            const numbersDom = document.getElementById('vuln-page-numbers');
            numbersDom.innerHTML = '';
            let startP = Math.max(1, vulnPage - 2);
            let endP = Math.min(totalPages, startP + 4);
            if (endP - startP < 4) startP = Math.max(1, endP - 4);
            for (let p = startP; p <= endP; p++) {
                const btn = document.createElement('button');
                btn.className = `page-btn ${p === vulnPage ? 'active' : ''}`;
                btn.innerText = p;
                btn.onclick = () => { vulnPage = p; renderVulnPageRows(sbom); };
                numbersDom.appendChild(btn);
            }
        }

        // 绑定漏洞分页事件
        document.getElementById('btn-vuln-page-first')?.addEventListener('click', () => { vulnPage = 1; renderVulnPageRows(); });
        document.getElementById('btn-vuln-page-prev')?.addEventListener('click', () => { if (vulnPage > 1) { vulnPage--; renderVulnPageRows(); } });
        document.getElementById('btn-vuln-page-next')?.addEventListener('click', () => { vulnPage++; renderVulnPageRows(); });
        document.getElementById('btn-vuln-page-last')?.addEventListener('click', () => {
            vulnPage = Math.ceil(currentVulnList.length / vulnPageSize);
            renderVulnPageRows();
        });
        document.getElementById('vuln-page-size-select')?.addEventListener('change', e => {
            vulnPageSize = parseInt(e.target.value, 10);
            vulnPage = 1;
            renderVulnPageRows();
        });

        function renderComponentTable(sbom) {
            const tbody = document.getElementById('comp-table-body');
            const paginationBar = document.getElementById('comp-pagination-bar');
            currentCompList = sbom.components || [];
            if (currentCompList.length === 0) {
                tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:40px;">暂无数据</td></tr>`;
                if (paginationBar) paginationBar.style.display = 'none';
                return;
            }

            if (paginationBar) paginationBar.style.display = 'flex';
            compPage = 1;
            renderComponentPageRows(sbom);
        }

        function renderComponentPageRows(sbom) {
            const tbody = document.getElementById('comp-table-body');
            const totalItems = currentCompList.length;
            const totalPages = Math.max(Math.ceil(totalItems / compPageSize), 1);
            if (compPage > totalPages) compPage = totalPages;
            if (compPage < 1) compPage = 1;

            const startIndex = (compPage - 1) * compPageSize;
            const endIndex = Math.min(startIndex + compPageSize, totalItems);
            const pageData = currentCompList.slice(startIndex, endIndex);

            const vulnRefs = new Set();
            const activeSbom = sbom || currentSbomData;
            if (Array.isArray(activeSbom?.vulnerabilities)) {
                activeSbom.vulnerabilities.forEach(v => {
                    (v.affects || []).forEach(a => { if (a.ref) vulnRefs.add(a.ref); });
                });
            }

            let html = '';
            pageData.forEach(c => {
                const isVuln = vulnRefs.has(c['bom-ref']);
                let locPath = 'runtime/manifest';
                let runtimeStatus = 'untraced';
                if (Array.isArray(c.properties)) {
                    const p = c.properties.find(x => x.name === 'syft:location:0:path');
                    if (p) locPath = p.value;
                    const st = c.properties.find(x => x.name === 'sbom:runtime:status');
                    if (st) runtimeStatus = st.value;
                }
                const ecoIdx = detectCategoryIndex(c.purl);
                const ecoName = CATEGORIES[ecoIdx]?.name || '其他';
                let license = 'UNKNOWN';
                if (Array.isArray(c.licenses) && c.licenses[0]) {
                    const choice = c.licenses[0];
                    license = choice.expression || choice.license?.id || choice.license?.name || 'UNKNOWN';
                }

                const statusTag = runtimeStatus === 'loaded'
                    ? '<span class="status-badge-loaded">🟢 活跃运行</span>'
                    : (runtimeStatus === 'dormant' ? '<span class="status-badge-dormant">⚪ 静态休眠</span>' : '<span class="status-badge-untraced">🔘 静态责任链</span>');

                html += `<tr>
                            <td><b style="color:#ffffff;">${escapeHtml(c.name)}</b></td>
                            <td style="font-family:var(--font-mono); color:#79c0ff;">${escapeHtml(c.version || '-')}</td>
                            <td><span class="badge-eco-tag">${escapeHtml(ecoName)}</span></td>
                            <td>${statusTag}</td>
                            <td><span class="badge-eco-tag" style="color:#3fb950;">${escapeHtml(license)}</span></td>
                            <td style="font-family:var(--font-mono); color:#8b949e; font-size:11px; word-break:break-all;">${escapeHtml(c.purl || '-')}</td>
                            <td style="font-family:var(--font-mono); color:#6e7681; font-size:11px;">${escapeHtml(locPath)}</td>
                            <td style="text-align:center;">
                                ${isVuln ? '<span style="color:#f85149; font-weight:bold;">🚨 风险</span>' : '<span style="color:#3fb950;">正常</span>'}
                            </td>
                         </tr>`;
            });
            tbody.innerHTML = html;

            // 更新组件分页条
            document.getElementById('comp-page-start').innerText = totalItems > 0 ? startIndex + 1 : 0;
            document.getElementById('comp-page-end').innerText = endIndex;
            document.getElementById('comp-page-total').innerText = totalItems;
            document.getElementById('comp-page-jump-input').max = totalPages;
            document.getElementById('comp-page-jump-input').value = compPage;

            document.getElementById('btn-comp-page-first').disabled = compPage <= 1;
            document.getElementById('btn-comp-page-prev').disabled = compPage <= 1;
            document.getElementById('btn-comp-page-next').disabled = compPage >= totalPages;
            document.getElementById('btn-comp-page-last').disabled = compPage >= totalPages;

            const numbersDom = document.getElementById('comp-page-numbers');
            numbersDom.innerHTML = '';
            let startP = Math.max(1, compPage - 2);
            let endP = Math.min(totalPages, startP + 4);
            if (endP - startP < 4) startP = Math.max(1, endP - 4);
            for (let p = startP; p <= endP; p++) {
                const btn = document.createElement('button');
                btn.className = `page-btn ${p === compPage ? 'active' : ''}`;
                btn.innerText = p;
                btn.onclick = () => { compPage = p; renderComponentPageRows(activeSbom); };
                numbersDom.appendChild(btn);
            }
        }

        // 绑定组件分页事件
        document.getElementById('btn-comp-page-first')?.addEventListener('click', () => { compPage = 1; renderComponentPageRows(); });
        document.getElementById('btn-comp-page-prev')?.addEventListener('click', () => { if (compPage > 1) { compPage--; renderComponentPageRows(); } });
        document.getElementById('btn-comp-page-next')?.addEventListener('click', () => { compPage++; renderComponentPageRows(); });
        document.getElementById('btn-comp-page-last')?.addEventListener('click', () => {
            compPage = Math.ceil(currentCompList.length / compPageSize);
            renderComponentPageRows();
        });
        document.getElementById('comp-page-size-select')?.addEventListener('change', e => {
            compPageSize = parseInt(e.target.value, 10);
            compPage = 1;
            renderComponentPageRows();
        });
        document.getElementById('btn-comp-page-jump')?.addEventListener('click', () => {
            const val = parseInt(document.getElementById('comp-page-jump-input').value, 10);
            if (val >= 1) {
                compPage = val;
                renderComponentPageRows();
            }
        });

        // 定位并高亮节点
        window.locateNode = function(refOrName) {
            document.querySelector('[data-tab="tab-graph"]').click();
            document.getElementById('node-search').value = refOrName;
            filterAndFocus(refOrName);
        };

        function filterAndFocus(keyword) {
            if (!keyword || !currentGraphData) return;
            const term = keyword.toLowerCase().trim();
            const matched = currentGraphData.nodes.find(n =>
                (n.cleanName && n.cleanName.toLowerCase().includes(term)) ||
                (n.purl && n.purl.toLowerCase().includes(term)) ||
                (n.id && n.id.toLowerCase().includes(term))
            );

            if (matched) {
                myChart.dispatchAction({
                    type: 'focusNodeAdjacency',
                    dataIndex: currentGraphData.nodes.indexOf(matched)
                });
                openDrawer(matched);
                showToast(`已定位: ${matched.cleanName}`);
            } else {
                showToast("未找到匹配节点", true);
            }
        }

        document.getElementById('node-search').addEventListener('keydown', (e) => {
            if (e.key === 'Enter') filterAndFocus(e.target.value);
        });

        // 仅看活跃 / 仅看漏洞过滤联动
        function applyGraphFilters() {
            if (!currentSbomData) return;
            const isVulnOnly = document.getElementById('filter-vuln-only').checked;
            const isLoadedOnly = document.getElementById('filter-loaded-only').checked;
            const filtered = convertCycloneDXToGraph(currentSbomData, isVulnOnly, isLoadedOnly);
            renderGraph(filtered);
        }

        document.getElementById('filter-vuln-only').addEventListener('change', () => {
            applyGraphFilters();
            showToast("已切换拓扑视图");
        });

        document.getElementById('filter-loaded-only').addEventListener('change', () => {
            applyGraphFilters();
            showToast("已切换活跃依赖过滤");
        });

        // 抽屉详情
        myChart.on('click', function(params) {
            if (params.dataType === 'node' && params.data.id !== '__VIRTUAL_PROJECT_ROOT__') {
                openDrawer(params.data);
            }
        });

        function openDrawer(nodeData) {
            const drawer = document.getElementById('node-drawer');
            const drawerBody = document.getElementById('drawer-body');
            document.getElementById('drawer-node-name').innerText = nodeData.cleanName;
            document.getElementById('drawer-eco-tag').innerText = nodeData.ecoName;

            const vulns = nodeData.vulns || [];
            let vulnBox = '';
            if (vulns.length > 0) {
                vulnBox = `
                    <div class="detail-vuln-box">
                        <b style="color:#f85149; font-size:12px;">🚨 命中 ${vulns.length} 项 OSV 漏洞告警</b>
                        ${vulns.map(v => `
                            <div style="margin-top:6px; border-top:1px solid rgba(248,81,73,0.3); padding-top:4px;">
                                <div style="display:flex; justify-content:space-between;">
                                    <b style="color:#ff7b72;">${escapeHtml(v.id)}</b>
                                    <span class="badge-sev ${escapeHtml(v.severity.toLowerCase())}">${escapeHtml(v.severity)} ${escapeHtml(v.score || '')}</span>
                                </div>
                                <div style="color:#f0f6fc; margin-top:2px;">${escapeHtml(v.description)}</div>
                                <div style="color:#3fb950; margin-top:2px; font-weight:600;">修复建议: ${escapeHtml(v.recommendation)}</div>
                            </div>
                        `).join('')}
                    </div>
                `;
            }

            drawerBody.innerHTML = `
                ${vulnBox}
                <div class="detail-block">
                    <div class="detail-title">版本号</div>
                    <div class="detail-val" style="color:#79c0ff;">${escapeHtml(nodeData.version || '未知')}</div>
                </div>
                <div class="detail-block">
                    <div class="detail-title">开源许可证 (SPDX License)</div>
                    <div class="detail-val" style="color:#3fb950;">${escapeHtml(nodeData.license || 'UNKNOWN')}</div>
                </div>
                <div class="detail-block">
                    <div class="detail-title">唯一实例身份证 (instance_id)</div>
                    <div class="detail-val">${escapeHtml(nodeData.id)}</div>
                </div>
                <div class="detail-block">
                    <div class="detail-title">标准 PURL 坐标</div>
                    <div class="detail-val" style="color:#8b949e;">${escapeHtml(nodeData.purl)}</div>
                </div>
                <div class="detail-block">
                    <div class="detail-title">运行时加载状态</div>
                    <div class="detail-val">
                        ${nodeData.runtimeStatus === 'loaded' ? '<span style="color:#2ea043;font-weight:700;">🟢 已观测到加载/引用 (LOADED)</span>' : (nodeData.runtimeStatus === 'dormant' ? '<span style="color:#8b949e;font-weight:700;">⚪ 未观测到加载（不代表不可达）</span>' : '<span style="color:#58a6ff;">🔘 静态责任链解析 (UNTRACED)</span>')}
                    </div>
                </div>
                <div class="detail-block">
                    <div class="detail-title">清单物理位置 (syft:location:0:path)</div>
                    <div class="detail-val">${escapeHtml(nodeData.locationPath)}</div>
                </div>
                <div class="detail-block">
                    <div class="detail-title">上游调用者 (被依赖 ${nodeData.callers ? nodeData.callers.length : 0} 次)</div>
                    <div class="detail-val" style="color:#8b949e;">
                        ${(nodeData.callers && nodeData.callers.length > 0) ? nodeData.callers.map(c => `<div>• ${escapeHtml(c.split('?')[0])}</div>`).join('') : '顶级直接依赖项'}
                    </div>
                </div>
            `;
            drawer.classList.add('open');
        }

        document.getElementById('btn-close-drawer').addEventListener('click', () => {
            document.getElementById('node-drawer').classList.remove('open');
        });

        // 画布缩放工具
        document.getElementById('btn-zoom-in').addEventListener('click', () => {
            const opt = myChart.getOption();
            const curZoom = (opt.series[0].zoom || 1) * 1.3;
            myChart.setOption({ series: [{ zoom: curZoom }] });
        });

        document.getElementById('btn-zoom-out').addEventListener('click', () => {
            const opt = myChart.getOption();
            const curZoom = Math.max((opt.series[0].zoom || 1) * 0.7, 0.2);
            myChart.setOption({ series: [{ zoom: curZoom }] });
        });

        document.getElementById('btn-reset-view').addEventListener('click', () => {
            myChart.dispatchAction({ type: 'restore' });
            showToast("已重置图谱比例");
        });

        document.getElementById('btn-export-png').addEventListener('click', () => {
            const url = myChart.getDataURL({ pixelRatio: 2, backgroundColor: '#0d1117' });
            const a = document.createElement('a');
            a.download = `sbom-network-${Date.now()}.png`;
            a.href = url;
            a.click();
            showToast("已导出高清 PNG 图片");
        });

        // 拓扑大空间、布局切换与间距疏密动态调节
        document.getElementById('select-graph-layout')?.addEventListener('change', (e) => {
            currentGraphLayout = e.target.value;
            myChart.setOption({
                series: [{
                    layout: currentGraphLayout,
                    circular: { rotateLabel: true }
                }]
            });
            showToast(`已切换拓扑布局模式: ${currentGraphLayout === 'force' ? '大空间力导向' : '环形分层拓扑'}`);
        });

        document.getElementById('slider-node-repulsion')?.addEventListener('input', (e) => {
            currentRepulsionMult = parseFloat(e.target.value);
            myChart.setOption({
                series: [{
                    force: {
                        repulsion: Math.round(1900 * currentRepulsionMult),
                        edgeLength: [Math.round(190 * currentRepulsionMult), Math.round(340 * currentRepulsionMult)]
                    }
                }]
            });
        });

        document.getElementById('btn-fullscreen-graph')?.addEventListener('click', () => {
            const graphPanel = document.getElementById('tab-graph');
            const isFull = graphPanel.classList.toggle('fullscreen-canvas-mode');
            document.getElementById('btn-fullscreen-graph').innerText = isFull ? '✕ 还原' : '⛶ 全屏';
            setTimeout(() => myChart && myChart.resize(), 100);
            showToast(isFull ? "已进入全屏超大视野模式 (按右上角还原或按 Esc 退出)" : "已退出全屏模式");
        });

        window.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                const graphPanel = document.getElementById('tab-graph');
                if (graphPanel?.classList.contains('fullscreen-canvas-mode')) {
                    graphPanel.classList.remove('fullscreen-canvas-mode');
                    document.getElementById('btn-fullscreen-graph').innerText = '⛶ 全屏';
                    setTimeout(() => myChart && myChart.resize(), 80);
                }
            }
        });

        document.getElementById('btn-empty-browse').addEventListener('click', () => {
            document.getElementById('btn-browse-dir').click();
        });
        document.getElementById('btn-empty-import').addEventListener('click', () => {
            document.getElementById('btn-import-sbom').click();
        });

        // 7. 统一数据装载入口 (无论是扫描产出还是直接文件导入)
        function loadSbomData(rawSbom, sourceTitle = '') {
            document.getElementById('graph-empty-state').classList.add('hidden');
            currentSbomData = rawSbom;
            const graphData = convertCycloneDXToGraph(rawSbom);
            currentGraphData = graphData;
            renderGraph(graphData);

            const comps = Array.isArray(rawSbom.components) ? rawSbom.components : [];
            const loadedRefs = new Set();
            let licensedCount = 0;
            comps.forEach(c => {
                if (Array.isArray(c.properties)) {
                    const st = c.properties.find(p => p.name === 'sbom:runtime:status');
                    if (st && st.value === 'loaded' && c['bom-ref']) {
                        loadedRefs.add(c['bom-ref']);
                    }
                }
                if (Array.isArray(c.licenses) && c.licenses.length > 0) {
                    licensedCount++;
                }
            });

            let activeVulnsCount = 0;
            (rawSbom.vulnerabilities || []).forEach(v => {
                if ((v.affects || []).some(a => loadedRefs.has(a.ref))) {
                    activeVulnsCount++;
                }
            });

            const licRate = comps.length > 0 ? (licensedCount / comps.length * 100).toFixed(1) + '%' : '0%';

            document.getElementById('metric-components').innerText = comps.length;
            const uniquePurlCount = new Set(comps.map(c => normalizePurl(c.purl)).filter(Boolean)).size;
            if (document.getElementById('metric-unique')) {
                document.getElementById('metric-unique').innerText = uniquePurlCount;
            }
            document.getElementById('metric-vulns').innerText = graphData.totalCves;

            if (graphData.totalCves > 0) {
                document.getElementById('metric-vulns').classList.add('alert');
                document.getElementById('tab-vuln-badge').style.display = 'inline-block';
                document.getElementById('tab-vuln-badge').innerText = graphData.totalCves;
            } else {
                document.getElementById('metric-vulns').classList.remove('alert');
                document.getElementById('tab-vuln-badge').style.display = 'none';
            }

            document.getElementById('metric-ecos').innerText = graphData.ecosystemsCount;

            renderVulnTable(rawSbom);
            renderComponentTable(rawSbom);
            document.getElementById('raw-json-block').textContent = JSON.stringify(rawSbom, null, 2);

            const statusDot = document.getElementById('status-dot');
            const statusText = document.getElementById('status-text');
            if (graphData.totalCves > 0) {
                statusDot.className = 'status-dot-sm danger';
                statusText.innerText = `${sourceTitle ? sourceTitle + ': ' : ''}完成！识别 ${comps.length} 个依赖 (🟢 ${graphData.loadedCount || 0} 活跃)，检出 ${graphData.totalCves} 项漏洞 (🚨 ${activeVulnsCount} 项命中活跃组件)`;
            } else {
                statusDot.className = 'status-dot-sm';
                statusText.innerText = `${sourceTitle ? sourceTitle + ': ' : ''}完成！识别 ${comps.length} 个依赖 (🟢 ${graphData.loadedCount || 0} 活跃)，未发现已知漏洞`;
            }
        }

        // 8. 核心分析调用入口
        document.getElementById('analyze-btn').addEventListener('click', async function() {
            let directory = document.getElementById('input-dir').value.trim();
            let outputPath = document.getElementById('input-save').value.trim();
            const isDynamic = document.getElementById('toggle-dynamic')?.checked ?? true;
            const isAllowExec = document.getElementById('toggle-allow-exec')?.checked ?? false;

            if (directory.startsWith('"') && directory.endsWith('"')) directory = directory.slice(1, -1);
            if (outputPath.startsWith('"') && outputPath.endsWith('"')) outputPath = outputPath.slice(1, -1);

            if (!directory) {
                alert("请先点击「打开文件夹」选取需要分析的项目代码根目录！");
                return;
            }
            if (!outputPath) {
                const sep = directory.includes('/') ? '/' : '\\';
                outputPath = `${directory.replace(/[\\/]$/, '')}${sep}sbom_result.json`;
                document.getElementById('input-save').value = outputPath;
            }

            const btn = document.getElementById('analyze-btn');
            const statusDot = document.getElementById('status-dot');
            const statusText = document.getElementById('status-text');

            try {
                btn.disabled = true;
                btn.innerHTML = `<span>⏳ 正在分析构建...</span>`;
                statusDot.className = 'status-dot-sm busy';
                statusText.innerText = '正在执行跨语言依赖拓扑解析、动态加载监测与 OSV 匹配...';
                myChart.showLoading({
                    text: '正在构建高密度依赖拓扑星系...',
                    textColor: '#fff',
                    maskColor: 'rgba(13, 17, 23, 0.85)',
                    color: '#38bdf8'
                });

                const jsonString = await tauriInvoke('run_sbom_analyze', {
                    directory,
                    outputPath,
                    dynamic: isDynamic,
                    allowExec: isAllowExec
                });

                const rawSbom = JSON.parse(jsonString);
                myChart.hideLoading();
                btn.disabled = false;
                btn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg><span>重新分析</span>`;

                loadSbomData(rawSbom, '扫描完成');
                showToast("依赖拓扑分析与动态加载监测完成！");

            } catch (err) {
                myChart.hideLoading();
                btn.disabled = false;
                btn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg><span>重新分析</span>`;
                statusDot.className = 'status-dot-sm danger';
                statusText.innerText = '分析失败';
                showToast("分析发生异常: " + err, true);
                alert("构建失败: " + err);
            }
        });

        // 注意: SBOM 深度交叉对比评测已全面迁移至独立大窗口 compare.html (提供 7 大量化图表与全屏体验)
        // 通过顶栏【🗗 SBOM 对比评测中心】按钮或 openCompareWindow() 触发
        // 10. 复制与下载 JSON
        document.getElementById('btn-copy-json').addEventListener('click', () => {
            const code = document.getElementById('raw-json-block').textContent;
            navigator.clipboard.writeText(code).then(() => showToast("已复制 SBOM JSON 到剪贴板"));
        });

        document.getElementById('btn-download-json').addEventListener('click', () => {
            const code = document.getElementById('raw-json-block').textContent;
            const blob = new Blob([code], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.download = `cyclonedx-sbom-${Date.now()}.json`;
            a.href = url;
            a.click();
            URL.revokeObjectURL(url);
            showToast("已下载 SBOM JSON 文件");
        });

        window.addEventListener('resize', () => {
            myChart && myChart.resize();
        });
