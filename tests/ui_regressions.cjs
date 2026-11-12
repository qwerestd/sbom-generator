const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function loadFunctions(file, names, extra = {}) {
    const source = fs.readFileSync(file, 'utf8');
    const context = vm.createContext({ CompareCore: require('../ui/compare-core.js'), ...extra });
    for (const name of names) {
        const start = source.indexOf(`function ${name}(`);
        assert.ok(start >= 0, name);
        const end = source.indexOf('\n        }', start) + '\n        }'.length;
        const declaration = source.slice(Math.max(0,start-6),start) === 'async ' ? start-6 : start;
        vm.runInContext(source.slice(declaration, end), context);
    }
    return context;
}

test('both viewers preserve PURL case and normalize PyPI separators identically', () => {
    for (const file of ['ui/index.js', 'ui/compare.js']) {
        const c = loadFunctions(file, ['normalizePurl']);
        assert.equal(c.normalizePurl('pkg:golang/example.com/Module@v1.0.0-RC1?type=module'), 'pkg:golang/example.com/Module@v1.0.0-RC1');
        assert.equal(c.normalizePurl('pkg:pypi/My__..Package@1.0-RC1'), 'pkg:pypi/my-package@1.0-RC1');
        assert.equal(c.normalizePurl('pkg:npm/%40scope/name@1.0%2Bbuild'), 'pkg:npm/@scope/name@1.0+build');
    }
});

function comparisonContext() {
    const elements = new Map();
    const document = { getElementById(id) {
        if (!elements.has(id)) elements.set(id, { innerText: '', innerHTML: '' });
        return elements.get(id);
    }};
    const c = loadFunctions('ui/compare.js', ['escapeHtml', 'normalizePurl', 'readCompareOptions', 'invalidateComparison', 'membershipInfo', 'graphLayoutFor', 'parseComparisonInput', 'setInputDocument', 'readComparisonText', 'loadInputDocument', 'loadPresetSample', 'renderComparisonDiagnostics', 'comparisonMarkdown', 'extractEco', 'isTargetEco', 'isValidThirdParty', 'extractMeta', 'extractToolName', 'extractToolBDetails', 'runBenchmarkComparison', 'renderTableRows'], {
        document, chartOverlap:null, chartEco:null, chartTopo:null, chartSplitLeft:null, chartSplitRight:null, initCharts() {}, renderChartsGroup() {}, applyFiltersAndRenderPage() {}, showToast() {},
        labelA: 'A', labelB: 'B', labelC: 'C', sbomC: null, lastComparison: null, currentDiffList: [], filteredDiffList: [], currentPage: 1, pageSize: 30,
        currentTopoView:'diff', compareGraphLayout:'auto', pendingInputLoad:false, inputRevision:0, slotRevisions:{a:0,b:0,c:0}, pendingSlots:new Set(), tauriCore:null,
    });
    return { c, elements };
}
const component = purl => ({ type: 'library', name: 'component', version: decodeURIComponent(purl.slice(purl.lastIndexOf('@') + 1)), purl });

test('unresolved components count toward totals and remain visible without matching pinned versions', () => {
    const { c, elements } = comparisonContext();
    c.sbomA = {bomFormat: 'CycloneDX',components: [{name: '<range-demo>', type: 'library', purl: 'pkg:npm/demo',
        properties: [{name: 'sbom:version:requirement', value: '^1.0.0'}]}]};
    c.sbomB = {bomFormat: 'CycloneDX',components: [component('pkg:npm/demo@1.0.0')]};
    c.runBenchmarkComparison();
    assert.equal(elements.get('kpi-instances-a').innerText, '1');
    assert.equal(elements.get('kpi-target-coverage').innerText, '0.00%');
    assert.ok(elements.get('kpi-instances-diff').innerText.includes('A:0/1'));
    assert.ok(elements.get('unresolved-tbody').innerHTML.includes('&lt;range-demo&gt;'));
    assert.ok(elements.get('unresolved-tbody').innerHTML.includes('^1.0.0'));
});

test('empty reference is N/A and target Jaccard excludes unsupported ecosystems', () => {
    const { c, elements } = comparisonContext();
    c.sbomA = {bomFormat: 'CycloneDX', components: [component('pkg:npm/a@1.0'), component('pkg:gem/extra@1.0')] };
    c.sbomB = {bomFormat: 'CycloneDX', components: [component('pkg:npm/a@1.0')] };
    c.runBenchmarkComparison();
    assert.equal(elements.get('kpi-jaccard').innerText, '100.0%');
    c.sbomB = {bomFormat: 'CycloneDX', components: [] };
    c.runBenchmarkComparison();
    assert.equal(elements.get('kpi-target-coverage').innerText, 'N/A');
    assert.equal(elements.get('kpi-total-coverage').innerText, 'N/A');
    c.sbomA = {bomFormat: 'CycloneDX', components: [] };
    c.runBenchmarkComparison();
    assert.equal(elements.get('kpi-jaccard').innerText, 'N/A');
    assert.equal(c.isValidThirdParty({ ...component('pkg:maven/a/b@runtime'), version: 'Runtime' }), true);
});

test('imported markup remains text in every comparison table field', () => {
    const { c, elements } = comparisonContext();
    const attack = `<img src=x onerror="alert('injected')">`;
    c.filteredDiffList = [{ type: 'onlyA', name: attack, version: attack, eco: attack,
        license: attack, purl: attack, location: attack, desc: attack }];
    c.renderTableRows();
    const html = elements.get('paginated-diff-tbody').innerHTML;
    assert.ok(!html.includes('<img'));
    assert.ok(html.includes('&lt;img'));
    assert.equal(c.escapeHtml(`'"<&>`), '&#39;&quot;&lt;&amp;&gt;');
});

test('report describes measured low overlap without claiming success', async () => {
    const { c, elements } = comparisonContext();
    c.sbomA = {bomFormat: 'CycloneDX', components: [component('pkg:npm/a@1')] };
    c.sbomB = {bomFormat: 'CycloneDX', components: [component('pkg:npm/b@1')] };
    c.runBenchmarkComparison();
    let report;
    c.navigator = { clipboard: { writeText(text) { report = text; return Promise.resolve(); } } };
    const source = fs.readFileSync('ui/compare.js', 'utf8');
    const start = source.indexOf("document.getElementById('btn-export-markdown').onclick");
    const end = source.indexOf("document.getElementById('btn-export-json').onclick", start);
    vm.runInContext(source.slice(start, end), c);
    elements.get('btn-export-markdown').onclick();
    await Promise.resolve();
    assert.ok(report.includes('0.00%'));
    assert.ok(report.includes('仅 B 出现: 1'));
    assert.ok(!report.includes('达到预设基准'));
    assert.ok(report.includes('不是独立真值'));
});

test('desktop CSP blocks inline script and both pages load external local scripts', () => {
    const csp = JSON.parse(fs.readFileSync('src-tauri/tauri.conf.json')).app.security.csp;
    const scriptPolicy = csp.split(';').find(p => p.trim().startsWith('script-src'));
    assert.ok(!scriptPolicy.includes('unsafe-inline'));
    for (const name of ['index', 'compare']) {
        const html = fs.readFileSync(`ui/${name}.html`, 'utf8');
        assert.ok(!html.includes('<script>'));
        assert.ok(html.includes(`src="${name}.js"`));
        new vm.Script(fs.readFileSync(`ui/${name}.js`, 'utf8'));
    }
});

test('main viewer escapes component and vulnerability fields without inline event handlers', () => {
    const elements = new Map();
    const document = {
        getElementById(id) {
            if (!elements.has(id)) elements.set(id, { innerHTML: '', querySelectorAll: () => [], appendChild() {} });
            return elements.get(id);
        },
        createElement() { return {}; },
    };
    const attack = `<img src=x onerror="alert('injected')">`;
    const c = loadFunctions('ui/index.js', ['escapeHtml', 'renderComponentPageRows', 'renderVulnPageRows'], {
        document, CATEGORIES: [{name: 'npm'}], detectCategoryIndex: () => 0,
        currentCompList: [{name: attack, version: attack, purl: attack,
            licenses: [{license: {name: attack}}], properties: [{name: 'syft:location:0:path', value: attack}]}],
        compPage: 1, compPageSize: 30, vulnPage: 1, vulnPageSize: 30,
        currentVulnList: [{id: attack, description: attack, recommendation: attack, affects: [{ref: attack}]}],
    });
    c.renderComponentPageRows({components: []});
    c.renderVulnPageRows({components: []});
    for (const id of ['comp-table-body', 'vuln-table-body']) {
        const html = elements.get(id).innerHTML;
        assert.ok(!html.includes('<img'));
        assert.ok(html.includes('&lt;img'));
        assert.ok(!html.includes('onclick='));
    }
});


test('same package with different versions is not counted as an identity missing on both sides', () => {
    const {c,elements} = comparisonContext();
    c.sbomA = {bomFormat:'CycloneDX',components:[component('pkg:npm/demo@1')]};
    c.sbomB = {bomFormat:'CycloneDX',components:[component('pkg:npm/demo@2')]};
    c.runBenchmarkComparison();
    assert.equal(c.lastComparison.exact.common,0);
    assert.equal(c.lastComparison.identity.common,1);
    assert.equal(c.currentDiffList.filter(r=>r.type==='versionMismatch').length,1);
    assert.equal(c.currentDiffList.filter(r=>r.type==='onlyA'||r.type==='onlyB').length,0);
    assert.equal(elements.get('tab-cnt-version-mismatch').innerText,'1');
});

test('third reference uses independent pairwise results and explicit target scope', () => {
    const {c,elements} = comparisonContext();
    c.sbomA = {bomFormat:'CycloneDX',components:[component('pkg:npm/a@1')]};
    c.sbomB = {bomFormat:'CycloneDX',components:[component('pkg:npm/b@1')]};
    c.sbomC = {bomFormat:'CycloneDX',components:[component('pkg:npm/a@1')]};
    c.runBenchmarkComparison();
    assert.equal(c.lastComparison.exact.coverage_b,0);
    assert.equal(c.lastComparisonAC.exact.coverage_b,100);
    assert.equal(c.lastComparisonBC.exact.coverage_b,0);
    assert.ok(elements.get('comparison-metrics-body').innerHTML.includes('A–C'));
});

test('invalid replacement input clears exportable result and does not reuse a previous report', () => {
    const {c} = comparisonContext();
    c.sbomA = {bomFormat:'CycloneDX',components:[component('pkg:npm/a@1')]};
    c.sbomB = c.sbomA;
    c.runBenchmarkComparison();
    assert.ok(c.lastComparison);
    c.sbomB = {components:[]};
    c.runBenchmarkComparison();
    assert.equal(c.lastComparison,null);
});

test('topology uses only validated reported references and marks layout links separately', () => {
    const {c} = comparisonContext();
    c.sbomA = {bomFormat:'CycloneDX',components:[{...component('pkg:npm/a@1'),'bom-ref':'a'}, {...component('pkg:npm/b@1'),'bom-ref':'b'}],dependencies:[{ref:'a',dependsOn:['b','pkg:npm/a@1']} ]};
    c.sbomB = c.sbomA;
    c.runBenchmarkComparison();
    const source = fs.readFileSync('ui/compare.js','utf8');
    const start = source.indexOf('function extractEdgesFromSbom(');
    const end = source.indexOf('\n        }',start)+'\n        }'.length;
    vm.runInContext(source.slice(start,end),c);
    const links = [], keys = new Set();
    c.extractEdgesFromSbom(c.sbomA,null,'root',new Map([['pkg:npm/a@1',0],['pkg:npm/b@1',1]]),keys,links);
    assert.equal(links.length,1);
    assert.equal(links[0].source,'pkg:npm/a@1');
    assert.equal(c.lastComparison.a.dangling_refs.length,1);
    assert.ok(source.includes("synthetic: true"));
});
