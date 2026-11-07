const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function loadFunctions(file, names, extra = {}) {
    const source = fs.readFileSync(file, 'utf8');
    const context = vm.createContext(extra);
    for (const name of names) {
        const start = source.indexOf(`function ${name}(`);
        assert.ok(start >= 0, name);
        const end = source.indexOf('\n        }', start) + '\n        }'.length;
        vm.runInContext(source.slice(start, end), context);
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
    const c = loadFunctions('ui/compare.js', ['escapeHtml', 'normalizePurl', 'extractEco', 'isTargetEco', 'isValidThirdParty', 'extractMeta', 'extractToolName', 'extractToolBDetails', 'runBenchmarkComparison', 'renderTableRows'], {
        document, initCharts() {}, renderChartsGroup() {}, applyFiltersAndRenderPage() {}, showToast() {},
        labelA: 'A', labelB: 'B', currentDiffList: [], filteredDiffList: [], currentPage: 1, pageSize: 30,
    });
    return { c, elements };
}
const component = purl => ({ type: 'library', name: 'component', version: '1.0', purl });

test('empty reference is N/A and target Jaccard excludes unsupported ecosystems', () => {
    const { c, elements } = comparisonContext();
    c.sbomA = { components: [component('pkg:npm/a@1.0'), component('pkg:gem/extra@1.0')] };
    c.sbomB = { components: [component('pkg:npm/a@1.0')] };
    c.runBenchmarkComparison();
    assert.equal(elements.get('kpi-jaccard').innerText, '100.0%');
    c.sbomB = { components: [] };
    c.runBenchmarkComparison();
    assert.equal(elements.get('kpi-target-coverage').innerText, 'N/A');
    assert.equal(elements.get('kpi-total-coverage').innerText, 'N/A');
    c.sbomA = { components: [] };
    c.runBenchmarkComparison();
    assert.equal(elements.get('kpi-jaccard').innerText, 'N/A');
    assert.equal(c.isValidThirdParty({ ...component('pkg:maven/a/b@runtime'), version: 'Runtime' }), false);
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
    c.sbomA = { components: [component('pkg:npm/a@1')] };
    c.sbomB = { components: [component('pkg:npm/b@1')] };
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
