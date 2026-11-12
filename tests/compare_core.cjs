const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const core = require('../ui/compare-core.js');
const cases = require('./fixtures/compare_cases.json');
const root = path.resolve(__dirname, '..');
const executable = process.env.SBOM_COMPARE_EXE || path.join(root, 'target', 'debug', process.platform === 'win32' ? 'sbom_compare.exe' : 'sbom_compare');

for (const fixture of cases) {
    test(`comparison conformance: ${fixture.name}`, () => {
        if (fixture.expect_error) {
            assert.throws(() => core.compare(fixture.a, fixture.b, fixture.options));
            return;
        }
        const actual = core.compare(fixture.a, fixture.b, fixture.options);
        for (const [selector, expected] of Object.entries(fixture.expected)) {
            const value = selector.split('.').reduce((v, key) => v[key], actual);
            if (typeof expected === 'number') assert.ok(Math.abs(value - expected) < 1e-9, `${selector}: ${value} != ${expected}`);
            else assert.deepEqual(value, expected, selector);
        }
    });
}

test('canonicalization is idempotent and does not turn constraints into versions', () => {
    for (const p of ['pkg:npm/%40Scope/Name@1.0%2Bbuild','pkg:pypi/DEMO__name@1%25local','pkg:golang/example.com/Module@1.0.0+incompatible','pkg:maven/org.example/project@1%40custom']) {
        const normalized = core.normalizePurl(p);
        assert.ok(normalized);
        assert.equal(core.normalizePurl(normalized), normalized);
    }
    for (const v of ['^1','~1','1.*','1.x','>=1','latest','${unexpanded}','1.+','workspace:*']) assert.equal(core.exactVersion(v),false,v);
    assert.equal(core.exactVersion('0.0.0'),true);
    assert.equal(core.exactVersion('1!2.0rc1+CPU'),true);
});

test('invalid input and empty/invalid target scopes are rejected', () => {
    for (const bad of [{components:[]},{bomFormat:'CycloneDX',components:{}},{bomFormat:'CycloneDX',components:[],dependencies:null}]) assert.throws(()=>core.compare(bad,{bomFormat:'CycloneDX',components:[]}));
    const empty = {bomFormat:'CycloneDX',components:[]};
    assert.throws(()=>core.compare(empty,empty,{ecosystems:[]}));
    assert.throws(()=>core.compare(empty,empty,{ecosystems:['npm,maven']}));
});

test('Rust CLI and browser engine agree on complete structured reports', {skip: !fs.existsSync(executable)}, () => {
    const directory = path.join(root,'target','test_outputs','compare_conformance');
    fs.mkdirSync(directory,{recursive:true});
    for (const fixture of cases) {
        const a = path.join(directory,'a.json'), b = path.join(directory,'b.json');
        const report = path.join(directory,'report.md'), json = path.join(directory,'report.json');
        fs.writeFileSync(a,JSON.stringify(fixture.a)); fs.writeFileSync(b,JSON.stringify(fixture.b));
        fs.writeFileSync(report,'previous report');
        const args = ['-a',a,'-b',b,'-o',report,'--json-output',json];
        if (fixture.options) {
            args.push('--ecosystems',fixture.options.ecosystems.join(','));
            if (fixture.options.include_applications) args.push('--include-applications');
            if (fixture.options.exclude_zero_versions) args.push('--exclude-zero-versions');
        }
        const output = spawnSync(executable,args,{encoding:'utf8',timeout:15000});
        if (fixture.expect_error) {
            assert.notEqual(output.status,0,fixture.name);
            assert.equal(fs.readFileSync(report,'utf8'),'previous report');
            continue;
        }
        assert.equal(output.status,0,`${fixture.name}: ${output.stderr}`);
        const rust = JSON.parse(fs.readFileSync(json,'utf8'));
        const js = JSON.parse(JSON.stringify(core.compare(fixture.a,fixture.b,fixture.options)));
        assert.deepEqual(rust,js,fixture.name);
        const markdown = fs.readFileSync(report,'utf8');
        assert.ok(markdown.includes('不是独立真值'));
        assert.ok(markdown.includes('依赖边独立比较'));
    }
});


test('CLI protects input SBOMs and checks both output paths before replacing a report', {skip: !fs.existsSync(executable)}, () => {
    const directory = path.join(root,'target','test_outputs','compare_output_guards');
    fs.mkdirSync(directory,{recursive:true});
    const input = path.join(directory,'input.json'), report = path.join(directory,'report.md');
    const content = JSON.stringify({bomFormat:'CycloneDX',components:[]});
    fs.writeFileSync(input,content); fs.writeFileSync(report,'previous report');
    for (const args of [['-o',input],['-o',report,'--json-output',report],['-o',report,'--json-output',path.join(directory,'missing-parent','report.json')]]) {
        const result = spawnSync(executable,['-a',input,'-b',input,...args],{encoding:'utf8',timeout:15000});
        assert.notEqual(result.status,0,result.stderr);
        assert.equal(fs.readFileSync(input,'utf8'),content);
        assert.equal(fs.readFileSync(report,'utf8'),'previous report');
    }
});
