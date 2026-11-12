/* Comparison policy shared with src/compare.rs; conformance fixtures verify CLI/browser parity. */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) module.exports = api;
    else root.CompareCore = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    'use strict';
    const DEFAULT_ECOS = ['cargo', 'golang', 'maven', 'npm', 'pypi'];
    const asciiLower = s => s.replace(/[A-Z]/g, c => c.toLowerCase());
    const text = value => typeof value === 'string' ? value : null;
    const sortText = (a, b) => {
        const aa = Array.from(a), bb = Array.from(b);
        for (let i = 0; i < Math.min(aa.length, bb.length); i++) {
            if (aa[i] !== bb[i]) return aa[i].codePointAt(0) - bb[i].codePointAt(0);
        }
        return aa.length - bb.length;
    };
    const sorted = values => [...values].sort(sortText);
    const intersection = (a,b) => new Set([...a].filter(x => b.has(x)));
    const difference = (a,b) => new Set([...a].filter(x => !b.has(x)));
    const eco = id => /^pkg:([^/]+)\//.exec(id)?.[1] || 'unknown';
    const encodePart = s => s.replace(/%/g,'%25').replace(/\?/g,'%3F').replace(/#/g,'%23').replace(/@/g,'%40');
    const version = (type,v) => type === 'golang' && /^\d/.test(v) ? 'v' + v : v;
    function splitPurl(raw) {
        if (typeof raw !== 'string') return null;
        const body = raw.trim().split(/[?#]/, 1)[0];
        const match = /^pkg:([a-zA-Z0-9.+-]+)\/(.+)$/u.exec(body);
        if (!match) return null;
        const type = asciiLower(match[1]), path = match[2];
        const at = path.lastIndexOf('@') > path.lastIndexOf('/') ? path.lastIndexOf('@') : -1;
        let name, v;
        try { name = decodeURIComponent(at >= 0 ? path.slice(0, at) : path); v = at >= 0 ? version(type, decodeURIComponent(path.slice(at + 1))) : null; }
        catch { return null; }
        if (!name || name.split('/').some(x => !x) || /[\s\x00-\x1f\x7f-\x9f]/u.test(name)) return null;
        if (type === 'pypi') name = asciiLower(name).split(/[-_.]+/).filter(Boolean).join('-');
        if (type === 'npm' || type === 'cargo') name = asciiLower(name);
        if (!name) return null;
        name = type === 'npm' && name.startsWith('@') ? '@' + encodePart(name.slice(1)) : encodePart(name);
        return { identity: `pkg:${type}/${name}`, version: v };
    }
    function normalizePurl(raw) {
        const p = splitPurl(raw);
        return p ? p.identity + (p.version === null ? '' : '@' + encodePart(p.version)) : '';
    }
    function exactVersion(v) {
        return typeof v === 'string' && !!v && !/[\s\x00-\x1f\x7f-\x9f*^~<>=,|\[\]()${}/\\]/u.test(v)
            && !['latest','latest.release','latest.integration','release','runtime','workspace','unknown'].includes(asciiLower(v))
            && !v.endsWith('.+') && !v.split('.').some(p => asciiLower(p) === 'x')
            && !v.startsWith('workspace:') && !v.startsWith('file:') && !v.includes('://');
    }
    const property = (c, name) => Array.isArray(c?.properties) ? text(c.properties.find(p => p?.name === name)?.value) : null;
    function locations(c) {
        const values = [];
        for (const property of Array.isArray(c?.properties) ? c.properties : []) {
            if (/^syft:location:\d+:path$/.test(property?.name || '') || ['aquasecurity:trivy:FilePath','trivy:FilePath'].includes(property?.name)) {
                if (typeof property.value === 'string') values.push(property.value);
            }
        }
        for (const occurrence of Array.isArray(c?.evidence?.occurrences) ? c.evidence.occurrences : []) {
            if (typeof occurrence?.location === 'string') values.push(occurrence.location);
        }
        return sorted(new Set(values.map(path=>path.replace(/\\/g,'/').replace(/^(?:\.\/)+/,'')).filter(Boolean)));
    }
    function flatten(components, result = []) {
        for (const c of components) {
            result.push(c);
            if (Array.isArray(c?.components)) flatten(c.components, result);
        }
        return result;
    }
    const ratio = (n,d) => d ? n / d * 100 : null;
    const metrics = (a,b,common) => ({a,b,common,only_a:a-common,only_b:b-common,coverage_a:ratio(common,a),coverage_b:ratio(common,b),jaccard:ratio(common,a+b-common)});
    const setMetrics = (a,b) => metrics(a.size,b.size,intersection(a,b).size);
    const multisetMetrics = (a,b) => metrics(Object.values(a).reduce((n,v)=>n+v,0),Object.values(b).reduce((n,v)=>n+v,0),Object.entries(a).reduce((n,[k,v])=>n+Math.min(v,b[k]||0),0));
    function policyOptions(options = {}) {
        const policy = {ecosystems: sorted(new Set((options.ecosystems || DEFAULT_ECOS).map(e => asciiLower(e.trim())).filter(Boolean))), include_applications: !!options.include_applications, exclude_zero_versions: !!options.exclude_zero_versions};
        if (!policy.ecosystems.length) throw new Error('至少选择一个目标生态');
        if (policy.ecosystems.some(e=>! /^[a-z0-9.+-]+$/.test(e))) throw new Error('目标生态名称无效');
        return policy;
    }
    function summarize(json, options) {
        const policy = policyOptions(options);
        if (json?.bomFormat !== 'CycloneDX') throw new Error('不是 CycloneDX SBOM');
        if (!Array.isArray(json.components)) throw new Error('缺少 components 数组');
        if ('dependencies' in json && !Array.isArray(json.dependencies)) throw new Error('dependencies 必须是数组');
        const all = flatten(json.components);
        if (json.metadata?.component && typeof json.metadata.component === 'object' && !Array.isArray(json.metadata.component)) {
            if (Array.isArray(json.metadata.component.components)) flatten(json.metadata.component.components,all);
            all.push(json.metadata.component);
        }
        const tool = (Array.isArray(json.metadata?.tools) ? json.metadata.tools : json.metadata?.tools?.components)?.[0];
        const result = {
            tool_name: text(tool?.name) ?? 'Unknown', tool_version:text(tool?.version), timestamp:text(json.metadata?.timestamp), spec_version: text(json.specVersion) ?? '未知',
            records: [], total_components:0, unresolved_components:0, inconsistent_components:0,
            excluded: Object.create(null), diagnostics: new Set(), keys:new Set(), identities:new Set(), versions:Object.create(null), occurrences:Object.create(null), located_occurrences:Object.create(null), missing_locations:0,
            graph_available:'dependencies' in json, edges:new Set(), dangling_refs:new Set(), duplicate_refs:new Set(), filtered_edges:0, unresolved_edges:0, methods:new Set()
        };
        const target = id => policy.ecosystems.includes(eco(id));
        const refs = new Map(), unresolvedRefs = new Set();
        for (const c of all) {
            const parsed = splitPurl(c?.purl), kind = text(c?.type) ?? 'library';
            const excluded = c === json.metadata?.component && !policy.include_applications ? 'metadata-root'
                : kind === 'application' && !policy.include_applications ? 'application'
                : !['library','framework','application'].includes(kind) ? 'component-type'
                : !parsed ? 'invalid-purl' : null;
            const reference = (text(c?.['bom-ref']) ?? text(c?.purl))?.trim();
            let key = null, unresolved = false;
            if (excluded) result.excluded[excluded] = (result.excluded[excluded] || 0) + 1;
            else {
                const id = parsed.identity, type = eco(id);
                const declared = text(c?.version)?.trim() ? version(type,c.version.trim()) : null;
                const v = declared ?? parsed.version;
                if (policy.exclude_zero_versions && ['0.0.0','v0.0.0'].includes(v)) result.excluded['zero-version'] = (result.excluded['zero-version']||0)+1;
                else {
                    const status = declared !== null && !exactVersion(declared) || parsed.version !== null && !exactVersion(parsed.version) || property(c,'sbom:version:status') === 'unresolved' || v === null ? 'unresolved'
                        : declared !== null && parsed.version !== null && declared !== parsed.version ? 'inconsistent' : 'exact';
                    if (status === 'exact') key = `${id}@${encodePart(v)}`;
                    else { unresolved = true; result.unresolved_components++; }
                    if (status === 'inconsistent') { result.inconsistent_components++; result.diagnostics.add(`version-conflict:${id}`); }
                    const paths = locations(c), loc = paths[0] || null;
                    result.identities.add(id);
                    if (key) {
                        result.keys.add(key);
                        (result.versions[id] ||= new Set()).add(v);
                        if (target(key)) {
                            result.occurrences[key] = (result.occurrences[key]||0)+1;
                            if (!paths.length) result.missing_locations++;
                            for (const path of paths) { const scoped = JSON.stringify([key,path]); result.located_occurrences[scoped] = (result.located_occurrences[scoped]||0)+1; }
                        }
                    }
                    const method = property(c,'sbom:analysis:method');
                    if (method !== null && target(id)) result.methods.add(method);
                    const metadata = {...c}; delete metadata.components;
                    result.records.push({identity:id,key,version:v,status,location:loc,locations:paths,component:metadata});
                    result.total_components++;
                }
            }
            if (reference) {
                if (refs.has(reference)) result.duplicate_refs.add(reference);
                refs.set(reference,key);
                if (unresolved) unresolvedRefs.add(reference);
            }
        }
        for (const declaration of json.dependencies || []) {
            const parent = text(declaration?.ref)?.trim() || '';
            if (declaration && 'dependsOn' in declaration && !Array.isArray(declaration.dependsOn)) throw new Error('dependsOn 必须是数组');
            if (!refs.has(parent)) result.dangling_refs.add(parent);
            for (const childValue of declaration?.dependsOn || []) {
                const child = text(childValue)?.trim() || '';
                if (!refs.has(child)) result.dangling_refs.add(child);
                if (result.duplicate_refs.has(parent) || result.duplicate_refs.has(child) || !refs.has(parent) || !refs.has(child)) continue;
                if (unresolvedRefs.has(parent) || unresolvedRefs.has(child)) { result.unresolved_edges++; continue; }
                const from = refs.get(parent), to = refs.get(child);
                if (from && to && from !== to && target(from) && target(to)) result.edges.add(JSON.stringify([from,to]));
                else result.filtered_edges++;
            }
        }
        for (const key of ['diagnostics','keys','identities','edges','dangling_refs','duplicate_refs','methods']) result[key] = sorted(result[key]);
        for (const key of Object.keys(result.versions)) result.versions[key] = sorted(result.versions[key]);
        return result;
    }
    function comparePrepared(a,b,policy) {
        const target = id => policy.ecosystems.includes(eco(id));
        const ka = new Set(a.keys.filter(target)), kb = new Set(b.keys.filter(target));
        const ia = new Set(a.identities.filter(target)), ib = new Set(b.identities.filter(target));
        const version_differences = [], unknown_versions = new Set();
        const unknown = new Set([...a.records,...b.records].filter(r=>!r.key).map(r=>r.identity));
        for (const id of sorted(intersection(ia,ib))) {
            const va = new Set(a.versions[id]||[]), vb = new Set(b.versions[id]||[]);
            if (!va.size || !vb.size || unknown.has(id)) unknown_versions.add(id);
            if (va.size && vb.size && (va.size !== vb.size || difference(va,vb).size)) version_differences.push({identity:id,versions_a:sorted(va),versions_b:sorted(vb),only_a:sorted(difference(va,vb)),only_b:sorted(difference(vb,va))});
        }
        const warnings = [], ea = new Set(a.edges), eb = new Set(b.edges);
        const incompatibleGo = a.methods.includes('go-package-imports') && b.methods.includes('go-module-graph') || b.methods.includes('go-package-imports') && a.methods.includes('go-module-graph');
        if (incompatibleGo) warnings.push('Go 导入图与模块要求图口径不同，依赖边重合率为 N/A');
        if (!a.graph_available || !b.graph_available) warnings.push('至少一侧未提供 dependencies，依赖边重合率为 N/A');
        if (a.missing_locations || b.missing_locations) warnings.push('部分记录缺少来源路径，路径指标只覆盖有路径的记录；不推断物理实例');
        if (a.dangling_refs.length || b.dangling_refs.length || a.duplicate_refs.length || b.duplicate_refs.length) warnings.push('依赖图存在悬空或重复引用，相关边已跳过；图指标可能不完整');
        if (JSON.stringify(a.methods) !== JSON.stringify(b.methods)) warnings.push('两侧解析方法或依赖作用域可能不同，需要核对源码提交、开发依赖、平台与扫描参数');
        return {policy,a,b,exact:setMetrics(ka,kb),all_exact:setMetrics(new Set(a.keys),new Set(b.keys)),identity:setMetrics(ia,ib),occurrences:multisetMetrics(a.occurrences,b.occurrences),located_occurrences:multisetMetrics(a.located_occurrences,b.located_occurrences),graph:a.graph_available && b.graph_available && !incompatibleGo ? setMetrics(ea,eb) : null,
            common_keys:sorted(intersection(ka,kb)),only_keys_a:sorted(difference(ka,kb)),only_keys_b:sorted(difference(kb,ka)),only_identities_a:sorted(difference(ia,ib)),only_identities_b:sorted(difference(ib,ia)),version_differences,unknown_versions:sorted(unknown_versions),only_edges_a:sorted(difference(ea,eb)),only_edges_b:sorted(difference(eb,ea)),warnings};
    }
    function compare(jsonA,jsonB,options) {
        const policy = policyOptions(options);
        return comparePrepared(summarize(jsonA,policy),summarize(jsonB,policy),policy);
    }
    function compareThree(jsonA,jsonB,jsonC,options) {
        const policy = policyOptions(options), a = summarize(jsonA,policy), b = summarize(jsonB,policy);
        const c = jsonC ? summarize(jsonC,policy) : null;
        return {ab:comparePrepared(a,b,policy),ac:c ? comparePrepared(a,c,policy) : null,bc:c ? comparePrepared(b,c,policy) : null};
    }
    function classifySets(a,b,c = null) {
        const groups = {1:[],2:[],3:[],4:[],5:[],6:[],7:[]};
        for (const key of new Set([...a,...b,...(c || [])])) {
            const mask = (a.has(key) ? 1 : 0) | (b.has(key) ? 2 : 0) | (c?.has(key) ? 4 : 0);
            groups[mask].push(key);
        }
        return groups;
    }
    function ecosystemStats(components, ecosystems) {
        const stats = Object.fromEntries(ecosystems.map(e => [e,{records:0,unique:0}]));
        const sets = Object.fromEntries(ecosystems.map(e => [e,new Set()]));
        for (const component of components) {
            const key = normalizePurl(component.purl), type = eco(key);
            if (!key || !stats[type]) continue;
            stats[type].records++;
            sets[type].add(key);
        }
        for (const type of ecosystems) stats[type].unique = sets[type].size;
        return stats;
    }
    return {compare,compareThree,summarize,normalizePurl,splitPurl,exactVersion,classifySets,ecosystemStats,DEFAULT_ECOS};
});
