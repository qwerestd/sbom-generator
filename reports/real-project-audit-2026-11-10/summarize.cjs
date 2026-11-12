const fs=require('fs'),path=require('path');
const root=path.resolve(__dirname,'../..'), dest=path.join(root,'target/test_outputs/real-project-audit-2026-11-10');
const core=require(path.join(root,'ui/compare-core.js'));
const read=p=>JSON.parse(fs.readFileSync(p,'utf8'));
const projects=['juice-shop','microservices','opentelemetry','quickstarts'];
const output={};
for(const name of projects){
 const dir=path.join(dest,name), ev=read(path.join(dir,'source-evidence.json')), provenance=read(path.join(dir,'provenance.json'));
 const evidence=new Set(Object.keys(ev.evidence)), tools={}, sets={};
 for(const tool of ['ours','trivy-default','trivy-dev','syft-static','syft-static-dev']){
  const raw=read(path.join(dir,`current-${tool}.json`)), s=core.summarize(raw), keys=s.keys.filter(k=>core.DEFAULT_ECOS.includes(k.split('/')[0].slice(4)));
  sets[tool]=new Set(keys);
  const refs=new Set((raw.components||[]).map(c=>c['bom-ref']));if(raw.metadata?.component?.['bom-ref'])refs.add(raw.metadata.component['bom-ref']);
  tools[tool]={raw_components:raw.components.length,exact:keys.length,ecosystems:{},evidence_supported:keys.filter(k=>evidence.has(k)).length,evidence_total:evidence.size,evidence_missing:[...evidence].filter(k=>!sets[tool].has(k)),unsupported:keys.filter(k=>!evidence.has(k)),quality:{excluded:s.excluded,invalid_purls:s.excluded['invalid-purl']||0,duplicate_refs:s.duplicate_refs,dangling_refs:s.dangling_refs,unresolved:s.unresolved_components,conflicts:s.inconsistent_components},identity_count:s.identities.filter(k=>core.DEFAULT_ECOS.includes(k.split('/')[0].slice(4))).length};
  for(const eco of core.DEFAULT_ECOS)tools[tool].ecosystems[eco]=keys.filter(k=>k.startsWith('pkg:'+eco+'/')).length;
  tools[tool].external_exact=keys.filter(k=>!Object.hasOwn(ev.local_definitions,core.splitPurl(k).identity)).length; tools[tool].quality.duplicate_edge_targets=(raw.dependencies||[]).reduce((n,d)=>n+(d.dependsOn||[]).length-new Set(d.dependsOn||[]).size,0);
 }
 const comparisons={};
 for(const ref of ['trivy-default','trivy-dev','syft-static','syft-static-dev']){
  const a=sets.ours,b=sets[ref],onlyA=[...a].filter(k=>!b.has(k)),onlyB=[...b].filter(k=>!a.has(k));
  const compare=core.compare(read(path.join(dir,'current-ours.json')),read(path.join(dir,`current-${ref}.json`)));
  comparisons[ref]={exact:compare.exact,identity:compare.identity,only_ours:onlyA,only_ref:onlyB,only_ours_supported:onlyA.filter(k=>evidence.has(k)),only_ref_supported:onlyB.filter(k=>evidence.has(k)),version_differences:compare.version_differences,graph:compare.graph,warnings:compare.warnings};
 }
 output[name]={head:provenance.head,remote:provenance.remote,inputs_unchanged:provenance.inputs_unchanged,manifest_counts:ev.manifest_counts,manifest_head_status:ev.manifest_head_status,tools,comparisons,local_definitions:ev.local_definitions,source_evidence:ev.evidence,runs:provenance.runs};
}
fs.writeFileSync(path.join(__dirname,'metrics.json'),JSON.stringify(output,null,2));
for(const [name,p] of Object.entries(output)){
 console.log(name,JSON.stringify({manifests:p.manifest_counts,tools:Object.fromEntries(Object.entries(p.tools).map(([k,v])=>[k,{raw:v.raw_components,exact:v.exact,ecos:v.ecosystems,supported:v.evidence_supported,missing:v.evidence_missing.length,quality:v.quality}])),pairs:Object.fromEntries(Object.entries(p.comparisons).map(([k,v])=>[k,{common:v.exact.common,ours:v.only_ours.length,ref:v.only_ref.length,ours_supported:v.only_ours_supported.length,ref_supported:v.only_ref_supported.length,examplesA:v.only_ours.slice(0,6),examplesB:v.only_ref.slice(0,6)}]))}));
}

