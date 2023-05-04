import test from 'node:test';
import assert from 'node:assert/strict';
import { auditBaseline, TOOL_ID, LIMITS, RULES } from '../src/index.mjs';
import { runCli } from '../src/cli.mjs';
import { mkdtempSync, writeFileSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const policy={schemaVersion:'1',asOf:'2026-09-26T00:00:00Z'};
const finding={fingerprint:'a'.repeat(64),ruleId:'synthetic-pattern',file:'src/example.txt',line:12};
const scanner={schemaVersion:'1',complete:true,scannedFiles:3,findings:[finding]};
const entry={...finding,owner:'team-a',reason:'synthetic test waiver',expiresAt:'2026-10-01T00:00:00Z'};
const baseline={schemaVersion:'1',complete:true,entries:[entry]};
const audit=(s=scanner,b=baseline,p=policy)=>auditBaseline(s,b,p);

test('exact approved synthetic fingerprint, rule and location passes without echoing values',()=>{
  const report=audit();assert.equal(TOOL_ID,'secret-scan-baseline-manager');assert.equal(report.status,'pass');assert.equal(report.summary.checked,3);
  assert.equal(JSON.stringify(report).includes(finding.fingerprint),false);assert.equal(JSON.stringify(report).includes(finding.file),false);
});

test('new location with same fingerprint is not suppressed by broad baseline',()=>{
  const newLocation={...finding,file:'src/new-place.txt'};
  const report=audit({...scanner,findings:[finding,newLocation]});
  assert.equal(report.status,'fail');assert.ok(report.findings.some(f=>f.ruleId==='new-finding'&&f.location.file==='@scanner'&&f.location.pointer==='/findings/1'));
  assert.equal(JSON.stringify(report).includes('new-place'),false);
});

test('expired exception and missing owner fail',()=>{
  const expired=audit(scanner,{...baseline,entries:[{...entry,expiresAt:'2026-09-26T00:00:00Z'}]});
  assert.equal(expired.status,'fail');assert.ok(expired.findings.some(f=>f.ruleId==='exception-expired'));
  const noOwner=audit(scanner,{...baseline,entries:[{...entry,owner:''}]});
  assert.equal(noOwner.status,'fail');assert.ok(noOwner.findings.some(f=>f.ruleId==='approval-owner-missing'));
});

test('partial scanner or baseline and malformed evidence cannot pass; clean scan needs coverage',()=>{
  assert.equal(audit({...scanner,complete:false}).status,'incomplete');
  assert.equal(audit(scanner,{...baseline,complete:false}).status,'incomplete');
  const rejected=audit({...scanner,findings:[{...finding,rawMatch:'CANARY_NOT_A_SECRET_123'}]});
  assert.equal(rejected.status,'incomplete');assert.equal(JSON.stringify(rejected).includes('CANARY_NOT_A_SECRET_123'),false);
  assert.equal(audit({...scanner,scannedFiles:0,findings:[]},{...baseline,entries:[]}).status,'incomplete');
  assert.equal(audit({...scanner,findings:[]},{...baseline,entries:[]}).status,'pass');
});

test('finding and entry N/N+1, depth N/N+1 and injected deadline',()=>{
  const findings=n=>({...scanner,findings:Array.from({length:n},(_,i)=>({...finding,line:i+1}))});
  assert.equal(audit(findings(LIMITS.findings),{...baseline,entries:[]}).findings.some(f=>f.ruleId==='limit-exceeded'),false);
  assert.ok(audit(findings(LIMITS.findings+1),baseline).findings.some(f=>f.ruleId==='limit-exceeded'));
  const entries=n=>({...baseline,entries:Array.from({length:n},(_,i)=>({...entry,line:i+1}))});
  assert.equal(audit({...scanner,findings:[]},entries(LIMITS.entries)).findings.some(f=>f.ruleId==='limit-exceeded'),false);
  assert.ok(audit(scanner,entries(LIMITS.entries+1)).findings.some(f=>f.ruleId==='limit-exceeded'));
  const deep=n=>{const d=structuredClone(scanner);let x=d;for(let i=0;i<n;i++){x.extra={};x=x.extra;}return d;};
  assert.equal(audit(deep(16)).findings.some(f=>f.ruleId==='limit-exceeded'),false);
  assert.ok(audit(deep(17)).findings.some(f=>f.ruleId==='limit-exceeded'));
  assert.equal(auditBaseline(scanner,baseline,policy,{now:()=>5000,deadline:5000}).status,'pass');
  assert.equal(auditBaseline(scanner,baseline,policy,{now:()=>5001,deadline:5000}).status,'incomplete');
});

test('CLI confines reads, rejects escaped duplicate keys, and enforces byte N/N+1',()=>{
  const root=mkdtempSync(join(tmpdir(),'baseline-')),outside=mkdtempSync(join(tmpdir(),'baseline-out-'));
  const args=['--root',root,'--policy','policy.json','--scanner','scanner.json','--baseline','baseline.json'];
  const capture=()=>{let stdout='',stderr='';return{io:{stdout:{write:s=>{stdout+=s;}},stderr:{write:s=>{stderr+=s;}}},get stdout(){return stdout;},get stderr(){return stderr;}};};
  try{const base={'policy.json':JSON.stringify(policy),'scanner.json':JSON.stringify(scanner),'baseline.json':JSON.stringify(baseline)};for(const [name,raw] of Object.entries(base))writeFileSync(join(root,name),raw);
    let o=capture();assert.equal(runCli(args,o.io),0);assert.equal(JSON.parse(o.stdout).status,'pass');
    writeFileSync(join(root,'baseline.json'),base['baseline.json'].replace('"complete":true','"compl\\u0065te":false,"complete":true'));
    o=capture();assert.equal(runCli(args,o.io),2);assert.equal(JSON.parse(o.stdout).status,'incomplete');
    writeFileSync(join(outside,'baseline.json'),base['baseline.json']);symlinkSync(join(outside,'baseline.json'),join(root,'linked.json'));
    o=capture();assert.equal(runCli(['--root',root,'--policy','policy.json','--scanner','scanner.json','--baseline','linked.json'],o.io),2);assert.equal(o.stdout,'');
    o=capture();assert.equal(runCli(['--root',join(root,'policy.json'),'--policy','policy.json','--scanner','scanner.json','--baseline','baseline.json'],o.io),2);assert.equal(o.stdout,'');
    for(const [file,limit] of [['policy.json',LIMITS.policyBytes],['scanner.json',LIMITS.scannerBytes],['baseline.json',LIMITS.baselineBytes]])for(const delta of [0,1]){for(const [name,raw] of Object.entries(base))writeFileSync(join(root,name),raw);const raw=base[file];writeFileSync(join(root,file),raw+' '.repeat(limit+delta-Buffer.byteLength(raw)));o=capture();runCli(args,o.io);if(file==='policy.json')assert.equal(o.stdout==='',delta===1);else assert.equal(JSON.parse(o.stdout).findings.some(f=>f.ruleId==='limit-exceeded'),delta===1);}
  }finally{rmSync(root,{recursive:true,force:true});rmSync(outside,{recursive:true,force:true});}
});

test('severity map is pinned',()=>{assert.deepEqual(RULES,{'policy-invalid':'warning','scanner-invalid':'warning','baseline-invalid':'warning','export-incomplete':'warning','scan-empty':'warning','limit-exceeded':'warning','input-unreadable':'warning','new-finding':'error','exception-expired':'error','approval-owner-missing':'error','approval-reason-missing':'error','stale-baseline':'error'});});
