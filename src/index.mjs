export const TOOL_ID='secret-scan-baseline-manager';
export const LIMITS=Object.freeze({policyBytes:65536,scannerBytes:1048576,baselineBytes:1048576,findings:10000,entries:10000,depth:16,milliseconds:5000});
export const RULES=Object.freeze({'policy-invalid':'warning','scanner-invalid':'warning','baseline-invalid':'warning','export-incomplete':'warning','scan-empty':'warning','limit-exceeded':'warning','input-unreadable':'warning','new-finding':'error','exception-expired':'error','approval-owner-missing':'error','approval-reason-missing':'error','stale-baseline':'error'});
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const only=(x,keys)=>Object.keys(x).every(k=>keys.includes(k));
const cmp=(a,b)=>a<b?-1:a>b?1:0;
const slug=x=>typeof x==='string'&&/^[a-z][a-z0-9-]{0,127}$/.test(x);
const file=x=>typeof x==='string'&&x.length>0&&x.length<=512&&!x.startsWith('/')&&!x.split('/').some(p=>p===''||p==='.'||p==='..')&&!/[\u0000-\u001f\u007f-\u009f\\\u200e\u200f\u202a-\u202e\u2066-\u2069]/u.test(x);
const reason=x=>typeof x==='string'&&x.trim().length>0&&x.length<=256&&!/[\u0000-\u001f\u007f-\u009f\u2028\u2029\p{Cf}]/u.test(x);
const instant=x=>typeof x==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(x)&&Number.isFinite(Date.parse(x))&&new Date(x).toISOString().slice(0,19)===x.slice(0,19);
const identity=x=>obj(x)&&/^[0-9a-f]{64}$/.test(x.fingerprint)&&slug(x.ruleId)&&file(x.file)&&Number.isSafeInteger(x.line)&&x.line>=1;
const scope=x=>`${x.fingerprint}\0${x.ruleId}\0${x.file}\0${x.line}`;
function depth(x){const stack=[[x,0,new Set()]];while(stack.length){const[v,n,a]=stack.pop();if(n>LIMITS.depth)return n;if(v&&typeof v==='object'){if(a.has(v))return LIMITS.depth+1;const next=new Set(a);next.add(v);for(const c of Object.values(v))stack.push([c,n+1,next]);}}return 0;}
export function validPolicy(p){return obj(p)&&only(p,['schemaVersion','asOf'])&&p.schemaVersion==='1'&&instant(p.asOf);}
export function auditBaseline(scanner,baseline,policy,{now=Date.now,deadline=now()+LIMITS.milliseconds}={}){
  const findings=[];
  const add=(ruleId,fileRole,pointer,message)=>{if(!Object.hasOwn(RULES,ruleId))throw new Error('Unknown rule');findings.push({ruleId,severity:RULES[ruleId],message,location:{file:fileRole,pointer}});};
  const finish=checked=>{findings.sort((a,b)=>cmp(a.location.file,b.location.file)||cmp(a.location.pointer,b.location.pointer)||cmp(a.ruleId,b.ruleId));return{schemaVersion:'1',tool:TOOL_ID,status:findings.some(f=>f.severity==='warning')?'incomplete':findings.length?'fail':checked?'pass':'incomplete',summary:{checked,errors:findings.filter(f=>f.severity==='error').length,warnings:findings.filter(f=>f.severity==='warning').length},findings};};
  if(!validPolicy(policy)){add('policy-invalid','@policy','','Baseline policy is invalid.');return finish(0);}
  if(depth(scanner)>LIMITS.depth){add('limit-exceeded','@scanner','','Scanner export JSON depth limit exceeded.');return finish(0);}
  if(depth(baseline)>LIMITS.depth){add('limit-exceeded','@baseline','','Baseline JSON depth limit exceeded.');return finish(0);}
  if(!obj(scanner)||!only(scanner,['schemaVersion','complete','scannedFiles','findings'])||scanner.schemaVersion!=='1'||typeof scanner.complete!=='boolean'||!Number.isSafeInteger(scanner.scannedFiles)||scanner.scannedFiles<0||!Array.isArray(scanner.findings)){add('scanner-invalid','@scanner','','Scanner export shape is invalid.');return finish(0);}
  if(!obj(baseline)||!only(baseline,['schemaVersion','complete','entries'])||baseline.schemaVersion!=='1'||typeof baseline.complete!=='boolean'||!Array.isArray(baseline.entries)){add('baseline-invalid','@baseline','','Baseline export shape is invalid.');return finish(0);}
  if(scanner.findings.length>LIMITS.findings){add('limit-exceeded','@scanner','/findings','Scanner finding limit exceeded.');return finish(0);}
  if(baseline.entries.length>LIMITS.entries){add('limit-exceeded','@baseline','/entries','Baseline entry limit exceeded.');return finish(0);}
  if(!scanner.complete)add('export-incomplete','@scanner','/complete','Scanner export declares partial coverage.');
  if(!baseline.complete)add('export-incomplete','@baseline','/complete','Baseline export declares partial coverage.');
  if(!scanner.scannedFiles)add('scan-empty','@scanner','/scannedFiles','Scanner export reports no scanned files.');
  const approvals=new Map(),approvalPositions=new Map();
  for(let i=0;i<baseline.entries.length;i++){
    if(now()>deadline){add('limit-exceeded','@baseline','','Evaluation deadline exceeded.');return finish(0);}
    const e=baseline.entries[i],at=`/entries/${i}`;
    if(!identity(e)||!only(e,['fingerprint','ruleId','file','line','owner','reason','expiresAt'])||!instant(e.expiresAt)){add('baseline-invalid','@baseline',at,'Baseline identity, scope, or expiry is invalid.');continue;}
    const key=scope(e);
    if(approvals.has(key)){add('baseline-invalid','@baseline',at,'Exact baseline scope is duplicated.');continue;}
    approvals.set(key,e);approvalPositions.set(key,i);
    if(!slug(e.owner))add('approval-owner-missing','@baseline',`${at}/owner`,'Approval owner is missing or unusable.');
    if(!reason(e.reason))add('approval-reason-missing','@baseline',`${at}/reason`,'Approval reason is missing or unusable.');
  }
  const observed=new Set();
  for(let i=0;i<scanner.findings.length;i++){
    if(now()>deadline){add('limit-exceeded','@scanner','','Evaluation deadline exceeded.');return finish(scanner.scannedFiles);}
    const f=scanner.findings[i],at=`/findings/${i}`;
    if(!identity(f)||!only(f,['fingerprint','ruleId','file','line'])){add('scanner-invalid','@scanner',at,'Scanner finding identity or location is invalid.');continue;}
    const key=scope(f);
    if(observed.has(key)){add('scanner-invalid','@scanner',at,'Scanner finding scope is duplicated.');continue;}
    observed.add(key);
    const e=approvals.get(key);
    if(!e){add('new-finding','@scanner',at,'Finding has no exact scoped baseline approval.');continue;}
    if(Date.parse(e.expiresAt)<=Date.parse(policy.asOf))add('exception-expired','@baseline',`/entries/${approvalPositions.get(key)}/expiresAt`,'Exact scoped approval has expired.');
  }
  if(scanner.complete)for(const [key,i] of approvalPositions)if(!observed.has(key))add('stale-baseline','@baseline',`/entries/${i}`,'Baseline scope is absent from complete scanner results.');
  return finish(scanner.scannedFiles);
}
