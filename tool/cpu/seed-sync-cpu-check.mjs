// Local workerd CPU measurement of the REAL seed-sync HTTP route (rate-limit writes, device-session auth twice, JSON, service, real passkey step-up
// verification for enroll) against local D1. Synthetic data only, no network, no Cloudflare account. Client-side signing happens in Node, outside the measurement.
// Method: Miniflare (real workerd). Around each sequential request the driver reads the workerd process's per-thread CPU time (/proc/<pid>/task/*/schedstat,
// ns) and subtracts the mean CPU of an equally sized /ping request. Warm rows: N iterations in one isolate. Cold rows: the prelude runs in one workerd instance,
// which is disposed, then ONE request is measured in a fresh workerd instance on the same persisted D1 (raw CPU, no baseline subtraction, includes module load).
// This is workerd on THIS machine with local D1 (overcounted D1 work), not Cloudflare's metered CPU. Indication only, never a qualification.
// Usage: node tool/cpu/seed-sync-cpu-check.mjs [N=60] [SEEDS=1000] [COLD=3] [ONLY=regex of scenario names]
import {createRequire} from 'node:module';import {readdirSync,readFileSync,mkdtempSync,rmSync} from 'node:fs';import {execSync} from 'node:child_process';import {tmpdir} from 'node:os';import {join} from 'node:path';
import {seedSyncProofMessage} from '../../src/seed-sync-proof.js';import {base64urlEncode} from '../../src/tokens.js';import {authenticator} from '../../test/passkey-fixture.js';
import {writeFileSync,appendFileSync,mkdirSync} from 'node:fs';import {dirname} from 'node:path';
const require=createRequire(import.meta.url);const {Miniflare,convertV4MiniflareOptions}=require('miniflare');
const N=Number(process.argv[2]||60),SEEDS=Number(process.argv[3]||1000),COLD=Number(process.argv[4]??3),KEY=process.env.CPU_URL?process.env.QUALIFICATION_KEY:'cpu-qualification-key',OWNER='cpu_owner';
const esbuild=require('esbuild');const bundled=await esbuild.build({entryPoints:['tool/cpu/seed-sync-cpu-worker.mjs'],bundle:true,format:'esm',write:false,platform:'neutral',mainFields:['module','main'],conditions:['workerd','worker','import'],minify:false,logLevel:'error'});
const REMOTE=process.env.CPU_URL,RUN=process.env.CPU_RUN||String(Date.now()),COLD_PHASE=process.env.CPU_COLD,COLD_FILE=process.env.CPU_COLD_FILE||'qualification-evidence/cold-prep.jsonl';
// REMOTE (CPU_URL=https://otpanda-seedsync-cpu-qualification-<run>.<subdomain>.workers.dev): same scenarios against the deployed temporary Worker; CPU comes from the
// platform (tool/cpu/collect.mjs), not from this process. Every request carries ?run=&sc=&i= so invocations can be matched. CPU_COLD=prep|fire = cold-first-request protocol.
const dir=mkdtempSync(join(tmpdir(),'cpu-d1-'));
async function start(){
 if(REMOTE)return {mf:{dispatchFetch:(u,init)=>{const x=new URL(u);return fetch(REMOTE+x.pathname+x.search,{...init,signal:AbortSignal.timeout(30000)});},dispose:async()=>{}},cpu:()=>0};
 const mf=new Miniflare({...await convertV4MiniflareOptions({modules:true,script:bundled.outputFiles[0].text,compatibilityDate:'2026-11-23',d1Databases:['DB'],bindings:{CPU_KEY:KEY}}),resourcePersistencePath:dir});await mf.ready;
 const tree=execSync('ps -eo pid,ppid,comm').toString().trim().split('\n').slice(1).map(l=>l.trim().split(/\s+/));
 const kids=new Set([String(process.pid)]);let grew=true;while(grew){grew=false;for(const [p,pp] of tree)if(kids.has(pp)&&!kids.has(p)){kids.add(p);grew=true;}}
 const wd=tree.filter(([p,pp,c])=>kids.has(p)&&/workerd/.test(c)).map(x=>x[0]);if(!wd.length)throw new Error('workerd pid not found');
 const cpu=()=>{let t=0;for(const pid of wd)for(const th of readdirSync(`/proc/${pid}/task`)){try{t+=Number(readFileSync(`/proc/${pid}/task/${th}/schedstat`,'utf8').split(' ')[0]);}catch{}}return t;};
 return {mf,cpu};
}
let token,seq=0;
// D1 rows read/written as Cloudflare counts them (index rows included) come back from the worker in headers. Remote runs HARD-STOP when the running total reaches the budget.
const METER={r:0,w:0},WB=Number(process.env.CPU_WRITE_BUDGET),RB=Number(process.env.CPU_READ_BUDGET),CAL=process.env.CPU_CALIBRATE==='1',EVID='qualification-evidence/';
// Cumulative across every driver child of one wrapper run: the wrapper creates the ledger, each driver starts from it and rewrites it after every response. The caps below are on the cumulative total.
const LEDGER=REMOTE?process.env.CPU_LEDGER:null;
if(REMOTE){if(!LEDGER)throw new Error('CPU_LEDGER required for a remote run (run through run.mjs)');let l;try{l=JSON.parse(readFileSync(LEDGER,'utf8'));}catch{throw new Error('ledger missing or unreadable: usage unknown, not running');}
 if(l.unknown||!Number.isFinite(l.w)||!Number.isFinite(l.r)||l.w<0||l.r<0)throw new Error('ledger says usage unknown or invalid, not running');METER.w=l.w;METER.r=l.r;}
const BASE0={...METER};
const unknownUsage=(why,info={},cause='usage-unknown')=>{const rec={unknown:true,cause,w:METER.w,r:METER.r,why,...info}; // counted rows only, never an estimate for the lost request
 if(LEDGER)writeFileSync(LEDGER,JSON.stringify(rec));console.error('ABORT ('+cause+'): D1 usage unknown ('+why+'). Metered so far (no estimate added): written',METER.w,'read',METER.r,JSON.stringify(info));process.exit(cause==='cpu-limit-1102'?6:3);};
const CID=Date.now().toString(36),INV=REMOTE?process.env.CPU_INVENTORY:null;
// EVERY remote request carries ?run=&sc=&i=<child>.<seq> and is written to the inventory BEFORE it is sent, so the collector can require exactly that set of invocations (missing, duplicate or extra logs fail closed).
const post=async(w,origPath,body,hd={})=>{let r,path=origPath;if(REMOTE&&!path.includes('?'))path+='?run='+RUN+'&sc=helper&i='+CID+'.'+(++seq);
 if(REMOTE){if(!INV)throw new Error('CPU_INVENTORY required for a remote run');const q=new URLSearchParams(path.split('?')[1]);appendFileSync(INV,JSON.stringify({run:q.get('run'),sc:q.get('sc'),i:q.get('i')})+'\n');}
 const at=path.replace(/^\/route\//,'');try{r=await w.mf.dispatchFetch('http://w'+path,{method:'POST',headers:{'x-cpu-key':KEY,'content-type':'application/json',...hd},body:JSON.stringify(body)});}catch(e){if(REMOTE)unknownUsage('request failed or timed out',{call:at,run:RUN,index:seq});throw e;}
 const hr=r.headers.get('x-cpu-rows-r'),hw=r.headers.get('x-cpu-rows-w');
 if(REMOTE&&(hr===null||hw===null)){const t=await r.clone().text().catch(()=>'');const lim=/1102|exceeded resource limits|exceeded CPU/i.test(t); // the platform CPU-limit error page carries no worker headers; other causes (wrong URL, 5xx edge) look the same, so only the text decides the label
  unknownUsage('metering headers missing',{call:at,run:RUN,index:seq,status:r.status,textSnippet:t.slice(0,120)},lim?'cpu-limit-1102':'usage-unknown');}
 if(REMOTE&&!(/^[0-9]{1,12}$/.test(hr)&&/^[0-9]{1,12}$/.test(hw)))unknownUsage('metering headers invalid',{call:at,run:RUN,index:seq,status:r.status,hr,hw});
 METER.r+=Number(hr)||0;METER.w+=Number(hw)||0;
 if(REMOTE&&LEDGER)writeFileSync(LEDGER,JSON.stringify({w:METER.w,r:METER.r}));
 if(REMOTE&&(METER.w>=WB||METER.r>=RB)){console.error('ABORT: D1 row budget reached (cumulative over all drivers, written',METER.w,'of',WB,', read',METER.r,'of',RB,'). Stopping before the account-wide Free daily limit.');if(LEDGER)writeFileSync(LEDGER,JSON.stringify({w:METER.w,r:METER.r,cause:'budget-reached'}));process.exit(3);}
 return r;};
const j=async(w,path,body)=>{const r=await post(w,path,body),t=await r.text();try{return JSON.parse(t);}catch{throw new Error(path+' '+r.status+' '+t.slice(0,200));}};
const route=async(w,op,body,label='prelude')=>{const hd={authorization:'Bearer '+token,'x-cpu-addr':RUN+'-'+(++seq)};const a=w.cpu();const r=await post(w,'/route/'+op+'?run='+RUN+'&sc='+encodeURIComponent(label)+'&i='+CID+'.'+seq,body,hd);const text=await r.text();const ms=(w.cpu()-a)/1e6;let out;try{out=JSON.parse(text);}catch{out={raw:text.slice(0,80)};}return {ms,status:r.status,out};};
const kp=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']),raw=await crypto.subtle.exportKey('jwk',kp.publicKey),jwk={kty:raw.kty,crv:raw.crv,x:raw.x,y:raw.y};
const sign=async(k,p,c)=>base64urlEncode(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},k.privateKey,seedSyncProofMessage(p,c))));
const authn=authenticator();let counter=0;
if(REMOTE){
 if(!(WB>0)||!(RB>0))throw new Error('CPU_WRITE_BUDGET and CPU_READ_BUDGET (rows) are required for a remote run; they come from the live account headroom, never a default');
 if(CAL&&N>5)throw new Error('calibration uses N<=5');
 if(!CAL&&!COLD_PHASE){ // refuse to start when the calibrated projection does not fit the budget
  let cal,cp,cf;try{cal=JSON.parse(readFileSync(EVID+'calibration.json','utf8'));cp=JSON.parse(readFileSync(EVID+'cold-prep.rows.json','utf8'));cf=JSON.parse(readFileSync(EVID+'cold-fire.rows.json','utf8'));}catch{throw new Error('run calibration first (CPU_CALIBRATE=1 with one cold cycle): qualification-evidence/calibration.json and cold-*.rows.json missing');}
  if(cal.seeds!==SEEDS)throw new Error('calibration was for another seed count');
  if(cal.dirty||cal.commit!==execSync('git rev-parse HEAD').toString().trim()||execSync('git status --porcelain -- src migrations tool').toString().trim()!=='')throw new Error('stale calibration: source commit differs from the calibrated one (or the tree is dirty), recalibrate');
  if(cal.utcDay!==new Date().toISOString().slice(0,10)||Date.now()-Date.parse(cal.at)>6*3600e3)throw new Error('stale calibration: not from this UTC day or older than 6 h, recalibrate and reread the live headroom');
  const cycles=Number(process.env.CPU_COLD_CYCLES||5),iters=N+3,sum=k=>Object.values(cal.perIteration).reduce((a,x)=>a+x[k],0);
  const pw=cal.seedRows.w+sum('w')*iters+(cp.w+cf.w)*cycles,pr=cal.seedRows.r+sum('r')*iters+(cp.r+cf.r)*cycles;
  console.log('projected rows (calibrated, index rows included): written',Math.round(pw),'of budget',WB,', read',Math.round(pr),'of budget',RB);
  if(pw>WB||pr>RB)throw new Error('projection exceeds the budget, lower N or raise the budget with live headroom evidence');
 }
}
let W=await start();
const db=REMOTE?null:await W.mf.getD1Database('DB');
if(!REMOTE)for(const f of readdirSync('migrations').sort())for(const sql of readFileSync('migrations/'+f,'utf8').replace(/^--.*$/gm,'').split(/;(?=\s*(?:CREATE|ALTER|PRAGMA|$))/).map(s=>s.trim()).filter(Boolean))await db.prepare(sql).run();
console.log('preparing',SEEDS,'synthetic seeds ...');const t0=Date.now();
const seedM0={...METER};
// COLD FIRE must make NO request before its one target (a /prepare or /versions call would warm the fresh isolate): token and key id come from the manifest written by the pre-deploy prep phase.
let prep;if(COLD_PHASE==='fire'){const man=JSON.parse(readFileSync(COLD_FILE+'.manifest.json','utf8'));prep={token:man.token,keyId:man.keyId,ids:[]};token=man.token;}
else{prep=await j(W,'/prepare',{setup:true,jwk,cred:{id:authn.credential.id,cose:[...authn.credential.publicKey]}});token=prep.token;prep.ids=[];}
if(!COLD_PHASE)for(let i=0;i<SEEDS;i+=8){await j(W,'/prepare',{from:i,count:Math.min(8,SEEDS-i)});}for(let i=0;i<SEEDS;i++)prep.ids.push('cpu-entry-'+i);console.log('prepared in',Date.now()-t0,'ms');
const keyId=prep.keyId,versions=COLD_PHASE==='fire'?{}:Object.fromEntries((await j(W,'/versions',{})).map(r=>[r.entry_id,r.seed_version]));
const restore=w=>j(w,'/restore',{jwk});
const stat=a=>{a=[...a].sort((x,y)=>x-y);const q=p=>a[Math.min(a.length-1,Math.floor(p*a.length))];return {n:a.length,mean:+(a.reduce((s,x)=>s+x,0)/a.length).toFixed(2),p50:+q(.5).toFixed(2),p95:+q(.95).toFixed(2),p99:+q(.99).toFixed(2),max:+a[a.length-1].toFixed(2)};};
const batchBody=async K=>{const eph=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']),rawE=base64urlEncode(new Uint8Array(await crypto.subtle.exportKey('raw',eph.publicKey)));return {keyId,epoch:1,ephemeralKey:rawE,entries:prep.ids.slice(0,K).map(id=>({entryId:id,seedVersion:versions[id]}))};};
// Each scenario: prelude(w) does the earlier unmeasured steps and returns the one measured request {op,body,after?}.
const mk=(op,body)=>({op,body});
const SC={
 'snapshot-begin':async w=>mk('snapshot-begin',{keyId,epoch:1}),
 [`snapshot-finish (${SEEDS} entries)`]:async w=>{const c=(await route(w,'snapshot-begin',{keyId,epoch:1})).out;return mk('snapshot-finish',{token:c.token,signature:await sign(kp,'seed-sync-snapshot',c.challenge)});},
 'batch-begin K=1':async w=>mk('batch-begin',await batchBody(1)),
 'batch-finish K=1':async w=>{const c=(await route(w,'batch-begin',await batchBody(1))).out;return mk('batch-finish',{token:c.token,signature:await sign(kp,'seed-sync-batch',c.challenge)});},
 'batch-begin K=3':async w=>mk('batch-begin',await batchBody(3)),
 'batch-finish K=3':async w=>{const c=(await route(w,'batch-begin',await batchBody(3))).out;return mk('batch-finish',{token:c.token,signature:await sign(kp,'seed-sync-batch',c.challenge)});},
 'status-begin (no session)':async w=>mk('status-begin',{keyId}),
 'status-finish (no session)':async w=>{const c=(await route(w,'status-begin',{keyId})).out;return mk('status-finish',{token:c.token,signature:await sign(kp,'seed-sync-status',{keyId:c.challenge.keyId,challenge:c.challenge.challenge,expiresAt:c.challenge.expiresAt})});},
 'list':async w=>mk('list',{}),
 'revoke-begin':async w=>mk('revoke-begin',{keyId}),
 'revoke-finish':async w=>{const c=(await route(w,'revoke-begin',{keyId})).out;return mk('revoke-finish',{token:c.token,signature:await sign(kp,'seed-sync-revoke',c.challenge)});},
};
// enroll uses a fresh device key and real passkey assertion each time
const enrollPre=async w=>{const k=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']),r=await crypto.subtle.exportKey('jwk',k.publicKey),pj={kty:r.kty,crv:r.crv,x:r.x,y:r.y},install='e'.repeat(21)+String(seq%10),keyId=[...crypto.getRandomValues(new Uint8Array(16))].map(b=>b.toString(16).padStart(2,'0')).join('');return {k,pj,install,keyId};};
SC['enroll step-up begin']=async w=>{const e=await enrollPre(w);return mk('stepup-begin',{installId:e.install,keyId:e.keyId,publicJwk:e.pj});};
const enrollBeginBody=async w=>{const e=await enrollPre(w);const s=(await route(w,'stepup-begin',{installId:e.install,keyId:e.keyId,publicJwk:e.pj})).out;const response=authn.assertion({expected:s.options.challenge,counter:++counter});return {e,body:{installId:e.install,keyId:e.keyId,publicJwk:e.pj,response,token:s.token}};};
SC['enroll begin (real passkey verify)']=async w=>mk('enroll-begin',(await enrollBeginBody(w)).body);
SC['enroll finish (+notice outbox write)']=async w=>{const {e,body}=await enrollBeginBody(w);const c=(await route(w,'enroll-begin',body)).out;if(!c?.token)console.log('enroll-begin warn',JSON.stringify(c).slice(0,150));return mk('enroll-finish',{token:c.token,signature:await sign(e.k,'seed-sync-enroll',c.challenge)});};
for(const k of Object.keys(SC))if(process.argv[5]&&!new RegExp(process.argv[5]).test(k))delete SC[k];
if(REMOTE&&N>60&&!process.env.CPU_ALLOW_LARGE)throw new Error('N over 60 needs CPU_ALLOW_LARGE=1 plus live headroom evidence (Free D1 limits are per account per day)');
const seedRows={w:METER.w-seedM0.w,r:METER.r-seedM0.r};
const res={seeds:SEEDS,N,COLD,note:'workerd on this machine, local D1; not Cloudflare-metered'};
try{
 mkdirSync(EVID,{recursive:true});
 if(COLD_PHASE==='prep'){ // unmeasured: build every scenario's single measured request (begin challenges are created now, valid for 120 s), save them, then deploy a NEW version and run 'fire'
  mkdirSync(dirname(COLD_FILE),{recursive:true});writeFileSync(COLD_FILE,'');await restore(W);await j(W,'/reset',{});
  // 'enroll begin' last: its passkey counter must be the highest, a later prelude would raise the stored counter above it
  for(const [name,pre] of Object.entries(SC).sort((a,b)=>a[0].startsWith('enroll begin')-b[0].startsWith('enroll begin'))){const m=await pre(W);appendFileSync(COLD_FILE,JSON.stringify({name,...m})+'\n');}
  writeFileSync(COLD_FILE+'.manifest.json',JSON.stringify({token,keyId}));console.log('cold prep saved',Object.keys(SC).length,'requests to',COLD_FILE);writeFileSync(EVID+'cold-prep.rows.json',JSON.stringify({w:METER.w-BASE0.w,r:METER.r-BASE0.r}));await W.mf.dispose();rmSync(dir,{recursive:true,force:true});process.exit(0);
 }
 if(COLD_PHASE==='fire'){ // ONE explicit route per fresh version: only the first request a new deployment serves can be a cold start (the collector verifies the platform coldStart flag)
  const want=new RegExp(process.env.CPU_COLD_ROUTE||'^$'),rows=readFileSync(COLD_FILE,'utf8').trim().split('\n').map(l=>JSON.parse(l)).filter(m=>want.test(m.name));
  if(rows.length!==1)throw new Error('CPU_COLD_ROUTE must select exactly one prepared route, got '+rows.length);
  for(const m of rows){const r=await route(W,m.op,m.body,'cold-first:'+m.name);console.log('cold-first',m.name,r.status);}
  writeFileSync(EVID+'cold-fire.rows.json',JSON.stringify({w:METER.w-BASE0.w,r:METER.r-BASE0.r}));
  await W.mf.dispose();rmSync(dir,{recursive:true,force:true});process.exit(0);
 }
 // baseline: /ping of equal size
 const sample=JSON.stringify({token:'x'.repeat(60),signature:'y'.repeat(86)});
 const ping=async w=>{const a=w.cpu();await (await w.mf.dispatchFetch('http://w/ping',{method:'POST',headers:{'x-cpu-key':KEY},body:sample})).text();return (w.cpu()-a)/1e6;};
 let b=0;if(!REMOTE){for(let i=0;i<10;i++)await ping(W);
 const base=[];for(let i=0;i<N;i++)base.push(await ping(W));b=base.reduce((s,x)=>s+x,0)/base.length;res.baselinePingMsMean=+b.toFixed(2);}
 // warm rows
 const warm={};const bad={};
 for(const [name,pre] of Object.entries(SC)){
  warm[name]=[];await restore(W);const m0={...METER};
  for(let i=0;i<N+3;i++){
   if(name.startsWith('revoke')||name.startsWith('enroll')){await restore(W);}else await j(W,'/reset',{});
   const m=await pre(W);const r=await route(W,m.op,m.body,'warm:'+name);if(r.status!==200){bad[name]=(bad[name]??0)+1;if(!bad.sample)bad.sample={name,status:r.status,out:JSON.stringify(r.out).slice(0,100)};}
   if(i>2)warm[name].push(Math.max(0,r.ms-b));
  }
  await restore(W);(res.d1RowsPerIteration??={})[name]={w:+((METER.w-m0.w)/(N+3)).toFixed(1),r:+((METER.r-m0.r)/(N+3)).toFixed(1)};
 }
 res.warmMsAboveBaseline=Object.fromEntries(Object.entries(warm).map(([k,v])=>[k,stat(v)]));res.nonOkResponses=bad;if(REMOTE){delete res.warmMsAboveBaseline;res.note='CPU is measured by the platform; run tool/cpu/collect.mjs with this CPU_RUN';res.run=RUN;}
 // cold rows: prelude in instance A, measured request in a fresh instance B on the same persisted D1
 if(COLD>0&&!REMOTE){
  const cold={};
  for(const [name,pre] of Object.entries(SC)){
   cold[name]=[];
   for(let i=0;i<COLD;i++){
    await restore(W);await j(W,'/reset',{});
    const m=await pre(W);await W.mf.dispose();
    W=await start();const r=await route(W,m.op,m.body,'localcold:'+name);if(r.status!==200)(bad['cold '+name]=(bad['cold '+name]??0)+1);cold[name].push(r.ms);
   }
  }
  // cold /ping for reference
  const cp=[];for(let i=0;i<COLD;i++){await W.mf.dispose();W=await start();cp.push(await ping(W));}
  res.coldRawMs=Object.fromEntries(Object.entries(cold).map(([k,v])=>[k,{n:v.length,min:+Math.min(...v).toFixed(2),max:+Math.max(...v).toFixed(2),values:v.map(x=>+x.toFixed(2))}]));res.coldPingRawMs=cp.map(x=>+x.toFixed(2));
 }
 res.rowsTotal={...METER};
 if(CAL){mkdirSync(EVID,{recursive:true});writeFileSync(EVID+'calibration.json',JSON.stringify({seeds:SEEDS,N,seedRows,perIteration:res.d1RowsPerIteration,commit:execSync('git rev-parse HEAD').toString().trim(),dirty:execSync('git status --porcelain -- src migrations tool').toString().trim()!=='',run:RUN,utcDay:new Date().toISOString().slice(0,10),at:new Date().toISOString()}));}
 console.log(JSON.stringify(res,null,1));
}finally{await W.mf.dispose();rmSync(dir,{recursive:true,force:true});}
