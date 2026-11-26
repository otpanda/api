import test from 'node:test';import assert from 'node:assert/strict';
import {database} from './sqlite-helper.js';import {SourceEntryStore} from '../src/source-entries.js';import {EntryAccess} from '../src/entry-access.js';import {CodeCipher} from '../src/code-cipher.js';import {SeedCipher} from '../src/seed-cipher.js';import {TotpSeedStore,EntryTotpGenerator} from '../src/totp-seeds.js';import {createCommonHorizonBatchHttp} from '../src/totp-common-batch-http.js';import {validateResponse,responsePolicy} from '../src/common-horizon-response-policy.js';import {finalizeCommonHorizon} from '../src/common-horizon-finalizer.js';import {totp,totpWindow} from '../src/totp.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',SECRET=new TextEncoder().encode('12345678901234567890');
async function fixture(periods=[30]){const db=database();let now=59000;for(const owner of ['owner','recipient','stranger'])await db.prepare('INSERT INTO accounts VALUES (?,?)').bind(owner,0).run();const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']),keys=new Map([['synthetic',key]]),sources=new SourceEntryStore(db,new CodeCipher({keys,activeKeyId:'synthetic'})),access=new EntryAccess(db,sources),seeds=new TotpSeedStore(db,new SeedCipher({keys,activeKeyId:'synthetic'})),generator=new EntryTotpGenerator(db,seeds,access);const ids=[];for(const [i,period] of periods.entries()){const entry=await sources.createEntry('owner','test','Synthetic'+i,0);await seeds.putSeed('owner',entry,{secret:SECRET,algorithm:'SHA-1',digits:i%2?7:8,period},0);ids.push(entry);}
 let actor={ownerId:'owner',deviceId:'web-device',generation:1,clientKind:'web',expiresAt:999999};const sessions={async authenticate(token){return token==='access'?actor:undefined;}};const horizonPolicy={entryCap:5,budget:20,minPeriod:20,maxPeriod:86400,maxWindow:600,minUsefulWindow:40};const http=createCommonHorizonBatchHttp({db,sessions,generator,clock:()=>now,horizonPolicy,ratePerMinute:24,minRemainingMs:1000});
 const run=(q,options={},meta={clientAddress:'trusted'})=>http.fetch(new Request(API+'/v1/manage/totp-codes'+q,{...options,headers:{Origin:APP,Authorization:'Bearer access',...options.headers}}),meta);const qs=(list,extra='')=>'?'+list.map(e=>'entry='+e).join('&')+extra;
 return{db,seeds,generator,access,sessions,ids,run,qs,setNow:v=>now=v,setActor:v=>actor=v,getActor:()=>actor};}
const close=f=>f.db.sqlite.close();

test('real HTTP decrypt/generate/finalize response validates on shared client7policy',async()=>{const f=await fixture([20,30,60]);try{const r=await f.run(f.qs(f.ids));assert.equal(r.status,200);const b=await r.json();const policy=responsePolicy({minPeriod:20,maxPeriod:86400,digits:[6,7,8],maxCodesPerEntry:31,budget:20});assert.equal(validateResponse(b,f.ids,policy),true);assert.equal(b.entries[1].digits,7);assert.ok(b.coverageUntil<659000);assert.ok(b.totalCodes<=20);assert.equal(b.windowExpiresAt,undefined);assert.equal(r.headers.get('cache-control'),'no-store');}finally{close(f);}});
test('warm response-time clock trims current code and expires whole response at horizon',async()=>{const f=await fixture([30]);try{await f.run(f.qs(f.ids));const gen=f.generator.generateWindowForActor.bind(f.generator);f.generator.generateWindowForActor=async(...args)=>{const r=await gen(...args);f.setNow(60000);return r;};let r=await f.run(f.qs(f.ids));assert.equal(r.status,200);let b=await r.json();assert.equal(b.serverNow,60000);assert.equal(b.entries[0].validFrom,60);f.setNow(59000);f.generator.generateWindowForActor=async(...args)=>{const r=await gen(...args);f.setNow(r.coverageUntil);return r;};r=await f.run(f.qs(f.ids));assert.equal(r.status,503);assert.deepEqual(await r.json(),{error:'unavailable'});}finally{close(f);}});
test('session changed during generator never returns codes; explicit empty coverage stays null',async()=>{const f=await fixture([19]);try{let r=await f.run(f.qs(f.ids));let b=await r.json();assert.equal(b.coverageUntil,null);assert.equal(b.totalCodes,0);assert.equal(b.entries.length,0);const gen=f.generator.generateWindowForActor.bind(f.generator);f.generator.generateWindowForActor=async(...args)=>{const result=await gen(...args);f.setActor(undefined);return result;};r=await f.run(f.qs(f.ids));assert.equal(r.status,401);}finally{close(f);}});

test('strict route boundary and rate deny before auth, no numeric default activation',async()=>{const f=await fixture([30]);try{
 for(const q of ['','?entry=a&entry=a','?entry=','?entry='+encodeURIComponent('a b'),'?entry=a&unknown=1','?entry=a&window=0',f.qs(Array(6).fill(0).map((_,i)=>'id'+i))])assert.equal((await f.run(q)).status,400);
 assert.equal((await f.run(f.qs(f.ids),{headers:{Origin:'https://other.test'}})).status,403);
 assert.equal((await f.run(f.qs(f.ids),{headers:{Authorization:''}})).status,401);
 let auth=0;const authenticate=f.sessions.authenticate;f.sessions.authenticate=async(...a)=>{auth++;return authenticate(...a)};
 for(let i=0;i<23;i++)await f.run(f.qs(f.ids));
 const before=auth,r=await f.run(f.qs(f.ids));assert.equal(r.status,429);assert.equal(auth,before);assert.ok(Number(r.headers.get('retry-after'))>0);
 const deps={db:f.db,sessions:f.sessions,generator:f.generator,ratePerMinute:24,minRemainingMs:1000};
 assert.throws(()=>createCommonHorizonBatchHttp(deps));
 assert.throws(()=>createCommonHorizonBatchHttp({...deps,horizonPolicy:{entryCap:2,budget:100,minPeriod:20,maxPeriod:86400,maxWindow:601,minUsefulWindow:40}}),/bounds/);
 assert.throws(()=>createCommonHorizonBatchHttp({...deps,horizonPolicy:{entryCap:2,budget:100,minPeriod:1,maxPeriod:86400,maxWindow:600,minUsefulWindow:40}}),/bounds/);
 }finally{close(f);}});

test('D1 constructor boundary and preflight use injected bounds',async()=>{const f=await fixture();try{const deps={db:f.db,sessions:f.sessions,generator:f.generator,ratePerMinute:24,minRemainingMs:1000},p={entryCap:49,budget:200,minPeriod:20,maxPeriod:86400,maxWindow:600,minUsefulWindow:40};assert.ok(createCommonHorizonBatchHttp({...deps,horizonPolicy:p}));assert.throws(()=>createCommonHorizonBatchHttp({...deps,horizonPolicy:{...p,entryCap:50}}),/D1/);for(const q of ['?entry='+('x'.repeat(65)),'?entry=a&window=abc',f.qs(Array.from({length:6},(_,i)=>'id'+i))]){assert.equal((await f.run(q)).status,400);assert.equal((await f.run(q,{method:'OPTIONS',headers:{'Access-Control-Request-Method':'GET'}})).status,403);}}finally{close(f);}});
test('native batch requires explicit activation and exact Android access kind; web keeps Origin binding',async()=>{const f=await fixture();try{const http=createCommonHorizonBatchHttp({db:f.db,sessions:f.sessions,generator:f.generator,clock:()=>59000,horizonPolicy:{entryCap:1,budget:32,minPeriod:20,maxPeriod:86400,maxWindow:600,minUsefulWindow:60},ratePerMinute:24,minRemainingMs:1000,native:true});const run=()=>http.fetch(new Request(API+'/v1/manage/totp-codes'+f.qs(f.ids),{headers:{Authorization:'Bearer access'}}),{clientAddress:'trusted'});assert.equal((await run()).status,401);f.setActor({...f.getActor(),clientKind:'android'});assert.equal((await run()).status,200);assert.equal((await f.run(f.qs(f.ids))).status,401);}finally{close(f);}});
test('first successful batch gives current code for every account and later batch expands future horizon',async()=>{const f=await fixture([20,30,60]);try{const a=await(await f.run(f.qs(f.ids))).json();assert.equal(a.entries.length,3);assert.equal(a.totalCodes,3);assert.ok(a.entries.every(e=>e.codes.length===1));const b=await(await f.run(f.qs(f.ids))).json();assert.ok(b.totalCodes>3);assert.ok(b.coverageUntil>a.coverageUntil);}finally{close(f);}});
test('concurrent first-use and failed first-use stay conservative; near-boundary current codes do not require long coverage',async()=>{const f=await fixture([30,60]);try{const original=f.generator.generateWindowForActor.bind(f.generator);let release;const gate=new Promise(r=>release=r),budgets=[];f.generator.generateWindowForActor=async(...a)=>{budgets.push(a[3].horizonPolicy.budget);await gate;return original(...a);};const pending=[f.run(f.qs(f.ids)),f.run(f.qs(f.ids))];await new Promise(r=>setTimeout(r,5));release();for(const p of pending){const b=await(await p).json();assert.equal(b.totalCodes,2);}assert.deepEqual(budgets,[2,2]);}finally{close(f);}const g=await fixture([30]);try{g.setNow(59999);const original=g.generator.generateWindowForActor.bind(g.generator);let fail=true;g.generator.generateWindowForActor=async(...a)=>{if(fail){fail=false;throw Error('fixture');}return original(...a);};assert.equal((await g.run(g.qs(g.ids))).status,503);const r=await g.run(g.qs(g.ids));assert.equal(r.status,200);const b=await r.json();assert.equal(b.totalCodes,1);assert.equal(b.coverageUntil-b.serverNow,1);}finally{close(g);}});

test('requester-chosen start: from=30 returns the codes that follow now, identical to asking at that time, and validates with the offset',async()=>{const f=await fixture([30]);try{
 f.setNow(89000);const later=await(await f.run(f.qs(f.ids))).json();
 const fresh=await fixture([30]);try{
  await fresh.run(fresh.qs(fresh.ids));// warm: not first use
  fresh.setNow(59000);const r=await fresh.run(fresh.qs(fresh.ids,'&from=30'));assert.equal(r.status,200);const b=await r.json();
  assert.equal(b.serverNow,59000);assert.equal(b.entries[0].validFrom,60,'first code is the period containing now+30 s');
  assert.ok(b.entries[0].validFrom*1000>b.serverNow,'does not include the code already held');
  const policy=responsePolicy({minPeriod:20,maxPeriod:86400,digits:[6,7,8],maxCodesPerEntry:31,budget:20});
  assert.equal(validateResponse(b,fresh.ids,policy,{startOffsetMs:30000}),true);
  assert.equal(validateResponse(b,fresh.ids,policy),false,'plain current-code validation rejects a future-start response');
  assert.equal(b.entries[0].codes[0],later.entries[0].codes[0]);
 }finally{close(fresh);}
}finally{close(f);}});
test('from=0 and no from are the same response; from=60 is the maximum',async()=>{const f=await fixture([30]);try{
 await f.run(f.qs(f.ids));const a=await(await f.run(f.qs(f.ids))).json(),b=await(await f.run(f.qs(f.ids,'&from=0'))).json();assert.deepEqual(a,b);
 assert.equal((await f.run(f.qs(f.ids,'&from=60'))).status,200);
}finally{close(f);}});
test('from is strict: out of range, malformed or repeated is rejected before auth and rate',async()=>{const f=await fixture([30]);try{
 let auth=0;const authenticate=f.sessions.authenticate;f.sessions.authenticate=async(...a)=>{auth++;return authenticate(...a)};
 for(const x of ['&from=61','&from=100','&from=-1','&from=1.5','&from=abc','&from=','&from=1&from=2','&from=001'])assert.equal((await f.run(f.qs(f.ids,x))).status,400,x);
 assert.equal(auth,0);
}finally{close(f);}});
test('cold first use with from keeps the minimal work bound: one code per entry',async()=>{const f=await fixture([30,60]);try{
 const b=await(await f.run(f.qs(f.ids,'&from=30'))).json();assert.equal(b.entries.length,2);for(const e of b.entries)assert.equal(e.codes.length,1);assert.ok(b.totalCodes<=2);
}finally{close(f);}});
test('from keeps authorization revalidation: a session change during generation returns no codes',async()=>{const f=await fixture([30]);try{
 await f.run(f.qs(f.ids));const gen=f.generator.generateWindowForActor.bind(f.generator);
 f.generator.generateWindowForActor=async(...a)=>{const r=await gen(...a);f.setActor({...f.getActor(),generation:2});return r;};
 const r=await f.run(f.qs(f.ids,'&from=30'));assert.equal(r.status,401);assert.equal((await r.text()).includes('codes'),false);
}finally{close(f);}});
test('generator rejects an out-of-range start offset and a stranger still gets nothing with from',async()=>{const f=await fixture([30]);try{
 await assert.rejects(f.generator.generateWindowForActor('owner',f.ids,59,{windowSeconds:60,startOffsetSeconds:61}),/start offset/);
 await assert.rejects(f.generator.generateWindowForActor('owner',f.ids,59,{windowSeconds:60,startOffsetSeconds:-1}),/start offset/);
 const r=await f.generator.generateWindowForActor('stranger',f.ids,59,{windowSeconds:60,startOffsetSeconds:30});assert.equal(r.entries.length,0);assert.equal(r.omitted[0].reason,'unavailable');
}finally{close(f);}});

const POLICY=responsePolicy({minPeriod:20,maxPeriod:86400,digits:[6,7,8],maxCodesPerEntry:31,budget:20});
test('mixed 20/30/60 s periods, from=30 and from=60: first code covers the start, no hole, same codes as asking at that time, real minRemaining and budget',async()=>{
 for(const from of [30,60]){const f=await fixture([20,30,60]),g=await fixture([20,30,60]);try{
  await f.run(f.qs(f.ids));await g.run(g.qs(g.ids));// warm both
  g.setNow(59000+from*1000);const at=await(await g.run(g.qs(g.ids))).json();
  f.setNow(59000);const r=await f.run(f.qs(f.ids,'&from='+from));assert.equal(r.status,200);const b=await r.json();
  const start=59000+from*1000;assert.equal(b.serverNow,59000);
  assert.equal(validateResponse(b,f.ids,POLICY,{startOffsetMs:from*1000}),true);
  assert.ok(b.totalCodes<=20&&b.totalCodes>=3);assert.ok(b.coverageUntil-start>=1000,'real minimum remaining at the start');
  for(const [i,e] of b.entries.entries()){
   assert.ok(e.validFrom*1000<=start&&start<(e.validFrom+e.period)*1000,'first code covers now+from');
   assert.ok((e.validFrom+e.codes.length*e.period)*1000>=b.coverageUntil,'no hole before coverage end');
   const same=at.entries[i];assert.equal(same.period,e.period);assert.equal(same.validFrom,e.validFrom);
   const n=Math.min(same.codes.length,e.codes.length);assert.deepEqual(e.codes.slice(0,n),same.codes.slice(0,n));
  }
 }finally{close(f);close(g);}}});
test('exact period boundary and one second before it with from=1',async()=>{
 for(const [now,from,validFrom] of [[59000,1,60],[59999,1,60],[58999,1,30],[60000,1,60],[60000,0,60]]){const f=await fixture([30]);try{
  await f.run(f.qs(f.ids));f.setNow(now);const r=await f.run(f.qs(f.ids,from?'&from='+from:''));assert.equal(r.status,200,now+'/'+from);const b=await r.json();
  assert.equal(b.entries[0].validFrom,validFrom,now+'/'+from);assert.equal(validateResponse(b,f.ids,POLICY,{startOffsetMs:from*1000}),true,now+'/'+from);
 }finally{close(f);}}});
test('warm from=60 with five entries stays inside budget, per-entry caps and minimum remaining',async()=>{const f=await fixture([20,20,30,30,60]);try{
 await f.run(f.qs(f.ids));f.setNow(59000);const b=await(await f.run(f.qs(f.ids,'&from=60'))).json();
 assert.ok(b.totalCodes<=20);for(const e of b.entries)assert.ok(e.codes.length<=31);assert.ok(b.coverageUntil-(59000+60000)>=1000);
 assert.equal(validateResponse(b,f.ids,POLICY,{startOffsetMs:60000}),true);
}finally{close(f);}});
test('finalizer offset: invalid values rejected, offset 0 equals omitted, trim and expiry judged at now+offset',()=>{
 const entry=()=>({entryId:'a',period:30,digits:6,validFrom:0,codes:['000001','000002','000003','000004']});
 const run=(extra,cov=120000)=>finalizeCommonHorizon({requestedIds:['a'],entries:[entry()],omitted:[],coverageUntil:cov,nowMs:59000,minRemainingMs:1000,policy:POLICY,...extra});
 for(const bad of [-1,60001,1.5,'30',NaN,Infinity,null])assert.throws(()=>run({offsetMs:bad}),TypeError,String(bad));
 assert.deepEqual(run({offsetMs:0}),run({}));
 const a=run({});assert.equal(a.entries[0].validFrom,30);assert.equal(a.entries[0].codes.length,3);
 const b=run({offsetMs:30000});assert.equal(b.entries[0].validFrom,60);assert.equal(b.entries[0].codes.length,2);assert.equal(b.serverNow,59000);
 assert.equal(run({offsetMs:60000}).entries[0].validFrom,90);
 assert.equal(run({offsetMs:30000},89500).status,'expired','coverage must outlast the requested start by minRemaining');
 assert.equal(run({},89500).status,'ok');
});
