import test from 'node:test';import assert from 'node:assert/strict';
import {createIdentityEdgeHost} from '../src/identity-edge-host.js';import {createBrowserWorkerAdapter} from '../src/browser-worker-adapter.js';import {createIdentityRuntime} from '../src/identity-runtime.js';
import {database} from './sqlite-helper.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',yes={limit:async()=>({success:true})};
const SYNC=['context','list','stepup-begin','enroll-begin','enroll-finish','snapshot-begin','snapshot-finish','batch-begin','batch-finish','status-begin','status-finish','revoke-begin','revoke-finish'].map(o=>'/v1/manage/seed-sync/'+o);
const BATCH=['batch-begin','batch-finish','batch-outcome'].map(o=>'/v1/manage/totp/'+o),EXPORT=['export-begin','export-finish'].map(o=>'/v1/manage/totp/'+o);
const post=(p,h={})=>new Request(API+p,{method:'POST',headers:{'Content-Type':'application/json',...h},body:'{}'});
test('adapter: every transfer and seed-sync path is 404 by default before any setup, and each flag opens only its own paths',async()=>{
 for(const [env,open] of [[{},[]],[{TOTP_BATCH_IMPORT_ENABLED:'1'},BATCH],[{TOTP_EXPORT_ENABLED:'1'},EXPORT],[{SEED_SYNC_ENABLED:'1',NATIVE_AUTH_ENABLED:'1'},SYNC],[{SEED_SYNC_ENABLED:'1'},[]],[{TOTP_BATCH_IMPORT_ENABLED:'true',TOTP_EXPORT_ENABLED:'yes',SEED_SYNC_ENABLED:'on',NATIVE_AUTH_ENABLED:'1'},[]]]){
  let touched=0;const a=createBrowserWorkerAdapter({resolveTrustedIngress:()=>{touched++;return '192.0.2.1';}});
  for(const p of [...BATCH,...EXPORT,...SYNC]){const r=await a.fetch(post(p),{...env},{});
   if(open.includes(p))assert.notEqual(r.status,404,p+' should pass the gate');else{assert.equal(r.status,404,p);}}
  if(!open.length)assert.equal(touched,0,'closed gates never reach ingress resolution');}});
test('edge host: seed-sync is native only, never any Origin, auth budget and never the read budget; transfer paths use the auth budget',async()=>{
 for(const p of [...SYNC,...BATCH,...EXPORT]){let auth=0,read=0,init=0;const mk=n=>createIdentityEdgeHost({nativeApi:n,resolveTrustedIngress:()=>'192.0.2.1',edgeAddress:yes,edgeAuthGlobal:{limit:async()=>{auth++;return{success:true};}},edgeReadGlobal:{limit:async()=>{read++;return{success:true};}},initialize:async()=>{init++;return{fetch:async()=>new Response('{}',{status:200})};}});
  const sync=SYNC.includes(p);
  if(sync){assert.equal((await mk(false).fetch(post(p))).status,404,p);assert.equal((await mk(true).fetch(post(p,{Origin:APP}))).status,403,p);assert.equal((await mk(true).fetch(new Request(API+p,{method:'OPTIONS',headers:{Origin:APP,'Access-Control-Request-Method':'POST'}}))).status,403,p);assert.equal(init,0);}
  assert.equal((await mk(true).fetch(post(p,{Authorization:'Bearer x'}))).status,200,p);assert.equal(auth,1,p);assert.equal(read,0,p);}
});
test('runtime: seed-sync and transfer handlers are not_found unless their own option is on; transfer does not need seed-sync',async()=>{
 const db=database();const base={db,keys:{},activeKeyId:'k',trustedRequestKey:()=>'a',native:{enabled:true,assetFingerprints:[],googleAudiences:[]}};
 const code=async(rt,p)=>(await rt.fetch(post(p,{Authorization:'Bearer x'}),{clientAddress:'t'})).status;
 const off=createIdentityRuntime(base);
 for(const p of [...SYNC,...BATCH,...EXPORT])assert.equal(await code(off,p),404,'off '+p);
 const tr=createIdentityRuntime({...base,transfer:{batchImport:true,export:true}});
 for(const p of SYNC)assert.equal(await code(tr,p),404,'transfer on, sync off '+p);
 for(const p of [...BATCH,...EXPORT])assert.notEqual(await code(tr,p),404,'transfer on '+p);
 const sy=createIdentityRuntime({...base,seedSync:{enabled:true}});
 for(const p of [...BATCH,...EXPORT])assert.equal(await code(sy,p),404,'sync on, transfer off '+p);
 for(const p of SYNC)assert.notEqual(await code(sy,p),404,'sync on '+p);
 const nonnative=createIdentityRuntime({db,keys:{},activeKeyId:'k',trustedRequestKey:()=>'a',seedSync:{enabled:true}});
 for(const p of SYNC)assert.equal(await code(nonnative,p),404,'sync needs native '+p);});
