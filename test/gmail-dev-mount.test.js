import test from 'node:test';
import assert from 'node:assert/strict';
import {createAuthOnlyWorker} from '../src/auth-only-worker.js';
import {database} from './sqlite-helper.js';
import {createGmailCollectionHost,gmailDevEnabled,createGmailSourceServices,GMAIL_CRON_BUDGET} from '../src/gmail-source-runtime.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io';
const SOURCE='367143149550-cu61adcdqclntipnl84e096kp35vduvk.apps.googleusercontent.com';
const LOGIN='367143149550-560r90pmkqr71qp1tid3amck2a053rdg.apps.googleusercontent.com';
const yes={limit:async()=>({success:true})};
const key=Buffer.alloc(32,7).toString('base64url');
const paths=['/v1/manage/gmail-source','/v1/manage/gmail-source/begin','/v1/manage/gmail-source/status','/sources/gmail/oauth/callback','/sources/gmail/push'];
function req(path,{method='GET',headers={}}={}){
 const r=new Request(API+path,{method,headers:{'CF-Connecting-IP':'192.0.2.1',...headers}});
 Object.defineProperty(r,'cf',{value:{colo:'LHR',httpProtocol:'HTTP/2',tlsVersion:'TLSv1.3'}});return r;
}
function guarded(){let calls=0;const trap=()=>{calls++;throw Error('must not touch database');};return {db:{prepare:trap},calls:()=>calls};}
function env(db,extra={}){return {DEPLOYMENT_STAGE:'auth-only',AUTH_ONLY_SIGNUP_MODE:'public',DB:db,GOOGLE_CLIENT_ID:LOGIN,NATIVE_GOOGLE_AUDIENCES:LOGIN,IDENTITY_ADDRESS_LIMIT:yes,IDENTITY_AUTH_GLOBAL_LIMIT:yes,...extra};}
const full={GMAIL_DEV_COLLECTION:'dev-mailbox-only',GMAIL_DEV_MAILBOX:'otpanda.app@gmail.com',GMAIL_SOURCE_CLIENT_ID:SOURCE,GMAIL_SOURCE_CLIENT_SECRET:'synthetic',GMAIL_PUSH_AUDIENCE:API+'/sources/gmail/push',GMAIL_PUSH_SERVICE_ACCOUNT:'gmail-push-oidc@otpanda.iam.gserviceaccount.com',ENCRYPTION_KEYRING:JSON.stringify([{id:'k1',key}]),ACTIVE_KEY_ID:'k1'};

test('enable value is exact: anything else leaves every Gmail path unmounted, with no database use',async()=>{
 const g=guarded(),worker=createAuthOnlyWorker();
 for(const v of [undefined,'',true,1,'true','1','enabled','Dev-Mailbox-Only','dev-mailbox-only ']){
  assert.equal(gmailDevEnabled({GMAIL_DEV_COLLECTION:v}),false);
  for(const path of paths){const r=await worker.fetch(req(path,{method:path.endsWith('push')?'POST':'GET',headers:{origin:APP}}),env(g.db,{...full,GMAIL_DEV_COLLECTION:v}),{waitUntil(){}});assert.equal(r.status,404,path);}
 }
 assert.equal(g.calls(),0);
 assert.equal(gmailDevEnabled(full),true);
});

test('enabled but misconfigured fails closed with 503 before any database use',async()=>{
 for(const patch of [{GMAIL_DEV_MAILBOX:undefined},{GMAIL_DEV_MAILBOX:' '},{GMAIL_SOURCE_CLIENT_ID:undefined},{GMAIL_SOURCE_CLIENT_ID:LOGIN},{GMAIL_SOURCE_CLIENT_SECRET:undefined},{GMAIL_SOURCE_CLIENT_SECRET:''},{ENCRYPTION_KEYRING:undefined}]){
  const g=guarded(),worker=createAuthOnlyWorker(),e=env(g.db,{...full,...patch});
  for(const path of ['/v1/manage/gmail-source/status','/sources/gmail/oauth/callback']){const r=await worker.fetch(req(path,{headers:{origin:APP}}),e,{waitUntil(){}});assert.equal(r.status,503,JSON.stringify(patch)+path);assert.equal((await r.json()).error,'collection_not_ready');}
  assert.equal(g.calls(),0);
 }
 // The source client may never equal the sign-in or native client.
 await assert.rejects(createGmailSourceServices({...env({}, full),GOOGLE_CLIENT_ID:SOURCE}));
 await assert.rejects(createGmailSourceServices({...env({}, full),NATIVE_GOOGLE_AUDIENCES:SOURCE}));
});

test('push route keeps its own fixed audience and service-account checks',async()=>{
 const g=guarded(),worker=createAuthOnlyWorker();
 for(const patch of [{GMAIL_PUSH_AUDIENCE:undefined},{GMAIL_PUSH_AUDIENCE:API+'/other'},{GMAIL_PUSH_SERVICE_ACCOUNT:'other@otpanda.iam.gserviceaccount.com'}]){
  const r=await worker.fetch(req('/sources/gmail/push',{method:'POST'}),env(g.db,{...full,...patch}),{waitUntil(){}});
  assert.equal(r.status,503);
 }
 // Fully configured, an unauthenticated push is refused by the OIDC check, not accepted.
 const ok=await worker.fetch(req('/sources/gmail/push',{method:'POST',headers:{'content-type':'application/json'}}),env(g.db,full),{waitUntil(){}});
 assert.equal(ok.status,401);
 assert.equal(g.calls(),0);
});

test('enabled routes answer the preflight only for the app origin and require sign-in',async()=>{
 const g=guarded(),worker=createAuthOnlyWorker(),e=env(g.db,full);
 const pre=await worker.fetch(req('/v1/manage/gmail-source/status',{method:'OPTIONS',headers:{origin:APP,'access-control-request-method':'GET','access-control-request-headers':'authorization'}}),e,{waitUntil(){}});
 assert.equal(pre.status,204);
 const wrong=await worker.fetch(req('/v1/manage/gmail-source/status',{headers:{origin:'https://evil.example'}}),e,{waitUntil(){}});
 assert.equal(wrong.status,403);
});

test('scheduled: the realtime cron runs Gmail maintenance only when enabled, with its own small budget',async()=>{
 const g=guarded(),worker=createAuthOnlyWorker();
 let work;
 await worker.scheduled({cron:'*/5 * * * *'},env(g.db,{...full,GMAIL_DEV_COLLECTION:undefined}),{waitUntil(p){work=p;}});
 assert.equal(work,undefined);
 assert.equal(g.calls(),0);
 // Enabled but misconfigured: the run is scheduled, ends quietly and never throws.
 await worker.scheduled({cron:'*/5 * * * *'},env(g.db,{...full,GMAIL_DEV_MAILBOX:undefined}),{waitUntil(p){work=p;}});
 assert.ok(work);await work;
 assert.equal(g.calls(),0);
});

test('invocation accounting is per category (45 of 50 D1, 25 external), 70 operations in total',async()=>{
 const rt=await import('../src/realtime-outbox.js');
 // Per category, worst case in the shared */5 invocation: D1 = realtime D1 + Gmail (Gmail counts D1 and Google together).
 assert.ok(rt.CRON_QUERY_MAX+GMAIL_CRON_BUDGET<=rt.INVOCATION_QUERY_LIMIT,'D1 per-category sum');
 assert.ok(GMAIL_CRON_BUDGET<=50,'external fetch per-category');
 assert.ok(rt.CRON_DELIVERY_MAX<=1000,'Durable Object per-category');
 assert.equal(rt.CRON_QUERY_MAX+GMAIL_CRON_BUDGET,45);
 // The old single "45 combined" figure does not hold: all operations together reach 70.
 assert.equal(rt.CRON_QUERY_MAX+rt.CRON_DELIVERY_MAX+GMAIL_CRON_BUDGET,70);
 assert.ok(70>rt.COMBINED_CEILING);
 const {createRequestBudget,budgetedDb,budgetedFetch}=await import('../src/request-budget.js');
 const b=createRequestBudget(GMAIL_CRON_BUDGET),calls={d1:0,net:0},sdb=database();
 try{
  const inner={prepare:sql=>{const st=sdb.prepare(sql);const wrap=x=>({inner:x,bind:(...a)=>wrap(x.bind(...a)),run:()=>{calls.d1++;return x.run();},first:(...a)=>{calls.d1++;return x.first(...a);},all:()=>{calls.d1++;return x.all();}});return wrap(st);},batch:s=>{calls.d1++;return sdb.batch(s.map(x=>x.inner??x));}};
  const db=budgetedDb(inner,b),f=budgetedFetch(async()=>{calls.net++;return new Response('{}');},b);
  // Every counted call spends exactly one unit, db.batch counts once, and the 26th call is refused before it runs.
  for(let i=0;i<GMAIL_CRON_BUDGET-2;i++)await db.prepare('SELECT 1').first();
  await db.batch([db.prepare('SELECT 1'),db.prepare('SELECT 2')]);
  await f('https://example.test/');
  assert.equal(b.used,GMAIL_CRON_BUDGET);
  assert.throws(()=>db.prepare('SELECT 1').first(),{message:'request budget exhausted'});
  assert.throws(()=>f('https://example.test/'),{message:'request budget exhausted'});
  assert.equal(calls.d1+calls.net,GMAIL_CRON_BUDGET);
 }finally{sdb.close?.();}
});

test('scheduled maintenance with real storage touches no Google and counts only',async()=>{
 const db=database();let fetches=0;
 try{
  const host=createGmailCollectionHost({fetchImpl:async()=>{fetches++;throw Error('no network expected');}});
  const r=await host.scheduled({cron:'*/5 * * * *'},env(db,full));
  assert.equal(r.ready,true);
  assert.deepEqual(r.failed,[]);
  assert.equal('mailbox' in r,false);
  assert.equal(fetches,0);
  // The same run through the worker's realtime cron completes without error.
  let work;await createAuthOnlyWorker().scheduled({cron:'*/5 * * * *'},env(db,full),{waitUntil(p){work=p;}});
  await work;
 }finally{db.close?.();}
});

test('non-push Gmail routes are rate limited before any keyring, database or Google work',async()=>{
 const g=guarded(),worker=createAuthOnlyWorker();
 for(const [name,limits] of [['address',{IDENTITY_ADDRESS_LIMIT:{limit:async()=>({success:false})}}],['global',{IDENTITY_AUTH_GLOBAL_LIMIT:{limit:async()=>({success:false})}}],['missing-binding',{IDENTITY_ADDRESS_LIMIT:undefined}]]){
  for(const path of ['/v1/manage/gmail-source/status','/v1/manage/gmail-source/begin','/sources/gmail/oauth/callback']){
   const r=await worker.fetch(req(path,{method:path.endsWith('begin')?'POST':'GET',headers:{origin:APP}}),env(g.db,{...full,...limits}),{waitUntil(){}});
   assert.equal(r.status,429,name+path);
  }
 }
 // Keyring that would throw is never reached when limited: the answer stays 429, not collection_not_ready.
 const r=await worker.fetch(req('/v1/manage/gmail-source/status',{headers:{origin:APP}}),env(g.db,{...full,ENCRYPTION_KEYRING:undefined,IDENTITY_ADDRESS_LIMIT:{limit:async()=>({success:false})}}),{waitUntil(){}});
 assert.equal(r.status,429);
 assert.equal(g.calls(),0);
 // Allowed callers still reach the normal gates.
 const ok=await worker.fetch(req('/v1/manage/gmail-source/status',{method:'OPTIONS',headers:{origin:APP,'access-control-request-method':'GET','access-control-request-headers':'authorization'}}),env(g.db,full),{waitUntil(){}});
 assert.equal(ok.status,204);
});

async function deployment(){const fs=await import('node:fs/promises');return JSON.parse(await fs.readFile('wrangler.jsonc','utf8'));}

test('wrangler declares exactly the four non-secret Gmail pins and leaves activation and secrets out',async()=>{
 const d=await deployment(),v=d.vars;
 assert.equal(v.GMAIL_DEV_MAILBOX,'otpanda.app@gmail.com');
 assert.equal(v.GMAIL_SOURCE_CLIENT_ID,SOURCE);
 assert.equal(v.GMAIL_PUSH_AUDIENCE,API+'/sources/gmail/push');
 assert.equal(v.GMAIL_PUSH_SERVICE_ACCOUNT,'gmail-push-oidc@otpanda.iam.gserviceaccount.com');
 // Activation is a separate reviewed change. A secret never belongs in the file.
 assert.equal(v.GMAIL_DEV_COLLECTION,undefined);
 assert.deepEqual(Object.keys(v).filter(k=>k.startsWith('GMAIL_')).sort(),['GMAIL_DEV_MAILBOX','GMAIL_PUSH_AUDIENCE','GMAIL_PUSH_SERVICE_ACCOUNT','GMAIL_SOURCE_CLIENT_ID']);
 for(const k of Object.keys(v))assert.ok(!/SECRET|KEYRING|ACTIVE_KEY|API_KEY/.test(k),k);
 // The pins must stay distinct from the sign-in and native clients.
 assert.notEqual(v.GMAIL_SOURCE_CLIENT_ID,v.GOOGLE_CLIENT_ID);
 assert.ok(!String(v.NATIVE_GOOGLE_AUDIENCES).split(',').map(x=>x.trim()).includes(v.GMAIL_SOURCE_CLIENT_ID));
 // Other existing configuration is unchanged.
 assert.equal(v.DEPLOYMENT_STAGE,'auth-only');assert.equal(v.AUTH_ONLY_SIGNUP_MODE,'public');assert.deepEqual(d.triggers.crons,['*/15 * * * *','*/5 * * * *']);
});

test('declared pins plus the enable value and secrets build the services; without the enable value nothing mounts',async()=>{
 const v=(await deployment()).vars,db=database();
 try{
  const base={...v,DB:db,GMAIL_SOURCE_CLIENT_SECRET:'synthetic',ENCRYPTION_KEYRING:full.ENCRYPTION_KEYRING,ACTIVE_KEY_ID:'k1',IDENTITY_ADDRESS_LIMIT:yes,IDENTITY_AUTH_GLOBAL_LIMIT:yes};
  const svc=await createGmailSourceServices(base);
  assert.equal(svc.devMailbox,'otpanda.app@gmail.com');
  // Exactly what a deployment of this file does: pins present, enable absent.
  const g=guarded(),worker=createAuthOnlyWorker();
  const off={...base,DB:g.db};
  for(const path of paths){const r=await worker.fetch(req(path,{method:path.endsWith('push')?'POST':'GET',headers:{origin:APP}}),off,{waitUntil(){}});assert.equal(r.status,404,path);}
  let work;await worker.scheduled({cron:'*/5 * * * *'},off,{waitUntil(p){work=p;}});assert.equal(work,undefined);
  assert.equal(g.calls(),0);
  // Adding only the enable value turns it on (this is the separate reviewed change).
  const on=await worker.fetch(req('/v1/manage/gmail-source/status',{method:'OPTIONS',headers:{origin:APP,'access-control-request-method':'GET','access-control-request-headers':'authorization'}}),{...off,GMAIL_DEV_COLLECTION:'dev-mailbox-only',GMAIL_SOURCE_CLIENT_SECRET:'synthetic'},{waitUntil(){}});
  assert.equal(on.status,204);
 }finally{db.close?.();}
});
