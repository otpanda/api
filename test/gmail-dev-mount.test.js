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
 assert.ok(GMAIL_CRON_BUDGET<=25);
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
