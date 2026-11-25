import test from 'node:test';
import assert from 'node:assert/strict';
import {createAuthOnlyWorker} from '../src/auth-only-worker.js';
import {database} from './sqlite-helper.js';
import {AccountIdentityService} from '../src/account-identity.js';
import {PasskeySignupService} from '../src/passkey-signup.js';
import {DeviceSessionService} from '../src/device-sessions.js';
import {authenticator} from './passkey-fixture.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io';
const yes={limit:async()=>({success:true})};
function request(path,{method='GET',headers={},body}={}){
 const r=new Request(API+path,{method,headers:{'CF-Connecting-IP':'192.0.2.1',...headers},...(body!==undefined?{body}:{})});
 Object.defineProperty(r,'cf',{value:{colo:'LHR',httpProtocol:'HTTP/2',tlsVersion:'TLSv1.3'}});return r;
}
const config=db=>({DEPLOYMENT_STAGE:'auth-only',AUTH_ONLY_SIGNUP_EMAIL:'owner@example.test',DB:db,BREVO_API_KEY:'synthetic',BREVO_SENDER_EMAIL:'project@example.test',BREVO_REPLY_TO_EMAIL:'project@example.test',SIGNUP_ADDRESS_LIMIT:yes,SIGNUP_GLOBAL_LIMIT:yes,SIGNUP_VERIFY_ADDRESS_LIMIT:yes,SIGNUP_VERIFY_GLOBAL_LIMIT:yes,IDENTITY_ADDRESS_LIMIT:yes,IDENTITY_AUTH_GLOBAL_LIMIT:yes,IDENTITY_READ_GLOBAL_LIMIT:yes});
async function account(db,email,clientKind='web'){
 const identity=new AccountIdentityService(db),signup=new PasskeySignupService(db),a=authenticator();
 const e=await identity.issueEmailChallenge({purpose:'signup-email',email}),c=await signup.begin({email,emailToken:e.token,binding:'em-'+email});
 const proof=await signup.finish({token:c.token,binding:'em-'+email,response:a.registration({expected:c.options.challenge})});
 const issued=await new DeviceSessionService(db).issue({proof:{...proof,purpose:'authenticate',verifiedAt:Date.now()},clientKind});
 return {ownerId:proof.ownerId,access:issued.access,deviceId:issued.deviceId};
}
const RENAME='/v1/manage/entry/rename',ACCOUNT='/v1/manage/entry/account',ASSIGN=['begin','finish','status'].map(p=>'/v1/manage/assignment/'+p);
const pre=(worker,env,path,method,headers='authorization, content-type',origin=APP)=>worker.fetch(request(path,{method:'OPTIONS',headers:{Origin:origin,'Access-Control-Request-Method':method,'Access-Control-Request-Headers':headers}}),env,{waitUntil(){}});
test('public entry: assignment and entry-management preflight is exact, POST only, no extra headers',async()=>{
 const worker=createAuthOnlyWorker(),env={DEPLOYMENT_STAGE:'auth-only'};
 for(const path of [RENAME,ACCOUNT,...ASSIGN]){
  const ok=await pre(worker,env,path,'POST');assert.equal(ok.status,204,path);
  assert.equal(ok.headers.get('access-control-allow-origin'),APP);assert.notEqual(ok.headers.get('access-control-allow-credentials'),'true');
  assert.deepEqual(ok.headers.get('access-control-allow-headers').toLowerCase().split(',').map(v=>v.trim()).sort(),['authorization','content-type']);
  assert.equal((await pre(worker,env,path,'POST','authorization, content-type, x-otpanda-enrollment')).status,403);
  assert.equal((await pre(worker,env,path,'POST','authorization, x-evil')).status,403);
  assert.equal((await pre(worker,env,path,'POST','authorization, content-type','https://wrong.test')).status,403);
  for(const method of ['GET','PUT','PATCH','DELETE'])assert.equal((await pre(worker,env,path,method)).status,403,path+method);
 }
});
test('public entry: assignment and entry routes need Origin, web bearer and POST; neighbours stay unmounted; state untouched',async()=>{
 const db=database(),worker=createAuthOnlyWorker(),env=config(db),ctx={waitUntil(){}};
 try{
  const a=await account(db,'em-a@example.test'),n=await account(db,'em-n@example.test','native').catch(()=>undefined);
  db.sqlite.prepare("INSERT INTO entries(entry_id,owner_id,service_id,label,created_at) VALUES ('e1',?,'service','Keep',1)").run(a.ownerId);
  const json={'Content-Type':'application/json'},body='{"entryId":"e1","label":"X"}';
  for(const path of [RENAME,ACCOUNT,...ASSIGN]){
   assert.equal((await worker.fetch(request(path,{method:'POST',headers:{Origin:APP,...json},body}),env,ctx)).status,401,'no bearer '+path);
   assert.equal((await worker.fetch(request(path,{method:'POST',headers:{Origin:APP,...json,Authorization:'Bearer automation'},body}),env,ctx)).status,401,'bad bearer');
   assert.equal((await worker.fetch(request(path,{method:'POST',headers:{...json,Authorization:'Bearer '+a.access},body}),env,ctx)).status,403,'no origin '+path);
   assert.equal((await worker.fetch(request(path,{method:'POST',headers:{Origin:'https://wrong.test',...json,Authorization:'Bearer '+a.access},body}),env,ctx)).status,403,'wrong origin');
   for(const method of ['GET','PUT','PATCH','DELETE'])assert.equal((await worker.fetch(request(path,{method,headers:{Origin:APP,...json,Authorization:'Bearer '+a.access},body:method==='GET'?undefined:body}),env,ctx)).status,405,path+method);
   if(n)assert.equal((await worker.fetch(request(path,{method:'POST',headers:{Origin:APP,...json,Authorization:'Bearer '+n.access},body}),env,ctx)).status,401,'native token refused '+path);
  }
  assert.equal(db.sqlite.prepare("SELECT label FROM entries WHERE entry_id='e1'").get().label,'Keep');
  for(const path of ['/v1/manage/entry','/v1/manage/entry/delete','/v1/manage/entry/rename/','/v1/manage/entry/create','/v1/manage/assignment','/v1/manage/assignment/begin/x','/v1/manage/confirm-assignment','/v1/manage/entries/rename'])assert.equal((await worker.fetch(request(path,{method:'POST',headers:{Origin:APP,...json,Authorization:'Bearer '+a.access},body}),env,ctx)).status,404,path);
  // Assignment refuses a query string before any work.
  assert.equal((await worker.fetch(request(ASSIGN[0]+'?x=1',{method:'POST',headers:{Origin:APP,...json,Authorization:'Bearer '+a.access},body:'{}'}),env,ctx)).status,400);
 }finally{db.sqlite.close();}
});
test('public entry: rename/account are owner-only, strict, revoke-aware, and bump the revision and outbox',async()=>{
 const db=database(),worker=createAuthOnlyWorker(),env=config(db),ctx={waitUntil(){}};
 try{
  const a=await account(db,'em-a2@example.test'),b=await account(db,'em-b2@example.test');
  const ins=db.sqlite.prepare("INSERT INTO entries(entry_id,owner_id,service_id,label,created_at,account_name) VALUES (?,?,'service','Orig',1,'acct')");ins.run('ea',a.ownerId);ins.run('eb',b.ownerId);
  db.sqlite.prepare("INSERT INTO entry_shares(entry_id,recipient_id,allow_automation,created_at,revoked_at) VALUES ('ea',?,0,1,NULL)").run(b.ownerId);
  const call=(who,path,body,extra={})=>worker.fetch(request(path,{method:'POST',headers:{Origin:APP,'Content-Type':'application/json',Authorization:'Bearer '+who.access,...extra},body:typeof body==='string'?body:JSON.stringify(body)}),env,ctx);
  const row=id=>db.sqlite.prepare('SELECT label,account_name,mutation_revision r FROM entries WHERE entry_id=?').get(id);
  const rev0=row('ea').r;
  let r=await call(a,RENAME,{entryId:'ea',label:'New name'});assert.equal(r.status,200);assert.deepEqual(await r.json(),{ok:true});assert.equal(r.headers.get('access-control-allow-origin'),APP);
  assert.equal(row('ea').label,'New name');assert.ok(row('ea').r>rev0,'revision bump invalidates pending assignments');
  r=await call(a,ACCOUNT,{entryId:'ea',accountName:'me@example.com'});assert.equal(r.status,200);assert.equal(row('ea').account_name,'me@example.com');
  r=await call(a,ACCOUNT,{entryId:'ea',accountName:null});assert.equal(r.status,200);assert.equal(row('ea').account_name,null);
  // Recipient (active share) and stranger cannot edit; both see the same 404 as an unknown entry.
  for(const path of [RENAME,ACCOUNT]){
   const bodyFor=id=>path===RENAME?{entryId:id,label:'Hijack'}:{entryId:id,accountName:'Hijack'};
   for(const id of ['ea','nope'])assert.equal((await call(b,path,bodyFor(id))).status,404,'recipient or unknown '+id);
   assert.equal((await call(a,path,bodyFor('eb'))).status,404,'cross owner');
  }
  assert.equal(row('ea').label,'New name');assert.equal(row('eb').label,'Orig');assert.equal(row('eb').account_name,'acct');
  // Strictness: exact fields, bounded values, JSON only, 4 KB cap, no query.
  const bad=[{entryId:'ea'},{label:'x'},{entryId:'ea',label:'x',owner:'b'},{entryId:'ea',label:'   '},{entryId:'ea',label:''},{entryId:'ea',label:5},{entryId:'ea',label:null},{entryId:'ea',label:'a'.repeat(121)},{entryId:'a/b',label:'x'},{entryId:'x'.repeat(129),label:'x'},{entryId:5,label:'x'},[],'null','{bad'];
  for(const b2 of bad)assert.equal((await call(a,RENAME,b2)).status,400,JSON.stringify(b2));
  for(const b2 of [{entryId:'ea',accountName:''},{entryId:'ea',accountName:'  '},{entryId:'ea',accountName:5},{entryId:'ea',accountName:'a'.repeat(121)},{entryId:'ea'},{entryId:'ea',accountName:'x',label:'y'}])assert.equal((await call(a,ACCOUNT,b2)).status,400,JSON.stringify(b2));
  assert.equal((await call(a,RENAME,{entryId:'ea',label:'x'},{'Content-Type':'text/plain'})).status,400);
  assert.equal((await call(a,RENAME,JSON.stringify({entryId:'ea',label:'x',pad:'p'.repeat(5000)}))).status,400);
  assert.equal((await worker.fetch(request(RENAME+'?owner='+b.ownerId,{method:'POST',headers:{Origin:APP,'Content-Type':'application/json',Authorization:'Bearer '+a.access},body:JSON.stringify({entryId:'ea',label:'x'})}),env,ctx)).status,400);
  assert.equal(row('ea').label,'New name');
  // Realtime outbox row written by the existing trigger for the rename.
  db.sqlite.prepare('DELETE FROM realtime_outbox').run();
  assert.equal((await call(a,RENAME,{entryId:'ea',label:'Again'})).status,200);
  assert.equal(db.sqlite.prepare("SELECT count(*) n FROM realtime_outbox WHERE kind='entry' AND scope_id='ea' AND account_id=?").get(a.ownerId).n,1);
  // Revocation wins: a revoked device cannot write.
  db.sqlite.prepare('UPDATE device_sessions SET revoked_at=? WHERE device_id=?').run(Date.now(),a.deviceId);
  assert.equal((await call(a,RENAME,{entryId:'ea',label:'Late'})).status,401);assert.equal(row('ea').label,'Again');
 }finally{db.sqlite.close();}
});
test('entry write is itself conditioned on the live session (revocation between auth and write)',async()=>{
 const {createEntryManageHttp}=await import('../src/entry-manage-http.js'),db=database();
 try{
  const a=await account(db,'em-c@example.test');
  db.sqlite.prepare("INSERT INTO entries(entry_id,owner_id,service_id,label,created_at) VALUES ('ec',?,'service','Orig',1)").run(a.ownerId);
  const sessions={authenticate:async()=>{db.sqlite.prepare('UPDATE device_sessions SET revoked_at=? WHERE device_id=?').run(Date.now(),a.deviceId);return {ownerId:a.ownerId,deviceId:a.deviceId,generation:0,clientKind:'web',expiresAt:Date.now()+1e6};}};
  const h=createEntryManageHttp({db,sessions});
  const r=await h.fetch(new Request(API+RENAME,{method:'POST',headers:{Origin:APP,Authorization:'Bearer '+'a'.repeat(43),'Content-Type':'application/json'},body:JSON.stringify({entryId:'ec',label:'Raced'})}));
  assert.equal(r.status,404);assert.equal(db.sqlite.prepare("SELECT label FROM entries WHERE entry_id='ec'").get().label,'Orig');
 }finally{db.sqlite.close();}
});

import{createEntryManageHttp}from'../src/entry-manage-http.js';
for(const revoke of ['generation','method','client'])test('rename final write rejects '+revoke+' changed after authentication',async()=>{const db=database();try{const a=await account(db,'race-'+revoke+'@example.test');db.sqlite.prepare("INSERT INTO entries(entry_id,owner_id,service_id,label,created_at)VALUES('race',?,'service','Keep',1)").run(a.ownerId);const real=new DeviceSessionService(db);const sessions={authenticate:async token=>{const result=await real.authenticate(token);if(revoke==='generation')db.sqlite.prepare('UPDATE account_security SET generation=generation+1 WHERE owner_id=?').run(a.ownerId);if(revoke==='method')db.sqlite.prepare('UPDATE passkey_credentials SET revoked_at=? WHERE owner_id=?').run(Date.now(),a.ownerId);if(revoke==='client')db.sqlite.prepare("UPDATE device_sessions SET client_kind='android' WHERE device_id=?").run(a.deviceId);return result;}};const h=createEntryManageHttp({db,sessions});const r=await h.fetch(new Request(API+RENAME,{method:'POST',headers:{Origin:APP,Authorization:'Bearer '+a.access,'Content-Type':'application/json'},body:JSON.stringify({entryId:'race',label:'Changed'})}));assert.equal(r.status,404);assert.equal(db.sqlite.prepare("SELECT label FROM entries WHERE entry_id='race'").get().label,'Keep');}finally{db.sqlite.close();}});
