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
 const r=new Request(API+path,{method,headers:{'CF-Connecting-IP':'192.0.2.1',...headers},...(body?{body}:{})});
 Object.defineProperty(r,'cf',{value:{colo:'LHR',httpProtocol:'HTTP/2',tlsVersion:'TLSv1.3'}});return r;
}
function config(db){return {DEPLOYMENT_STAGE:'auth-only',AUTH_ONLY_SIGNUP_EMAIL:'owner@example.test',DB:db,BREVO_API_KEY:'synthetic',BREVO_SENDER_EMAIL:'project@example.test',BREVO_REPLY_TO_EMAIL:'project@example.test',SIGNUP_ADDRESS_LIMIT:yes,SIGNUP_GLOBAL_LIMIT:yes,SIGNUP_VERIFY_ADDRESS_LIMIT:yes,SIGNUP_VERIFY_GLOBAL_LIMIT:yes,IDENTITY_ADDRESS_LIMIT:yes,IDENTITY_AUTH_GLOBAL_LIMIT:yes,IDENTITY_READ_GLOBAL_LIMIT:yes};}
const PATHS=['/v1/manage/organization','/v1/manage/organization-copy'];
const pre=(worker,env,path,method,headers='authorization, content-type',origin=APP)=>worker.fetch(request(path,{method:'OPTIONS',headers:{Origin:origin,'Access-Control-Request-Method':method,'Access-Control-Request-Headers':headers}}),env,{waitUntil(){}});
async function account(db,email){
 const identity=new AccountIdentityService(db),signup=new PasskeySignupService(db),a=authenticator();
 const e=await identity.issueEmailChallenge({purpose:'signup-email',email}),c=await signup.begin({email,emailToken:e.token,binding:'org-'+email});
 const proof=await signup.finish({token:c.token,binding:'org-'+email,response:a.registration({expected:c.options.challenge})});
 const issued=await new DeviceSessionService(db).issue({proof:{...proof,purpose:'authenticate',verifiedAt:Date.now()},clientKind:'web'});
 return {ownerId:proof.ownerId,access:issued.access,deviceId:issued.deviceId};
}

test('public entry: organization preflight is exact and needs no bindings or database',async()=>{
 const worker=createAuthOnlyWorker(),env={DEPLOYMENT_STAGE:'auth-only'};
 for(const [path,method] of [[PATHS[0],'GET'],[PATHS[0],'PUT'],[PATHS[1],'POST']]){
  const ok=await pre(worker,env,path,method);assert.equal(ok.status,204,path+method);
  assert.equal(ok.headers.get('access-control-allow-origin'),APP);assert.notEqual(ok.headers.get('access-control-allow-credentials'),'true');
  assert.deepEqual(ok.headers.get('access-control-allow-headers').toLowerCase().split(',').map(v=>v.trim()).sort(),['authorization','content-type']);
  assert.equal(await ok.text(),'');
  assert.equal((await pre(worker,env,path,method,'authorization, content-type, x-otpanda-enrollment')).status,403,'no extra header');
  assert.equal((await pre(worker,env,path,method,'authorization, x-evil')).status,403);
  assert.equal((await pre(worker,env,path,method,'authorization, content-type','https://wrong.test')).status,403);
 }
 for(const method of ['DELETE','PATCH','HEAD'])for(const path of PATHS)assert.equal((await pre(worker,env,path,method)).status,403,path+method);
 assert.equal((await pre(worker,env,PATHS[1],'PUT')).status,403,'copy is POST only');
 assert.equal((await pre(worker,env,PATHS[1],'GET')).status,403);
 assert.equal((await pre(worker,env,PATHS[0],'POST')).status,403,'organization is GET and PUT only');
});

test('public entry: organization routes require origin, bearer and the right method before touching state',async()=>{
 const db=database(),worker=createAuthOnlyWorker(),env=config(db),ctx={waitUntil(){}};
 try{
  const json={'Content-Type':'application/json'};
  for(const [path,method] of [[PATHS[0],'GET'],[PATHS[0],'PUT'],[PATHS[1],'POST']]){
   const body=method==='GET'?undefined:'{}';
   assert.equal((await worker.fetch(request(path,{method,headers:{Origin:APP,...json},body}),env,ctx)).status,401,'no bearer '+path+method);
   assert.equal((await worker.fetch(request(path,{method,headers:{Origin:APP,...json,Authorization:'Bearer automation'},body}),env,ctx)).status,401,'bad bearer');
   assert.equal((await worker.fetch(request(path,{method,headers:{Origin:'https://wrong.test',...json,Authorization:'Bearer '+'a'.repeat(43)},body}),env,ctx)).status,403,'wrong origin');
   assert.equal((await worker.fetch(request(path,{method,headers:{...json,Authorization:'Bearer '+'a'.repeat(43)},body}),env,ctx)).status,403,'no origin');
  }
  for(const method of ['POST','PATCH','DELETE'])assert.equal((await worker.fetch(request(PATHS[0],{method,headers:{Origin:APP,...json},body:'{}'}),env,ctx)).status,405,'organization '+method);
  for(const method of ['GET','PUT','PATCH','DELETE'])assert.equal((await worker.fetch(request(PATHS[1],{method,headers:{Origin:APP,...json},body:method==='GET'?undefined:'{}'}),env,ctx)).status,405,'copy '+method);
  assert.equal(db.sqlite.prepare('SELECT count(*) n FROM personal_organization').get().n,0);
  assert.equal(db.sqlite.prepare('SELECT count(*) n FROM personal_copy_receipts').get().n,0);
  // Neighbours stay unmounted.
  for(const path of ['/v1/manage/organization/','/v1/manage/organization-copy/x','/v1/manage/organizations'])assert.equal((await worker.fetch(request(path,{headers:{Origin:APP}}),env,ctx)).status,404,path);
 }finally{db.sqlite.close();}
});

test('public entry: each signed-in account reads and writes only its own organization, revocation wins',async()=>{
 const db=database(),worker=createAuthOnlyWorker(),env=config(db),ctx={waitUntil(){}};
 try{
  const a=await account(db,'org-a@example.test'),b=await account(db,'org-b@example.test');
  const call=(who,path,method='GET',body)=>worker.fetch(request(path,{method,headers:{Origin:APP,'Content-Type':'application/json',Authorization:'Bearer '+who.access},body:body===undefined?undefined:JSON.stringify(body)}),env,ctx);
  let r=await call(a,PATHS[0]);assert.equal(r.status,200);assert.equal(r.headers.get('access-control-allow-origin'),APP);assert.equal(r.headers.get('cache-control'),'no-store');
  assert.deepEqual(await r.json(),{revision:0,tags:[],entries:[],ranking:[]});
  r=await call(a,PATHS[0],'PUT',{revision:0,document:{tags:[{id:'t1',label:'Work'}],entries:[]}});assert.equal(r.status,200);
  const saved=await (await call(a,PATHS[0])).json();assert.equal(saved.revision,1);assert.deepEqual(saved.tags,[{id:'t1',label:'Work'}]);
  const other=await (await call(b,PATHS[0])).json();assert.deepEqual(other,{revision:0,tags:[],entries:[],ranking:[]});
  assert.equal((await call(a,PATHS[0],'PUT',{revision:0,document:{tags:[],entries:[]}})).status,409,'stale revision is a conflict, not a silent overwrite');
  assert.equal((await call(b,PATHS[0],'PUT',{revision:0,document:{tags:[{id:'x',label:'Mine'}],entries:[]}})).status,200);
  assert.deepEqual((await (await call(a,PATHS[0])).json()).tags,[{id:'t1',label:'Work'}]);
  // An owner-supplied id in the query or body never selects another account.
  assert.equal((await call(a,PATHS[0]+'?owner='+b.ownerId)).status,400);
  // Copy receipts record only entries this account can reach.
  db.sqlite.prepare("INSERT INTO entries(entry_id,owner_id,service_id,label,created_at) VALUES ('ea',?,'service','A',?)").run(a.ownerId,Date.now());
  const receipt={entryId:'ea',receiptId:'q'.repeat(22),createdAt:Date.now()};
  assert.deepEqual(await (await call(b,PATHS[1],'POST',receipt)).json(),{accepted:false});
  assert.deepEqual(await (await call(a,PATHS[1],'POST',receipt)).json(),{accepted:true});
  assert.deepEqual(await (await call(a,PATHS[1],'POST',receipt)).json(),{accepted:false});
  assert.equal(db.sqlite.prepare('SELECT count(*) n FROM personal_copy_receipts').get().n,1);
  // Revoking the device ends access at once.
  await new DeviceSessionService(db).revoke({ownerId:a.ownerId,deviceId:a.deviceId});
  assert.equal((await call(a,PATHS[0])).status,401);
  assert.equal((await call(a,PATHS[0],'PUT',{revision:1,document:{tags:[],entries:[]}})).status,401);
  assert.deepEqual((await (await call(b,PATHS[0])).json()).tags,[{id:'x',label:'Mine'}]);
 }finally{db.sqlite.close();}
});
