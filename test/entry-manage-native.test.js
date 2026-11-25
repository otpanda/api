import test from 'node:test';import assert from 'node:assert/strict';
import{database}from'./sqlite-helper.js';import{AccountIdentityService}from'../src/account-identity.js';import{PasskeySignupService}from'../src/passkey-signup.js';import{DeviceSessionService}from'../src/device-sessions.js';import{authenticator}from'./passkey-fixture.js';
import{CodeCipher}from'../src/code-cipher.js';import{SourceEntryStore}from'../src/source-entries.js';import{createEntryManageHttp}from'../src/entry-manage-http.js';
const NOW=1800000000000,API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io';
async function fx(native=true){
 const db=database(),a=authenticator(),clock=()=>NOW,identity=new AccountIdentityService(db,{clock}),signup=new PasskeySignupService(db,{clock}),e=await identity.issueEmailChallenge({purpose:'signup-email',email:'em@example.test'}),c=await signup.begin({email:'em@example.test',emailToken:e.token,binding:'fixture'}),account=await signup.finish({token:c.token,binding:'fixture',response:a.registration({expected:c.options.challenge})}),sessions=new DeviceSessionService(db,{clock});
 const mk=kind=>sessions.issue({proof:{...account,purpose:'authenticate',verifiedAt:NOW},clientKind:kind}),web=await mk('web'),android=await mk('android');
 const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']),store=new SourceEntryStore(db,new CodeCipher({keys:new Map([['f',key]]),activeKeyId:'f'})),entryId=await store.createEntry(account.ownerId,'test','Target',NOW);
 const http=createEntryManageHttp({db,sessions,clock,native}),
  run=(path,body,{token,origin,ct='application/json',method='POST'}={})=>http.fetch(new Request(API+'/v1/manage/entry/'+path,{method,headers:{...(origin?{Origin:origin}:{}),Authorization:'Bearer '+token,'Content-Type':ct},...(method==='POST'?{body:JSON.stringify(body)}:{})}));
 return{db,web,android,entryId,run,account,row:()=>db.sqlite.prepare('SELECT label,account_name,mutation_revision FROM entries WHERE entry_id=?').get(entryId),sessions};
}
test('android: rename and account with no Origin, exact JSON, no CORS, same strict fields, revision and outbox bump like web',async()=>{const f=await fx();try{
 const before=f.row().mutation_revision,ob=f.db.sqlite.prepare('SELECT count(*) n FROM realtime_outbox').get().n;
 const r=await f.run('rename',{entryId:f.entryId,label:'  Phone label  '},{token:f.android.access});assert.equal(r.status,200);assert.deepEqual(await r.json(),{ok:true});assert.equal(r.headers.get('access-control-allow-origin'),null);assert.equal(r.headers.get('cache-control'),'no-store');
 assert.equal(f.row().label,'Phone label');assert.notEqual(f.row().mutation_revision,before);assert.ok(f.db.sqlite.prepare('SELECT count(*) n FROM realtime_outbox').get().n>ob);
 assert.equal((await f.run('account',{entryId:f.entryId,accountName:'me@x.test'},{token:f.android.access})).status,200);assert.equal(f.row().account_name,'me@x.test');
 assert.equal((await f.run('account',{entryId:f.entryId,accountName:null},{token:f.android.access})).status,200);assert.equal(f.row().account_name,null);
 const same=f.row().mutation_revision;assert.equal((await f.run('rename',{entryId:f.entryId,label:'Phone label'},{token:f.android.access})).status,200);assert.equal(f.row().mutation_revision,same);// identical write is a no-op
 for(const bad of [{entryId:f.entryId},{entryId:f.entryId,label:''},{entryId:f.entryId,label:'x'.repeat(121)},{entryId:f.entryId,label:'a',extra:1},{entryId:'bad id',label:'a'},{entryId:f.entryId,label:5}])assert.equal((await f.run('rename',bad,{token:f.android.access})).status,400);
 assert.equal((await f.run('rename',{entryId:f.entryId,label:'a'},{token:f.android.access,ct:'application/json; charset=utf-8'})).status,400);// exactly application/json
 assert.equal((await f.run('rename',{entryId:'missing',label:'a'},{token:f.android.access})).status,404);
 assert.equal((await f.run('rename',{},{token:f.android.access,method:'OPTIONS'})).status,405);assert.equal((await f.run('rename',{entryId:f.entryId,label:'a'},{token:f.android.access,method:'GET'})).status,405);}finally{f.db.sqlite.close();}});
test('android/web segregation: web token without Origin and android token with Origin are refused; web still works only with APP Origin; foreign Origin refused',async()=>{const f=await fx();try{
 const b={entryId:f.entryId,label:'Z'};
 assert.equal((await f.run('rename',b,{token:f.web.access})).status,401);assert.equal((await f.run('rename',b,{token:f.android.access,origin:APP})).status,401);
 assert.equal((await f.run('rename',b,{token:f.web.access,origin:'https://evil.test'})).status,403);assert.equal((await f.run('rename',b,{token:f.android.access,origin:'https://evil.test'})).status,403);
 assert.equal(f.row().label,'Target');
 const w=await f.run('rename',b,{token:f.web.access,origin:APP});assert.equal(w.status,200);assert.equal(w.headers.get('access-control-allow-origin'),APP);assert.equal(f.row().label,'Z');}finally{f.db.sqlite.close();}});
test('native off (default): no-Origin requests are refused 403 even with an android token',async()=>{const f=await fx(false);try{assert.equal((await f.run('rename',{entryId:f.entryId,label:'Z'},{token:f.android.access})).status,403);assert.equal(f.row().label,'Target');}finally{f.db.sqlite.close();}});
test('android: owner-only (other owner 404), revoked session refused, write conditioned on android kind',async()=>{const f=await fx();try{
 const o2=await new PasskeySignupService(f.db,{clock:()=>NOW}).begin({email:'o2@example.test',emailToken:(await new AccountIdentityService(f.db,{clock:()=>NOW}).issueEmailChallenge({purpose:'signup-email',email:'o2@example.test'})).token,binding:'f2'}),acc2=await new PasskeySignupService(f.db,{clock:()=>NOW}).finish({token:o2.token,binding:'f2',response:authenticator().registration({expected:o2.options.challenge})});f.db.sqlite.prepare("INSERT INTO entries(entry_id,owner_id,service_id,label,created_at) VALUES ('e2',?,'service','Other',1)").run(acc2.ownerId);
 assert.equal((await f.run('rename',{entryId:'e2',label:'Hack'},{token:f.android.access})).status,404);assert.equal(f.db.sqlite.prepare("SELECT label FROM entries WHERE entry_id='e2'").get().label,'Other');
 await f.sessions.revoke({ownerId:f.account.ownerId,deviceId:f.android.deviceId});assert.equal((await f.run('rename',{entryId:f.entryId,label:'Z'},{token:f.android.access})).status,401);assert.equal(f.row().label,'Target');}finally{f.db.sqlite.close();}});
