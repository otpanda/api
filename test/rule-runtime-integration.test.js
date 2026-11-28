import test from 'node:test';import assert from 'node:assert/strict';
import{database}from'./sqlite-helper.js';import{AccountIdentityService}from'../src/account-identity.js';import{PasskeySignupService}from'../src/passkey-signup.js';import{PasskeyService}from'../src/passkey-service.js';import{DeviceSessionService}from'../src/device-sessions.js';import{authenticator}from'./passkey-fixture.js';
import{CodeCipher}from'../src/code-cipher.js';import{SourceEntryStore}from'../src/source-entries.js';import{AssignmentIntents}from'../src/assignment-intents.js';import{createEntryRulesHttp}from'../src/entry-rules-http.js';import{ServiceMetadata}from'../src/service-metadata.js';
const SECRET=Array.from({length:32},(_,i)=>(i*7+13).toString(16).padStart(2,'0')).join('');
const NOW=1800000000000,API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io';
async function acct(db,email,clock,a){
 const identity=new AccountIdentityService(db,{clock}),signup=new PasskeySignupService(db,{clock}),e=await identity.issueEmailChallenge({purpose:'signup-email',email}),c=await signup.begin({email,emailToken:e.token,binding:'b-'+email});
 return signup.finish({token:c.token,binding:'b-'+email,response:a.registration({expected:c.options.challenge})});
}
async function fx({rules=true}={}){
 const db=database(),clock=()=>NOW,a=authenticator(),b=authenticator(),sessions=new DeviceSessionService(db,{clock}),account=await acct(db,'own@example.test',clock,a),other=await acct(db,'rcpt@example.test',clock,b);
 const mk=(acc,kind)=>sessions.issue({proof:{...acc,purpose:'authenticate',verifiedAt:NOW},clientKind:kind});
 const web=await mk(account,'web'),android=await mk(account,'android'),otherWeb=await mk(other,'web'),auth=await sessions.authenticate(web.access);
 const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']),cipher=new CodeCipher({keys:new Map([['f',key]]),activeKeyId:'f'}),meta=new ServiceMetadata(db),store=new SourceEntryStore(db,cipher,{matcher:meta,templateSecret:SECRET});
 const o=account.ownerId;db.sqlite.prepare("INSERT OR IGNORE INTO services(service_id,name)VALUES('test','Test'),('custom-totp','Authenticator')").run();
 const gmail=await store.createSource(o,'gmail','Personal Gmail',NOW),phone=await store.createSource(o,'sms','Phone',NOW),entry=await store.createEntry(o,'test','Target',NOW),entry2=await store.createEntry(o,'test','Second',NOW),custom=await store.createEntry(o,'custom-totp','Mine',NOW),custom2=await store.createEntry(o,'custom-totp','Mine2',NOW);
 await meta.setReceiver(o,gmail,'me@example.test');await meta.setReceiver(o,phone,'+15550001111');
 const passkeys=new PasskeyService(db,{clock}),intents=new AssignmentIntents({db,passkeys,cipher,clock,rules}),http=createEntryRulesHttp({db,sessions,metadata:meta,clock,native:true});
 const call=(token,path,{method='GET',body,origin=APP}={})=>http.fetch(new Request(API+path,{method,headers:{...(origin?{Origin:origin}:{}),Authorization:'Bearer '+token,...(body!==undefined?{'Content-Type':'application/json'}:{})},...(body!==undefined?{body:JSON.stringify(body)}:{})}));
 const mail=(eventId,over={})=>({sourceId:gmail,eventId,code:'123456',receivedAt:NOW-1000,expiresAt:NOW+60000,sender:'noreply@bank.example',receiver:'me@example.test',accountHint:'me@example.test',text:'Your bank code',subject:'Your bank code',...over});
 const sms=(eventId,over={})=>({sourceId:phone,eventId,code:'654321',receivedAt:NOW-1000,expiresAt:NOW+60000,sender:'+15557778888',receiver:'+15550001111',text:'Netflix code 654321',...over});
 const begin=(ev,entryId,phrase)=>intents.begin(auth,{sourceId:ev.sourceId,eventId:ev.eventId,entryId,...(phrase!==undefined?{phrase}:{})});
 const finish=(bg,over={})=>intents.finish(auth,{intentId:bg.intentId,token:bg.token,action:over.action??bg.action,response:bg.options?a.assertion({expected:bg.options.challenge}):undefined});
 const assign=async(ev,entryId,phrase)=>{await store.receive(o,ev);const bg=await begin(ev,entryId,phrase);assert.ok(bg);return{bg,res:await finish(bg)};};
 const rows=()=>db.sqlite.prepare('SELECT * FROM service_routes ORDER BY route_id').all();
 return{key,db,store,meta,o,other,web,android,otherWeb,gmail,phone,entry,entry2,custom,custom2,call,mail,sms,begin,finish,assign,intents,auth,rows,sessions};
}

import {createIdentityRuntime} from '../src/identity-runtime.js';
test('actual main identity runtime: v3 Assign, list, revoke/reconnect paused, signed v5 Resume and Edit',async()=>{
 const f=await fx();try{
  const runtime=createIdentityRuntime({db:f.db,trustedRequestKey:()=> '192.0.2.1',keys:new Map([['f',f.key]]),activeKeyId:'f',templateSecret:SECRET,context:{contextRetentionMs:30*86400000,contextDigestSecret:SECRET},native:{enabled:true},clock:()=>NOW});
  const post=async(path,body)=>{const r=await runtime.fetch(new Request(API+'/v1/manage/'+path,{method:'POST',headers:{Origin:APP,Authorization:'Bearer '+f.web.access,'Content-Type':'application/json'},body:JSON.stringify(body)}));assert.equal(r.status,200,path+': '+r.status);return r.json();};
  await f.store.receive(f.o,f.mail('runtime-event'));
  const bg=await post('assignment/begin',{sourceId:f.gmail,eventId:'runtime-event',entryId:f.entry});assert.equal(JSON.parse(bg.action)[1],3);assert.equal(bg.summary.rule.status,'will_save');
  const assigned=await post('assignment/finish',{intentId:bg.intentId,action:bg.action});assert.equal(assigned.rule.status,'saved');
  const list=async()=>{const r=await runtime.fetch(new Request(API+'/v1/manage/entry/rules',{headers:{Origin:APP,Authorization:'Bearer '+f.web.access}}));assert.equal(r.status,200);return(await r.json()).rules;};
  let rule=(await list())[0];assert.equal(rule.status,'active');
  f.db.sqlite.prepare('UPDATE sources SET revoked_at=? WHERE source_id=?').run(NOW,f.gmail);rule=(await list())[0];assert.equal(rule.status,'paused');
  f.db.sqlite.prepare('UPDATE sources SET revoked_at=NULL WHERE source_id=?').run(f.gmail);rule=(await list())[0];assert.equal(rule.status,'paused');
  const resume=await post('rule-intent/begin',{operation:'resume',entryId:f.entry,ruleId:rule.ruleId});assert.equal(JSON.parse(resume.action)[1],5);assert.equal(resume.summary.resumesPausedRule,true);
  const result=await post('rule-intent/finish',{intentId:resume.intentId,action:resume.action});assert.deepEqual(result,{status:'applied',rule:{status:'resumed'}});assert.deepEqual(await post('rule-intent/status',{intentId:resume.intentId}),result);
  const edit=await post('rule-intent/begin',{operation:'edit',entryId:f.entry,ruleId:rule.ruleId,phrase:'bank'});assert.equal(edit.summary.basisBefore,'template');assert.equal(edit.summary.basis,'phrase');
  assert.equal((await post('rule-intent/finish',{intentId:edit.intentId,action:edit.action})).rule.status,'updated');assert.equal((await list())[0].phrase,'bank');
 }finally{f.db.sqlite.close();}
});

import {createAuthOnlyWorker} from '../src/auth-only-worker.js';
test('public auth-only Worker mounts rules and permits proof-free private Android Resume finish',async()=>{
 const f=await fx();try{
  const raw=new Uint8Array(await crypto.subtle.exportKey('raw',await crypto.subtle.generateKey({name:'AES-GCM',length:256},true,['encrypt','decrypt'])));
  // Private Assign is exercised by the runtime above;
  // this route-level check seeds a phrase rule, which does not need encrypted message material.
  f.db.sqlite.prepare("INSERT INTO service_routes(route_id,owner_id,service_id,source_id,origin_kind,origin_value,entry_id,phrase,paused_at,created_at) VALUES('paused-native',?,'test',?,'email_address','noreply@bank.example',?,'bank',?,?)").run(f.o,f.gmail,f.entry,NOW-1000,NOW-2000);
  const yes={limit:async()=>({success:true})},env={DB:f.db,DEPLOYMENT_STAGE:'auth-only',AUTH_ONLY_SIGNUP_EMAIL:'own@example.test',NATIVE_AUTH_ENABLED:'1',NATIVE_ASSET_FINGERPRINTS:Array(32).fill('AA').join(':'),ACTIVE_KEY_ID:'f',ENCRYPTION_KEYRING:JSON.stringify([{id:'f',key:Buffer.from(raw).toString('base64url')}]),CONTEXT_DIGEST_SECRET:SECRET,CONTEXT_RETENTION_DAYS:'30',IDENTITY_ADDRESS_LIMIT:yes,IDENTITY_AUTH_GLOBAL_LIMIT:yes,IDENTITY_READ_GLOBAL_LIMIT:yes};
  const worker=createAuthOnlyWorker({clock:()=>NOW}),call=async(path,body)=>{
   const r=new Request(API+'/v1/manage/'+path,{method:body?'POST':'GET',headers:{'CF-Connecting-IP':'192.0.2.51',Authorization:'Bearer '+f.android.access,...(body?{'Content-Type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{})});Object.defineProperty(r,'cf',{value:{colo:'LHR',httpProtocol:'HTTP/2',tlsVersion:'TLSv1.3'}});
   const out=await worker.fetch(r,env,{waitUntil(){}});assert.equal(out.status,200,path+': '+out.status+' '+await out.clone().text());return out.json();
  };
  const probe=async({origin=null,token=f.android.access,method='GET'}={})=>{
   const r=new Request(API+'/v1/manage/rules/capabilities',{method,headers:{'CF-Connecting-IP':'192.0.2.51',...(origin?{Origin:origin}:{}),...(token?{Authorization:'Bearer '+token}:{})}});Object.defineProperty(r,'cf',{value:{colo:'LHR',httpProtocol:'HTTP/2',tlsVersion:'TLSv1.3'}});return worker.fetch(r,env,{waitUntil(){}});
  };
  for(const [origin,token]of [[null,f.android.access],[APP,f.web.access]]){
   const r=await probe({origin,token});assert.equal(r.status,200);assert.deepEqual(await r.json(),{version:1,rules:{available:true,managementAvailable:true,disconnectPolicy:true}});
   assert.equal((await probe({origin,token:null})).status,401);assert.equal((await probe({origin,token,method:'POST'})).status,405);
  }
  assert.equal((await probe({origin:'https://foreign.invalid',token:f.web.access})).status,403);
  assert.deepEqual(await call('rules/capabilities'),{version:1,rules:{available:true,managementAvailable:true,disconnectPolicy:true}});
  assert.equal((await call('entry/rules')).rules[0].status,'paused');
  const bg=await call('rule-intent/begin',{operation:'resume',entryId:f.entry,ruleId:'paused-native'});assert.equal(bg.proofRequired,false);
  assert.deepEqual(await call('rule-intent/finish',{intentId:bg.intentId,action:bg.action}),{status:'applied',rule:{status:'resumed'}});
  assert.equal((await call('rule-intent/status',{intentId:bg.intentId})).status,'applied');
  assert.equal((await call('unassigned-context')).contexts instanceof Array,true);
 }finally{f.db.sqlite.close();}
});
test('mounted capability requires auth, operational keys/retention/schema and lifecycle migration; off keeps legacy Assign',async()=>{
 const f=await fx();try{
 for(const cfg of [{expected:false},{templateSecret:SECRET,expected:false},{templateSecret:SECRET,context:{contextRetentionMs:30*86400000,contextDigestSecret:SECRET},expected:true}]){
 const runtime=createIdentityRuntime({db:f.db,trustedRequestKey:()=> '192.0.2.1',keys:new Map([['f',f.key]]),activeKeyId:'f',native:{enabled:true},clock:()=>NOW,...cfg});
 const get=token=>runtime.fetch(new Request(API+'/v1/manage/rules/capabilities',{headers:{Origin:APP,Authorization:'Bearer '+token}}));assert.equal((await get('bad')).status,401);const r=await get(f.web.access);assert.equal(r.status,200);assert.deepEqual(await r.json(),{version:1,rules:{available:cfg.expected,managementAvailable:true,disconnectPolicy:true}});
 }
 f.db.sqlite.prepare('DROP TRIGGER sources_pause_rules_on_revoke').run();const runtime=createIdentityRuntime({db:f.db,trustedRequestKey:()=> '192.0.2.1',keys:new Map([['f',f.key]]),activeKeyId:'f',templateSecret:SECRET,context:{contextRetentionMs:30*86400000,contextDigestSecret:SECRET},clock:()=>NOW});const r=await runtime.fetch(new Request(API+'/v1/manage/rules/capabilities',{headers:{Origin:APP,Authorization:'Bearer '+f.web.access}}));assert.deepEqual(await r.json(),{version:1,rules:{available:false,managementAvailable:true,disconnectPolicy:false}});
 }finally{f.db.sqlite.close();}
});
test('config-off preserves existing list/delete, legacy code-only Assign rejects phrase and creates no rule; issued rule finish survives config flip',async()=>{
 const f=await fx();try{
 await f.assign(f.mail('retained'),f.entry);const rule=f.rows()[0];
 const make=on=>createIdentityRuntime({db:f.db,trustedRequestKey:()=> '192.0.2.1',keys:new Map([['f',f.key]]),activeKeyId:'f',templateSecret:on?SECRET:null,context:on?{contextRetentionMs:30*86400000,contextDigestSecret:SECRET}:{},clock:()=>NOW});
 const on=make(true),off=make(false),call=(rt,path,body)=>rt.fetch(new Request(API+'/v1/manage/'+path,{method:body?'POST':'GET',headers:{Origin:APP,Authorization:'Bearer '+f.web.access,...(body?{'Content-Type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{})}));
 const b=await(await call(on,'rule-intent/begin',{operation:'edit',ruleId:rule.route_id,entryId:f.entry,phrase:'bank'})).json();assert.ok(b.intentId);
 assert.equal((await call(off,'rule-intent/begin',{operation:'edit',ruleId:rule.route_id,entryId:f.entry,phrase:'other'})).status,503);
 const fin=await call(off,'rule-intent/finish',{intentId:b.intentId,action:b.action});assert.equal(fin.status,200);assert.equal((await fin.json()).status,'applied');assert.equal((await(await call(off,'rule-intent/status',{intentId:b.intentId})).json()).status,'applied');
 assert.equal((await call(off,'entry/rules')).status,200);
 await f.store.receive(f.o,f.mail('off-assign',{sender:'other@bank.example'}));const input={sourceId:f.gmail,eventId:'off-assign',entryId:f.entry2};assert.notEqual((await call(off,'assignment/begin',{...input,phrase:'bank'})).status,200);
 const a=await(await call(off,'assignment/begin',input)).json();assert.equal(JSON.parse(a.action)[1],1);const assigned=await call(off,'assignment/finish',{intentId:a.intentId,action:a.action});assert.equal(assigned.status,200);assert.deepEqual(await assigned.json(),{status:'assigned'});assert.equal(f.rows().length,1);
 assert.equal((await call(off,'entry/rule/delete',{ruleId:rule.route_id})).status,200);assert.equal(f.rows().length,0);
 }finally{f.db.sqlite.close();}
});
test('partial schema missing causal revision trigger advertises create unavailable but preserves management',async()=>{
 const f=await fx();try{f.db.sqlite.prepare('DROP TRIGGER audience_machine_profile_entries_delete').run();const rt=createIdentityRuntime({db:f.db,trustedRequestKey:()=> '192.0.2.1',keys:new Map([['f',f.key]]),activeKeyId:'f',templateSecret:SECRET,context:{contextRetentionMs:30*86400000,contextDigestSecret:SECRET},clock:()=>NOW});const r=await rt.fetch(new Request(API+'/v1/manage/rules/capabilities',{headers:{Origin:APP,Authorization:'Bearer '+f.web.access}}));assert.deepEqual(await r.json(),{version:1,rules:{available:false,managementAvailable:true,disconnectPolicy:true}});
 }finally{f.db.sqlite.close();}
});
test('same-named old 0065 machine trigger body fails operational readiness',async()=>{
 const f=await fx();try{const fs=await import('node:fs/promises'),sql=await fs.readFile(new URL('../migrations/0065_action_audience_revisions.sql',import.meta.url),'utf8'),old=sql.match(/CREATE TRIGGER audience_machine_profile_entries_delete .*?END;/s)[0];f.db.sqlite.prepare('DROP TRIGGER audience_machine_profile_entries_delete').run();f.db.sqlite.exec(old);
 const rt=createIdentityRuntime({db:f.db,trustedRequestKey:()=> '192.0.2.1',keys:new Map([['f',f.key]]),activeKeyId:'f',templateSecret:SECRET,context:{contextRetentionMs:30*86400000,contextDigestSecret:SECRET},clock:()=>NOW});const r=await rt.fetch(new Request(API+'/v1/manage/rules/capabilities',{headers:{Origin:APP,Authorization:'Bearer '+f.web.access}}));assert.deepEqual(await r.json(),{version:1,rules:{available:false,managementAvailable:true,disconnectPolicy:true}});
 }finally{f.db.sqlite.close();}
});
