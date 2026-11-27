import {expireRecoveryCodeJobs as expireJobs,deliverRecoveryCodeJob as deliverJob} from '../src/recovery-notifier.js';
import test from 'node:test';import assert from 'node:assert/strict';
import {DeviceSessionService} from '../src/device-sessions.js';import {PasskeyService} from '../src/passkey-service.js';import {database} from './sqlite-helper.js';import {authenticator} from './passkey-fixture.js';
import {hashText} from '../src/sessions.js';import {ExtraVerification} from '../src/extra-verification.js';
import {RecoveryControls,recoveryAction,DELAY_MS} from '../src/recovery-controls.js';import {createRecoveryControlsHttp} from '../src/recovery-controls-http.js';
import {createIdentityRuntime} from '../src/identity-runtime.js';
const NOW=1800000000000,API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io';
const key=(db,a)=>db.sqlite.prepare('INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) VALUES(?,?,?,?,?,?,?,?)').run(a.credential.id,'owner',a.credential.publicKey,0,'[]','singleDevice',0,NOW);
async function setup({google=true,second=true,lv}={}){const db=database(),t={now:NOW},clock=()=>t.now;
 db.sqlite.prepare('INSERT INTO accounts(owner_id,created_at) VALUES(?,?)').run('owner',NOW);db.sqlite.prepare('INSERT INTO account_emails VALUES(?,?,?,?)').run('owner','a@gmail.com',NOW,NOW);db.sqlite.prepare('INSERT INTO account_security(owner_id) VALUES(?)').run('owner');
 db.sqlite.prepare("INSERT INTO provider_identities(identity_id,owner_id,provider,issuer,subject,email,created_at) VALUES('one','owner','google','https://accounts.google.com','one','a@gmail.com',?)").run(NOW);
 if(!google)db.sqlite.prepare('UPDATE provider_identities SET revoked_at=?').run(NOW);
 const a=authenticator(),b=authenticator();key(db,a);if(second)key(db,b);
 const sessions=new DeviceSessionService(db,{clock}),passkeys=new PasskeyService(db,{clock});
 const mk=async()=>sessions.issue({proof:{authMethod:'google',issuer:'https://accounts.google.com',subject:'one',ownerId:'owner',generation:0,purpose:'authenticate',verifiedAt:NOW},clientKind:'web'});
 const d=await mk();
 const http=createRecoveryControlsHttp({db,sessions,clock,passkeys,service:new RecoveryControls(db,{clock,localVerification:lv})});
 const call=(step,value,{auth=d.access,method=step==='status'?'GET':'POST',origin=APP}={})=>http.fetch(new Request(API+'/v1/manage/recovery/'+step,{method,headers:{Origin:origin,'Content-Type':'application/json',...(auth?{Authorization:'Bearer '+auth}:{})},...(method==='POST'?{body:JSON.stringify(value??{})}:{})}),{clientAddress:'t'});
 // full flow with a given authenticator; action kind and target can be overridden for the assertion.
 let n=0;const flow=async(kind,{target,by=a,extra={},actionKind=kind,actionTarget=target,auth=d.access}={})=>{const base={kind,...(target!==undefined?{target}:{}),...extra};
  const bg=await call('begin',base,{auth});if(bg.status!==200)return bg;const c=await bg.json();
  return call('finish',{...base,token:c.token,response:by.assertion({expected:c.options.challenge,counter:++n})},{auth});};
 return{db,t,a,b,sessions,passkeys,d,mk,call,flow,clock,http};}
const optin=db=>db.sqlite.prepare('SELECT * FROM email_recovery_optin').all();
const active=db=>db.sqlite.prepare('SELECT credential_id id FROM passkey_credentials WHERE revoked_at IS NULL').all().map(x=>x.id);
test('escape hatch defaults off; enable needs warning and fresh passkey proof, stores exactly seven days, disable reverts',async()=>{const x=await setup();
 let s=await (await x.call('status')).json();assert.equal(s.emailEscape.enabled,false);assert.equal(s.emailEscape.delayDays,7);assert.equal(DELAY_MS,604800000);
 assert.equal((await x.flow('email-escape-on')).status,400);assert.equal((await x.flow('email-escape-on',{extra:{warningAccepted:false}})).status,400);assert.equal(optin(x.db).length,0);
 const r=await x.flow('email-escape-on',{extra:{warningAccepted:true}});assert.equal(r.status,200);assert.deepEqual(await r.json(),{emailEscape:true});
 assert.equal(optin(x.db)[0].delay_ms,604800000);s=await (await x.call('status')).json();assert.equal(s.emailEscape.enabled,true);
 assert.equal((await x.flow('email-escape-off')).status,200);assert.equal(optin(x.db).length,0);});
test('a Google-only session, stale proof, wrong-action proof and unknown kinds cannot change the setting',async()=>{const x=await setup();
 const svc=new RecoveryControls(x.db,{clock:x.clock}),user={ownerId:'owner',deviceId:x.d.deviceId,generation:0};
 const proof=async(o={})=>({purpose:'step-up',ownerId:'owner',credentialId:x.a.credential.id,generation:0,verifiedAt:NOW,actionDigest:await hashText(recoveryAction('email-escape-on')),...o});
 assert.ok(await svc.apply({user,kind:'email-escape-on',proof:await proof(),warningAccepted:true}));x.db.sqlite.prepare('DELETE FROM email_recovery_optin').run();
 for(const bad of [{verifiedAt:NOW-120000},{actionDigest:await hashText('passkey:add')},{actionDigest:await hashText(recoveryAction('email-escape-off'))},{generation:1},{ownerId:'x'},{purpose:'authenticate'},{credentialId:'nope'}])assert.equal(await svc.apply({user,kind:'email-escape-on',proof:await proof(bad),warningAccepted:true}),undefined,JSON.stringify(bad));
 assert.equal(await svc.apply({user,kind:'bogus',proof:await proof(),warningAccepted:true}),undefined);assert.equal(await svc.apply({user,kind:'email-escape-on',proof:await proof(),warningAccepted:false}),undefined);assert.equal(optin(x.db).length,0);
 assert.equal((await x.call('begin',{kind:'email-escape-on',warningAccepted:true},{auth:null})).status,401);assert.equal((await x.call('begin',{kind:'email-escape-on',warningAccepted:true},{origin:'https://evil.test'})).status,403);
 assert.equal((await x.call('begin',{kind:'email-escape-on',warningAccepted:true,x:1})).status,400);assert.equal((await x.call('begin',{kind:'passkey-revoke'})).status,400);assert.equal((await x.call('begin',{kind:'session-revoke',target:'t',warningAccepted:true})).status,400);});
test('escape hatch and Google new-device protection are mutually exclusive in both directions, no silent toggle',async()=>{const x=await setup();
 const ev=new ExtraVerification(x.db,{clock:x.clock}),proof=async action=>({purpose:'step-up',ownerId:'owner',credentialId:x.a.credential.id,generation:0,verifiedAt:NOW,actionDigest:await hashText(action)});
 assert.equal((await x.flow('email-escape-on',{extra:{warningAccepted:true}})).status,200);
 assert.equal(await ev.enable({proof:await proof('extra-verification:enable'),warningAccepted:true}),undefined);assert.equal(await ev.enabled('owner'),false);
 assert.equal(await ev.createSettingChange({...{ownerId:'owner',deviceId:x.d.deviceId,generation:0},enabled:true,warningAccepted:true}),undefined);
 assert.throws(()=>x.db.sqlite.prepare('INSERT INTO new_device_verification VALUES(?,?,?)').run('owner',NOW,0),/exclusive/);
 assert.equal(optin(x.db).length,1);
 x.db.sqlite.prepare('DELETE FROM email_recovery_optin').run();assert.ok(await ev.enable({proof:await proof('extra-verification:enable'),warningAccepted:true}));
 assert.equal((await x.flow('email-escape-on',{extra:{warningAccepted:true}})).status,403);assert.equal(optin(x.db).length,0);assert.equal(await ev.enabled('owner'),true);
 assert.throws(()=>x.db.sqlite.prepare('INSERT INTO email_recovery_optin VALUES(?,?,?,?)').run('owner',NOW,0,DELAY_MS),/exclusive/);
 const s=await (await x.call('status')).json();assert.equal(s.emailEscape.blockedByGoogleProtection,true);assert.equal(s.emailEscape.enabled,false);});
test('client-approved enable batch is refused cleanly when the escape hatch was enabled after the request',async()=>{const x=await setup(),ev=new ExtraVerification(x.db,{clock:x.clock,localVerification:async()=>true}),u={ownerId:'owner',deviceId:x.d.deviceId,generation:0};
 x.db.sqlite.prepare('UPDATE device_sessions SET browser_binding_digest=? WHERE device_id=?').run('a'.repeat(64),x.d.deviceId);const d2=await x.sessions.issue({proof:{ownerId:'owner',credentialId:x.a.credential.id,generation:0,purpose:'authenticate',verifiedAt:NOW},clientKind:'web'});x.db.sqlite.prepare('UPDATE device_sessions SET browser_binding_digest=? WHERE device_id=?').run('3'.repeat(64),d2.deviceId);const u2={ownerId:'owner',deviceId:d2.deviceId,generation:0};
 const c=await ev.createSettingChange({...u,enabled:true,warningAccepted:true});assert.ok(c);assert.ok(await ev.approveSettingChange({...u2,changeId:c.changeId}));
 x.db.sqlite.prepare('INSERT INTO email_recovery_optin VALUES(?,?,?,?)').run('owner',NOW,0,DELAY_MS);
 assert.equal(await ev.consumeSettingChange({...u,changeId:c.changeId}),undefined);assert.equal(await ev.enabled('owner'),false);
 assert.equal(x.db.sqlite.prepare('SELECT consumed_at FROM setting_changes').get().consumed_at,null);});
test('lost passkey is revoked by another passkey; self-revoke and wrong-action proofs fail; revoked key cannot sign sessions',async()=>{const x=await setup();
 assert.equal((await x.flow('passkey-revoke',{target:x.a.credential.id})).status,403);assert.equal(active(x.db).length,2);
 const wrong=await x.call('begin',{kind:'passkey-revoke',target:x.a.credential.id}),c=await wrong.json();
 const r=await x.call('finish',{kind:'passkey-revoke',target:x.b.credential.id,token:c.token,response:x.b.assertion({expected:c.options.challenge,counter:99})});assert.equal(r.status,403);assert.equal(active(x.db).length,2);
 const ok=await x.flow('passkey-revoke',{target:x.a.credential.id,by:x.b});assert.equal(ok.status,200);assert.deepEqual(active(x.db),[x.b.credential.id]);
 assert.equal((await x.flow('passkey-revoke',{target:x.a.credential.id,by:x.a})).status,403);
 assert.equal((await x.flow('passkey-revoke',{target:x.b.credential.id,by:x.b})).status,403);assert.deepEqual(active(x.db),[x.b.credential.id]);
 assert.equal((await x.flow('passkey-revoke',{target:'unknown',by:x.b})).status,403);});
test('last passkey is kept unless an active Google link remains (case 9 vs case 11)',async()=>{
 for(const google of [false,true]){const x=await setup({google}),ps=new PasskeyService(x.db,{clock:x.clock});
  assert.equal(await ps.revoke({ownerId:'owner',credentialId:x.b.credential.id}),true);
  assert.equal(await ps.revoke({ownerId:'owner',credentialId:x.a.credential.id}),google);assert.equal(active(x.db).length,google?0:1);}});
test('session revoke needs fresh passkey proof, only reaches the caller owner, and revoking the current session still succeeds',async()=>{const x=await setup(),other=await x.mk();
 assert.equal((await x.call('begin',{kind:'session-revoke',target:other.deviceId})).status,200);
 assert.equal((await x.flow('session-revoke',{target:other.deviceId})).status,200);assert.ok(x.db.sqlite.prepare('SELECT revoked_at FROM device_sessions WHERE device_id=?').get(other.deviceId).revoked_at);
 assert.equal((await x.flow('session-revoke',{target:other.deviceId})).status,403);
 const fo=authenticator();x.db.sqlite.prepare("INSERT INTO accounts(owner_id,created_at) VALUES('o2',?)").run(NOW);x.db.sqlite.prepare('INSERT INTO account_security(owner_id) VALUES(?)').run('o2');
 x.db.sqlite.prepare('INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) VALUES(?,?,?,?,?,?,?,?)').run(fo.credential.id,'o2',fo.credential.publicKey,0,'[]','singleDevice',0,NOW);
 x.db.sqlite.prepare("INSERT INTO device_sessions(device_id,owner_id,credential_id,provider_identity_id,generation,client_kind,created_at,last_used_at,expires_at) VALUES('foreign','o2',?,NULL,0,'web',1,1,?)").run(fo.credential.id,NOW+1e9);
 assert.equal((await x.flow('session-revoke',{target:'foreign'})).status,403);assert.equal(x.db.sqlite.prepare("SELECT revoked_at FROM device_sessions WHERE device_id='foreign'").get().revoked_at,null);
 assert.equal((await x.flow('passkey-revoke',{target:fo.credential.id,by:x.b})).status,403);assert.equal(x.db.sqlite.prepare('SELECT revoked_at FROM passkey_credentials WHERE credential_id=?').get(fo.credential.id).revoked_at,null);
 {const {call}=await clients(x),ap=await x.sessions.issue({proof:{ownerId:'owner',credentialId:x.a.credential.id,generation:0,purpose:'authenticate',verifiedAt:NOW},clientKind:'web'});bind(x,ap.deviceId,'5');
  const c=await call('request-change',{kind:'session-revoke',target:'foreign'},x.d.access);const {changeId}=await c.json();await call('approve-change',{changeId},ap.access);await call('consume-change',{changeId},x.d.access);
  assert.equal(x.db.sqlite.prepare("SELECT revoked_at FROM device_sessions WHERE device_id='foreign'").get().revoked_at,null);}
 const s=await (await x.call('status')).json();assert.ok(!s.sessions.some(z=>z.id==='foreign'||z.id===x.d.deviceId&&!z.current));assert.equal(s.sessions.filter(z=>z.current).length,1);
 assert.equal((await x.flow('session-revoke',{target:x.d.deviceId})).status,200);assert.equal((await x.call('status')).status,401);});
test('runtime mounts the three routes; unknown steps stay 404',async()=>{const db=database(),rt=createIdentityRuntime({db,keys:{},activeKeyId:'k',trustedRequestKey:async()=>'203.0.113.9',clock:()=>NOW});
 for(const [s,m] of [['status','GET'],['begin','POST'],['finish','POST']])assert.equal((await rt.fetch(new Request(API+'/v1/manage/recovery/'+s,{method:m,headers:{Origin:APP,'Content-Type':'application/json'},...(m==='POST'?{body:'{}'}:{})}))).status,401);
 assert.equal((await rt.fetch(new Request(API+'/v1/manage/recovery/other',{method:'POST',headers:{Origin:APP,'Content-Type':'application/json'},body:'{}'}))).status,404);db.sqlite.close();});

test('Google-link allowance never bypasses the protection-on last-key guard',async()=>{const x=await setup(),ps=new PasskeyService(x.db,{clock:x.clock}),ev=new ExtraVerification(x.db,{clock:x.clock});
 assert.ok(await ev.enable({proof:{purpose:'step-up',ownerId:'owner',credentialId:x.a.credential.id,generation:0,verifiedAt:NOW,actionDigest:await hashText('extra-verification:enable')},warningAccepted:true}));
 assert.equal(await ps.revoke({ownerId:'owner',credentialId:x.b.credential.id}),true);
 assert.equal(await ps.revoke({ownerId:'owner',credentialId:x.a.credential.id}),false);assert.deepEqual(active(x.db),[x.a.credential.id]);
 assert.throws(()=>x.db.sqlite.prepare('UPDATE passkey_credentials SET revoked_at=1 WHERE credential_id=?').run(x.a.credential.id),/last verifier/);
 x.db.sqlite.prepare('DELETE FROM new_device_verification').run();assert.equal(await ps.revoke({ownerId:'owner',credentialId:x.a.credential.id}),true);});
import {createEmailRecoveryHttp} from '../src/email-recovery-http.js';import {EmailRecovery} from '../src/email-recovery.js';import {CodeCipher} from '../src/code-cipher.js';import {deliverRecoveryNotifications,drainRecoveryCodeJobs,recoveryDeliveryHealth,retryFailedRecoveryNotifications} from '../src/recovery-notifier.js';
const bind=(x,id,b)=>x.db.sqlite.prepare('UPDATE device_sessions SET browser_binding_digest=? WHERE device_id=?').run(b.repeat(64),id);
async function clients(x){bind(x,x.d.deviceId,'a');const ap=await x.sessions.issue({proof:{ownerId:'owner',credentialId:x.a.credential.id,generation:0,purpose:'authenticate',verifiedAt:NOW},clientKind:'web'});bind(x,ap.deviceId,'3');
 const gg=await x.mk();bind(x,gg.deviceId,'4');
 const call=(step,value,auth,method='POST')=>x.http.fetch(new Request(API+'/v1/manage/recovery/'+step,{method,headers:{Origin:APP,'Content-Type':'application/json',Authorization:'Bearer '+auth},...(method==='POST'?{body:JSON.stringify(value)}:{})}),{clientAddress:'t'});
 return{ap,gg,call};}
const B43='B'.repeat(43);
const hcall=(x,step,value,auth,method='POST')=>x.http.fetch(new Request(API+'/v1/manage/recovery/'+step,{method,headers:{Origin:APP,'Content-Type':'application/json',Authorization:'Bearer '+auth},...(method==='POST'?{body:JSON.stringify(value)}:{})}),{clientAddress:'t'});
// approver: a DIFFERENT session of the owner (here a Google-only one) holding an enrolled device key.
async function approve(x,dk,call,approverAuth,changeId,{signWith}={}){const b=await call('approve-begin',{changeId,keyId:dk.key.keyId},approverAuth);if(b.status!==200)return b;const c=await b.json();
 return call('approve-change',{changeId,token:c.token,signature:await (signWith??dk.sign)(c.challenge)},approverAuth);}
const V=async()=>true; // stand-in for a FUTURE verifier-enforced local verification; none exists today
test('enrolled-client approval needs a device-key proof bound to the exact change; a bare session never approves; requester consumes once',async()=>{const x=await setup({lv:V}),{gg,call}=await clients(x),dk=await deviceKey(x),key=x.b.credential.id;
 const r=await call('request-change',{kind:'passkey-revoke',target:key},x.d.access);assert.equal(r.status,200);const {changeId}=await r.json();
 assert.equal((await call('consume-change',{changeId},x.d.access)).status,409);
 // bare browser-session approval is gone: the old shape and an unsigned shape are refused
 assert.equal((await call('approve-change',{changeId},gg.access)).status,400);assert.equal((await call('approve-change',{changeId,token:'x',signature:'y'},gg.access)).status,409);
 // requester itself cannot approve even with the key
 assert.equal((await approve(x,dk,call,x.d.access,changeId)).status,409);
 // the approver sees the pending change and needs no particular login method
 assert.equal((await (await call('status',{},gg.access,'GET')).json()).changes.length,1);
 const b=await call('approve-begin',{changeId,keyId:dk.key.keyId},gg.access);assert.equal(b.status,200);const c=await b.json();
 assert.equal((await call('approve-change',{changeId,token:c.token,signature:'z'.repeat(86)},gg.access)).status,409);
 const b2=await (await call('approve-begin',{changeId,keyId:dk.key.keyId},gg.access)).json();
 assert.equal((await call('consume-change',{changeId},x.d.access)).status,409);assert.equal(active(x.db).length,2);
 const ok=await call('approve-change',{changeId,token:b2.token,signature:await dk.sign(b2.challenge)},gg.access);assert.equal(ok.status,200);assert.deepEqual(await ok.json(),{status:'ok'});
 assert.equal((await call('approve-change',{changeId,token:b2.token,signature:await dk.sign(b2.challenge)},gg.access)).status,409);
 assert.equal(x.db.sqlite.prepare('SELECT approver_key_id k FROM recovery_changes').get().k,dk.key.keyId);
 assert.equal((await call('consume-change',{changeId},x.d.access)).status,200);assert.deepEqual(active(x.db),[x.a.credential.id]);
 assert.equal((await call('consume-change',{changeId},x.d.access)).status,409);});
test('a device-key proof for one change cannot approve another change or kind',async()=>{const x=await setup({lv:V}),{gg,call}=await clients(x),dk=await deviceKey(x);
 const one=(await (await call('request-change',{kind:'session-revoke',target:'abc'},x.d.access)).json()).changeId,two=(await (await call('request-change',{kind:'email-escape-on',warningAccepted:true},x.d.access)).json()).changeId;
 const c=await (await call('approve-begin',{changeId:one,keyId:dk.key.keyId},gg.access)).json();
 assert.equal((await call('approve-change',{changeId:two,token:c.token,signature:await dk.sign(c.challenge)},gg.access)).status,409);
 assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM recovery_changes WHERE approved_at IS NOT NULL').get().n,0);
 assert.equal((await call('approve-begin',{changeId:one,keyId:'nope'},gg.access)).status,409);
 const other=await deviceKey(x,'2'.repeat(43));x.db.sqlite.prepare('UPDATE durable_device_keys SET revoked_at=1 WHERE key_id=?').run(other.key.keyId);
 assert.equal((await approve(x,other,call,gg.access,one)).status,409);});
test('client approval denies on expiry, revoked approver key, revoked approver session and generation change; never removes the last passkey',async()=>{
 for(const c of ['expire','key','owner-gen','approver-session','approver-expired','requester-session']){const x=await setup({lv:V}),{gg,call}=await clients(x),dk=await deviceKey(x);
  const {changeId}=await (await call('request-change',{kind:'email-escape-on',warningAccepted:true},x.d.access)).json();assert.equal((await approve(x,dk,call,gg.access,changeId)).status,200);
  if(c==='expire')x.db.sqlite.prepare('UPDATE recovery_changes SET created_at=?,expires_at=?').run(NOW-10,NOW);
  if(c==='key')await dk.svc.revoke({ownerId:'owner',keyId:dk.key.keyId});
  if(c==='owner-gen')x.db.sqlite.prepare('UPDATE account_security SET generation=1').run();
  if(c==='approver-session')x.db.sqlite.prepare('UPDATE device_sessions SET revoked_at=1 WHERE device_id=?').run(gg.deviceId);
  if(c==='approver-expired')x.db.sqlite.prepare('UPDATE device_sessions SET expires_at=? WHERE device_id=?').run(NOW,gg.deviceId);
  if(c==='requester-session')x.db.sqlite.prepare('UPDATE device_sessions SET revoked_at=1 WHERE device_id=?').run(x.d.deviceId);
  assert.equal((await call('consume-change',{changeId},x.d.access)).status,['owner-gen','requester-session'].includes(c)?401:409,c);assert.equal(optin(x.db).length,0,c);}
 {const x=await setup({lv:V}),{gg,call}=await clients(x),dk=await deviceKey(x);x.db.sqlite.prepare('UPDATE device_sessions SET revoked_at=1 WHERE device_id=?').run(gg.deviceId);
  const {changeId}=await (await call('request-change',{kind:'email-escape-on',warningAccepted:true},x.d.access)).json();assert.equal((await approve(x,dk,call,gg.access,changeId)).status,401);}
 const x=await setup({second:false,lv:V}),{gg,call}=await clients(x),dk=await deviceKey(x);
 const {changeId}=await (await call('request-change',{kind:'passkey-revoke',target:x.a.credential.id},x.d.access)).json();await approve(x,dk,call,gg.access,changeId);
 assert.equal((await call('consume-change',{changeId},x.d.access)).status,409);assert.deepEqual(active(x.db),[x.a.credential.id]);
 const exclusive=await setup({lv:V}),k=await clients(exclusive);exclusive.db.sqlite.prepare('INSERT INTO new_device_verification VALUES(?,?,?)').run('owner',NOW,0);
 assert.equal((await k.call('request-change',{kind:'email-escape-on',warningAccepted:true},exclusive.d.access)).status,403);
 assert.equal((await call('request-change',{kind:'email-escape-on'},x.d.access)).status,400);assert.equal((await call('request-change',{kind:'passkey-revoke'},x.d.access)).status,400);});
test('FAIL CLOSED: possession-only device keys (platformVerified:false) cannot approve or authorize protected changes',async()=>{
 const x=await setup(),{gg,call}=await clients(x),dk=await deviceKey(x),rc=new RecoveryControls(x.db,{clock:x.clock});
 const {changeId}=await (await call('request-change',{kind:'passkey-revoke',target:x.b.credential.id},x.d.access)).json();
 // default runtime wiring: approval is unavailable, with no possession fallback
 for(const [step,v] of [['approve-begin',{changeId,keyId:dk.key.keyId}],['approve-change',{changeId,token:'t',signature:'s'}]]){const r=await call(step,v,gg.access);assert.equal(r.status,503);assert.deepEqual(await r.json(),{error:'unavailable',reason:'local_verification_unavailable'});}
 assert.equal(await rc.beginApproval({user:{ownerId:'owner',deviceId:gg.deviceId,generation:0},changeId,keyId:dk.key.keyId,deviceKeys:dk.svc}),undefined);
 assert.equal((await call('consume-change',{changeId},x.d.access)).status,409);assert.equal(active(x.db).length,2);
 // a verifier that reports no local verification still cannot approve, even with a valid signature
 for(const lv of [async()=>false,async()=>undefined,async()=>'yes']){const y=await setup({lv}),k=await clients(y),d2=await deviceKey(y);
  const id=(await (await k.call('request-change',{kind:'passkey-revoke',target:y.b.credential.id},y.d.access)).json()).changeId;
  const r=await approve(y,d2,k.call,k.gg.access,id);assert.equal(r.status,409);assert.equal(y.db.sqlite.prepare('SELECT count(*) n FROM recovery_changes WHERE approved_at IS NOT NULL').get().n,0);
  assert.equal((await k.call('consume-change',{changeId:id},y.d.access)).status,409);assert.equal(active(y.db).length,2);}
 // the direct service path refuses a device-key proof for every kind
 const user={ownerId:'owner',deviceId:'d',generation:0};
 for(const [kind,target,extra] of [['email-escape-on',undefined,{warningAccepted:true}],['passkey-revoke',x.a.credential.id,{}],['session-revoke','abc',{}]])assert.equal(await rc.apply({user,kind,target,proof:await dk.prove(kind,target),...extra}),undefined,kind);
 assert.equal(optin(x.db).length,0);assert.equal(active(x.db).length,2);});
// ---- email recovery over the real HTTP surface; mail is captured, never sent ----
let CIPHER;const cipher=async()=>CIPHER??=new CodeCipher({keys:new Map([['k',await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt'])]]),activeKeyId:'k'});
async function recovery(opts){const x=await setup(opts),mail=[],er=createEmailRecoveryHttp({db:x.db,clock:x.clock,passkeys:x.passkeys,getCipher:cipher,deliver:async m=>{mail.push(m);}});
 const call=(step,value,{origin=APP,addr='1.1.1.1'}={})=>er.fetch(new Request(API+'/auth/recovery/email/'+step,{method:'POST',headers:{Origin:origin,'Content-Type':'application/json'},body:JSON.stringify(value)}),{clientAddress:addr});
 return{...x,mail,call};}
const em='a@gmail.com';
const status=async(r,step,v,n)=>{const res=await r.call(step,v);assert.equal(res.status,n,step+' '+JSON.stringify(await res.clone().json()));return res;};
test('email recovery: generic code request, no mail without the opt-in or for unknown mailboxes; a code only starts a seven day wait and signs nobody in',async()=>{const x=await recovery();
 for(const email of [em,'nobody@example.com']){const r=await x.call('request',{email,binding:B43});assert.equal(r.status,200);assert.deepEqual(await r.json(),{status:'accepted'});}
 assert.equal(x.mail.length,0);
 assert.equal((await x.flow('email-escape-on',{extra:{warningAccepted:true}})).status,200);
 await x.call('request',{email:'nobody@example.com',binding:B43});assert.equal(x.mail.length,0);
 const r=await x.call('request',{email:em,binding:B43});assert.deepEqual(await r.json(),{status:'accepted'});assert.equal(x.mail.length,1);assert.equal(x.mail[0].kind,'recovery-request');assert.equal(x.mail[0].to,'a@gmail.com');
 const code=x.mail[0].code;
 await status(x,'verify',{email:em,code:'AAAAAAAA',binding:B43},403);await status(x,'verify',{email:em,code,binding:'C'.repeat(43)},403);
 const v=await (await status(x,'verify',{email:em,code,binding:B43},200)).json();assert.equal(v.status,'waiting');assert.equal(v.availableAt,NOW+604800000);
 await status(x,'verify',{email:em,code,binding:B43},403);
 assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM device_sessions WHERE created_at>?').get(NOW).n,0);assert.equal(active(x.db).length,2);
 assert.deepEqual(x.db.sqlite.prepare('SELECT kind FROM recovery_notifications').all().map(n=>n.kind),['requested']);
 // no caller-supplied proof object or extra field is accepted at the boundary
 await status(x,'verify',{email:em,code,binding:B43,proof:{ownerId:'owner'}},400);await status(x,'request',{email:em},400);await status(x,'request',{email:em,binding:B43},200);
 assert.equal((await x.call('request',{email:em,binding:B43},{origin:'https://evil.test'})).status,403);});
test('email recovery: no completion before seven days, a stale code, a wrong-purpose code or a canceled/disabled request',async()=>{const x=await recovery();
 await x.flow('email-escape-on',{extra:{warningAccepted:true}});await x.call('request',{email:em,binding:B43});await x.call('verify',{email:em,code:x.mail[0].code,binding:B43});
 x.t.now=NOW+604800000-1;await x.call('complete-code',{email:em,binding:B43});assert.equal(x.mail.length,1);
 await status(x,'complete-begin',{email:em,code:x.mail[0].code,binding:B43},403);
 x.t.now=NOW+604800000;await x.call('complete-code',{email:em,binding:B43});assert.equal(x.mail.length,2);assert.equal(x.mail[1].kind,'recovery-complete');
 await status(x,'complete-begin',{email:em,code:x.mail[0].code,binding:B43},403);
 x.t.now+=1800000;await status(x,'complete-begin',{email:em,code:x.mail[1].code,binding:B43},403);
 await x.call('complete-code',{email:em,binding:B43});assert.equal(x.mail.length,3);
 x.db.sqlite.prepare('DELETE FROM email_recovery_optin').run();
 await status(x,'complete-begin',{email:em,code:x.mail[2].code,binding:B43},403);assert.equal(x.db.sqlite.prepare('SELECT canceled_by c FROM email_recovery_requests').get().c,'setting-off');
 assert.equal(active(x.db).length,2);});
async function begin(x){await x.flow('email-escape-on',{extra:{warningAccepted:true}});await x.call('request',{email:em,binding:B43});await x.call('verify',{email:em,code:x.mail[0].code,binding:B43});
 x.t.now=NOW+604800000;await x.call('complete-code',{email:em,binding:B43});return(await status(x,'complete-begin',{email:em,code:x.mail[1].code,binding:B43},200)).json();}
test('email recovery completion: a NEW passkey retires every old passkey, device key, session and automation token atomically; data, shares and Google stay',async()=>{const x=await recovery(),dk=await deviceKey(x);
 const {gg}=await clients(x);
 x.db.sqlite.exec('PRAGMA foreign_keys=OFF');
 x.db.sqlite.prepare('INSERT INTO access_tokens(token_id,token_digest,owner_id,client_id,service_id,scopes,created_at,not_before,expires_at) VALUES(?,?,?,?,?,?,?,?,?)').run('t1',new Uint8Array(32),'owner','c','s','[]',NOW,NOW,NOW+9e9);
 x.db.sqlite.prepare('INSERT INTO entry_tokens(token_id,token_digest,actor_id,entry_id,client_id,created_at,expires_at) VALUES(?,?,?,?,?,?,?)').run('e1',new Uint8Array(32),'owner','entry','c',NOW,NOW+9e9);
 x.db.sqlite.prepare("INSERT INTO sessions(session_id,session_digest,csrf_digest,owner_id,created_at,expires_at) VALUES('s1',?,?,'owner',?,?)").run(new Uint8Array(32),new Uint8Array(32),NOW,NOW+9e9);
 x.db.sqlite.exec('PRAGMA foreign_keys=ON');
 const g=await begin(x);assert.ok(g.grant&&g.ceremony.token);
 // nothing is retired, and no session exists, until a new passkey is registered
 assert.equal(active(x.db).length,2);assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM device_sessions WHERE revoked_at IS NULL').get().n,3);
 const neu=authenticator();
 // wrong ceremony or an already registered credential changes nothing
 await status(x,'complete-finish',{grant:g.grant,token:g.ceremony.token,response:x.a.registration({expected:g.ceremony.options.challenge})},403);
 assert.equal(active(x.db).length,2);assert.equal(x.db.sqlite.prepare("SELECT count(*) n FROM email_recovery_requests WHERE completed_at IS NOT NULL").get().n,0);
 // the grant is single use
 await status(x,'complete-finish',{grant:g.grant,token:g.ceremony.token,response:neu.registration({expected:g.ceremony.options.challenge})},403);
 x.t.now+=3600001;const before=x.mail.length;await x.call('complete-code',{email:em,binding:B43});assert.equal(x.mail.length,before+1);
 const g2=await status(x,'complete-begin',{email:em,code:x.mail.at(-1).code,binding:B43},200).then(r=>r.json());
 const r=await status(x,'complete-finish',{grant:g2.grant,token:g2.ceremony.token,response:neu.registration({expected:g2.ceremony.options.challenge})},200);assert.deepEqual(await r.json(),{status:'completed',signIn:'with the new passkey'});
 assert.deepEqual(active(x.db),[neu.credential.id]);
 assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM device_sessions WHERE revoked_at IS NULL').get().n,0);
 assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM durable_device_keys WHERE revoked_at IS NULL').get().n,0);
 assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM access_tokens WHERE revoked_at IS NULL').get().n,0);assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM entry_tokens WHERE revoked_at IS NULL').get().n,0);
 assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM sessions').get().n,0);
 assert.equal(x.db.sqlite.prepare('SELECT generation g FROM account_security').get().g,1);
 // preserved: account, mailbox, linked Google, the opt-in setting itself
 assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM provider_identities WHERE revoked_at IS NULL').get().n,1);assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM accounts').get().n,1);assert.equal(optin(x.db).length,1);
 assert.deepEqual(x.db.sqlite.prepare('SELECT kind FROM recovery_notifications ORDER BY created_at,kind').all().map(n=>n.kind).sort(),['completed','requested']);
 // old sessions cannot reach recovery state; the request cannot be completed twice
 assert.equal((await hcall(x,'status',{},gg.access,'GET')).status,401);assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM email_recovery_requests WHERE completed_at IS NOT NULL').get().n,1);
 const n=x.mail.length;x.t.now+=3600001;await x.call('complete-code',{email:em,binding:B43});assert.equal(x.mail.length,n);});
test('email recovery completion is all-or-nothing: losing eligibility between grant and finish retires nothing',async()=>{
 for(const lose of ['optin','cancel','generation']){const x=await recovery(),g=await begin(x);
  if(lose==='optin')x.db.sqlite.prepare('DELETE FROM email_recovery_optin').run();
  if(lose==='cancel')x.db.sqlite.prepare("UPDATE email_recovery_requests SET canceled_at=?,canceled_by='client'").run(x.t.now);
  if(lose==='generation')x.db.sqlite.prepare('UPDATE account_security SET generation=1').run();
  const neu=authenticator();await status(x,'complete-finish',{grant:g.grant,token:g.ceremony.token,response:neu.registration({expected:g.ceremony.options.challenge})},403);
  assert.ok(!active(x.db).includes(neu.credential.id),lose);assert.equal(active(x.db).length,2,lose);assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM device_sessions WHERE revoked_at IS NULL').get().n,1,lose);}});
test('finish re-checks the seven day wait itself, not only the grant',async()=>{const x=await recovery(),g=await begin(x);
 x.db.sqlite.prepare('UPDATE email_recovery_requests SET requested_at=requested_at+86400000,available_at=available_at+86400000').run();
 const neu=authenticator();await status(x,'complete-finish',{grant:g.grant,token:g.ceremony.token,response:neu.registration({expected:g.ceremony.options.challenge})},403);assert.equal(active(x.db).length,2);});
test('cancel: only a passkey session cancels, outbox gets a canceled row, turning the opt-in off cancels a waiting request',async()=>{const x=await recovery(),{ap,call:rc}=await clients(x);
 await x.flow('email-escape-on',{extra:{warningAccepted:true}});await x.call('request',{email:em,binding:B43});await x.call('verify',{email:em,code:x.mail[0].code,binding:B43});
 const st=await (await rc('status',{},x.d.access,'GET')).json();const id=st.emailRecoveryRequest.requestId;
 assert.equal((await rc('cancel-request',{requestId:id},x.d.access)).status,409);assert.ok(st.emailRecoveryRequest);
 assert.equal((await rc('cancel-request',{requestId:id},ap.access)).status,200);assert.equal((await (await rc('status',{},x.d.access,'GET')).json()).emailRecoveryRequest,null);
 assert.deepEqual(x.db.sqlite.prepare('SELECT kind FROM recovery_notifications').all().map(n=>n.kind).sort(),['canceled','requested']);assert.equal((await rc('cancel-request',{requestId:id},ap.access)).status,409);
 await x.call('request',{email:em,binding:B43});await x.call('verify',{email:em,code:x.mail.at(-1).code,binding:B43});
 assert.equal((await x.flow('email-escape-off')).status,200);assert.equal(x.db.sqlite.prepare("SELECT canceled_by c FROM email_recovery_requests WHERE canceled_by='setting-off'").get().c,'setting-off');});
test('the request, status and approval routes need no caller-held proof; runtime mounts email recovery only with injected delivery',async()=>{
 const db=database(),rt=createIdentityRuntime({db,keys:new Map([['k',await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt'])]]),activeKeyId:'k',trustedRequestKey:()=>'1.2.3.4',deliverRecoveryMail:async()=>{}});
 const r=await rt.fetch(new Request(API+'/auth/recovery/email/request',{method:'POST',headers:{Origin:APP,'Content-Type':'application/json'},body:JSON.stringify({email:em,binding:B43})}));assert.equal(r.status,200);
 const noMail=createIdentityRuntime({db,keys:{},activeKeyId:'k',trustedRequestKey:()=>'1.2.3.4'});
 assert.equal((await noMail.fetch(new Request(API+'/auth/recovery/email/request',{method:'POST',headers:{Origin:APP,'Content-Type':'application/json'},body:JSON.stringify({email:em,binding:B43})}))).status,200);
 assert.equal((await rt.fetch(new Request(API+'/auth/recovery/email/nope',{method:'POST',headers:{Origin:APP}}))).status,404);});
import {DurableDeviceKeys} from '../src/durable-device-keys.js';import {deviceProofMessage} from '../src/device-key-proof.js';import {base64urlEncode} from '../src/tokens.js';
const BIND='b'.repeat(43);
async function deviceKey(x,bindingOverride){const pair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']),raw=await crypto.subtle.exportKey('jwk',pair.publicKey),jwk={kty:raw.kty,crv:raw.crv,x:raw.x,y:raw.y},svc=new DurableDeviceKeys(x.db,{clock:x.clock});
 const {deviceEnrollmentAction}=await import('../src/durable-device-keys.js');
 const sign=async ch=>base64urlEncode(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},pair.privateKey,deviceProofMessage(ch))));
 const c=await svc.beginEnrollment({jwk,strongProof:{purpose:'step-up',ownerId:'owner',credentialId:x.a.credential.id,generation:0,verifiedAt:NOW,actionDigest:await deviceEnrollmentAction(jwk)},browserBinding:BIND});
 const key=await svc.finish({token:c.token,browserBinding:BIND,signature:await sign(c.challenge)});
 const prove=async(kind,target)=>{const b=await svc.beginProof({keyId:key.keyId,purpose:'step-up',actionDigest:await hashText(recoveryAction(kind,target)),browserBinding:BIND});return svc.finish({token:b.token,browserBinding:BIND,signature:await sign(b.challenge)});};
 return{svc,key,prove,sign};}
test('code delivery is durable: opted-in, non-opted-in and unknown mailboxes write the same shape, and the code is never stored in clear',async()=>{
 const run=async(email,optIn)=>{const x=await setup(),mail=[],jobs=[];if(optIn)await x.flow('email-escape-on',{extra:{warningAccepted:true}});
  const svc=new EmailRecovery(x.db,{clock:x.clock,passkeys:x.passkeys,getCipher:cipher,deliver:async m=>{mail.push(m);}});
  const r=await svc.requestCode({email,binding:B43,clientAddress:'1.1.1.1',purpose:'request',defer:p=>jobs.push(p)});await Promise.all(jobs);
  return{r,codes:x.db.sqlite.prepare('SELECT purpose,proof_id FROM human_email_codes').all(),jobsRows:x.db.sqlite.prepare('SELECT kind,owner_id,delivered_at,envelope FROM recovery_code_jobs').all(),mail,jobs:jobs.length};};
 const real=await run(em,true),off=await run(em,false),unknown=await run('nobody@example.com',false);
 for(const o of [real,off,unknown]){assert.deepEqual(o.r,{status:'accepted'});assert.equal(o.codes.length,1);assert.equal(o.jobsRows.length,1);}
 assert.equal(real.mail.length,1);assert.equal(real.jobsRows[0].kind,'recovery-request');assert.notEqual(real.jobsRows[0].delivered_at,null);assert.equal(real.jobsRows[0].envelope,'');
 for(const o of [off,unknown]){assert.equal(o.mail.length,0);assert.equal(o.jobs,0);assert.equal(o.jobsRows[0].kind,'decoy');assert.equal(o.jobsRows[0].owner_id,null);assert.equal(o.codes[0].purpose,'recovery-decoy');assert.ok(o.jobsRows[0].envelope.length>20);}
 // while pending, the stored envelope holds no plaintext code
 const y=await setup();await y.flow('email-escape-on',{extra:{warningAccepted:true}});let sent;const sv=new EmailRecovery(y.db,{clock:y.clock,passkeys:y.passkeys,getCipher:cipher,deliver:async m=>{sent=m;throw new Error('down');}});
 await sv.requestCode({email:em,binding:B43,clientAddress:'a',purpose:'request'});assert.ok(sent.code);const env=y.db.sqlite.prepare('SELECT envelope FROM recovery_code_jobs').get().envelope;assert.ok(!env.includes(sent.code));
 // a decoy code can never start a request
 assert.equal(await sv.verifyRequest({email:'nobody@example.com',code:'AAAAAAAA',binding:B43}),undefined);});
test('a real request is never silently dropped: saturation, a throwing defer, provider failure and a missing defer all leave a retried durable job',async()=>{
 const x=await setup();await x.flow('email-escape-on',{extra:{warningAccepted:true}});const mail=[];let down=true;
 const deliver=async m=>{if(down)throw new Error('provider down');mail.push(m);},t=x.t;
 const svc=()=>new EmailRecovery(x.db,{clock:x.clock,passkeys:x.passkeys,getCipher:cipher,deliver});
 // provider failure with a working defer
 const jobs=[];await svc().requestCode({email:em,binding:B43,clientAddress:'a',purpose:'request',defer:p=>jobs.push(p)});await Promise.all(jobs);
 let j=x.db.sqlite.prepare('SELECT attempts,delivered_at d FROM recovery_code_jobs').get();assert.equal(j.attempts,1);assert.equal(j.d,null);
 // drain honours backoff, then delivers once the provider recovers; the SAME code is sent
 const dr=()=>drainRecoveryCodeJobs({db:x.db,cipher:CIPHER,deliver,clock:x.clock});
 assert.deepEqual(await dr(),{delivered:0,failed:0,expired:0});down=false;t.now+=61000;assert.deepEqual(await dr(),{delivered:1,failed:0,expired:0});assert.equal(mail.length,1);
 assert.deepEqual(await dr(),{delivered:0,failed:0,expired:0});assert.equal(mail.length,1);
 assert.ok(await new EmailRecovery(x.db,{clock:x.clock,passkeys:x.passkeys,getCipher:cipher,deliver}).verifyRequest({email:em,code:mail[0].code,binding:B43}));
 // a defer that throws: the started send still completes once, releases its slot, and nothing is lost or duplicated
 const y=await setup();await y.flow('email-escape-on',{extra:{warningAccepted:true}});const m2=[];const d2=async m=>{m2.push(m);};
 const s2=new EmailRecovery(y.db,{clock:y.clock,passkeys:y.passkeys,getCipher:cipher,deliver:d2}),started=[];
 for(let i=0;i<6;i++){y.t.now+=3700000;await s2.requestCode({email:em,binding:B43+i,clientAddress:'a'+i,purpose:'request',defer:p=>{started.push(p);throw new Error('defer broke');}});await Promise.all(started.splice(0));}
 assert.equal(m2.length,6);assert.equal(y.db.sqlite.prepare('SELECT count(*) n FROM recovery_code_jobs WHERE delivered_at IS NULL').get().n,0);
 const live=[];y.t.now+=3700000;await s2.requestCode({email:em,binding:B43+'z',clientAddress:'q',purpose:'request',defer:p=>live.push(p)});assert.equal(live.length,1,'slots were not leaked by a throwing defer');await Promise.all(live);
 // saturation: hung sends hold all four slots; the fifth real request still has a durable job and everything is delivered by the drain
 const z=await setup();await z.flow('email-escape-on',{extra:{warningAccepted:true}});const hung=[];let reached;const zs=new EmailRecovery(z.db,{clock:z.clock,passkeys:z.passkeys,getCipher:cipher,deliver:()=>{reached();return new Promise(()=>{});}});
 for(let i=0;i<5;i++){const sending=new Promise(r=>{reached=r;});z.t.now+=3700000;await zs.requestCode({email:em,binding:B43+i,clientAddress:'ip'+i,purpose:'request',defer:p=>hung.push(p)});if(i<4)await sending;}
 assert.equal(hung.length,4);assert.equal(z.db.sqlite.prepare('SELECT count(*) n FROM recovery_code_jobs WHERE delivered_at IS NULL').get().n,5);
 const m3=[];z.t.now+=61000;const out=await drainRecoveryCodeJobs({db:z.db,cipher:CIPHER,deliver:async m=>{m3.push(m);},clock:z.clock,limit:25});assert.equal(out.delivered,1);
 // expiry and attempt caps bound the retries
 const e=await setup();await e.flow('email-escape-on',{extra:{warningAccepted:true}});let n=0;const se=new EmailRecovery(e.db,{clock:e.clock,passkeys:e.passkeys,getCipher:cipher,deliver:async()=>{n++;throw new Error('x');}});
 await se.requestCode({email:em,binding:B43,clientAddress:'a',purpose:'request'});for(let i=0;i<12;i++){e.t.now+=40000*2**Math.min(i,3);await drainRecoveryCodeJobs({db:e.db,cipher:CIPHER,deliver:async()=>{n++;throw new Error('x');},clock:e.clock});}
 assert.ok(n<=6);e.t.now+=700000;const before=n;await drainRecoveryCodeJobs({db:e.db,cipher:CIPHER,deliver:async()=>{n++;},clock:e.clock});assert.equal(n,before);});
test('outbox delivery: bounded retries, backoff, lease, idempotent after success, recipient is the stored mailbox',async()=>{
 const x=await setup(),t=x.t;x.db.sqlite.prepare("INSERT INTO email_recovery_requests(request_id,owner_id,generation,requested_at,available_at) VALUES('r','owner',0,?,?)").run(NOW,NOW+604800000);
 x.db.sqlite.prepare("INSERT INTO recovery_notifications(notification_id,owner_id,request_id,kind,created_at) VALUES('n1','owner','r','requested',?)").run(NOW);
 const sent=[];let fail=true;const deliver=async m=>{sent.push(m);if(fail)throw new Error('down');};const run=()=>deliverRecoveryNotifications({db:x.db,deliver,clock:x.clock});
 assert.deepEqual(await run(),{delivered:0,failed:1});assert.deepEqual(sent[0],{kind:'requested',to:'a@gmail.com'});
 assert.deepEqual(await run(),{delivered:0,failed:0});assert.equal(sent.length,1); // backoff holds it
 for(let i=0;i<8;i++){t.now+=60000*2**i+1;await run();}
 assert.equal(sent.length,5);assert.equal(x.db.sqlite.prepare('SELECT attempts a FROM recovery_notifications').get().a,5);assert.equal(x.db.sqlite.prepare('SELECT delivered_at d FROM recovery_notifications').get().d,null);
 x.db.sqlite.prepare("UPDATE recovery_notifications SET attempts=1,next_attempt_at=0,claimed_until=0,failed_at=NULL").run();fail=false;t.now+=1e6;
 const [a,b]=await Promise.all([run(),run()]);assert.equal(a.delivered+b.delivered,1);assert.equal(sent.length,6);
 assert.deepEqual(await run(),{delivered:0,failed:0});assert.equal(sent.length,6);
 // a live lease blocks a second worker
 x.db.sqlite.prepare("INSERT INTO recovery_notifications(notification_id,owner_id,request_id,kind,created_at,claimed_until) VALUES('n2','owner','r','canceled',?,?)").run(NOW,t.now+30000);
 assert.deepEqual(await run(),{delivered:0,failed:0});t.now+=30001;assert.equal((await run()).delivered,1);assert.equal(sent.at(-1).kind,'canceled');});
test('terminal failures are visible and retried only deliberately',async()=>{
 const x=await setup(),t=x.t;x.db.sqlite.prepare("INSERT INTO email_recovery_requests(request_id,owner_id,generation,requested_at,available_at) VALUES('r','owner',0,?,?)").run(NOW,NOW+604800000);
 x.db.sqlite.prepare("INSERT INTO recovery_notifications(notification_id,owner_id,request_id,kind,created_at) VALUES('n1','owner','r','completed',?)").run(NOW);
 assert.deepEqual(await recoveryDeliveryHealth({db:x.db,clock:x.clock}),{pendingNotifications:1,deadNotifications:0,oldestPendingNotificationAgeMs:0,pendingCodeJobs:0,deadCodeJobs:0,expiredCodeJobs:0,staleCodeJobs:0});
 let sent=0;const deliver=async()=>{sent++;throw new Error('down');};
 for(let i=0;i<9;i++){t.now+=60000*2**i+1;await deliverRecoveryNotifications({db:x.db,deliver,clock:x.clock});}
 assert.equal(sent,5);const h=await recoveryDeliveryHealth({db:x.db,clock:x.clock});assert.equal(h.deadNotifications,1);assert.equal(h.pendingNotifications,0);
 t.now+=1e9;await deliverRecoveryNotifications({db:x.db,deliver,clock:x.clock});assert.equal(sent,5,'no silent automatic retry');
 assert.equal(await retryFailedRecoveryNotifications({db:x.db,clock:x.clock}),1);const ok=[];await deliverRecoveryNotifications({db:x.db,deliver:async m=>{ok.push(m);},clock:x.clock});assert.equal(ok.length,1);
 assert.equal((await recoveryDeliveryHealth({db:x.db,clock:x.clock})).deadNotifications,0);
 // code jobs: exhausting attempts is also terminal and visible
 const y=await setup();await y.flow('email-escape-on',{extra:{warningAccepted:true}});const sv=new EmailRecovery(y.db,{clock:y.clock,passkeys:y.passkeys,getCipher:cipher,deliver:async()=>{throw new Error('x');}});
 await sv.requestCode({email:em,binding:B43,clientAddress:'a',purpose:'request'});for(let i=0;i<8;i++){y.t.now+=1000;y.db.sqlite.prepare('UPDATE recovery_code_jobs SET next_attempt_at=0').run();await drainRecoveryCodeJobs({db:y.db,cipher:CIPHER,deliver:async()=>{throw new Error('x');},clock:y.clock});}
 const hy=await recoveryDeliveryHealth({db:y.db,clock:y.clock});assert.equal(hy.deadCodeJobs,1);assert.equal(hy.pendingCodeJobs,0);});
test('completion preserves shares and the recipients\' own tokens; only the owner\'s tokens are retired',async()=>{const x=await recovery();
 x.db.sqlite.exec('PRAGMA foreign_keys=OFF');
 x.db.sqlite.prepare("INSERT INTO accounts(owner_id,created_at) VALUES('friend',?)").run(NOW);
 x.db.sqlite.prepare("INSERT INTO entry_shares(entry_id,recipient_id,allow_automation,created_at) VALUES('entry','friend',1,?)").run(NOW);
 for(const [id,actor] of [['mine','owner'],['theirs','friend']])x.db.sqlite.prepare('INSERT INTO entry_tokens(token_id,token_digest,actor_id,entry_id,client_id,created_at,expires_at) VALUES(?,?,?,?,?,?,?)').run(id,new Uint8Array(32),actor,'entry','c',NOW,NOW+9e9);
 x.db.sqlite.exec('PRAGMA foreign_keys=ON');
 const g=await begin(x),neu=authenticator();await status(x,'complete-finish',{grant:g.grant,token:g.ceremony.token,response:neu.registration({expected:g.ceremony.options.challenge})},200);
 assert.deepEqual(x.db.sqlite.prepare('SELECT token_id,revoked_at IS NOT NULL r FROM entry_tokens ORDER BY token_id').all().map(r=>[r.token_id,r.r]),[['mine',1],['theirs',0]]);
 const sh=x.db.sqlite.prepare('SELECT revoked_at,allow_automation FROM entry_shares').get();assert.equal(sh.revoked_at,null);assert.equal(sh.allow_automation,1);});

test('primary review: retirement batch abort rolls back new passkey and old-key revocation',async()=>{
 const x=await recovery(),g=await begin(x),neu=authenticator();
 x.db.sqlite.exec("CREATE TRIGGER fail_recovery_retirement BEFORE UPDATE OF revoked_at ON device_sessions BEGIN SELECT RAISE(ABORT,'synthetic fault'); END");
 await status(x,'complete-finish',{grant:g.grant,token:g.ceremony.token,response:neu.registration({expected:g.ceremony.options.challenge})},403);
 assert.equal(active(x.db).length,2);assert.ok(!active(x.db).includes(neu.credential.id));
 assert.equal(x.db.sqlite.prepare('SELECT generation g FROM account_security').get().g,0);
 assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM email_recovery_requests WHERE completed_at IS NOT NULL').get().n,0);
 assert.equal(x.db.sqlite.prepare("SELECT count(*) n FROM recovery_notifications WHERE kind='completed'").get().n,0);
});
test('primary review: simultaneous same-grant completion commits once',async()=>{
 const x=await recovery(),g=await begin(x),neu=authenticator(),v={grant:g.grant,token:g.ceremony.token,response:neu.registration({expected:g.ceremony.options.challenge})};
 const rs=await Promise.all([x.call('complete-finish',v),x.call('complete-finish',v)]);
 assert.deepEqual(rs.map(r=>r.status).sort(),[200,403]);assert.deepEqual(active(x.db),[neu.credential.id]);
 assert.equal(x.db.sqlite.prepare('SELECT generation g FROM account_security').get().g,1);
 assert.equal(x.db.sqlite.prepare("SELECT count(*) n FROM recovery_notifications WHERE kind='completed'").get().n,1);
});
test('primary review: existing credential with same creation millisecond cannot satisfy NEW passkey',async()=>{
 const x=await recovery(),g=await begin(x);
 x.db.sqlite.prepare('UPDATE passkey_credentials SET created_at=? WHERE credential_id=?').run(x.t.now,x.a.credential.id);
 const r=await x.call('complete-finish',{grant:g.grant,token:g.ceremony.token,response:x.a.registration({expected:g.ceremony.options.challenge})});
 assert.equal(r.status,403);assert.equal(active(x.db).length,2);
});

test('NEW passkey must be inserted by the batch: foreign-owner and same-owner collisions refuse and retire nothing',async()=>{
 for(const who of ['owner','foreign']){const x=await recovery(),g=await begin(x);
  const other=authenticator();x.db.sqlite.exec('PRAGMA foreign_keys=OFF');
  if(who==='foreign'){x.db.sqlite.prepare("INSERT INTO accounts(owner_id,created_at) VALUES('other',?)").run(NOW);x.db.sqlite.prepare('INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) VALUES(?,?,?,?,?,?,?,?)').run(other.credential.id,'other',other.credential.publicKey,0,'[]','singleDevice',0,x.t.now);}
  x.db.sqlite.exec('PRAGMA foreign_keys=ON');
  const r=await x.call('complete-finish',{grant:g.grant,token:g.ceremony.token,response:(who==='owner'?x.b:other).registration({expected:g.ceremony.options.challenge})});
  assert.equal(r.status,403,who);assert.equal(x.db.sqlite.prepare("SELECT count(*) n FROM passkey_credentials WHERE owner_id='owner' AND revoked_at IS NULL").get().n,2,who);if(who==='foreign')assert.equal(x.db.sqlite.prepare("SELECT count(*) n FROM passkey_credentials WHERE owner_id='other' AND revoked_at IS NULL").get().n,1);assert.equal(x.db.sqlite.prepare('SELECT generation g FROM account_security WHERE owner_id=?').get('owner').g,0);
  assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM email_recovery_requests WHERE completed_at IS NOT NULL').get().n,0);assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM device_sessions WHERE revoked_at IS NULL').get().n,1);}});
test('saturation with five distinct opted-in real mailboxes: four sends occupy slots, the fifth is durable, the drain delivers all five',async()=>{
 const x=await setup();x.db.sqlite.exec('PRAGMA foreign_keys=OFF');
 for(let i=1;i<=5;i++){const o='o'+i;x.db.sqlite.prepare('INSERT INTO accounts(owner_id,created_at) VALUES(?,?)').run(o,NOW);x.db.sqlite.prepare('INSERT INTO account_emails VALUES(?,?,?,?)').run(o,o+'@example.com',NOW,NOW);x.db.sqlite.prepare('INSERT INTO account_security(owner_id) VALUES(?)').run(o);x.db.sqlite.prepare('INSERT INTO email_recovery_optin(owner_id,enabled_at,generation,delay_ms) VALUES(?,?,0,?)').run(o,NOW,DELAY_MS);}
 x.db.sqlite.exec('PRAGMA foreign_keys=ON');
 const held=[],sv=new EmailRecovery(x.db,{clock:x.clock,passkeys:x.passkeys,getCipher:cipher,deliver:()=>new Promise(()=>{})});
 for(let i=1;i<=5;i++)assert.deepEqual(await sv.requestCode({email:'o'+i+'@example.com',binding:B43,clientAddress:'ip'+i,purpose:'request',defer:p=>held.push(p)}),{status:'accepted'});
 assert.equal(held.length,4);assert.equal(x.db.sqlite.prepare("SELECT count(*) n FROM recovery_code_jobs WHERE kind='recovery-request' AND delivered_at IS NULL").get().n,5);
 const got=[];x.t.now+=61000;const r=await drainRecoveryCodeJobs({db:x.db,cipher:CIPHER,deliver:async m=>{got.push(m.to);},clock:x.clock,limit:25});
 assert.equal(r.delivered,5);assert.deepEqual(got.sort(),[1,2,3,4,5].map(i=>'o'+i+'@example.com'));assert.equal(x.db.sqlite.prepare("SELECT count(*) n FROM recovery_code_jobs WHERE delivered_at IS NULL").get().n,0);});
test('real mounted extra-verification HTTP: approve and approve-change fail closed with 503 when no local verifier exists',async()=>{
 const {createExtraVerificationHttp}=await import('../src/extra-verification-http.js');const x=await setup();
 const mount=ev=>createExtraVerificationHttp({db:x.db,sessions:x.sessions,clock:x.clock,service:ev,passkeys:x.passkeys});
 const post=(h,a,v)=>h.fetch(new Request(API+'/v1/manage/security/'+a,{method:'POST',headers:{Origin:APP,'Content-Type':'application/json',Authorization:'Bearer '+x.d.access},body:JSON.stringify(v)}),{clientAddress:'t'});
 const h=mount(new ExtraVerification(x.db,{clock:x.clock}));
 for(const [a,v] of [['approve',{pendingId:'p'}],['approve-change',{changeId:'c'}]]){const r=await post(h,a,v);assert.equal(r.status,503);assert.deepEqual(await r.json(),{error:'unavailable',reason:'local_verification_unavailable'});}
 const h2=mount(new ExtraVerification(x.db,{clock:x.clock,localVerification:async()=>false}));
 for(const [a,v] of [['approve',{pendingId:'p'}],['approve-change',{changeId:'c'}]]){const r=await post(h2,a,v);assert.notEqual(r.status,200);assert.notEqual(r.status,503);}
 assert.equal((await post(h,'deny',{pendingId:'p'})).status,403);});
async function codeJobSetup(down=true){const x=await setup();await x.flow('email-escape-on',{extra:{warningAccepted:true}});const mail=[],st={down};
 const deliver=async m=>{if(st.down)throw new Error('down');mail.push(m);};
 const svc=()=>new EmailRecovery(x.db,{clock:x.clock,passkeys:x.passkeys,getCipher:cipher,deliver});
 const req=()=>svc().requestCode({email:em,binding:B43,clientAddress:'a',purpose:'request'});
 const dr=()=>drainRecoveryCodeJobs({db:x.db,cipher:CIPHER,deliver,clock:x.clock});
 const job=()=>x.db.sqlite.prepare("SELECT * FROM recovery_code_jobs WHERE kind<>'decoy' ORDER BY created_at DESC,rowid DESC").all();
 return{x,mail,st,svc,req,dr,job};}
test('newer request supersedes the older job, including one already leased: only the active code is ever sent',async()=>{
 const {x,mail,st,svc,req,dr,job}=await codeJobSetup(false);const t=x.t;
 await req();const first=job()[0];assert.equal(first.delivered_at,x.t.now);
 // old job in flight: claimed, decrypting, then a newer request arrives before the send
 st.down=true;t.now+=1000;await req();const old=job()[0];t.now+=1000;
 const racing={decrypt:async(...a)=>{const r=await CIPHER.decrypt(...a);t.now+=1;await svc().requestCode({email:em,binding:B43,clientAddress:'b',purpose:'request'});return r;}};
 x.db.sqlite.prepare('UPDATE recovery_code_jobs SET next_attempt_at=0').run();const before=mail.length;assert.equal(await deliverJob({db:x.db,cipher:racing,deliver:async m=>{mail.push(m);},clock:x.clock,jobId:old.job_id}),false);
 assert.equal(mail.length,before,'superseded in-flight job must not send');
 const rows=job();assert.equal(rows.filter(r=>r.superseded_at!==null).length>=1,true);assert.equal(rows.find(r=>r.job_id===old.job_id).envelope,'');
 st.down=false;t.now+=61000;const r=await dr();assert.equal(r.delivered,1);assert.equal(mail.length,before+1);
 assert.ok(await svc().verifyRequest({email:em,code:mail.at(-1).code,binding:B43}),'the delivered code is the active one');
 assert.equal(await dr().then(v=>v.delivered),0);});
test('retry revalidates mailbox, security generation and opt-in: stale jobs are discarded, wiped and counted',async()=>{
 for(const mutate of [x=>x.db.sqlite.prepare("UPDATE account_emails SET email='new@gmail.com'").run(),x=>x.db.sqlite.prepare('UPDATE account_security SET generation=generation+1').run(),x=>x.db.sqlite.prepare('DELETE FROM email_recovery_optin').run()]){
  const {x,mail,st,req,dr,job}=await codeJobSetup(true);await req();assert.equal(job()[0].attempts,1);mutate(x);st.down=false;x.t.now+=61000;
  assert.deepEqual(await dr(),{delivered:0,failed:1,expired:0});assert.equal(mail.length,0);const j=job()[0];assert.equal(j.failure,'stale');assert.equal(j.envelope,'');assert.ok(j.failed_at);
  assert.equal((await recoveryDeliveryHealth({db:x.db,clock:x.clock})).staleCodeJobs,1);x.t.now+=61000;assert.equal((await dr()).delivered,0);}});
test('undelivered expired and exhausted jobs become explicit failures with the encrypted code wiped',async()=>{
 const {x,req,dr,job}=await codeJobSetup(true);await req();x.t.now+=1_900_000;
 assert.equal(await expireJobs({db:x.db,clock:x.clock}),1);const j=job()[0];assert.equal(j.failure,'expired');assert.equal(j.envelope,'');assert.ok(j.failed_at);
 const h=await recoveryDeliveryHealth({db:x.db,clock:x.clock});assert.equal(h.expiredCodeJobs,1);assert.equal(h.deadCodeJobs,1);assert.equal(h.pendingCodeJobs,0);assert.equal(await expireJobs({db:x.db,clock:x.clock}),0);
 const y=await codeJobSetup(true);await y.req();for(let i=0;i<8;i++){y.x.t.now+=1000;y.x.db.sqlite.prepare('UPDATE recovery_code_jobs SET next_attempt_at=0').run();await y.dr();}
 const k=y.job()[0];assert.equal(k.failure,'attempts');assert.equal(k.envelope,'');assert.equal(k.attempts,6);
 // the scheduled cleanup classifies before deleting
 const z=await codeJobSetup(true);await z.req();z.x.t.now+=1_900_000;await expireJobs({db:z.x.db,clock:z.x.clock});assert.equal(z.job()[0].failure,'expired');});
test('the scheduled drain itself classifies lapsed jobs as expired failures',async()=>{
 const z=await codeJobSetup(true);await z.req();z.x.t.now+=1_900_000;assert.equal((await z.dr()).expired,1);assert.equal(z.job()[0].failure,'expired');});
const curCode=x=>x.db.sqlite.prepare("SELECT code_id FROM human_email_codes WHERE purpose='recovery-request'").all();
test('job is bound to the exact human code row: concurrent issues leave one active job whose code_id is the current code, and only that code is sent',async()=>{
 const {x,mail,st,svc,dr,job}=await codeJobSetup(true);const t=x.t;
 // A and B race: all awaits interleave, batches commit one after the other
 await Promise.all([svc().requestCode({email:em,binding:B43,clientAddress:'a',purpose:'request'}),svc().requestCode({email:em,binding:B43,clientAddress:'b',purpose:'request'})]);
 const active=job().filter(j=>!j.superseded_at&&!j.delivered_at&&!j.failed_at);assert.equal(active.length,1);const cc=curCode(x);assert.equal(cc.length,1);assert.equal(active[0].code_id,cc[0].code_id);
 st.down=false;t.now+=61000;x.db.sqlite.prepare('UPDATE recovery_code_jobs SET next_attempt_at=0').run();assert.equal((await dr()).delivered,1);assert.equal(mail.length,1);
 assert.ok(await svc().verifyRequest({email:em,code:mail[0].code,binding:B43}));});
test('a job whose code_id is no longer the current code row never sends, even if marked active (exact predicate, not a flag)',async()=>{
 const {x,mail,st,req,dr,job}=await codeJobSetup(true);await req();
 x.db.sqlite.prepare("UPDATE human_email_codes SET code_id='newer-issue' WHERE purpose='recovery-request'").run();
 st.down=false;x.t.now+=61000;x.db.sqlite.prepare('UPDATE recovery_code_jobs SET next_attempt_at=0').run();assert.equal((await dr()).delivered,0);assert.equal(mail.length,0);
 // and a claimed (deleted) code is never mailed afterwards
 const y=await codeJobSetup(true);await y.req();y.x.db.sqlite.prepare("DELETE FROM human_email_codes WHERE purpose='recovery-request'").run();y.st.down=false;y.x.t.now+=61000;y.x.db.sqlite.prepare('UPDATE recovery_code_jobs SET next_attempt_at=0').run();assert.equal((await y.dr()).delivered,0);assert.equal(y.mail.length,0);});
test('cipher failure on a newer request issues nothing: the older code and job stay intact and deliverable',async()=>{
 const {x,mail,st,svc,req,dr,job}=await codeJobSetup(true);await req();const before=curCode(x)[0].code_id,jb=job()[0];
 x.t.now+=1000;const bad=new EmailRecovery(x.db,{clock:x.clock,passkeys:x.passkeys,getCipher:async()=>({encrypt:async()=>{throw new Error('kms down');}}),deliver:async()=>{}});
 await assert.rejects(bad.requestCode({email:em,binding:B43,clientAddress:'z',purpose:'request'}));
 assert.equal(curCode(x)[0].code_id,before);const after=job();assert.equal(after.length,1);assert.equal(after[0].superseded_at,null);assert.equal(after[0].code_id,before);assert.equal(after[0].envelope,jb.envelope);
 st.down=false;x.t.now+=61000;x.db.sqlite.prepare('UPDATE recovery_code_jobs SET next_attempt_at=0').run();assert.equal((await dr()).delivered,1);assert.ok(await svc().verifyRequest({email:em,code:mail[0].code,binding:B43}),'the older code still works');});
test('review: cipher failure after a replacement request never mails an invalid code; whatever is mailed is the active code',async()=>{
 const {x,mail,st,svc,req,dr}=await codeJobSetup(true);await req();
 const broken=new EmailRecovery(x.db,{clock:x.clock,passkeys:x.passkeys,deliver:async()=>{},getCipher:async()=>({encrypt:async()=>{throw Error('synthetic cipher failure');}})});
 await assert.rejects(()=>broken.requestCode({email:em,binding:B43,clientAddress:'b',purpose:'request'}));
 st.down=false;x.t.now+=61000;await dr();
 assert.equal(mail.length,1);assert.ok(await svc().verifyRequest({email:em,code:mail[0].code,binding:B43}),'no invalid code mailed');});
test('terminal code-job failures keep a bounded 7-day metric record with the code wiped, then are removed; unclassified lapsed jobs are not deleted before classification',async()=>{
 const {x,req,dr,job}=await codeJobSetup(true);const {cleanupIdentity,RETAIN_FAILED}=await import('../src/identity-cleanup.js');await req();x.t.now+=1_900_000;
 await expireJobs({db:x.db,clock:x.clock});await cleanupIdentity({db:x.db,clock:x.clock,limit:50});const kept=job();assert.equal(kept.length,1);assert.equal(kept[0].envelope,'');
 assert.equal((await recoveryDeliveryHealth({db:x.db,clock:x.clock})).expiredCodeJobs,1);
 x.t.now+=RETAIN_FAILED+1000;await cleanupIdentity({db:x.db,clock:x.clock,limit:50});assert.equal(job().length,0);
 const y=await codeJobSetup(true);await y.req();y.x.t.now+=1_900_000;await expireJobs({db:y.x.db,clock:y.x.clock});assert.equal(y.job()[0].failure,'expired','classified (not deleted) before cleanup runs');});
test('stale-generation open request is retired atomically and a new mailbox proof starts a full new wait',async()=>{
 const {x,mail,svc,req}=await codeJobSetup(false);await req();const old=await svc().verifyRequest({email:em,code:mail.at(-1).code,binding:B43});assert.ok(old);
 x.t.now+=1000;x.db.sqlite.prepare('UPDATE account_security SET generation=generation+1').run();assert.equal(await svc().status('owner'),undefined);
 await req();const fresh=await svc().verifyRequest({email:em,code:mail.at(-1).code,binding:B43});assert.ok(fresh);assert.notEqual(fresh.requestId,old.requestId);assert.equal(fresh.availableAt,x.t.now+DELAY_MS);
 const prior=x.db.sqlite.prepare('SELECT canceled_at,canceled_by FROM email_recovery_requests WHERE request_id=?').get(old.requestId);assert.equal(prior.canceled_at,x.t.now);assert.equal(prior.canceled_by,'generation-changed');
 assert.equal(x.db.sqlite.prepare('SELECT generation FROM email_recovery_requests WHERE request_id=?').get(fresh.requestId).generation,1);assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM email_recovery_requests WHERE canceled_at IS NULL AND completed_at IS NULL').get().n,1);
});
// Seed-sync key links: a remote sign-out revokes the seed-sync key last used by exactly the revoked session(s), in the same batch.
const addKey=(db,id,owner,dev,extra={})=>db.sqlite.prepare("INSERT INTO seed_sync_keys(key_id,owner_id,install_id,public_jwk,public_key_digest,generation,created_at,last_device_id,revoked_at,revoked_reason) VALUES(?,?,?,'{}',?,0,1,?,?,?)").run(id,owner,'inst-'+id,'dg-'+id,dev,extra.at??null,extra.reason??null);
const keyRow=(db,id)=>({...db.sqlite.prepare('SELECT revoked_at,revoked_reason FROM seed_sync_keys WHERE key_id=?').get(id)});
async function keyWorld(x){const other=await x.mk(),pk=await x.sessions.issue({proof:{ownerId:'owner',credentialId:x.a.credential.id,generation:0,purpose:'authenticate',verifiedAt:NOW},clientKind:'web'});
 db2(x);addKey(x.db,'k-other','owner',other.deviceId);addKey(x.db,'k-self','owner',x.d.deviceId);addKey(x.db,'k-pk','owner',pk.deviceId);addKey(x.db,'k-old','owner',other.deviceId,{at:5,reason:'superseded'});addKey(x.db,'k-foreign','o2','foreign');
 return{other,pk};}
function db2(x){x.db.sqlite.prepare("INSERT OR IGNORE INTO accounts(owner_id,created_at) VALUES('o2',?)").run(NOW);x.db.sqlite.prepare("INSERT OR IGNORE INTO account_security(owner_id) VALUES('o2')").run();}
test('seed-sync links: apply session-revoke revokes only the key last used by that session; others, foreign owners and earlier revocations are untouched; no replay effect',async()=>{const x=await setup(),{other}=await keyWorld(x);
 assert.equal((await x.flow('session-revoke',{target:other.deviceId})).status,200);
 const k=keyRow(x.db,'k-other');assert.equal(k.revoked_reason,'remote');assert.equal(k.revoked_at,NOW);
 for(const id of ['k-self','k-pk','k-foreign'])assert.deepEqual(keyRow(x.db,id),{revoked_at:null,revoked_reason:null},id);
 assert.deepEqual(keyRow(x.db,'k-old'),{revoked_at:5,revoked_reason:'superseded'});
 x.t.now+=1000;assert.equal((await x.flow('session-revoke',{target:other.deviceId})).status,403);assert.equal(keyRow(x.db,'k-other').revoked_at,NOW,'a refused replay changes nothing');});
test('seed-sync links: a session already revoked elsewhere is refused and its key is not revoked by this path',async()=>{const x=await setup(),{other}=await keyWorld(x);
 x.db.sqlite.prepare('UPDATE device_sessions SET revoked_at=? WHERE device_id=?').run(NOW-10,other.deviceId);
 assert.equal((await x.flow('session-revoke',{target:other.deviceId})).status,403);assert.deepEqual(keyRow(x.db,'k-other'),{revoked_at:null,revoked_reason:null});});
test('seed-sync links: consume-change session-revoke revokes the same key under the same guard; passkey-revoke touches no key',async()=>{const x=await setup({lv:V}),{other}=await keyWorld(x),{gg,call}=await clients(x),dk=await deviceKey(x);
 const r=await call('request-change',{kind:'session-revoke',target:other.deviceId},x.d.access);const {changeId}=await r.json();
 assert.equal((await call('consume-change',{changeId},x.d.access)).status,409);assert.equal(keyRow(x.db,'k-other').revoked_at,null,'unapproved consume revokes nothing');
 assert.equal((await approve(x,dk,call,gg.access,changeId)).status,200);
 assert.equal((await call('consume-change',{changeId},x.d.access)).status,200);
 assert.equal(keyRow(x.db,'k-other').revoked_reason,'remote');for(const id of ['k-self','k-pk','k-foreign'])assert.equal(keyRow(x.db,id).revoked_at,null,id);
 assert.equal((await call('consume-change',{changeId},x.d.access)).status,409);
 const r2=await call('request-change',{kind:'passkey-revoke',target:x.b.credential.id},x.d.access),c2=(await r2.json()).changeId;
 assert.equal((await approve(x,dk,call,gg.access,c2)).status,200);assert.equal((await call('consume-change',{changeId:c2},x.d.access)).status,200);
 for(const id of ['k-self','k-pk','k-foreign'])assert.equal(keyRow(x.db,id).revoked_at,null,id);});
test('seed-sync links: google-unlink revokes keys of the Google-linked sessions only, not a passkey session or another owner',async()=>{const x=await setup(),{other,pk}=await keyWorld(x);
 assert.equal((await x.flow('google-unlink')).status,200);
 assert.equal(keyRow(x.db,'k-other').revoked_reason,'remote');assert.equal(keyRow(x.db,'k-self').revoked_reason,'remote');
 assert.deepEqual(keyRow(x.db,'k-pk'),{revoked_at:null,revoked_reason:null});assert.deepEqual(keyRow(x.db,'k-foreign'),{revoked_at:null,revoked_reason:null});
 assert.deepEqual(keyRow(x.db,'k-old'),{revoked_at:5,revoked_reason:'superseded'});});
