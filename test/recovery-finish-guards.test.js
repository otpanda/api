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
import {createEmailRecoveryHttp} from '../src/email-recovery-http.js';import {EmailRecovery} from '../src/email-recovery.js';import {CodeCipher} from '../src/code-cipher.js';import {deliverRecoveryNotifications,drainRecoveryCodeJobs,recoveryDeliveryHealth,retryFailedRecoveryNotifications} from '../src/recovery-notifier.js';
const bind=(x,id,b)=>x.db.sqlite.prepare('UPDATE device_sessions SET browser_binding_digest=? WHERE device_id=?').run(b.repeat(64),id);
async function clients(x){bind(x,x.d.deviceId,'a');const ap=await x.sessions.issue({proof:{ownerId:'owner',credentialId:x.a.credential.id,generation:0,purpose:'authenticate',verifiedAt:NOW},clientKind:'web'});bind(x,ap.deviceId,'3');
 const gg=await x.mk();bind(x,gg.deviceId,'4');
 const call=(step,value,auth,method='POST')=>x.http.fetch(new Request(API+'/v1/manage/recovery/'+step,{method,headers:{Origin:APP,'Content-Type':'application/json',Authorization:'Bearer '+auth},...(method==='POST'?{body:JSON.stringify(value)}:{})}),{clientAddress:'t'});
 return{ap,gg,call};}
const B43='B'.repeat(43);
let CIPHER;const cipher=async()=>CIPHER??=new CodeCipher({keys:new Map([['k',await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt'])]]),activeKeyId:'k'});
async function recovery(opts){const x=await setup(opts),mail=[],er=createEmailRecoveryHttp({db:x.db,clock:x.clock,passkeys:x.passkeys,getCipher:cipher,deliver:async m=>{mail.push(m);}});
 const call=(step,value,{origin=APP,addr='1.1.1.1'}={})=>er.fetch(new Request(API+'/auth/recovery/email/'+step,{method:'POST',headers:{Origin:origin,'Content-Type':'application/json'},body:JSON.stringify(value)}),{clientAddress:addr});
 return{...x,mail,call};}
const em='a@gmail.com';
const status=async(r,step,v,n)=>{const res=await r.call(step,v);assert.equal(res.status,n,step+' '+JSON.stringify(await res.clone().json()));return res;};
async function begin(x){await x.flow('email-escape-on',{extra:{warningAccepted:true}});await x.call('request',{email:em,binding:B43});await x.call('verify',{email:em,code:x.mail[0].code,binding:B43});
 x.t.now=NOW+604800000;await x.call('complete-code',{email:em,binding:B43});return(await status(x,'complete-begin',{email:em,code:x.mail[1].code,binding:B43},200)).json();}
// Overlay regressions for finishCompletion guards. See per-test comments for redundant vs real defense.
const fin=(x,g,neu,o={})=>x.call('complete-finish',{grant:o.grant??g.grant,token:g.ceremony.token,response:neu.registration({expected:g.ceremony.options.challenge})});
const intact=(x,neu)=>{assert.ok(!active(x.db).includes(neu.credential.id));assert.equal(active(x.db).length,2);assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM device_sessions WHERE revoked_at IS NULL').get().n,1);assert.equal(x.db.sqlite.prepare('SELECT generation g FROM account_security').get().g,0);assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM email_recovery_requests WHERE completed_at IS NOT NULL').get().n,0);};
test('wrong grant secret: refused, retires nothing, and does not burn the real grant',async()=>{const x=await recovery(),g=await begin(x),neu=authenticator();
 const bad=g.grant.slice(0,-1)+(g.grant.endsWith('A')?'B':'A');
 assert.equal((await fin(x,g,neu,{grant:bad})).status,403);intact(x,neu);
 assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM email_recovery_grants').get().n,1);});
test('expired grant (grant TTL only; ceremony still valid): refused, retires nothing',async()=>{const x=await recovery(),g=await begin(x),neu=authenticator();
 x.db.sqlite.prepare('UPDATE email_recovery_grants SET expires_at=created_at+1').run();x.db.sqlite.prepare('UPDATE passkey_ceremonies SET expires_at=?').run(x.t.now+3600000);x.t.now+=5000;
 assert.equal((await fin(x,g,neu)).status,403);intact(x,neu);});
test('expired ceremony (grant still valid): refused, retires nothing',async()=>{const x=await recovery(),g=await begin(x),neu=authenticator();
 x.db.sqlite.prepare('UPDATE passkey_ceremonies SET expires_at=created_at+1').run();
 x.db.sqlite.prepare('UPDATE email_recovery_grants SET expires_at=?').run(x.t.now+3600000);x.t.now+=5000;
 assert.equal((await fin(x,g,neu)).status,403);intact(x,neu);});
test('grant/ceremony generation mismatch while the account generation is unchanged: refused, retires nothing',async()=>{const x=await recovery(),g=await begin(x),neu=authenticator();
 x.db.sqlite.prepare('UPDATE email_recovery_grants SET generation=7').run();
 assert.equal((await fin(x,g,neu)).status,403);intact(x,neu);});
test('grant bound to another owner is refused and retires nothing',async()=>{const x=await recovery(),g=await begin(x),neu=authenticator();
 x.db.sqlite.exec('PRAGMA foreign_keys=OFF');x.db.sqlite.prepare("INSERT INTO accounts(owner_id,created_at) VALUES('other',?)").run(NOW);x.db.sqlite.prepare("UPDATE email_recovery_grants SET owner_id='other'").run();x.db.sqlite.exec('PRAGMA foreign_keys=ON');
 assert.equal((await fin(x,g,neu)).status,403);intact(x,neu);});
test('grant is single use even after a refused finish (replay of a consumed grant)',async()=>{const x=await recovery(),g=await begin(x),neu=authenticator();
 const r=await fin(x,g,neu);assert.equal(r.status,200);assert.equal((await fin(x,g,authenticator())).status,403);});
