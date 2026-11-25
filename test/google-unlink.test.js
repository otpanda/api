import test from 'node:test';import assert from 'node:assert/strict';
import {DeviceSessionService} from '../src/device-sessions.js';import {PasskeyService} from '../src/passkey-service.js';import {database} from './sqlite-helper.js';import {authenticator} from './passkey-fixture.js';
import {hashText} from '../src/sessions.js';import {ExtraVerification} from '../src/extra-verification.js';
import {RecoveryControls,recoveryAction,DELAY_MS} from '../src/recovery-controls.js';import {createRecoveryControlsHttp} from '../src/recovery-controls-http.js';
import {createIdentityRuntime} from '../src/identity-runtime.js';
const NOW=1800000000000,API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io';
const key=(db,a)=>db.sqlite.prepare('INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) VALUES(?,?,?,?,?,?,?,?)').run(a.credential.id,'owner',a.credential.publicKey,0,'[]','singleDevice',0,NOW);
async function setup({google=true,second=true,first=true,lv}={}){const db=database(),t={now:NOW},clock=()=>t.now;
 db.sqlite.prepare('INSERT INTO accounts(owner_id,created_at) VALUES(?,?)').run('owner',NOW);db.sqlite.prepare('INSERT INTO account_emails VALUES(?,?,?,?)').run('owner','a@gmail.com',NOW,NOW);db.sqlite.prepare('INSERT INTO account_security(owner_id) VALUES(?)').run('owner');
 db.sqlite.prepare("INSERT INTO provider_identities(identity_id,owner_id,provider,issuer,subject,email,created_at) VALUES('one','owner','google','https://accounts.google.com','one','a@gmail.com',?)").run(NOW);
 if(!google)db.sqlite.prepare('UPDATE provider_identities SET revoked_at=?').run(NOW);
 const a=authenticator(),b=authenticator();if(first)key(db,a);if(second)key(db,b);
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
const active=db=>db.sqlite.prepare('SELECT credential_id id FROM passkey_credentials WHERE revoked_at IS NULL').all();
const q=(x,s,...p)=>x.db.sqlite.prepare(s).get(...p);
const LINK="SELECT count(*) n FROM provider_identities WHERE owner_id='owner' AND revoked_at IS NULL";
const INS="INSERT INTO provider_identities(identity_id,owner_id,provider,issuer,subject,email,created_at) VALUES(?,'owner','google','https://accounts.google.com','one','a@gmail.com',1) ON CONFLICT(issuer,subject) WHERE revoked_at IS NULL DO NOTHING";
test('google unlink: passkey step-up revokes link, Google sessions (incl. this one), recognition, pending; passkey sessions and protection stay',async()=>{
 const x=await setup();
 const pk=await x.sessions.issue({proof:{authMethod:'passkey',credentialId:x.a.credential.id,ownerId:'owner',generation:0,purpose:'authenticate',verifiedAt:NOW},clientKind:'web'});
 x.db.sqlite.prepare("INSERT INTO recognized_browsers(recognition_id,secret_digest,owner_id,provider_identity_id,generation,created_at) VALUES('r1',?,'owner','one',0,1)").run('0'.repeat(64));
 x.db.sqlite.prepare("INSERT INTO new_device_verification(owner_id,enabled_at,generation) VALUES('owner',1,0)").run();
 const r=await x.flow('google-unlink');assert.equal(r.status,200);assert.deepEqual(await r.json(),{revoked:'google'});
 assert.equal(q(x,LINK).n,0);assert.ok(q(x,"SELECT revoked_at r FROM provider_identities WHERE identity_id='one'").r);
 assert.equal((await x.sessions.authenticate(x.d.access)),undefined,'google session ended, including the one that did the unlink');
 assert.equal(q(x,"SELECT count(*) n FROM device_sessions WHERE provider_identity_id='one' AND revoked_at IS NULL").n,0,'revoked_at written so the realtime trigger fires');
 assert.ok((await x.sessions.authenticate(pk.access)),'passkey session untouched');
 assert.equal(q(x,'SELECT revoked_at r FROM recognized_browsers').r!==null,true);
 assert.equal(q(x,'SELECT count(*) n FROM new_device_verification').n,1,'protection setting left as is');
 assert.equal(active(x.db).length,2);
});
test('google unlink: not linked is 409 before any ceremony; nothing to revoke',async()=>{
 const x=await setup({google:false});const pk=await x.sessions.issue({proof:{authMethod:'passkey',credentialId:x.a.credential.id,ownerId:'owner',generation:0,purpose:'authenticate',verifiedAt:NOW},clientKind:'web'});
 const r=await x.call('begin',{kind:'google-unlink'},{auth:pk.access});assert.equal(r.status,409);assert.equal((await r.json()).error,'not_linked');
 assert.equal(q(x,'SELECT count(*) n FROM passkey_ceremonies').n,0);
});
test('google unlink: replay, stale generation, revoked proving passkey, wrong shape and approval path all fail closed',async()=>{
 const x=await setup();const base={kind:'google-unlink'};
 const bg=await (await x.call('begin',base)).json(),resp=x.a.assertion({expected:bg.options.challenge,counter:1});
 assert.equal((await x.call('finish',{...base,token:bg.token,response:resp})).status,200);
 assert.equal((await x.call('finish',{...base,token:bg.token,response:resp})).status,401,'session already ended; replay cannot pass');
 // revoked proving passkey between begin and finish
 const y=await setup();const b2=await (await y.call('begin',base)).json();y.db.sqlite.prepare('UPDATE passkey_credentials SET revoked_at=? WHERE credential_id=?').run(NOW,y.a.credential.id);
 assert.equal((await y.call('finish',{...base,token:b2.token,response:y.a.assertion({expected:b2.options.challenge,counter:1})})).status,403);assert.equal(q(y,LINK).n,1);
 // generation bump between begin and finish
 const z=await setup();const b3=await (await z.call('begin',base)).json();z.db.sqlite.prepare("UPDATE account_security SET generation=generation+1 WHERE owner_id='owner'").run();
 assert.notEqual((await z.call('finish',{...base,token:b3.token,response:z.a.assertion({expected:b3.options.challenge,counter:1})})).status,200);assert.equal(q(z,LINK).n,1);
 // target not allowed, and the enrolled-client approval path never accepts this kind
 const w=await setup();assert.equal((await w.call('begin',{kind:'google-unlink',target:'x'})).status,400);
 assert.equal((await w.call('request-change',{kind:'google-unlink'})).status,403);assert.equal(q(w,LINK).n,1);
 // wrong-action proof: ceremony begun for session-revoke cannot unlink
 const v=await setup();const b4=await (await v.call('begin',{kind:'session-revoke',target:'zzz'})).json();
 const r4=await v.call('finish',{...base,token:b4.token,response:v.a.assertion({expected:b4.options.challenge,counter:1})});assert.notEqual(r4.status,200);assert.equal(q(v,LINK).n,1);
});
test('reconnect: partial unique index allows relinking the same Google subject after unlink, but never two active links',async()=>{
 const x=await setup();assert.equal((await x.flow('google-unlink')).status,200);
 assert.equal(x.db.sqlite.prepare(INS).run('two').changes,1,'relink after unlink');
 assert.equal(x.db.sqlite.prepare(INS).run('three').changes,0,'second active link for the same subject is a no-op');
 assert.equal(q(x,"SELECT count(*) n FROM provider_identities WHERE subject='one'").n,2,'revoked row kept for audit');
 assert.equal(q(x,LINK).n,1);
 // second unlink of the new link works too (revoked rows accumulate)
 const pk=await x.sessions.issue({proof:{authMethod:'passkey',credentialId:x.a.credential.id,ownerId:'owner',generation:0,purpose:'authenticate',verifiedAt:NOW},clientKind:'web'});
 const base={kind:'google-unlink'},bg=await (await x.call('begin',base,{auth:pk.access})).json();
 assert.equal((await x.call('finish',{...base,token:bg.token,response:x.a.assertion({expected:bg.options.challenge,counter:9})},{auth:pk.access})).status,200);assert.equal(q(x,LINK).n,0);
});
test('google unlink: zero active passkeys is 409 no_passkey before any ceremony; finish cannot apply; link and sessions unchanged',async()=>{
 const x=await setup({first:false,second:false});
 const r=await x.call('begin',{kind:'google-unlink'});assert.equal(r.status,409);assert.equal((await r.json()).error,'no_passkey');
 assert.equal(q(x,'SELECT count(*) n FROM passkey_ceremonies').n,0);
 const f=await x.call('finish',{kind:'google-unlink',token:'x'.repeat(40),response:x.a.assertion({expected:'AAAA',counter:1})});assert.notEqual(f.status,200);
 assert.equal(q(x,LINK).n,1);assert.ok(await x.sessions.authenticate(x.d.access),'google session untouched');
 // all passkeys revoked after linking behaves the same
 const y=await setup();y.db.sqlite.prepare('UPDATE passkey_credentials SET revoked_at=?').run(NOW);
 const r2=await y.call('begin',{kind:'google-unlink'});assert.equal(r2.status,409);assert.equal((await r2.json()).error,'no_passkey');assert.equal(q(y,LINK).n,1);
});
