import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { PasskeySignupService } from '../src/passkey-signup.js';
import { AccountIdentityService } from '../src/account-identity.js';
import { DeviceSessionService } from '../src/device-sessions.js';
import { ExtraVerification, ACTION, PENDING_TTL, MAX_PENDING } from '../src/extra-verification.js';
import { hashText } from '../src/sessions.js';
import { authenticator } from './passkey-fixture.js';
const NOW=1_800_000_000_000,REDIRECT='https://otpanda.github.io/app/',CH='a'.repeat(43),B1='1'.repeat(64),B2='2'.repeat(64);
async function setup(){
 const db=database();let now=NOW;
 const identity=new AccountIdentityService(db,{clock:()=>now}),signup=new PasskeySignupService(db,{clock:()=>now});
 const {token}=await identity.issueEmailChallenge({purpose:'signup-email',email:'a@example.com'});
 const c=await signup.begin({email:'a@example.com',emailToken:token,binding:'binding'}),a=authenticator();
 const account=await signup.finish({token:c.token,binding:'binding',response:a.registration({expected:c.options.challenge})});
 db.sqlite.prepare("INSERT INTO provider_identities(identity_id,owner_id,provider,issuer,subject,email,created_at) VALUES('g1',?,'google','https://accounts.google.com','sub-1','a@example.com',?)").run(account.ownerId,NOW);
 const sessions=new DeviceSessionService(db,{clock:()=>now}),ev=new ExtraVerification(db,{clock:()=>now});
 const credentialId=db.sqlite.prepare('SELECT credential_id c FROM passkey_credentials').get().c;
 const google={ownerId:account.ownerId,generation:account.generation,verifiedAt:NOW,purpose:'authenticate',authMethod:'google',issuer:'https://accounts.google.com',subject:'sub-1'};
 const passkey={...account,verifiedAt:NOW,purpose:'authenticate'};
 const step=async action=>({ownerId:account.ownerId,credentialId,generation:account.generation,verifiedAt:now,purpose:'step-up',actionDigest:await hashText(action)});
 const login=(extra={},bind=B1,proof=google)=>sessions.issueBrowserLogin({proof:{...proof,verifiedAt:now},browserBindingDigest:bind,priorRefresh:undefined,challenge:CH,redirectUri:REDIRECT,deadline:now+60000,...extra});
 return {db,account,sessions,ev,google,passkey,step,login,credentialId,setNow:v=>now=v,owner:account.ownerId,gen:account.generation};
}
const pendingArgs=x=>({ownerId:x.owner,generation:x.gen,issuer:'https://accounts.google.com',subject:'sub-1',challenge:CH,browserBindingDigest:B1,remember:true,context:'envelope'});
async function enabled(){const x=await setup();assert.deepEqual(await x.ev.enable({proof:await x.step(ACTION.enable),warningAccepted:true}),{enabled:true});return x;}
test('default off: Google login works, recognition is recorded for later, then enabling does not force this browser',async()=>{
 const x=await setup(),rec=await x.ev.newRecognition();
 assert.ok(await x.login({protection:{newRecognition:rec}}));assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM recognized_browsers').get().n,1);
 await x.ev.enable({proof:await x.step(ACTION.enable),warningAccepted:true});
 assert.ok(await x.login({protection:{recognition:{id:rec.id,digest:rec.digest}}},B2));
 assert.equal(await x.login({},B2),undefined);
 assert.equal(await x.login({protection:{recognition:{id:rec.id,digest:'f'.repeat(64)}}},B2),undefined);x.db.sqlite.close();
});
test('enable and disable need warning acceptance and exact fresh passkey proof',async()=>{
 const x=await setup();
 assert.equal(await x.ev.enable({proof:await x.step(ACTION.enable),warningAccepted:false}),undefined);
 assert.equal(await x.ev.enable({proof:await x.step(ACTION.disable),warningAccepted:true}),undefined);
 assert.equal(await x.ev.enable({proof:{...await x.step(ACTION.enable),purpose:'authenticate'},warningAccepted:true}),undefined);
 assert.equal(await x.ev.enable({proof:{...await x.step(ACTION.enable),verifiedAt:NOW-120000},warningAccepted:true}),undefined);
 assert.equal(await x.ev.enable({proof:await x.step(ACTION.enable)}),undefined);
 assert.equal(await x.ev.enabled(x.owner),false);
 assert.ok(await x.ev.enable({proof:await x.step(ACTION.enable),warningAccepted:true}));
 assert.equal(await x.ev.disable({proof:await x.step(ACTION.enable)}),undefined);assert.equal(await x.ev.enabled(x.owner),true);
 assert.deepEqual(await x.ev.disable({proof:await x.step(ACTION.disable)}),{enabled:false});assert.equal(await x.ev.enabled(x.owner),false);x.db.sqlite.close();
});
test('enable refused when proving passkey was revoked or generation changed',async()=>{
 for(const c of ['revoked','generation']){const x=await setup(),proof=await x.step(ACTION.enable);
  if(c==='revoked')x.db.sqlite.prepare('UPDATE passkey_credentials SET revoked_at=?').run(NOW);else x.db.sqlite.prepare('UPDATE account_security SET generation=generation+1').run();
  assert.equal(await x.ev.enable({proof,warningAccepted:true}),undefined);assert.equal(await x.ev.enabled(x.owner),false);x.db.sqlite.close();}
});
test('passkey login is never gated, and enabled gate fails closed even with no passkey left',async()=>{
 const x=await enabled();assert.ok(await x.login({},B1,x.passkey));
 x.db.sqlite.prepare('DELETE FROM passkey_credentials').run();assert.equal(await x.login({}),undefined);x.db.sqlite.close();
});
test('last active passkey cannot be revoked while on; any path; second passkey allows one revoke',async()=>{
 const x=await enabled();
 assert.throws(()=>x.db.sqlite.prepare('UPDATE passkey_credentials SET revoked_at=? WHERE credential_id=?').run(NOW,x.credentialId),/last verifier/);
 assert.throws(()=>x.db.sqlite.prepare('UPDATE passkey_credentials SET revoked_at=?').run(NOW),/last verifier/);
 x.db.sqlite.prepare("INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) VALUES('c2',?,x'00',0,'[]','multiDevice',1,1)").run(x.owner);
 x.db.sqlite.prepare('UPDATE passkey_credentials SET revoked_at=? WHERE credential_id=?').run(NOW,x.credentialId);
 assert.throws(()=>x.db.sqlite.prepare("UPDATE passkey_credentials SET revoked_at=? WHERE credential_id='c2'").run(NOW),/last verifier/);
 assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM passkey_credentials WHERE revoked_at IS NULL').get().n,1);x.db.sqlite.close();
});
test('revoking is unrestricted when the setting is off or after disabling',async()=>{
 const x=await setup();x.db.sqlite.prepare('UPDATE passkey_credentials SET revoked_at=?').run(NOW);x.db.sqlite.close();
 const y=await enabled();await y.ev.disable({proof:await y.step(ACTION.disable)});y.db.sqlite.prepare('UPDATE passkey_credentials SET revoked_at=?').run(NOW);y.db.sqlite.close();
});
test('pending needs the setting on, an active link, current generation and respects the cap',async()=>{
 const off=await setup();assert.equal(await off.ev.createPending(pendingArgs(off)),undefined);off.db.sqlite.close();
 const x=await enabled();
 assert.equal(await x.ev.createPending({...pendingArgs(x),subject:'other'}),undefined);
 assert.equal(await x.ev.createPending({...pendingArgs(x),generation:x.gen+1}),undefined);
 assert.equal(await x.ev.createPending({...pendingArgs(x),remember:'yes'}),undefined);
 assert.equal(await x.ev.createPending({...pendingArgs(x),context:'x'.repeat(4097)}),undefined);
 for(let i=0;i<MAX_PENDING;i++)assert.ok(await x.ev.createPending(pendingArgs(x)));
 assert.equal(await x.ev.createPending(pendingArgs(x)),undefined);
 x.db.sqlite.prepare('UPDATE provider_identities SET revoked_at=?').run(NOW);x.db.sqlite.prepare('DELETE FROM pending_logins').run();assert.equal(await x.ev.createPending(pendingArgs(x)),undefined);x.db.sqlite.close();
});
test('unapproved pending carries no authority; poll is bound to the waiting browser',async()=>{
 const x=await enabled(),p=await x.ev.createPending(pendingArgs(x)),tok=await x.ev.parseToken(p.token);
 assert.deepEqual(await x.ev.poll({token:p.token,browserBindingDigest:B1}),{status:'waiting'});
 assert.deepEqual(await x.ev.poll({token:p.token,browserBindingDigest:B2}),{status:'denied'});
 assert.equal(await x.login({protection:{pending:{id:tok.id,digest:tok.digest}}}),undefined);
 x.setNow(NOW+PENDING_TTL);assert.deepEqual(await x.ev.poll({token:p.token,browserBindingDigest:B1}),{status:'expired'});x.db.sqlite.close();
});
test('passkey approval is exact-action bound; issue consumes once, remembers, replay fails',async()=>{
 const x=await enabled(),p=await x.ev.createPending(pendingArgs(x)),other=await x.ev.createPending(pendingArgs(x));
 assert.equal(await x.ev.approveWithPasskey({proof:await x.step(ACTION.approve(other.pendingId)),pendingId:p.pendingId}),undefined);
 assert.equal(await x.ev.approveWithPasskey({proof:await x.step(ACTION.enable),pendingId:p.pendingId}),undefined);
 assert.equal(await x.ev.approveWithPasskey({proof:await x.step(ACTION.approve(p.pendingId)),pendingId:p.pendingId}),true);
 assert.equal(await x.ev.approveWithPasskey({proof:await x.step(ACTION.approve(p.pendingId)),pendingId:p.pendingId}),false);
 const polled=await x.ev.poll({token:p.token,browserBindingDigest:B1});assert.equal(polled.status,'approved');assert.equal(polled.context,'envelope');
 const pend={id:polled.pendingId,digest:polled.digest},rec=await x.ev.newRecognition();
 // wrong browser or wrong PKCE challenge cannot redeem
 assert.equal(await x.login({protection:{pending:pend}},B2),undefined);
 assert.equal(await x.login({protection:{pending:pend},challenge:'b'.repeat(43)}),undefined);
 const issued=await x.login({protection:{pending:pend,newRecognition:rec}});assert.ok(issued);
 assert.equal(await x.login({protection:{pending:pend}}),undefined);
 assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM recognized_browsers').get().n,1);
 assert.ok(await x.login({protection:{recognition:{id:rec.id,digest:rec.digest}}},B2));x.db.sqlite.close();
});
test('unchecked remember creates no recognition',async()=>{
 const x=await enabled(),p=await x.ev.createPending({...pendingArgs(x),remember:false});
 await x.ev.approveWithPasskey({proof:await x.step(ACTION.approve(p.pendingId)),pendingId:p.pendingId});
 const polled=await x.ev.poll({token:p.token,browserBindingDigest:B1});assert.equal(polled.remember,false);
 assert.ok(await x.login({protection:{pending:{id:polled.pendingId,digest:polled.digest}}}));
 assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM recognized_browsers').get().n,0);x.db.sqlite.close();
});
test('recognition dies with link revocation, generation change or another link',async()=>{
 for(const c of ['link','generation','other']){
  const x=await setup(),rec=await x.ev.newRecognition();assert.ok(await x.login({protection:{newRecognition:rec}}));await x.ev.enable({proof:await x.step(ACTION.enable),warningAccepted:true});
  const use=()=>x.login({protection:{recognition:{id:rec.id,digest:rec.digest}}},B2);
  if(c==='link')x.db.sqlite.prepare('UPDATE provider_identities SET revoked_at=?').run(NOW);
  if(c==='generation')x.db.sqlite.prepare('UPDATE account_security SET generation=generation+1').run();
  if(c==='other'){x.db.sqlite.prepare("INSERT INTO provider_identities(identity_id,owner_id,provider,issuer,subject,email,created_at) VALUES('g2',?,'google','https://accounts.google.com','sub-2','a@example.com',?)").run(x.owner,NOW);const r=await x.login({proof:{...x.google,subject:'sub-2'}},B2);assert.equal(r,undefined);x.db.sqlite.close();continue;}
  assert.equal(await use(),undefined);x.db.sqlite.close();
 }
});
async function withSessions(){
 const x=await setup(),old=await x.sessions.issue({proof:x.google,clientKind:'web',browserBindingDigest:'3'.repeat(64)});
 assert.ok(await x.ev.enable({proof:await x.step(ACTION.enable),warningAccepted:true}));
 x.setNow(NOW+1000);return {...x,old};
}
test('canceled pending cannot be approved or used; list shows ids only',async()=>{
 const x=await withSessions(),p=await x.ev.createPending(pendingArgs(x));
 const list=await x.ev.listForApprover({ownerId:x.owner,generation:x.gen});assert.deepEqual(Object.keys(list[0]).sort(),['createdAt','expiresAt','pendingId']);
 assert.equal(await x.ev.cancel({ownerId:'other',generation:x.gen,pendingId:p.pendingId}),false);
 assert.equal(await x.ev.cancel({ownerId:x.owner,generation:x.gen,pendingId:p.pendingId}),true);
 assert.equal(await x.ev.approveWithClient({ownerId:x.owner,deviceId:x.old.deviceId,generation:x.gen,pendingId:p.pendingId}),false);
 assert.deepEqual(await x.ev.poll({token:p.token,browserBindingDigest:B1}),{status:'denied'});assert.ok(await x.ev.cleanup({limit:10})>=1);x.db.sqlite.close();
});
const web=(x,b)=>x.sessions.issue({proof:x.google,clientKind:'web',browserBindingDigest:b});
const ids=x=>({ownerId:x.owner,generation:x.gen});
test('client path: exact-action enable and disable need a different-browser approver and one consume',async()=>{
 const x=await setup(),a=await web(x,B1),b=await web(x,'3'.repeat(64)),base=ids(x),bad=await web(x,B1);
 assert.equal(await x.ev.createSettingChange({...base,deviceId:a.deviceId,enabled:true}),undefined);
 const en=await x.ev.createSettingChange({...base,deviceId:a.deviceId,enabled:true,warningAccepted:true});
 assert.equal(await x.ev.consumeSettingChange({...base,deviceId:a.deviceId,changeId:en.changeId}),undefined);
 assert.deepEqual(await x.ev.listSettingChanges({...base,deviceId:a.deviceId}),[]);
 assert.equal((await x.ev.listSettingChanges({...base,deviceId:b.deviceId})).length,1);
 assert.equal(await x.ev.approveSettingChange({...base,deviceId:a.deviceId,changeId:en.changeId}),false);
 assert.equal(await x.ev.approveSettingChange({...base,deviceId:bad.deviceId,changeId:en.changeId}),false,'same browser');
 assert.equal(await x.ev.approveSettingChange({...base,ownerId:'other',deviceId:b.deviceId,changeId:en.changeId}),false);
 assert.equal(await x.ev.approveSettingChange({...base,deviceId:b.deviceId,changeId:en.changeId}),true);
 assert.equal(await x.ev.consumeSettingChange({...base,deviceId:b.deviceId,changeId:en.changeId}),undefined);
 assert.deepEqual(await x.ev.consumeSettingChange({...base,deviceId:a.deviceId,changeId:en.changeId}),{enabled:true});
 assert.equal(await x.ev.consumeSettingChange({...base,deviceId:a.deviceId,changeId:en.changeId}),undefined);
 const dis=await x.ev.createSettingChange({...base,deviceId:a.deviceId,enabled:false});
 assert.equal(await x.ev.consumeSettingChange({...base,deviceId:a.deviceId,changeId:dis.changeId}),undefined);assert.equal(await x.ev.enabled(x.owner),true);
 assert.ok(await x.ev.approveSettingChange({...base,deviceId:b.deviceId,changeId:dis.changeId}));
 assert.deepEqual(await x.ev.consumeSettingChange({...base,deviceId:a.deviceId,changeId:dis.changeId}),{enabled:false});x.db.sqlite.close();
});

function raw(x,{binding,created,kind='web',credential=null,link='g1'}){
 const id=crypto.randomUUID();
 x.db.sqlite.prepare("INSERT INTO device_sessions(device_id,owner_id,credential_id,provider_identity_id,generation,client_kind,created_at,last_used_at,expires_at,browser_binding_digest) VALUES(?,?,?,?,?,?,?,?,?,?)").run(id,x.owner,credential,credential?null:link,x.gen,kind,created,created,created+30*86400000,binding);return id;
}
const addPasskey=x=>x.db.sqlite.prepare("INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) VALUES('c2',?,x'00',0,'[]','multiDevice',1,1)").run(x.owner);
const enableNow=async x=>assert.ok(await x.ev.enable({proof:await x.step(ACTION.enable),warningAccepted:true}));
test('signed-in client approves only older, different-browser, active, same-owner sessions',async()=>{
 const x=await setup(),old=await web(x,'3'.repeat(64));await enableNow(x);x.setNow(NOW+1000);
 const mk=()=>x.ev.createPending(pendingArgs(x)),a=(deviceId,pendingId,o={})=>x.ev.approveWithClient({ownerId:x.owner,deviceId,generation:x.gen,pendingId,...o});
 const p1=await mk();assert.equal(await a(old.deviceId,p1.pendingId,{ownerId:'other'}),false);assert.equal(await a('nope',p1.pendingId),false);
 const same=raw(x,{binding:B1,created:NOW+10});const p2=await mk();assert.equal(await a(same,p2.pendingId),false);
 const later=raw(x,{binding:'4'.repeat(64),created:NOW+5000});assert.equal(await a(later,p2.pendingId),false);
 assert.equal(await a(old.deviceId,p1.pendingId,{generation:x.gen+1}),false);
 await x.sessions.revoke({ownerId:x.owner,deviceId:old.deviceId});assert.equal(await a(old.deviceId,p1.pendingId),false);
 const fresh=raw(x,{binding:'5'.repeat(64),created:NOW+500});const p3=await mk();
 assert.equal(await a(fresh,p3.pendingId),true);assert.equal(await a(fresh,p3.pendingId),false);
 assert.equal((await x.ev.poll({token:p3.token,browserBindingDigest:B1})).status,'approved');x.db.sqlite.close();
});
test('approver of another owner or with a revoked method cannot approve',async()=>{
 const x=await setup(),gs=await web(x,'3'.repeat(64)),pk=await x.sessions.issue({proof:x.passkey,clientKind:'web',browserBindingDigest:'6'.repeat(64)});
 x.db.sqlite.prepare("INSERT INTO accounts(owner_id,created_at) VALUES('o2',1)").run();x.db.sqlite.prepare("INSERT INTO account_security(owner_id,generation) VALUES('o2',0)").run();
 x.db.sqlite.prepare("INSERT INTO account_emails VALUES('o2','b@example.com',1,1)").run();
 x.db.sqlite.prepare("INSERT INTO provider_identities(identity_id,owner_id,provider,issuer,subject,email,created_at) VALUES('g2','o2','google','https://accounts.google.com','sub-2','b@example.com',1)").run();
 const foreign=crypto.randomUUID();x.db.sqlite.prepare("INSERT INTO device_sessions(device_id,owner_id,provider_identity_id,generation,client_kind,created_at,last_used_at,expires_at,browser_binding_digest) VALUES(?,'o2','g2',0,'web',?,?,?,?)").run(foreign,NOW,NOW,NOW+9e9,'7'.repeat(64));
 await enableNow(x);x.setNow(NOW+1000);const p=await x.ev.createPending(pendingArgs(x)),q=await x.ev.createPending(pendingArgs(x));
 assert.equal(await x.ev.approveWithClient({ownerId:x.owner,deviceId:foreign,generation:x.gen,pendingId:p.pendingId}),false);
 addPasskey(x);x.db.sqlite.prepare('UPDATE passkey_credentials SET revoked_at=? WHERE credential_id=?').run(NOW,x.credentialId);
 assert.equal(await x.ev.approveWithClient({ownerId:x.owner,deviceId:pk.deviceId,generation:x.gen,pendingId:q.pendingId}),false,'passkey-backed approver after its passkey was revoked');
 assert.equal(await x.ev.approveWithClient({ownerId:x.owner,deviceId:gs.deviceId,generation:x.gen,pendingId:q.pendingId}),true);x.db.sqlite.close();
});
test('client path: exact-action change; revoked parties, generation and expiry block consume',async()=>{
 for(const c of ['approver','requester','generation','expired']){
  const x=await setup(),a=await web(x,B1),b=await web(x,B2),base=ids(x);
  const en=await x.ev.createSettingChange({...base,deviceId:a.deviceId,enabled:true,warningAccepted:true});await x.ev.approveSettingChange({...base,deviceId:b.deviceId,changeId:en.changeId});
  if(c==='approver')await x.sessions.revoke({ownerId:x.owner,deviceId:b.deviceId});
  if(c==='requester')await x.sessions.revoke({ownerId:x.owner,deviceId:a.deviceId});
  if(c==='generation')x.db.sqlite.prepare('UPDATE account_security SET generation=generation+1').run();
  if(c==='expired')x.setNow(NOW+PENDING_TTL);
  assert.equal(await x.ev.consumeSettingChange({...base,deviceId:a.deviceId,changeId:en.changeId}),undefined);assert.equal(await x.ev.enabled(x.owner),false);x.db.sqlite.close();
 }
 const y=await setup(),a=await web(y,B1),b=await web(y,B2),base=ids(y);await enableNow(y);
 const dis=await y.ev.createSettingChange({...base,deviceId:a.deviceId,enabled:false});await y.ev.approveSettingChange({...base,deviceId:b.deviceId,changeId:dis.changeId});
 assert.deepEqual(await y.ev.consumeSettingChange({...base,deviceId:a.deviceId,changeId:dis.changeId}),{enabled:false});y.db.sqlite.close();
});
test('last-passkey guard is strict: blocked while on, allowed with a second passkey, and after disabling',async()=>{
 const x=await setup(),g=await web(x,B1);await enableNow(x);assert.ok(g);
 assert.throws(()=>x.db.sqlite.prepare('UPDATE passkey_credentials SET revoked_at=?').run(NOW),/last verifier/,'a signed-in session does not relax it');
 assert.throws(()=>x.db.sqlite.prepare('UPDATE passkey_credentials SET revoked_at=? WHERE credential_id=?').run(NOW,x.credentialId),/last verifier/);
 addPasskey(x);x.db.sqlite.prepare('UPDATE passkey_credentials SET revoked_at=? WHERE credential_id=?').run(NOW,x.credentialId);
 assert.throws(()=>x.db.sqlite.prepare("UPDATE passkey_credentials SET revoked_at=? WHERE credential_id='c2'").run(NOW),/last verifier/);
 x.db.sqlite.prepare('DELETE FROM new_device_verification').run();x.db.sqlite.prepare("UPDATE passkey_credentials SET revoked_at=? WHERE credential_id='c2'").run(NOW);x.db.sqlite.close();
});
test('non-browser issue never creates a Google session while the setting is on',async()=>{
 const x=await setup();await enableNow(x);assert.equal(await x.sessions.issue({proof:x.google,clientKind:'web'}),undefined);assert.ok(await x.sessions.issue({proof:x.passkey,clientKind:'web'}));x.db.sqlite.close();
});
test('recognition rows need matching owner, generation, link and not revoked',async()=>{
 const base=async()=>{const x=await setup(),rec=await x.ev.newRecognition();await x.login({protection:{newRecognition:rec}});await enableNow(x);return{x,rec};};
 for(const [name,sql] of [['owner',"INSERT INTO accounts(owner_id,created_at) VALUES('o2',1);UPDATE recognized_browsers SET owner_id='o2'"],['generation','UPDATE recognized_browsers SET generation=generation+7'],['revoked','UPDATE recognized_browsers SET revoked_at=1']]){
  const {x,rec}=await base();assert.ok(await x.login({protection:{recognition:{id:rec.id,digest:rec.digest}}},B2),'control');x.db.sqlite.exec(sql);
  assert.equal(await x.login({protection:{recognition:{id:rec.id,digest:rec.digest}}},'8'.repeat(64)),undefined,name);x.db.sqlite.close();}
});
test('pending authority at the issuance write: unapproved, canceled, expired, replayed, wrong link or generation all fail',async()=>{
 for(const [name,mutate] of [['unapproved',null],['canceled',"UPDATE pending_logins SET canceled_at=1"],['expired',"UPDATE pending_logins SET created_at=1,expires_at=2"],['consumed',"UPDATE pending_logins SET consumed_at=1"],['generation',"UPDATE pending_logins SET generation=generation+5"],['link',"INSERT INTO provider_identities(identity_id,owner_id,provider,issuer,subject,email,created_at) SELECT 'g9',owner_id,'google','https://accounts.google.com','sub-9','a@example.com',1 FROM accounts LIMIT 1;UPDATE pending_logins SET provider_identity_id='g9'"],['owner',"INSERT INTO accounts(owner_id,created_at) VALUES('o2',1);UPDATE pending_logins SET owner_id='o2'"]]){
  const x=await enabled(),p=await x.ev.createPending(pendingArgs(x)),tok=await x.ev.parseToken(p.token);
  if(name!=='unapproved')await x.ev.approveWithPasskey({proof:await x.step(ACTION.approve(p.pendingId)),pendingId:p.pendingId});
  if(mutate)x.db.sqlite.exec(mutate);
  assert.equal(await x.login({protection:{pending:{id:tok.id,digest:tok.digest}}}),undefined,name);
  assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM device_sessions WHERE revoked_at IS NULL').get().n,0,name);x.db.sqlite.close();}
});
test('a pending usable by recognition-less login is consumed exactly once even when remember is true',async()=>{
 const x=await enabled(),p=await x.ev.createPending(pendingArgs(x)),tok=await x.ev.parseToken(p.token);
 await x.ev.approveWithPasskey({proof:await x.step(ACTION.approve(p.pendingId)),pendingId:p.pendingId});
 const r=await Promise.all([x.login({protection:{pending:{id:tok.id,digest:tok.digest},newRecognition:await x.ev.newRecognition()}}),x.login({protection:{pending:{id:tok.id,digest:tok.digest}}})]);
 assert.equal(r.filter(Boolean).length,1);x.db.sqlite.close();
});
test('setting-change replay at the identical clock cannot reapply an old toggle; cross-owner same id changes nothing',async()=>{
 const x=await setup(),a=await web(x,B1),b=await web(x,B2),base=ids(x);
 const en=await x.ev.createSettingChange({...base,deviceId:a.deviceId,enabled:true,warningAccepted:true});await x.ev.approveSettingChange({...base,deviceId:b.deviceId,changeId:en.changeId});
 assert.deepEqual(await x.ev.consumeSettingChange({...base,deviceId:a.deviceId,changeId:en.changeId}),{enabled:true});
 const dis=await x.ev.createSettingChange({...base,deviceId:a.deviceId,enabled:false});await x.ev.approveSettingChange({...base,deviceId:b.deviceId,changeId:dis.changeId});
 assert.deepEqual(await x.ev.consumeSettingChange({...base,deviceId:a.deviceId,changeId:dis.changeId}),{enabled:false});
 assert.equal(await x.ev.consumeSettingChange({...base,deviceId:a.deviceId,changeId:en.changeId}),undefined);
 assert.equal(await x.ev.enabled(x.owner),false,'same-millisecond replay of the old enable');
 assert.equal(await x.ev.consumeSettingChange({...base,ownerId:'other',deviceId:a.deviceId,changeId:dis.changeId}),undefined);
 // statement-level: consumed row with another owner/generation/receipt never toggles
 const rows=x.db.sqlite.prepare('SELECT change_id,consume_receipt FROM setting_changes').all();assert.ok(rows.every(r=>r.consume_receipt&&r.consume_receipt.length>8));
 assert.equal(new Set(rows.map(r=>r.consume_receipt)).size,rows.length);x.db.sqlite.close();
});
test('approval revoked after approval and before completion fails at the issuance write',async()=>{
 for(const c of ['client','passkey']){
  const x=await setup(),gs=await web(x,'3'.repeat(64)),pk=await x.sessions.issue({proof:x.passkey,clientKind:'web',browserBindingDigest:'6'.repeat(64)});await enableNow(x);x.setNow(NOW+1000);
  const p=await x.ev.createPending(pendingArgs(x)),tok=await x.ev.parseToken(p.token);
  if(c==='client')assert.equal(await x.ev.approveWithClient({ownerId:x.owner,deviceId:gs.deviceId,generation:x.gen,pendingId:p.pendingId}),true);
  else assert.equal(await x.ev.approveWithPasskey({proof:{...await x.step(ACTION.approve(p.pendingId)),verifiedAt:NOW+1000},pendingId:p.pendingId}),true);
  if(c==='client')await x.sessions.revoke({ownerId:x.owner,deviceId:gs.deviceId});else{addPasskey(x);x.db.sqlite.prepare('UPDATE passkey_credentials SET revoked_at=? WHERE credential_id=?').run(NOW,x.credentialId);}
  assert.equal(await x.login({protection:{pending:{id:tok.id,digest:tok.digest}}}),undefined,c);
  assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM device_sessions WHERE revoked_at IS NULL AND created_at>=?').get(NOW+1000).n,0);x.db.sqlite.close();
 }
});
test('approver generation change and expired approver session fail at issuance',async()=>{
 for(const c of ['generation','expired']){
  const x=await setup(),gs=await web(x,'3'.repeat(64));await enableNow(x);x.setNow(NOW+1000);
  const p=await x.ev.createPending(pendingArgs(x)),tok=await x.ev.parseToken(p.token);
  assert.equal(await x.ev.approveWithClient({ownerId:x.owner,deviceId:gs.deviceId,generation:x.gen,pendingId:p.pendingId}),true);
  if(c==='generation')x.db.sqlite.prepare('UPDATE account_security SET generation=generation+1').run();else x.db.sqlite.prepare('UPDATE device_sessions SET expires_at=?').run(NOW+1000);
  assert.equal(await x.login({protection:{pending:{id:tok.id,digest:tok.digest}}}),undefined,c);x.db.sqlite.close();
 }
});
test('stale Google proof requires exact approved pending even after setting disabled or recognition added',async()=>{for(const variant of ['none','canceled','wrong-binding','valid']){const x=await enabled(),p=await x.ev.createPending(pendingArgs(x));await x.ev.approveWithPasskey({proof:await x.step(ACTION.approve(p.pendingId)),pendingId:p.pendingId});const q=await x.ev.poll({token:p.token,browserBindingDigest:B1});await x.ev.disable({proof:await x.step(ACTION.disable)});x.setNow(NOW+181000);if(variant==='canceled')await x.ev.cancel({ownerId:x.owner,generation:x.gen,pendingId:p.pendingId});const pending=variant==='none'?undefined:{id:q.pendingId,digest:q.digest};const result=await x.sessions.issueBrowserLogin({proof:x.google,browserBindingDigest:variant==='wrong-binding'?B2:B1,challenge:CH,redirectUri:REDIRECT,deadline:NOW+240000,protection:{pending}});assert.equal(Boolean(result),variant==='valid',variant);x.db.sqlite.close();}});
