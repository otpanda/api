import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync, readdirSync } from 'node:fs';
import { database } from './sqlite-helper.js';
import { PasskeySignupService } from '../src/passkey-signup.js';
import { AccountIdentityService } from '../src/account-identity.js';
import { BrowserExchangeService, pkceChallenge } from '../src/browser-exchanges.js';
import { DeviceSessionService } from '../src/device-sessions.js';
import { authenticator } from './passkey-fixture.js';
const NOW=1_800_000_000_000,redirectUri='https://otpanda.github.io/app/',verifier='a'.repeat(43);
async function setup(){
 const db=database();let now=NOW;
 const identity=new AccountIdentityService(db,{clock:()=>now}),signup=new PasskeySignupService(db,{clock:()=>now});
 const {token}=await identity.issueEmailChallenge({purpose:'signup-email',email:'a@example.com'});
 const c=await signup.begin({email:'a@example.com',emailToken:token,binding:'binding'}),a=authenticator();
 const account=await signup.finish({token:c.token,binding:'binding',response:a.registration({expected:c.options.challenge})});
 const passkeyProof={...account,verifiedAt:NOW,purpose:'authenticate'};
 db.sqlite.prepare("INSERT INTO provider_identities(identity_id,owner_id,provider,issuer,subject,email,created_at) VALUES('g1',?,'google','https://accounts.google.com','sub-1','a@example.com',?)").run(account.ownerId,NOW);
 const googleProof={ownerId:account.ownerId,generation:account.generation,verifiedAt:NOW,purpose:'authenticate',authMethod:'google',issuer:'https://accounts.google.com',subject:'sub-1'};
 return {db,account,passkeyProof,googleProof,service:new DeviceSessionService(db,{clock:()=>now}),exchange:new BrowserExchangeService(db,{redirectUri,clock:()=>now}),setNow:v=>now=v};
}
test('Google session issues without a credential and every operation works',async()=>{
 const {db,service,googleProof}=await setup(),s=await service.issue({proof:googleProof,clientKind:'web'});assert.ok(s);
 const row=db.sqlite.prepare('SELECT credential_id,provider_identity_id FROM device_sessions').get();assert.equal(row.credential_id,null);assert.equal(row.provider_identity_id,'g1');
 const a=await service.authenticate(s.access);assert.equal(a.authMethod,'google');assert.equal(a.ownerId,googleProof.ownerId);
 const r=await service.rotate(s.refresh);assert.equal(r.status,'rotated');assert.ok(await service.authenticate(r.access));db.sqlite.close();
});
test('passkey sessions stay passkey and legacy proofs need no authMethod',async()=>{
 const {db,service,passkeyProof}=await setup(),s=await service.issue({proof:passkeyProof,clientKind:'web'});assert.equal((await service.authenticate(s.access)).authMethod,'passkey');db.sqlite.close();
});
test('Google proof denies for unlinked, revoked, other-owner,  stale-generation and mixed proofs',async()=>{
 const base=await setup(),{db,service,googleProof}=base;
 assert.equal(await service.issue({proof:{...googleProof,subject:'other'},clientKind:'web'}),undefined);
 assert.equal(await service.issue({proof:{...googleProof,credentialId:'x'},clientKind:'web'}),undefined);
 assert.equal(await service.issue({proof:{...googleProof,issuer:''},clientKind:'web'}),undefined);
 assert.equal(await service.issue({proof:{...googleProof,authMethod:'other'},clientKind:'web'}),undefined);
 assert.equal(await service.issue({proof:{...base.passkeyProof,issuer:'https://accounts.google.com',subject:'sub-1'},clientKind:'web'}),undefined);
 db.sqlite.prepare("INSERT INTO accounts(owner_id,created_at) VALUES('o2',1)").run();
 db.sqlite.prepare("UPDATE provider_identities SET owner_id='o2'").run();
 assert.equal(await service.issue({proof:googleProof,clientKind:'web'}),undefined);
 db.sqlite.prepare("UPDATE provider_identities SET owner_id=?").run(googleProof.ownerId);
 db.sqlite.prepare("UPDATE provider_identities SET email='b@example.com'").run();
 const drift=await service.issue({proof:googleProof,clientKind:'web'});assert.ok(drift);await service.revoke({ownerId:googleProof.ownerId,deviceId:drift.deviceId});
 db.sqlite.prepare("UPDATE provider_identities SET email='a@example.com'").run();
 assert.equal(await service.issue({proof:{...googleProof,generation:googleProof.generation+1},clientKind:'web'}),undefined);
 db.sqlite.prepare("UPDATE provider_identities SET revoked_at=?").run(NOW);
 assert.equal(await service.issue({proof:googleProof,clientKind:'web'}),undefined);
 assert.equal(db.sqlite.prepare('SELECT count(*) n FROM device_sessions WHERE revoked_at IS NULL').get().n,0);db.sqlite.close();
});
test('revoking the provider link or generation ends Google sessions; passkey revoke leaves them',async()=>{
 for(const change of ['link','generation','passkey']){
  const {db,service,googleProof}=await setup(),s=await service.issue({proof:googleProof,clientKind:'web'});
  if(change==='link')db.sqlite.prepare('UPDATE provider_identities SET revoked_at=?').run(NOW);
  if(change==='generation')db.sqlite.prepare('UPDATE account_security SET generation=generation+1').run();
  if(change==='passkey')db.sqlite.prepare('UPDATE passkey_credentials SET revoked_at=?').run(NOW);
  const alive=change==='passkey';
  assert.equal(!!await service.authenticate(s.access),alive);assert.equal((await service.rotate(s.refresh)).status,alive?'rotated':'denied');db.sqlite.close();
 }
});
test('passkey revocation ends passkey sessions only, not Google sessions of the same account',async()=>{
 const {db,service,googleProof,passkeyProof}=await setup(),g=await service.issue({proof:googleProof,clientKind:'web'}),p=await service.issue({proof:passkeyProof,clientKind:'web'});
 db.sqlite.prepare('UPDATE passkey_credentials SET revoked_at=?').run(NOW);assert.equal(await service.authenticate(p.access),undefined);assert.ok(await service.authenticate(g.access));db.sqlite.close();
});
test('issueBrowserLogin with Google commits PKCE exchange atomically and retires same-owner prior web device',async()=>{
 const {db,service,exchange,googleProof,passkeyProof}=await setup();
 const prior=await service.issue({proof:passkeyProof,clientKind:'web'}),challenge=await pkceChallenge(verifier);
 const login=await service.issueBrowserLogin({proof:googleProof,browserBindingDigest:'b'.repeat(64),priorRefresh:prior.refresh,challenge,redirectUri,deadline:NOW+60000});
 assert.ok(login?.code);assert.equal(await service.authenticate(prior.access),undefined);
 const got=await exchange.exchange({code:login.code,verifier,redirectUri});assert.ok(got?.access);assert.equal((await service.authenticate(got.access)).authMethod,'google');
 assert.equal(await exchange.exchange({code:login.code,verifier,redirectUri}),undefined);
 const bad=await service.issueBrowserLogin({proof:{...googleProof,subject:'nope'},browserBindingDigest:'c'.repeat(64),priorRefresh:undefined,challenge,redirectUri,deadline:NOW+60000});assert.equal(bad,undefined);
 assert.equal(db.sqlite.prepare("SELECT count(*) n FROM device_sessions WHERE revoked_at IS NULL").get().n,1);db.sqlite.close();
});
test('mint works for Google sessions and denies after link revocation',async()=>{
 const {db,service,exchange,googleProof}=await setup(),s=await service.issue({proof:googleProof,clientKind:'web'}),challenge=await pkceChallenge(verifier);
 assert.ok(await exchange.mint({deviceId:s.deviceId,challenge,redirectUri}));db.sqlite.prepare('UPDATE provider_identities SET revoked_at=?').run(NOW);assert.equal(await exchange.mint({deviceId:s.deviceId,challenge,redirectUri}),undefined);db.sqlite.close();
});
test('a session cannot be both or neither method',async()=>{
 const {db,googleProof,passkeyProof,service}=await setup();await service.issue({proof:passkeyProof,clientKind:'web'});
 const insert=(c,p)=>db.sqlite.prepare("INSERT INTO device_sessions(device_id,owner_id,credential_id,provider_identity_id,generation,client_kind,created_at,last_used_at,expires_at) VALUES(?,?,?,?,0,'web',1,1,2)").run(crypto.randomUUID(),googleProof.ownerId,c,p);
 const cred=db.sqlite.prepare('SELECT credential_id c FROM passkey_credentials').get().c;
 assert.throws(()=>insert(cred,'g1'));assert.throws(()=>insert(null,null));db.sqlite.close();
});
test('populated migration preserves sessions, handles, exchanges, intents and receipts',()=>{
 const sqlite=new DatabaseSync(':memory:');sqlite.exec('PRAGMA foreign_keys = ON');
 const files=readdirSync(new URL('../migrations/',import.meta.url)).sort();
 const sql=f=>readFileSync(new URL('../migrations/'+f,import.meta.url),'utf8');
 for(const f of files.filter(f=>f<'0022'))sqlite.exec(sql(f));
 sqlite.exec(`INSERT INTO accounts VALUES('o',1);INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) VALUES('c','o',x'00',0,'[]','multiDevice',1,1);
 INSERT INTO device_sessions(device_id,owner_id,credential_id,generation,client_kind,created_at,last_used_at,expires_at,revoked_at,browser_binding_digest) VALUES('d1','o','c',0,'web',1,2,3,NULL,'bind'),('d2','o','c',0,'android',1,2,3,4,NULL);
 INSERT INTO device_refresh_handles VALUES('r1','${'a'.repeat(64)}','d1',1,NULL);INSERT INTO device_access_handles VALUES('a1','${'b'.repeat(64)}','d1',1,9);
 INSERT INTO browser_exchanges VALUES('x1','${'c'.repeat(64)}','d1','${'e'.repeat(43)}','u',1,9);
 INSERT INTO assignment_intents(intent_id,owner_id,device_id,generation,source_id,event_id,entry_id,entry_revision,envelope,received_at,code_expires_at,action_digest,created_at,expires_at,consumed_at,result_expires_at,retired_at) VALUES('i1','o','d1',0,'s','e','en',0,'{}',1,2,'ad',1,2,5,9,NULL),('i2','o','d1',0,'s','e2','en',0,'{}',1,2,'ad',1,2,NULL,9,6);
 INSERT INTO assignment_receipts VALUES('i1',1);`);
 sqlite.exec(sql('0022_provider_session_methods.sql'));
 const n=t=>sqlite.prepare(`SELECT count(*) n FROM ${t}`).get().n;
 assert.deepEqual(['device_sessions','device_refresh_handles','device_access_handles','browser_exchanges','assignment_intents','assignment_receipts'].map(n),[2,1,1,1,2,1]);
 assert.deepEqual({...sqlite.prepare("SELECT credential_id,provider_identity_id,browser_binding_digest,revoked_at FROM device_sessions WHERE device_id='d1'").get()},{credential_id:'c',provider_identity_id:null,browser_binding_digest:'bind',revoked_at:null});
 assert.equal(sqlite.prepare("SELECT retired_at FROM assignment_intents WHERE intent_id='i2'").get().retired_at,6);
 assert.equal(sqlite.prepare("SELECT consumed_at FROM assignment_intents WHERE intent_id='i1'").get().consumed_at,5);
 assert.deepEqual(sqlite.prepare('PRAGMA foreign_key_check').all(),[]);
 assert.equal(sqlite.prepare("SELECT count(*) n FROM sqlite_master WHERE name LIKE '\\_bak%' ESCAPE '\\'").get().n,0);
 // cascades still work after the rebuild
 sqlite.exec("DELETE FROM device_sessions WHERE device_id='d1'");assert.deepEqual(['device_refresh_handles','browser_exchanges','assignment_intents','assignment_receipts'].map(n),[0,0,0,0]);
 sqlite.close();
});
