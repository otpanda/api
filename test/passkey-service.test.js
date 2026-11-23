import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { AccountIdentityService } from '../src/account-identity.js';
import { PasskeyService } from '../src/passkey-service.js';
import { PasskeyVerifier } from '../src/passkey-verifier.js';
import { authenticator } from './passkey-fixture.js';
const NOW=1_800_000_000_000,binding='opaque-browser-binding';
async function setup(){
 const db=database();let now=NOW;const identity=new AccountIdentityService(db,{clock:()=>now});
 async function signup(email){const {token}=await identity.issueEmailChallenge({purpose:'signup-email',email});return identity.createEmailAccount({email,token});}
 const owner=await signup('a@example.com'),other=await signup('b@example.com');
 const service=new PasskeyService(db,{clock:()=>now});
 async function enroll(a=authenticator(),ownerId=owner){const c=await service.begin({purpose:'register',ownerId,binding,action:'add-passkey'});assert.equal(await service.finishRegistration({token:c.token,ownerId,binding,action:'add-passkey',response:a.registration({expected:c.options.challenge})}),true);return a;}
 async function assertion(a,{ownerId=null,action=null,counter=1,handle=owner}={}){const c=await service.begin({purpose:ownerId?'step-up':'authenticate',ownerId,binding,action});const response=a.assertion({expected:c.options.challenge,counter});response.response.userHandle=Buffer.from(handle).toString('base64url');return {token:c.token,binding,response,ownerId,action};}
 return {db,owner,other,service,enroll,assertion,setNow:v=>now=v};
}
test('one-use bound registration stores public material, exact owner and no bearer secrets',async()=>{
 const {db,owner,service}=await setup(),a=authenticator();const c=await service.begin({purpose:'register',ownerId:owner,binding,action:'add-passkey'});
 assert.equal(await service.finishRegistration({token:c.token,ownerId:owner,binding:'wrong',action:'add-passkey',response:a.registration({expected:c.options.challenge})}),false);
 assert.equal(await service.finishRegistration({token:c.token,ownerId:owner,binding,action:'delete-account',response:a.registration({expected:c.options.challenge})}),false);
 assert.ok(!JSON.stringify(db.sqlite.prepare('SELECT * FROM passkey_ceremonies').all()).includes(c.token));
 const args={token:c.token,ownerId:owner,binding,action:'add-passkey',response:a.registration({expected:c.options.challenge})};
 assert.equal(await service.finishRegistration(args),true);assert.equal(await service.finishRegistration(args),false);
 const row=db.sqlite.prepare('SELECT * FROM passkey_credentials').get();assert.equal(row.owner_id,owner);assert.equal(row.credential_id,a.credential.id);assert.equal(row.counter,0);assert.equal(row.revoked_at,null);assert.deepEqual((await service.active(owner)).map(x=>x.id),[a.credential.id]);db.sqlite.close();
});
test('discoverable authentication requires exact userHandle, valid signature and consumes attempt',async()=>{
 const {db,service,enroll,assertion}=await setup(),a=await enroll();
 const wrong=await assertion(a,{handle:'other-owner'});assert.equal(await service.finishAuthentication(wrong),undefined);assert.equal(await service.finishAuthentication(wrong),undefined);
 const missing=await assertion(a);delete missing.response.response.userHandle;assert.equal(await service.finishAuthentication(missing),undefined);
 const forged=await assertion(a);forged.response.response.signature='AA';assert.equal(await service.finishAuthentication(forged),undefined);
 const good=await assertion(a);const result=await service.finishAuthentication(good);assert.ok(result);assert.equal(result.purpose,'authenticate');assert.equal(await service.finishAuthentication(good),undefined);
 assert.equal(db.sqlite.prepare('SELECT counter FROM passkey_credentials').get().counter,1);db.sqlite.close();
});
test('step-up binds owner, action and security generation; credential IDs never rebind',async()=>{
 const {db,owner,other,service,enroll,assertion}=await setup(),a=await enroll();
 const c=await service.begin({purpose:'register',ownerId:other,binding,action:'add-passkey'});assert.equal(await service.finishRegistration({token:c.token,ownerId:other,binding,action:'add-passkey',response:a.registration({expected:c.options.challenge})}),false);
 const wrong=await assertion(a,{ownerId:other,action:'delete-account'});assert.equal(await service.finishAuthentication(wrong),undefined);
 const good=await assertion(a,{ownerId:owner,action:'remove-passkey'});assert.equal(await service.finishAuthentication({...good,action:'delete-account'}),undefined);assert.equal((await service.finishAuthentication(good)).purpose,'step-up');
 const stale=await assertion(a,{ownerId:owner,action:'remove-passkey',counter:2});db.sqlite.prepare('UPDATE account_security SET generation=generation+1 WHERE owner_id=?').run(owner);assert.equal(await service.finishAuthentication(stale),undefined);db.sqlite.close();
});
test('expired/future ceremonies and failed registration fail closed without credentials',async()=>{
 const {db,owner,service,setNow}=await setup(),a=authenticator();
 for(const offset of [-1,120000]){setNow(NOW);const c=await service.begin({purpose:'register',ownerId:owner,binding,action:'add-passkey'});setNow(NOW+offset);assert.equal(await service.finishRegistration({token:c.token,ownerId:owner,binding,action:'add-passkey',response:a.registration({expected:c.options.challenge})}),false);}
 setNow(NOW);const c=await service.begin({purpose:'register',ownerId:owner,binding,action:'add-passkey'});const args={token:c.token,ownerId:owner,binding,action:'add-passkey'};assert.equal(await service.finishRegistration({...args,response:{}}),false);assert.equal(await service.finishRegistration({...args,response:a.registration({expected:c.options.challenge})}),false);assert.equal(db.sqlite.prepare('SELECT count(*) n FROM passkey_credentials').get().n,0);db.sqlite.close();
});
test('revocation during signature verification wins and revoked IDs cannot enroll again',async()=>{
 const {db,owner,other,service,enroll,assertion}=await setup(),a=await enroll();
 assert.equal(await service.revoke({ownerId:other,credentialId:a.credential.id}),false);
 const actual=new PasskeyVerifier();service.verifier={verifyAuthentication:async args=>{const result=await actual.verifyAuthentication(args);await service.revoke({ownerId:owner,credentialId:a.credential.id});return result;},authenticationOptions:args=>actual.authenticationOptions(args)};
 assert.equal(await service.finishAuthentication(await assertion(a)),undefined);assert.deepEqual(await service.active(owner),[]);
 service.verifier=actual;const c=await service.begin({purpose:'register',ownerId:owner,binding,action:'add-passkey'});assert.equal(await service.finishRegistration({token:c.token,ownerId:owner,binding,action:'add-passkey',response:a.registration({expected:c.options.challenge})}),false);db.sqlite.close();
});
test('concurrent zero-counter authentications serialize with revision CAS',async()=>{
 const {db,owner,service,enroll,assertion}=await setup(),a=await enroll();const first=await assertion(a,{counter:0}),second=await assertion(a,{counter:0});
 const actual=new PasskeyVerifier();let arrived=0,release;const gate=new Promise(r=>release=r);
 service.verifier={verifyAuthentication:async args=>{const result=await actual.verifyAuthentication(args);if(++arrived===2)release();await gate;return result;}};
 const results=await Promise.all([service.finishAuthentication(first),service.finishAuthentication(second)]);assert.equal(results.filter(Boolean).length,1);assert.equal(db.sqlite.prepare('SELECT revision FROM passkey_credentials').get().revision,1);
 db.sqlite.prepare('DELETE FROM accounts WHERE owner_id=?').run(owner);assert.equal(db.sqlite.prepare('SELECT count(*) n FROM passkey_credentials').get().n,0);db.sqlite.close();
});
test('security reset during verification denies result and registration',async()=>{
 const {db,owner,service,enroll,assertion}=await setup(),a=await enroll(),args=await assertion(a);const actual=new PasskeyVerifier();
 service.verifier={verifyAuthentication:async v=>{const result=await actual.verifyAuthentication(v);db.sqlite.prepare('UPDATE account_security SET generation=generation+1 WHERE owner_id=?').run(owner);return result;}};assert.equal(await service.finishAuthentication(args),undefined);
 service.verifier=actual;const c=await service.begin({purpose:'register',ownerId:owner,binding,action:'add-passkey'}),b=authenticator();db.sqlite.prepare('UPDATE account_security SET generation=generation+1 WHERE owner_id=?').run(owner);assert.equal(await service.finishRegistration({token:c.token,ownerId:owner,binding,action:'add-passkey',response:b.registration({expected:c.options.challenge})}),false);db.sqlite.close();
});
test('bounded cleanup removes only expired ceremonies and leaves live attempts',async()=>{
 const {db,owner,service,setNow}=await setup();
 for(let i=0;i<3;i++)await service.begin({purpose:'register',ownerId:owner,binding,action:'add-passkey'});
 setNow(NOW+120000);await service.begin({purpose:'authenticate',binding});
 assert.equal(await service.cleanupExpired({limit:2}),2);assert.equal(await service.cleanupExpired({limit:2}),1);assert.equal(db.sqlite.prepare('SELECT count(*) n FROM passkey_ceremonies').get().n,1);await assert.rejects(service.cleanupExpired({limit:501}));db.sqlite.close();
});
