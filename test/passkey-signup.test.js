import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { AccountIdentityService } from '../src/account-identity.js';
import { PasskeySignupService } from '../src/passkey-signup.js';
import { authenticator } from './passkey-fixture.js';
const NOW=1_800_000_000_000,binding='signup-browser-binding';
function setup(){const db=database();let now=NOW;const identity=new AccountIdentityService(db,{clock:()=>now}),service=new PasskeySignupService(db,{clock:()=>now});async function begin(email='a@example.com'){const {token}=await identity.issueEmailChallenge({purpose:'signup-email',email});return service.begin({email,emailToken:token,binding});}return {db,service,identity,begin,setNow:v=>now=v};}
function response(a,c){return a.registration({expected:c.options.challenge});}
function counts(db){return ['accounts','account_emails','account_security','passkey_credentials'].map(t=>db.sqlite.prepare('SELECT count(*) n FROM '+t).get().n);}
test('email verification plus first passkey creates every account row in one transaction',async()=>{
 const {db,service,begin}=setup(),c=await begin(),a=authenticator();assert.deepEqual(counts(db),[0,0,0,0]);
 assert.ok(!JSON.stringify(db.sqlite.prepare('SELECT * FROM passkey_signups').all()).includes(c.token));
 const args={token:c.token,binding,response:response(a,c)};assert.equal(await service.finish({...args,binding:'wrong'}),undefined);
 const result=await service.finish(args);assert.ok(result);assert.deepEqual(counts(db),[1,1,1,1]);assert.equal(Buffer.from(c.options.user.id,'base64url').toString(),result.ownerId);assert.equal(db.sqlite.prepare('SELECT owner_id FROM passkey_credentials').get().owner_id,result.ownerId);assert.equal(await service.finish(args),undefined);db.sqlite.close();
});
test('wrong or replayed mailbox proof never starts signup and email is not reserved',async()=>{
 const {db,service,identity,begin}=setup();const {token}=await identity.issueEmailChallenge({purpose:'signup-email',email:'a@example.com'});
 assert.equal(await service.begin({email:'b@example.com',emailToken:token,binding}),undefined);
 assert.ok(await service.begin({email:'a@example.com',emailToken:token,binding}));assert.equal(await service.begin({email:'a@example.com',emailToken:token,binding}),undefined);
 assert.ok(await begin('a@example.com'));assert.deepEqual(counts(db),[0,0,0,0]);db.sqlite.close();
});
test('invalid signatures and expired signup create no account; attempt consumed',async()=>{
 const {db,service,begin,setNow}=setup();let c=await begin();assert.equal(await service.finish({token:c.token,binding,response:{}}),undefined);assert.equal(await service.finish({token:c.token,binding,response:response(authenticator(),c)}),undefined);
 c=await begin();setNow(NOW+120000);assert.equal(await service.finish({token:c.token,binding,response:response(authenticator(),c)}),undefined);assert.deepEqual(counts(db),[0,0,0,0]);assert.equal(await service.cleanupExpired(),1);db.sqlite.close();
});
test('duplicate email or credential rolls back every candidate account row',async()=>{
 const {db,service,begin}=setup(),a=authenticator();const first=await begin(),second=await begin();assert.ok(await service.finish({token:first.token,binding,response:response(a,first)}));assert.equal(await service.finish({token:second.token,binding,response:response(authenticator(),second)}),undefined);assert.deepEqual(counts(db),[1,1,1,1]);
 const third=await begin('b@example.com');assert.equal(await service.finish({token:third.token,binding,response:response(a,third)}),undefined);assert.deepEqual(counts(db),[1,1,1,1]);db.sqlite.close();
});
test('storage failure mid-batch rolls back account/email/security and consumes signup',async()=>{
 const {db,service,begin}=setup(),c=await begin();db.sqlite.exec("CREATE TRIGGER reject_credential BEFORE INSERT ON passkey_credentials BEGIN SELECT RAISE(ABORT, 'test storage failure'); END;");
 const args={token:c.token,binding,response:response(authenticator(),c)};assert.equal(await service.finish(args),undefined);assert.deepEqual(counts(db),[0,0,0,0]);assert.equal(await service.finish(args),undefined);db.sqlite.close();
});
