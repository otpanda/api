import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { AccountIdentityService, canonicalAccountEmail, googleEmailEvidence } from '../src/account-identity.js';
const NOW = 1_800_000_000_000;
const google = email => ({ issuer:'https://accounts.google.com', subject:'google-subject-a', email });
async function setup() {
 const db=database(); let now=NOW; const service=new AccountIdentityService(db,{clock:()=>now});
 async function signup(email) { const {token}=await service.issueEmailChallenge({purpose:'signup-email',email});return service.createEmailAccount({email,token}); }
 return {db,service,signup,setNow:v=>now=v};
}
test('email policy rejects unsupported/ambiguous input, does not fold aliases',()=>{
 assert.equal(canonicalAccountEmail('Alice+tag@Example.COM'),'alice+tag@example.com');
 assert.notEqual(canonicalAccountEmail('a.b@gmail.com'),canonicalAccountEmail('ab@gmail.com'));
 for(const email of [' x@example.com','x@example.com ','x\n@example.com','x@localhost','a..b@example.com','a@-bad.com','a@bad-.com','a@b..com','ü@example.com','a@@example.com','a@exam_ple.com'])assert.throws(()=>canonicalAccountEmail(email));
});
test('signup challenge is mailbox-bound, single-use, hash-only and cannot reserve email',async()=>{
 const {db,service,signup}=await setup();
 const {token}=await service.issueEmailChallenge({purpose:'signup-email',email:'A@example.com'});
 assert.equal(db.sqlite.prepare('SELECT count(*) n FROM accounts').get().n,0);
 assert.ok(!JSON.stringify(db.sqlite.prepare('SELECT * FROM auth_challenges').all()).includes(token));
 assert.equal(await service.createEmailAccount({email:'b@example.com',token}),undefined);
 const owner=await service.createEmailAccount({email:'a@example.com',token});assert.ok(owner);
 assert.equal(await service.emailForOwner(owner),'a@example.com');
 assert.equal(await service.createEmailAccount({email:'a@example.com',token}),undefined);
 assert.equal(await signup('A@example.com'),undefined);
 assert.equal(db.sqlite.prepare('SELECT count(*) n FROM accounts').get().n,1);
 assert.equal(db.sqlite.prepare('SELECT count(*) n FROM account_security').get().n,1);
 db.sqlite.close();
});
test('expired or future-dated challenge cannot verify email',async()=>{
 const {db,service,setNow}=await setup();const {token}=await service.issueEmailChallenge({purpose:'signup-email',email:'a@example.com',ttlMs:1000});
 setNow(NOW-1);assert.equal(await service.createEmailAccount({email:'a@example.com',token}),undefined);
 setNow(NOW+1000);assert.equal(await service.createEmailAccount({email:'a@example.com',token}),undefined);
 assert.equal(db.sqlite.prepare('SELECT count(*) n FROM accounts').get().n,0);db.sqlite.close();
});
test('purpose/owner/provider binding rejects confused challenge without consuming original',async()=>{
 const {db,service,signup}=await setup();const owner=await signup('a@example.com'),identity=google('a@example.com');
 const {token}=await service.issueEmailChallenge({purpose:'link-provider',email:identity.email,ownerId:owner,identity});
 assert.equal(await service.claim({token,purpose:'change-email',email:identity.email,ownerId:owner}),false);
 assert.equal(await service.linkProvider({ownerId:owner,identity:{...identity,subject:'other'},token}),false);
 assert.equal(await service.ownerForProvider(identity),undefined);
 assert.equal(await service.linkProvider({ownerId:owner,identity,token}),true);
 assert.equal(await service.ownerForProvider(identity),owner);
 assert.equal(await service.ownerForProvider({...identity,subject:'other'}),undefined);
 assert.equal(await service.ownerForProvider({...identity,email:'changed@example.com'}),undefined);
 db.sqlite.close();
});
test('different provider-email cannot link and equal emails alone never locate account',async()=>{
 const {db,service,signup}=await setup();const owner=await signup('a@example.com');
 const other=google('b@example.com');const {token}=await service.issueEmailChallenge({purpose:'link-provider',email:other.email,ownerId:owner,identity:other});
 assert.equal(await service.linkProvider({ownerId:owner,identity:other,token}),false);
 assert.equal(await service.ownerForProvider(google('a@example.com')),undefined);
 assert.equal(db.sqlite.prepare('SELECT count(*) n FROM identities').get().n,0);db.sqlite.close();
});
test('Google email evidence distinguishes hosted/Gmail authority from arbitrary verified email',()=>{
 const claims={iss:'https://accounts.google.com',sub:'subject',email_verified:true,email:'a@gmail.com'};
 assert.equal(googleEmailEvidence(claims).authoritative,true);
 assert.equal(googleEmailEvidence({...claims,email:'a@example.com'}).authoritative,false);
 assert.equal(googleEmailEvidence({...claims,email:'a@example.com',hd:'example.com'}).authoritative,true);
 assert.equal(googleEmailEvidence({...claims,email:'a@example.com',hd:'other.com'}).authoritative,false);
 assert.throws(()=>googleEmailEvidence({...claims,email_verified:'true'}));
 assert.throws(()=>googleEmailEvidence({...claims,iss:'https://evil.test'}));
});
test('bounded challenge inputs fail before SQL writes',async()=>{
 const {db,service}=await setup();
 for(const change of [{purpose:'anything'},{ttlMs:0},{ttlMs:900001},{ownerId:'owner'},{identity:google('a@example.com')}])await assert.rejects(service.issueEmailChallenge({purpose:'signup-email',email:'a@example.com',...change}));
 assert.equal(db.sqlite.prepare('SELECT count(*) n FROM auth_challenges').get().n,0);db.sqlite.close();
});
