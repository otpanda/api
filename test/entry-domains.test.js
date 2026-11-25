import test from 'node:test';import assert from 'node:assert/strict';
import{database}from'./sqlite-helper.js';import{AccountIdentityService}from'../src/account-identity.js';import{PasskeySignupService}from'../src/passkey-signup.js';import{DeviceSessionService}from'../src/device-sessions.js';import{authenticator}from'./passkey-fixture.js';
import{CodeCipher}from'../src/code-cipher.js';import{SourceEntryStore}from'../src/source-entries.js';import{createEntryDomainsHttp}from'../src/entry-domains-http.js';
const NOW=1800000000000,API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io';
async function fx(native=true){
 const db=database(),a=authenticator(),clock=()=>NOW,identity=new AccountIdentityService(db,{clock}),signup=new PasskeySignupService(db,{clock}),e=await identity.issueEmailChallenge({purpose:'signup-email',email:'em@example.test'}),c=await signup.begin({email:'em@example.test',emailToken:e.token,binding:'fixture'}),account=await signup.finish({token:c.token,binding:'fixture',response:a.registration({expected:c.options.challenge})}),sessions=new DeviceSessionService(db,{clock});
 const mk=kind=>sessions.issue({proof:{...account,purpose:'authenticate',verifiedAt:NOW},clientKind:kind}),web=await mk('web'),android=await mk('android');
 const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']),store=new SourceEntryStore(db,new CodeCipher({keys:new Map([['f',key]]),activeKeyId:'f'})),entryId=await store.createEntry(account.ownerId,'test','Target',NOW);
 const http=createEntryDomainsHttp({db,sessions,clock,native}),
  run=(path,body,{token,origin,ct='application/json',method='POST'}={})=>http.fetch(new Request(API+'/v1/manage/entry/domains',{method,headers:{...(origin?{Origin:origin}:{}),Authorization:'Bearer '+token,'Content-Type':ct},...(method==='POST'?{body:JSON.stringify(body)}:{})}));
 return{db,web,android,entryId,run,account,row:()=>db.sqlite.prepare('SELECT label,account_name,mutation_revision FROM entries WHERE entry_id=?').get(entryId),sessions};
}

test('private domain associations persist, normalize and remain exact',async()=>{const f=await fx();try{
 const opts={token:f.android.access};
 assert.equal((await f.run('',{entryId:f.entryId,domains:['EXAMPLE.COM','login.example.com','example.com']},opts)).status,200);
 const read=await f.run('',null,{...opts,method:'GET'});assert.deepEqual(await read.json(),{associations:[{entryId:f.entryId,domains:['example.com','login.example.com']}]});
 for(const domains of [['*.example.com'],['https://example.com'],['user@example.com'],['127.0.0.1'],['example.com.'],[' example.com'],Array(33).fill('example.com')])assert.equal((await f.run('',{entryId:f.entryId,domains},opts)).status,400);
 assert.equal((await f.run('',{entryId:'missing',domains:['example.com']},opts)).status,404);
 assert.equal((await f.run('',{entryId:f.entryId,domains:[],ownerId:'someone'},opts)).status,400);
 assert.equal((await f.run('',{entryId:f.entryId,domains:[]},{token:f.web.access})).status,401);
 assert.equal((await f.run('',{entryId:f.entryId,domains:[]},{...opts,origin:APP})).status,401);
 await f.sessions.revoke({ownerId:f.account.ownerId,deviceId:f.android.deviceId});assert.equal((await f.run('',null,{...opts,method:'GET'})).status,401);
 }finally{f.db.sqlite.close();}});
import {websiteEligible,normalizeWebsiteDomains} from '../src/website-domains.js';
test('listed plus personal domain union is exact and never implicit suffix matching',()=>{
 assert.equal(websiteEligible('https://example.com/x',['example.com'],[]),true);
 assert.equal(websiteEligible('https://login.other.com/path',['example.com'],['login.other.com']),true);
 for(const site of ['http://example.com','https://www.example.com','https://example.com.evil.test','https://evil-example.com','https://user@example.com','https://example.com:444','https://127.0.0.1'])assert.equal(websiteEligible(site,['example.com'],[]),false);
 assert.deepEqual(normalizeWebsiteDomains(['EXAMPLE.COM','example.com']),['example.com']);
});

test('shared viewer extras are private and hidden after revocation',async()=>{const f=await fx();try{
 const now=NOW,identity=new AccountIdentityService(f.db,{clock:()=>now}),signup=new PasskeySignupService(f.db,{clock:()=>now}),ec=await identity.issueEmailChallenge({purpose:'signup-email',email:'other@example.test'}),b=await signup.begin({email:'other@example.test',emailToken:ec.token,binding:'other'}),a=await signup.finish({token:b.token,binding:'other',response:authenticator().registration({expected:b.options.challenge})}),other=await f.sessions.issue({proof:{...a,purpose:'authenticate',verifiedAt:now},clientKind:'android'});
 const run=token=>({token});
 assert.equal((await f.run('',{entryId:f.entryId,domains:['private.test']},run(other.access))).status,404);
 f.db.sqlite.prepare('INSERT INTO entry_shares(entry_id,recipient_id,created_at) VALUES (?,?,?)').run(f.entryId,a.ownerId,now);
 assert.equal((await f.run('',{entryId:f.entryId,domains:['mine.test']},run(f.android.access))).status,200);
 assert.equal((await f.run('',{entryId:f.entryId,domains:['theirs.test']},run(other.access))).status,200);
 assert.deepEqual((await (await f.run('',null,{...run(f.android.access),method:'GET'})).json()).associations[0].domains,['mine.test']);
 assert.deepEqual((await (await f.run('',null,{...run(other.access),method:'GET'})).json()).associations[0].domains,['theirs.test']);
 f.db.sqlite.prepare('UPDATE entry_shares SET revoked_at=? WHERE entry_id=?').run(now,f.entryId);
 assert.deepEqual((await (await f.run('',null,{...run(other.access),method:'GET'})).json()).associations,[]);
 assert.equal((await f.run('',{entryId:f.entryId,domains:['again.test']},run(other.access))).status,404);
 f.db.sqlite.prepare('DELETE FROM entries WHERE entry_id=?').run(f.entryId);assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM entry_domain_associations').get().n,0);
 }finally{f.db.sqlite.close();}});
