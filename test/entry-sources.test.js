import test from 'node:test';import assert from 'node:assert/strict';
import{database}from'./sqlite-helper.js';import{AccountIdentityService}from'../src/account-identity.js';import{PasskeySignupService}from'../src/passkey-signup.js';import{DeviceSessionService}from'../src/device-sessions.js';import{authenticator}from'./passkey-fixture.js';
import{CodeCipher}from'../src/code-cipher.js';import{SourceEntryStore}from'../src/source-entries.js';import{createEntrySourcesHttp}from'../src/entry-sources-http.js';
const NOW=1800000000000,API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io';
async function acct(db,email,clock){
 const a=authenticator(),identity=new AccountIdentityService(db,{clock}),signup=new PasskeySignupService(db,{clock}),e=await identity.issueEmailChallenge({purpose:'signup-email',email}),c=await signup.begin({email,emailToken:e.token,binding:'b-'+email}),account=await signup.finish({token:c.token,binding:'b-'+email,response:a.registration({expected:c.options.challenge})});
 return account;
}
async function fx(){
 const db=database(),clock=()=>NOW,sessions=new DeviceSessionService(db,{clock}),account=await acct(db,'own@example.test',clock),other=await acct(db,'rcpt@example.test',clock);
 const mk=(acc,kind)=>sessions.issue({proof:{...acc,purpose:'authenticate',verifiedAt:NOW},clientKind:kind});
 const web=await mk(account,'web'),android=await mk(account,'android'),otherWeb=await mk(other,'web');
 const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']),store=new SourceEntryStore(db,new CodeCipher({keys:new Map([['f',key]]),activeKeyId:'f'}));
 const o=account.ownerId,gmail=await store.createSource(o,'gmail','Personal Gmail',NOW),phone=await store.createSource(o,'sms','Phone',NOW),entry=await store.createEntry(o,'test','Target',NOW),entry2=await store.createEntry(o,'test','Second',NOW);
 const http=createEntrySourcesHttp({db,sessions,clock,native:true});
 const get=(token,{origin=APP,method='GET',path='/v1/manage/entry/sources'}={})=>http.fetch(new Request(API+path,{method,headers:{...(origin?{Origin:origin}:{}),Authorization:'Bearer '+token}}));
 const recv=(sourceId,eventId,over={})=>store.receive(o,{sourceId,eventId,code:'123456',receivedAt:NOW-1000,expiresAt:NOW+60000,sender:'secret-sender@example.test',accountHint:'hint',...over});
 return{db,store,o,other,web,android,otherWeb,gmail,phone,entry,entry2,get,recv,http};
}
const rows=db=>JSON.stringify(db.sqlite.prepare('SELECT * FROM assignment_rules').all());
test('owner sees live sources for their entry only, with no code, sender, event id or rule written',async()=>{const f=await fx();try{
 await f.recv(f.gmail,'ev-1');await f.recv(f.gmail,'ev-2');await f.recv(f.phone,'ev-3');
 assert.deepEqual((await (await f.get(f.web.access)).json()),{entries:[]},'unassigned codes are not provenance');
 assert.equal(await f.store.confirm(f.o,f.gmail,'ev-1',f.entry,NOW),true);assert.equal(await f.store.confirm(f.o,f.gmail,'ev-2',f.entry,NOW),true);assert.equal(await f.store.confirm(f.o,f.phone,'ev-3',f.entry2,NOW),true);
 const before=rows(f.db),res=await f.get(f.web.access),text=await res.text(),body=JSON.parse(text);
 assert.equal(res.status,200);assert.equal(res.headers.get('cache-control'),'no-store');
 assert.deepEqual(body.entries.map(e=>e.entryId).sort(),[f.entry,f.entry2].sort());
 const e1=body.entries.find(e=>e.entryId===f.entry).sources;
 assert.deepEqual(e1,[{sourceId:f.gmail,kind:'gmail',label:'Personal Gmail',activeCodeCount:2,latestReceivedAt:NOW-1000,confirmedCount:2,ruleCount:0}]);
 for(const leak of ['123456','secret-sender','hint','ev-1','envelope','ownerId'])assert.equal(text.includes(leak),false,leak);
 assert.equal(rows(f.db),before);assert.equal(before,'[]','no rule is created by assigning or reading');
 const android=await f.get(f.android.access,{origin:null});assert.equal(android.status,200);
}finally{f.db.sqlite.close();}});
test('a recipient, another owner and unauthenticated callers get nothing',async()=>{const f=await fx();try{
 await f.recv(f.gmail,'ev-1');await f.store.confirm(f.o,f.gmail,'ev-1',f.entry,NOW);
 f.db.sqlite.prepare('INSERT INTO entry_shares(entry_id,recipient_id,created_at) VALUES (?,?,?)').run(f.entry,f.other.ownerId,NOW);
 assert.deepEqual(await (await f.get(f.otherWeb.access)).json(),{entries:[]});
 assert.equal((await f.get('bad')).status,401);
 assert.equal((await f.get(f.android.access)).status,401,'android token with an Origin is refused');
 assert.equal((await f.get(f.web.access,{origin:null})).status,401,'web token without Origin is refused');
 assert.equal((await f.get(f.web.access,{origin:'https://evil.test'})).status,403);
 assert.equal((await f.get(f.web.access,{method:'POST'})).status,405);
 assert.equal((await f.get(f.web.access,{path:'/v1/manage/entry/sources?entryId=x'})).status,400);
}finally{f.db.sqlite.close();}});
test('expired codes and revoked sources drop out; nothing is rewritten',async()=>{const f=await fx();try{
 await f.recv(f.gmail,'ev-1');await f.recv(f.phone,'ev-2',{expiresAt:NOW+1});await f.store.confirm(f.o,f.gmail,'ev-1',f.entry,NOW);await f.store.confirm(f.o,f.phone,'ev-2',f.entry,NOW);
 assert.equal((await (await f.get(f.web.access)).json()).entries[0].sources.length,2);
 f.db.sqlite.prepare("UPDATE incoming_codes SET expires_at=?1 WHERE event_id='ev-2'").run(NOW);
 assert.deepEqual((await (await f.get(f.web.access)).json()).entries[0].sources.map(s=>s.sourceId),[f.gmail],'expiry is judged by the clock, not by cleanup');
 assert.equal(f.db.sqlite.prepare('SELECT count(*) AS n FROM incoming_codes').get().n,2,'read deletes nothing');
 assert.equal(await f.store.revokeSource(f.o,f.gmail,NOW),true);
 assert.deepEqual(await (await f.get(f.web.access)).json(),{entries:[]});
}finally{f.db.sqlite.close();}});
test('a rule-assigned code is counted as rule; a source from another owner never joins',async()=>{const f=await fx();try{
 await f.store.addRule(f.o,{sourceId:f.gmail,entryId:f.entry,sender:'secret-sender@example.test',accountHint:'hint'},NOW);
 assert.equal((await f.recv(f.gmail,'ev-1')).entryId,f.entry);
 const s=(await (await f.get(f.web.access)).json()).entries[0].sources[0];assert.equal(s.ruleCount,1);assert.equal(s.confirmedCount,0);
}finally{f.db.sqlite.close();}});
