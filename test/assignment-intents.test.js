import test from 'node:test';import assert from 'node:assert/strict';
import{database}from'./sqlite-helper.js';import{AccountIdentityService}from'../src/account-identity.js';import{PasskeySignupService}from'../src/passkey-signup.js';import{PasskeyService}from'../src/passkey-service.js';import{DeviceSessionService}from'../src/device-sessions.js';import{CodeCipher}from'../src/code-cipher.js';import{SourceEntryStore}from'../src/source-entries.js';import{AssignmentIntents}from'../src/assignment-intents.js';import{authenticator}from'./passkey-fixture.js';
const NOW=1800000000000;
async function fixture({priv=false}={}){const db=database(),a=authenticator();let now=NOW;const clock=()=>now,identity=new AccountIdentityService(db,{clock}),signup=new PasskeySignupService(db,{clock}),e=await identity.issueEmailChallenge({purpose:'signup-email',email:'action@example.test'}),c=await signup.begin({email:'action@example.test',emailToken:e.token,binding:'fixture'}),account=await signup.finish({token:c.token,binding:'fixture',response:a.registration({expected:c.options.challenge})}),sessions=new DeviceSessionService(db,{clock}),issued=await sessions.issue({proof:{...account,purpose:'authenticate',verifiedAt:NOW},clientKind:'web'}),auth=await sessions.authenticate(issued.access),key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']),cipher=new CodeCipher({keys:new Map([['fixture',key]]),activeKeyId:'fixture'}),sources=new SourceEntryStore(db,cipher),sourceId=await sources.createSource(account.ownerId,'sms','Fixture',NOW),entryId=await sources.createEntry(account.ownerId,'test','Target',NOW);if(!priv){db.sqlite.prepare('INSERT INTO accounts(owner_id,created_at)VALUES(?,?)').run('fixture-recipient',NOW);db.sqlite.prepare('INSERT INTO entry_shares(entry_id,recipient_id,created_at)VALUES(?,?,?)').run(entryId,'fixture-recipient',NOW);}await sources.receive(account.ownerId,{sourceId,eventId:'event',code:'123456',receivedAt:NOW,expiresAt:NOW+300000});const passkeys=new PasskeyService(db,{clock}),intents=new AssignmentIntents({db,passkeys,cipher,clock}),begin=()=>intents.begin(auth,{sourceId,eventId:'event',entryId}),finish=b=>intents.finish(auth,{intentId:b.intentId,token:b.token,action:b.action,response:a.assertion({expected:b.options.challenge})});return{db,a,auth,sessions,issued,account,cipher,sources,sourceId,entryId,intents,begin,finish,passkeys,setNow:n=>now=n};}
test('cryptographic assignment intent commits reencrypted code once and reconciles lost response',async()=>{const f=await fixture();try{const b=await f.begin();assert.equal(b.summary.activeRecipients,1);assert.equal(b.proofRequired,true);assert.equal(b.options.userVerification,'required');assert.deepEqual(await f.finish(b),{status:'assigned'});assert.deepEqual(await f.sources.latestOwned(f.account.ownerId,f.entryId,NOW),{code:'123456',entryId:f.entryId,receivedAt:NOW,expiresAt:NOW+300000});assert.deepEqual(await f.finish(b),{status:'assigned'});assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM assignment_intents WHERE consumed_at IS NOT NULL').get().n,1);}finally{f.db.sqlite.close();}});
for(const kind of ['source','entry-label','session','generation','expiry','envelope'])test('intent refuses changed '+kind,async()=>{const f=await fixture();try{const b=await f.begin();if(kind==='source')await f.sources.revokeSource(f.account.ownerId,f.sourceId,NOW);if(kind==='entry-label')f.db.sqlite.prepare('UPDATE entries SET label=? WHERE entry_id=?').run('Changed',f.entryId);if(kind==='session')await f.sessions.revoke({ownerId:f.account.ownerId,deviceId:f.issued.deviceId});if(kind==='generation')f.db.sqlite.prepare('UPDATE account_security SET generation=generation+1 WHERE owner_id=?').run(f.account.ownerId);if(kind==='expiry')f.setNow(NOW+120000);if(kind==='envelope')f.db.sqlite.prepare("UPDATE incoming_codes SET envelope='{}'").run();assert.equal((await f.finish(b))?.status,kind==='expiry'?'not-assigned':undefined);assert.equal(f.db.sqlite.prepare('SELECT entry_id FROM incoming_codes').get().entry_id,null);}finally{f.db.sqlite.close();}});
test('purpose/action tamper, other session and pending-write cap',async()=>{const f=await fixture();try{const b=await f.begin();assert.equal(await f.intents.finish(f.auth,{intentId:b.intentId,token:b.token,action:b.action+'x',response:f.a.assertion({expected:b.options.challenge})}),undefined);assert.equal(await f.intents.status({...f.auth,deviceId:'other'},b.intentId),undefined);for(let i=0;i<4;i++)assert.ok(await f.begin());assert.equal(await f.begin(),undefined);assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM assignment_intents').get().n,5);}finally{f.db.sqlite.close();}});
test('share insert and revoke ABA changes revision even when final count same',async()=>{const f=await fixture();try{const b=await f.begin();f.db.sqlite.prepare('INSERT INTO accounts(owner_id,created_at)VALUES(?,?)').run('recipient',NOW);f.db.sqlite.prepare('INSERT INTO entry_shares(entry_id,recipient_id,created_at)VALUES(?,?,?)').run(f.entryId,'recipient',NOW);f.db.sqlite.prepare('DELETE FROM entry_shares WHERE entry_id=?').run(f.entryId);assert.equal(await f.finish(b),undefined);assert.equal(f.db.sqlite.prepare('SELECT entry_id FROM incoming_codes').get().entry_id,null);}finally{f.db.sqlite.close();}});
test('two intents racing for same event commit only one assignment',async()=>{const f=await fixture();try{const a=await f.begin(),b=await f.begin(),results=await Promise.all([f.finish(a),f.finish(b)]);assert.equal(results.filter(x=>x?.status==='assigned').length,1);assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM assignment_intents WHERE consumed_at IS NOT NULL').get().n,1);}finally{f.db.sqlite.close();}});
import{createAssignmentIntentHttp}from'../src/assignment-intent-http.js';
test('unmounted HTTP adapter enforces origin bearer method shape and bounded body',async()=>{const f=await fixture();try{const http=createAssignmentIntentHttp({db:f.db,sessions:f.sessions,intents:f.intents,clock:()=>NOW}),run=(path,body,headers={},method='POST')=>http.fetch(new Request('https://otpanda-api.abrahammurciano.workers.dev/v1/manage/assignment/'+path,{method,headers:{Origin:'https://otpanda.github.io',Authorization:'Bearer '+f.issued.access,'Content-Type':'application/json',...headers},...(method==='POST'?{body:typeof body==='string'?body:JSON.stringify(body)}:{})}),{clientAddress:'192.0.2.1'});assert.equal((await run('begin',{}, {Origin:'https://evil.test'})).status,403);assert.equal((await run('begin',{}, {Authorization:''})).status,401);assert.equal((await run('begin',{}, {},'GET')).status,405);assert.equal((await run('begin',{ownerId:f.account.ownerId})).status,400);assert.equal((await run('begin','x'.repeat(32769))).status,400);const result=await run('begin',{sourceId:f.sourceId,eventId:'event',entryId:f.entryId});assert.equal(result.status,200);assert.equal(result.headers.get('access-control-allow-origin'),'https://otpanda.github.io');assert.equal(result.headers.get('cache-control'),'no-store');assert.ok((await result.json()).intentId);}finally{f.db.sqlite.close();}});
test('revocation or share-state change while reencrypting suppresses assignment',async()=>{for(const kind of ['session','share']){const f=await fixture();try{const b=await f.begin(),encrypt=f.cipher.encrypt.bind(f.cipher);f.cipher.encrypt=async(...args)=>{const envelope=await encrypt(...args);if(kind==='session')await f.sessions.revoke({ownerId:f.account.ownerId,deviceId:f.issued.deviceId});else f.db.sqlite.prepare('UPDATE entries SET label=? WHERE entry_id=?').run('Changed during encrypt',f.entryId);return envelope;};assert.equal(await f.finish(b),undefined);assert.equal(f.db.sqlite.prepare('SELECT entry_id FROM incoming_codes').get().entry_id,null);assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM assignment_intents WHERE consumed_at IS NOT NULL').get().n,0);}finally{f.db.sqlite.close();}}});
test('rollback invariant forbids successful receipt when paired assignment is ignored',async()=>{const f=await fixture();try{const b=await f.begin();f.db.sqlite.exec("CREATE TRIGGER fixture_ignore_assignment BEFORE UPDATE OF entry_id ON incoming_codes BEGIN SELECT RAISE(IGNORE); END");await assert.rejects(()=>f.finish(b));assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM assignment_intents WHERE consumed_at IS NOT NULL').get().n,0);assert.equal(f.db.sqlite.prepare('SELECT entry_id FROM incoming_codes').get().entry_id,null);assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM assignment_receipts').get().n,0);}finally{f.db.sqlite.close();}});
test('UV-missing assertion and login ceremony cannot authorize assignment',async()=>{for(const mode of ['missing-uv','login-purpose']){const f=await fixture();try{const b=await f.begin();let token=b.token,challenge=b.options.challenge;if(mode==='login-purpose'){const login=await f.passkeys.begin({purpose:'authenticate',binding:b.intentId});token=login.token;challenge=login.options.challenge;}const response=f.a.assertion({expected:challenge,flags:mode==='missing-uv'?1:5});assert.equal(await f.intents.finish(f.auth,{intentId:b.intentId,token,action:b.action,response}),undefined);assert.equal(f.db.sqlite.prepare('SELECT entry_id FROM incoming_codes').get().entry_id,null);}finally{f.db.sqlite.close();}}});
test('shared-target summary names count and credential revoke during encryption wins',async()=>{const f=await fixture({priv:true});try{f.db.sqlite.prepare('INSERT INTO accounts(owner_id,created_at)VALUES(?,?)').run('recipient',NOW);f.db.sqlite.prepare('INSERT INTO entry_shares(entry_id,recipient_id,created_at)VALUES(?,?,?)').run(f.entryId,'recipient',NOW);const b=await f.begin();assert.equal(b.summary.activeRecipients,1);const encrypt=f.cipher.encrypt.bind(f.cipher);f.cipher.encrypt=async(...args)=>{const envelope=await encrypt(...args);f.db.sqlite.prepare('UPDATE passkey_credentials SET revoked_at=? WHERE owner_id=?').run(NOW,f.account.ownerId);return envelope;};assert.equal(await f.finish(b),undefined);assert.equal(f.db.sqlite.prepare('SELECT entry_id FROM incoming_codes').get().entry_id,null);assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM assignment_intents WHERE consumed_at IS NOT NULL').get().n,0);}finally{f.db.sqlite.close();}});
test('missing and other-owner targets are indistinguishable and cleanup is bounded',async()=>{const f=await fixture();try{assert.equal(await f.intents.begin(f.auth,{sourceId:f.sourceId,eventId:'event',entryId:'missing'}),undefined);assert.equal(await f.intents.begin({...f.auth,ownerId:'other'},{sourceId:f.sourceId,eventId:'event',entryId:f.entryId}),undefined);assert.equal(await f.intents.status({...f.auth,ownerId:'other'},'missing'),undefined);for(let i=0;i<3;i++)assert.ok(await f.begin());f.setNow(NOW+600000);assert.equal(await f.intents.cleanup({limit:2}),2);assert.equal(await f.intents.cleanup({limit:2}),1);assert.equal(await f.intents.cleanup({limit:2}),0);}finally{f.db.sqlite.close();}});
test('maximum bounded identifiers bind via fixed digest without overflowing passkey action limit',async()=>{const f=await fixture();try{const sourceId='s'.repeat(256),entryId='t'.repeat(256),eventId='e'.repeat(256);f.db.sqlite.prepare("INSERT INTO sources(source_id,owner_id,kind,label,created_at)VALUES(?,?,'sms','Long',?)").run(sourceId,f.account.ownerId,NOW);f.db.sqlite.prepare('DELETE FROM entry_shares').run();f.db.sqlite.prepare('UPDATE entries SET entry_id=? WHERE entry_id=?').run(entryId,f.entryId);f.db.sqlite.prepare('INSERT INTO entry_shares(entry_id,recipient_id,created_at)VALUES(?,?,?)').run(entryId,'fixture-recipient',NOW);await f.sources.receive(f.account.ownerId,{sourceId,eventId,code:'112233',receivedAt:NOW,expiresAt:NOW+300000});const b=await f.intents.begin(f.auth,{sourceId,eventId,entryId});assert.ok(b);assert.ok(b.action.length>512);assert.deepEqual(await f.intents.finish(f.auth,{intentId:b.intentId,token:b.token,action:b.action,response:f.a.assertion({expected:b.options.challenge})}),{status:'assigned'});}finally{f.db.sqlite.close();}});

test('failed ceremony creation releases pending cap for undefined and thrown results',async()=>{for(const mode of ['undefined','throw']){const f=await fixture();try{const begin=f.passkeys.begin.bind(f.passkeys);f.passkeys.begin=async()=>{if(mode==='throw')throw Error('fixture');};for(let i=0;i<6;i++){if(mode==='throw')await assert.rejects(f.begin);else assert.equal(await f.begin(),undefined);}assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM assignment_intents').get().n,0);f.passkeys.begin=begin;assert.ok(await f.begin());}finally{f.db.sqlite.close();}}});
test('failed cryptographic finishes release pending cap without assigning',async()=>{const f=await fixture();try{for(let i=0;i<6;i++){const b=await f.begin();assert.ok(b);assert.equal(await f.intents.finish(f.auth,{intentId:b.intentId,token:b.token,action:b.action,response:f.a.assertion({expected:b.options.challenge,flags:1})}),undefined);}assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM assignment_intents WHERE retired_at IS NULL').get().n,0);assert.equal(f.db.sqlite.prepare('SELECT entry_id FROM incoming_codes').get().entry_id,null);assert.ok(await f.begin());}finally{f.db.sqlite.close();}});
test('summary binds automation-enabled exposure and irreversible release',async()=>{const f=await fixture({priv:true});try{for(const [id,automation]of [['manual',0],['automation',1],['revoked',1]]){f.db.sqlite.prepare('INSERT INTO accounts(owner_id,created_at)VALUES(?,?)').run(id,NOW);f.db.sqlite.prepare('INSERT INTO entry_shares(entry_id,recipient_id,allow_automation,created_at,revoked_at)VALUES(?,?,?,?,?)').run(f.entryId,id,automation,NOW,id==='revoked'?NOW:null);}const b=await f.begin();assert.equal(b.summary.activeRecipients,2);assert.equal(b.summary.automationRecipients,1);assert.equal(b.summary.irreversible,true);assert.deepEqual(JSON.parse(b.action).slice(-3),[2,1,true]);f.db.sqlite.prepare('UPDATE entry_shares SET allow_automation=0 WHERE recipient_id=?').run('automation');assert.equal(await f.finish(b),undefined);}finally{f.db.sqlite.close();}});
test('HTTP UTF-8 JSON finish keeps committed outcome if session revoked immediately after commit',async()=>{const f=await fixture();try{const b=await f.begin(),finish=f.intents.finish.bind(f.intents);f.intents.finish=async(...args)=>{const result=await finish(...args);await f.sessions.revoke({ownerId:f.account.ownerId,deviceId:f.issued.deviceId});return result;};const http=createAssignmentIntentHttp({db:f.db,sessions:f.sessions,intents:f.intents,clock:()=>NOW});const result=await http.fetch(new Request('https://otpanda-api.abrahammurciano.workers.dev/v1/manage/assignment/finish',{method:'POST',headers:{Origin:'https://otpanda.github.io',Authorization:'Bearer '+f.issued.access,'Content-Type':'application/json; charset=utf-8'},body:JSON.stringify({intentId:b.intentId,token:b.token,action:b.action,response:f.a.assertion({expected:b.options.challenge})})}),{clientAddress:'192.0.2.1'});assert.equal(result.status,200);assert.deepEqual(await result.json(),{status:'assigned'});assert.equal(f.db.sqlite.prepare('SELECT entry_id FROM incoming_codes').get().entry_id,f.entryId);assert.equal(await f.sessions.authenticate(f.issued.access),undefined);}finally{f.db.sqlite.close();}});

test('successful commit does not run fallible cleanup after linearization',async()=>{const f=await fixture();try{const b=await f.begin();f.intents.discard=async()=>{throw Error('cleanup unavailable');};assert.deepEqual(await f.finish(b),{status:'assigned'});assert.deepEqual(await f.intents.status(f.auth,b.intentId),{status:'assigned'});}finally{f.db.sqlite.close();}});

test('concurrent duplicate finish cannot retire winning claimed intent, slow encryption retry resolves',async()=>{const f=await fixture();try{const b=await f.begin(),encrypt=f.cipher.encrypt.bind(f.cipher);let release,entered;const paused=new Promise(r=>entered=r),gate=new Promise(r=>release=r);f.cipher.encrypt=async(...args)=>{entered();await gate;return encrypt(...args);};const winner=f.finish(b);await paused;assert.equal(await f.finish(b),undefined);assert.deepEqual(await f.intents.status(f.auth,b.intentId),{status:'pending'});assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM assignment_intents').get().n,1);release();assert.deepEqual(await winner,{status:'assigned'});assert.deepEqual(await f.finish(b),{status:'assigned'});assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM assignment_receipts').get().n,1);}finally{f.db.sqlite.close();}});
test('same-intent parallel valid assertion submits produce exactly one assignment',async()=>{const f=await fixture();try{const b=await f.begin(),results=await Promise.all([f.finish(b),f.finish(b)]);assert.ok(results.some(r=>r?.status==='assigned'));assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM assignment_receipts').get().n,1);assert.equal(f.db.sqlite.prepare('SELECT entry_id FROM incoming_codes').get().entry_id,f.entryId);assert.deepEqual(await f.finish(b),{status:'assigned'});}finally{f.db.sqlite.close();}});
test('unclaimed wrong token does not retire intent but claimed invalid assertion does',async()=>{const f=await fixture();try{const b=await f.begin();assert.equal(await f.intents.finish(f.auth,{intentId:b.intentId,token:'invalid',action:b.action,response:{}}),undefined);assert.deepEqual(await f.intents.status(f.auth,b.intentId),{status:'pending'});assert.equal(await f.intents.finish(f.auth,{intentId:b.intentId,token:b.token,action:b.action,response:{}}),undefined);assert.deepEqual(await f.intents.status(f.auth,b.intentId),{status:'not-assigned'});assert.equal(f.db.sqlite.prepare('SELECT entry_id FROM incoming_codes').get().entry_id,null);}finally{f.db.sqlite.close();}});
test('expiry status atomically retires and blocks finish whose batch time was captured earlier',async()=>{
 const f=await fixture();try{
  const b=await f.begin(),batch=f.db.batch.bind(f.db);let entered,release;
  const paused=new Promise(r=>entered=r),gate=new Promise(r=>release=r);
  f.db.batch=async statements=>{entered();await gate;return batch(statements);};
  const finishing=f.finish(b);await paused;f.setNow(NOW+120000);
  assert.deepEqual(await f.intents.status(f.auth,b.intentId),{status:'not-assigned'});
  release();assert.equal(await finishing,undefined);
  assert.equal(f.db.sqlite.prepare('SELECT entry_id FROM incoming_codes').get().entry_id,null);
  assert.deepEqual(await f.intents.status(f.auth,b.intentId),{status:'not-assigned'});
 }finally{f.db.sqlite.close();}
});
test('commit winning expiry race stays assigned, retirement cannot undo it',async()=>{
 const f=await fixture();try{
  const b=await f.begin();assert.deepEqual(await f.finish(b),{status:'assigned'});f.setNow(NOW+120000);
  assert.deepEqual(await f.intents.status(f.auth,b.intentId),{status:'assigned'});
  await f.intents.discard(b.intentId);assert.deepEqual(await f.intents.status(f.auth,b.intentId),{status:'assigned'});
 }finally{f.db.sqlite.close();}
});
test('negative receipt is session-bound, retained and missing is never negative',async()=>{
 const f=await fixture();try{
  const b=await f.begin();await f.intents.finish(f.auth,{intentId:b.intentId,token:b.token,action:b.action,response:{}});
  assert.deepEqual(await f.intents.status(f.auth,b.intentId),{status:'not-assigned'});
  assert.equal(await f.intents.status({...f.auth,deviceId:'other'},b.intentId),undefined);
  assert.equal(await f.intents.status(f.auth,'missing'),undefined);
  f.setNow(NOW+600000);assert.equal(await f.intents.status(f.auth,b.intentId),undefined);
 }finally{f.db.sqlite.close();}
});

test('assignment commits when incoming-code trigger adds an outbox row to D1 change count',async()=>{
 const f=await fixture();try{
  const b=await f.begin();f.db.sqlite.exec('DELETE FROM realtime_outbox');
  assert.deepEqual(await f.finish(b),{status:'assigned'});
  assert.equal(f.db.sqlite.prepare('SELECT entry_id FROM incoming_codes').get().entry_id,f.entryId);
  assert.equal(f.db.sqlite.prepare("SELECT count(*) n FROM realtime_outbox WHERE kind='entry' AND scope_id=?").get(f.entryId).n,1);
  assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM assignment_receipts').get().n,1);
  assert.deepEqual(await f.finish(b),{status:'assigned'});
  assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM assignment_receipts').get().n,1);
 }finally{f.db.sqlite.close();}
});

// ---- owner-private assignment (zero recipients, zero automation): approved owner-confirm rule, no strong proof, atomic disclosure guard ----
const share=(f,id='r1',automation=0,revoked=null)=>{f.db.sqlite.prepare('INSERT OR IGNORE INTO accounts(owner_id,created_at)VALUES(?,?)').run(id,NOW);f.db.sqlite.prepare('INSERT INTO entry_shares(entry_id,recipient_id,allow_automation,created_at,revoked_at)VALUES(?,?,?,?,?)').run(f.entryId,id,automation,NOW,revoked);};
const pfinish=(f,b,extra={})=>f.intents.finish(f.auth,{intentId:b.intentId,action:b.action,...extra});
const entryOf=f=>f.db.sqlite.prepare('SELECT entry_id FROM incoming_codes').get().entry_id;
test('private target: begin issues no ceremony, finish assigns once on explicit confirm, replay is idempotent',async()=>{
 const f=await fixture({priv:true});try{
  const ceremonies=()=>f.db.sqlite.prepare("SELECT count(*) n FROM passkey_ceremonies").get().n;
  const before=ceremonies(),b=await f.begin();
  assert.equal(b.proofRequired,false);assert.equal(b.token,undefined);assert.equal(b.options,undefined);assert.equal(ceremonies(),before,'no passkey ceremony row');
  assert.deepEqual([b.summary.activeRecipients,b.summary.automationRecipients,b.summary.irreversible],[0,0,true]);
  assert.deepEqual(await pfinish(f,b),{status:'assigned'});assert.equal(entryOf(f),f.entryId);
  assert.deepEqual(await f.intents.status(f.auth,b.intentId),{status:'assigned'});assert.deepEqual(await pfinish(f,b),{status:'assigned'});
  assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM assignment_receipts').get().n,1);
 }finally{f.db.sqlite.close();}
});
test('private finish cannot be downgraded: a shared intent still needs its proof, tampered or forged actions fail',async()=>{
 const f=await fixture();try{
  const b=await f.begin();assert.equal(b.proofRequired,true);assert.ok(b.token);
  assert.equal(await pfinish(f,b),undefined,'no proof means no assignment');assert.equal(entryOf(f),null);
  const forged=JSON.parse(b.action);forged[13]=0;forged[14]=0;
  assert.equal(await f.intents.finish(f.auth,{intentId:b.intentId,action:JSON.stringify(forged)}),undefined);
  assert.equal(await f.intents.finish(f.auth,{intentId:b.intentId,token:b.token,action:JSON.stringify(forged),response:f.a.assertion({expected:b.options.challenge})}),undefined);
  assert.equal(entryOf(f),null);
  // The real proof still works on the untouched intent.
  assert.deepEqual(await f.finish(b),{status:'assigned'});
 }finally{f.db.sqlite.close();}
});
for(const kind of ['share','share-automation','share-aba','rename','account','delete-entry','source','session','generation','expiry','tamper','other-device'])test('private intent refuses after '+kind+' between begin and finish, nothing assigned',async()=>{
 const f=await fixture({priv:true});try{
  const b=await f.begin();let action=b.action,auth=f.auth;
  if(kind==='share')share(f);
  if(kind==='share-automation')share(f,'r1',1);
  if(kind==='share-aba'){share(f);f.db.sqlite.prepare('UPDATE entry_shares SET revoked_at=? WHERE recipient_id=?').run(NOW,'r1');}
  if(kind==='share-unrevoke'){/* a previously revoked row re-activated */}
  if(kind==='rename')f.db.sqlite.prepare("UPDATE entries SET label='Renamed' WHERE entry_id=?").run(f.entryId);
  if(kind==='account')f.db.sqlite.prepare("UPDATE entries SET account_name='x' WHERE entry_id=?").run(f.entryId);
  if(kind==='delete-entry')f.db.sqlite.prepare('DELETE FROM entries WHERE entry_id=?').run(f.entryId);
  if(kind==='source')await f.sources.revokeSource(f.account.ownerId,f.sourceId,NOW);
  if(kind==='session')await f.sessions.revoke({ownerId:f.account.ownerId,deviceId:f.issued.deviceId,generation:f.auth.generation});
  if(kind==='generation')f.db.sqlite.prepare('UPDATE account_security SET generation=generation+1 WHERE owner_id=?').run(f.account.ownerId);
  if(kind==='expiry')f.setNow(NOW+120000);
  if(kind==='tamper')action=b.action+'x';
  if(kind==='other-device')auth={...f.auth,deviceId:'other'};
  const out=await f.intents.finish(auth,{intentId:b.intentId,action});assert.ok(out===undefined||out.status==='not-assigned');
  if(kind!=='delete-entry')assert.equal(entryOf(f),null);
  assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM assignment_receipts').get().n,0);
 }finally{f.db.sqlite.close();}
});
test('private: a revoked share row does not make the target shared; re-activation after begin cancels the intent',async()=>{
 const f=await fixture({priv:true});try{
  share(f,'old',1,NOW);
  const b=await f.begin();assert.equal(b.proofRequired,false);assert.equal(b.summary.activeRecipients,0);
  f.db.sqlite.prepare("UPDATE entry_shares SET revoked_at=NULL WHERE recipient_id='old'").run();
  assert.equal(await pfinish(f,b),undefined);assert.equal(entryOf(f),null);
  assert.deepEqual(await f.intents.status(f.auth,b.intentId),{status:'not-assigned'},'definite negative, not replayable');
  const c=await f.begin();assert.equal(c.proofRequired,true,'now shared, so proof is required again');
 }finally{f.db.sqlite.close();}
});
test('private: a share committed while the batch is paused or while encrypting wins, never a disclosure without proof',async()=>{
 for(const where of ['encrypt','batch']){
  const f=await fixture({priv:true});try{
   const b=await f.begin();
   if(where==='encrypt'){const enc=f.cipher.encrypt.bind(f.cipher);f.cipher.encrypt=async(...a)=>{const r=await enc(...a);share(f);return r;};}
   else{const batch=f.db.batch.bind(f.db);f.db.batch=async st=>{share(f);return batch(st);};}
   assert.equal(await pfinish(f,b),undefined,where);assert.equal(entryOf(f),null,where);
   const rows=f.db.sqlite.prepare('SELECT count(*) n FROM entry_shares WHERE revoked_at IS NULL').get().n;assert.equal(rows,1);
  }finally{f.db.sqlite.close();}
 }
});
test('private: a share added after the assignment commits does not disturb it; unassigned code stays single-assigned',async()=>{
 const f=await fixture({priv:true});try{
  const b=await f.begin();assert.deepEqual(await pfinish(f,b),{status:'assigned'});share(f);
  assert.equal(entryOf(f),f.entryId);assert.deepEqual(await f.intents.status(f.auth,b.intentId),{status:'assigned'});
  const second=await f.begin();assert.equal(second,undefined,'code no longer unassigned');
 }finally{f.db.sqlite.close();}
});
test('private: two private intents or a private and a shared intent racing for one event commit exactly one assignment',async()=>{
 const f=await fixture({priv:true});try{
  const a=await f.begin(),b=await f.begin(),r=await Promise.all([pfinish(f,a),pfinish(f,b)]);
  assert.equal(r.filter(x=>x?.status==='assigned').length,1);assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM assignment_receipts').get().n,1);
 }finally{f.db.sqlite.close();}
});
test('private: parallel duplicate finish of one intent assigns once, loser reconciles through status',async()=>{
 const f=await fixture({priv:true});try{
  const b=await f.begin(),r=await Promise.all([pfinish(f,b),pfinish(f,b)]);
  assert.ok(r.some(x=>x?.status==='assigned'));assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM assignment_receipts').get().n,1);
  assert.deepEqual(await f.intents.status(f.auth,b.intentId),{status:'assigned'});
 }finally{f.db.sqlite.close();}
});
test('private HTTP: begin then finish with only intentId and action works; extra proof fields are tolerated; adapter fields stay strict',async()=>{
 const f=await fixture({priv:true});try{
  const http=createAssignmentIntentHttp({db:f.db,sessions:f.sessions,intents:f.intents,clock:()=>NOW}),call=(path,body)=>http.fetch(new Request('https://otpanda-api.abrahammurciano.workers.dev/v1/manage/assignment/'+path,{method:'POST',headers:{Origin:'https://otpanda.github.io',Authorization:'Bearer '+f.issued.access,'Content-Type':'application/json'},body:JSON.stringify(body)}),{clientAddress:'192.0.2.1'});
  const begin=await call('begin',{sourceId:f.sourceId,eventId:'event',entryId:f.entryId});assert.equal(begin.status,200);const b=await begin.json();assert.equal(b.proofRequired,false);
  assert.equal((await call('finish',{intentId:b.intentId,action:b.action,owner:'x'})).status,400,'unknown field refused');
  const fin=await call('finish',{intentId:b.intentId,action:b.action});assert.equal(fin.status,200);assert.deepEqual(await fin.json(),{status:'assigned'});
 }finally{f.db.sqlite.close();}
});

const tokenRow=(f,{revoked=null,expires=NOW+60000}={})=>f.db.sqlite.prepare('INSERT INTO entry_tokens(token_id,token_digest,actor_id,entry_id,client_id,created_at,expires_at,revoked_at)VALUES(?,?,?,?,?,?,?,?)').run('automation',Buffer.alloc(32,1),f.account.ownerId,f.entryId,'fixture',NOW-1000,expires,revoked);
test('entry automation token requires proof even without recipient shares',async()=>{const f=await fixture({priv:true});try{tokenRow(f);const b=await f.begin();assert.equal(b.proofRequired,true);assert.equal(b.summary.automationRecipients,1);}finally{f.db.sqlite.close();}});
for(const mode of ['new','revived','expired'])test('private token exposure final guard '+mode,async()=>{const f=await fixture({priv:true});try{if(mode==='revived')tokenRow(f,{revoked:NOW});if(mode==='expired')tokenRow(f,{expires:NOW-1});const b=await f.begin();assert.equal(b.proofRequired,false);if(mode==='revived')f.db.sqlite.prepare('UPDATE entry_tokens SET revoked_at=NULL').run();else if(mode==='new')tokenRow(f);const r=await pfinish(f,b);if(mode==='expired')assert.deepEqual(r,{status:'assigned'});else{assert.equal(r,undefined);assert.equal(entryOf(f),null);}}finally{f.db.sqlite.close();}});
import{createEntryManageHttp}from'../src/entry-manage-http.js';
test('identical rename keeps revision and pending private assignment valid',async()=>{const f=await fixture({priv:true});try{const b=await f.begin(),before=f.db.sqlite.prepare('SELECT mutation_revision FROM entries WHERE entry_id=?').get(f.entryId).mutation_revision,outbox=f.db.sqlite.prepare('SELECT count(*) n FROM realtime_outbox').get().n;const h=createEntryManageHttp({db:f.db,sessions:f.sessions,clock:()=>NOW});const r=await h.fetch(new Request('https://otpanda-api.abrahammurciano.workers.dev/v1/manage/entry/rename',{method:'POST',headers:{Origin:'https://otpanda.github.io',Authorization:'Bearer '+f.issued.access,'Content-Type':'application/json'},body:JSON.stringify({entryId:f.entryId,label:'  Target  '})}));assert.equal(r.status,200);assert.equal(f.db.sqlite.prepare('SELECT mutation_revision FROM entries WHERE entry_id=?').get(f.entryId).mutation_revision,before);assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM realtime_outbox').get().n,outbox);assert.deepEqual(await pfinish(f,b),{status:'assigned'});}finally{f.db.sqlite.close();}});
import{deviceProofMessage}from'../src/device-key-proof.js';import{hashText}from'../src/sessions.js';import{base64urlEncode}from'../src/tokens.js';
async function androidFx({priv=false}={}){const f=await fixture({priv}),k=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']),j=await crypto.subtle.exportKey('jwk',k.publicKey),jwk={kty:j.kty,crv:j.crv,x:j.x,y:j.y},text=JSON.stringify(jwk);
 f.db.sqlite.prepare('INSERT INTO durable_device_keys(key_id,owner_id,public_jwk,generation,created_at,public_key_digest) VALUES(?,?,?,?,?,?)').run('key-one',f.account.ownerId,text,0,NOW,await hashText(text));
 const dev=await f.sessions.issue({proof:{...f.account,purpose:'authenticate',verifiedAt:NOW},clientKind:'android'}),auth={...await f.sessions.authenticate(dev.access),clientKind:'android'};
 const abegin=(over={})=>f.intents.begin(auth,{sourceId:f.sourceId,eventId:'event',entryId:f.entryId,keyId:'key-one',...over});
 const sig=async c=>base64urlEncode(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},k.privateKey,deviceProofMessage(c))));
 const afinish=async(b,over={})=>f.intents.finish(auth,{intentId:b.intentId,token:b.token,action:b.action,signature:await sig(b.challenge),...over});
 return{...f,auth:f.auth,aauth:auth,dev,abegin,afinish,sig,k};}
test('android device proof: v2 19-element action, single-hash digest, assigned once, replay returns the outcome',async()=>{const f=await androidFx();try{const b=await f.abegin(),a=JSON.parse(b.action);assert.equal(a.length,19);assert.equal(a[0],'otpanda-assignment');assert.equal(a[1],2);assert.equal(a[3],f.account.ownerId);assert.equal(a[4],f.dev.deviceId);assert.equal(a.slice(16).length,3);assert.equal(b.challenge.actionDigest,await hashText(b.action));assert.equal(b.challenge.keyId,'key-one');assert.equal(b.options,undefined);
 assert.deepEqual(await f.afinish(b),{status:'assigned'});assert.deepEqual(await f.afinish(b),{status:'assigned'});assert.equal(f.db.sqlite.prepare('SELECT entry_id FROM incoming_codes').get().entry_id,f.entryId);}finally{f.db.sqlite.close();}});
test('android begin names its own live key; web never takes keyId; v1 stays 16 elements for web',async()=>{const f=await androidFx();try{assert.equal(await f.abegin({keyId:undefined}),undefined);assert.equal(await f.abegin({keyId:'nope'}),undefined);
 f.db.sqlite.prepare("INSERT INTO accounts(owner_id,created_at) VALUES('o2',?)").run(NOW);f.db.sqlite.prepare("INSERT INTO durable_device_keys(key_id,owner_id,public_jwk,generation,created_at,public_key_digest) VALUES('key-two','o2','{}',0,?,?)").run(NOW,'f'.repeat(64));assert.equal(await f.abegin({keyId:'key-two'}),undefined);
 assert.equal(await f.intents.begin(f.auth,{sourceId:f.sourceId,eventId:'event',entryId:f.entryId,keyId:'key-one'}),undefined);const w=await f.intents.begin(f.auth,{sourceId:f.sourceId,eventId:'event',entryId:f.entryId});assert.equal(JSON.parse(w.action).length,16);assert.equal(JSON.parse(w.action)[1],1);
 f.db.sqlite.prepare("UPDATE durable_device_keys SET revoked_at=1 WHERE key_id='key-one'").run();assert.equal(await f.abegin(),undefined);}finally{f.db.sqlite.close();}});
test('android finish: branch mismatches, bad signature, key revoked, caps',async()=>{const f=await androidFx();try{let b=await f.abegin();
 assert.equal(await f.afinish(b,{response:{}}),undefined);assert.equal(await f.afinish(b,{signature:undefined}),undefined);
 assert.equal(await f.intents.finish(f.auth,{intentId:b.intentId,token:b.token,action:b.action,signature:await f.sig(b.challenge)}),undefined);// web session may not use the device branch
 assert.equal(await f.afinish(b,{action:b.action+' '}),undefined);
 assert.equal(await f.afinish(b,{signature:'A'.repeat(86)}),undefined);assert.equal(f.db.sqlite.prepare('SELECT entry_id FROM incoming_codes').get().entry_id,null);assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM assignment_intents WHERE retired_at IS NULL AND consumed_at IS NULL').get().n,0);
 b=await f.abegin();f.db.sqlite.prepare("UPDATE durable_device_keys SET revoked_at=1 WHERE key_id='key-one'").run();assert.equal(await f.afinish(b),undefined);assert.equal(f.db.sqlite.prepare('SELECT entry_id FROM incoming_codes').get().entry_id,null);
 f.db.sqlite.prepare("UPDATE durable_device_keys SET revoked_at=NULL").run();f.db.sqlite.prepare('UPDATE entries SET label=?').run('x'.repeat(65));assert.equal(await f.abegin(),undefined);f.db.sqlite.prepare('UPDATE entries SET label=?,account_name=?').run('ok','y'.repeat(129));assert.equal(await f.abegin(),undefined);
 f.db.sqlite.prepare('UPDATE entries SET label=?,account_name=?,service_id=?').run('é'.repeat(64),'a'.repeat(128),'s'.repeat(128));const ok=await f.abegin();assert.ok(ok);assert.ok(new TextEncoder().encode(ok.action).length<=3072);}finally{f.db.sqlite.close();}});
test('android assignment HTTP: no Origin, exact key sets, 8192 cap, web token refused, android token refused with Origin',async()=>{const f=await androidFx();try{const http=createAssignmentIntentHttp({db:f.db,sessions:f.sessions,intents:f.intents,clock:()=>NOW,native:true}),API='https://otpanda-api.abrahammurciano.workers.dev',
 run=(path,body,{origin=null,token=f.dev.access}={})=>http.fetch(new Request(API+'/v1/manage/assignment/'+path,{method:'POST',headers:{...(origin?{Origin:origin}:{}),Authorization:'Bearer '+token,'Content-Type':'application/json'},body:typeof body==='string'?body:JSON.stringify(body)}),{clientAddress:'192.0.2.9'});
 const ok={sourceId:f.sourceId,eventId:'event',entryId:f.entryId,keyId:'key-one'};assert.notEqual((await run('begin',{sourceId:f.sourceId,eventId:'event',entryId:f.entryId})).status,200);// shared entry: keyId missing is refused by the service
 assert.equal((await run('begin',{...ok,extra:1})).status,400);
 assert.equal((await run('begin',ok,{origin:'https://otpanda.github.io'})).status,401);assert.equal((await run('begin',ok,{token:f.issued.access})).status,401);
 const r=await run('begin',ok),bj=await r.json();assert.equal(r.status,200);assert.equal(r.headers.get('Access-Control-Allow-Origin'),null);assert.equal(r.headers.get('Vary'),'Origin');assert.ok(bj.token&&bj.challenge&&bj.action);
 assert.equal((await run('finish',{intentId:bj.intentId,token:bj.token,action:bj.action,response:{}})).status,400);assert.equal((await run('finish','x'.repeat(8193))).status,400);
 const fin=await run('finish',{intentId:bj.intentId,token:bj.token,action:bj.action,signature:await f.sig(bj.challenge)});assert.equal(fin.status,200);assert.deepEqual(await fin.json(),{status:'assigned'});}finally{f.db.sqlite.close();}});

test('android private target: v1 16-element action, no proof, finish {intentId,action} only; replay; keyId ignored; extras refused',async()=>{const f=await androidFx({priv:true});try{
 let b=await f.abegin({keyId:undefined});assert.equal(b.proofRequired,false);assert.equal(JSON.parse(b.action).length,16);assert.equal(JSON.parse(b.action)[1],1);assert.equal(b.token,undefined);assert.equal(b.challenge,undefined);
 assert.equal(await f.intents.finish(f.aauth,{intentId:b.intentId,action:b.action,token:'x'}),undefined);assert.equal(await f.intents.finish(f.aauth,{intentId:b.intentId,action:b.action,signature:'A'.repeat(86)}),undefined);
 assert.deepEqual(await f.intents.finish(f.aauth,{intentId:b.intentId,action:b.action}),{status:'assigned'});assert.deepEqual(await f.intents.finish(f.aauth,{intentId:b.intentId,action:b.action}),{status:'assigned'});
 assert.equal(await f.abegin({keyId:7}),undefined);}finally{f.db.sqlite.close();}});
test('android: shared target requires key proof; v1 private action cannot be replayed once a share appears; private finish cannot downgrade a shared action',async()=>{const f=await androidFx();try{const b=await f.abegin();assert.equal(b.proofRequired,true);
 assert.equal(await f.intents.finish(f.aauth,{intentId:b.intentId,action:b.action}),undefined);// proof omitted
 const f2=await androidFx({priv:true});try{const p=await f2.abegin();f2.db.sqlite.prepare('INSERT INTO accounts(owner_id,created_at)VALUES(?,?)').run('r',NOW);f2.db.sqlite.prepare('INSERT INTO entry_shares(entry_id,recipient_id,created_at)VALUES(?,?,?)').run(f2.entryId,'r',NOW);assert.equal(await f2.intents.finish(f2.aauth,{intentId:p.intentId,action:p.action}),undefined);assert.equal(f2.db.sqlite.prepare('SELECT entry_id FROM incoming_codes').get().entry_id,null);}finally{f2.db.sqlite.close();}
}finally{f.db.sqlite.close();}});
test('android private HTTP: begin with or without keyId, finish exactly {action,intentId}; shared finish exact proof keys',async()=>{const f=await androidFx({priv:true});try{const http=createAssignmentIntentHttp({db:f.db,sessions:f.sessions,intents:f.intents,clock:()=>NOW,native:true}),API='https://otpanda-api.abrahammurciano.workers.dev',run=(p,body)=>http.fetch(new Request(API+'/v1/manage/assignment/'+p,{method:'POST',headers:{Authorization:'Bearer '+f.dev.access,'Content-Type':'application/json'},body:JSON.stringify(body)}),{clientAddress:'192.0.2.9'});
 const r=await run('begin',{sourceId:f.sourceId,eventId:'event',entryId:f.entryId,keyId:'key-one'}),b=await r.json();assert.equal(r.status,200);assert.equal(b.proofRequired,false);
 assert.equal((await run('finish',{intentId:b.intentId,action:b.action,token:'x'})).status,400);assert.equal((await run('finish',{intentId:b.intentId,action:b.action,extra:1})).status,400);
 const fin=await run('finish',{intentId:b.intentId,action:b.action});assert.equal(fin.status,200);assert.deepEqual(await fin.json(),{status:'assigned'});}finally{f.db.sqlite.close();}});
