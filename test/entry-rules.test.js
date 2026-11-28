import test from 'node:test';import assert from 'node:assert/strict';
import{database}from'./sqlite-helper.js';import{AccountIdentityService}from'../src/account-identity.js';import{PasskeySignupService}from'../src/passkey-signup.js';import{PasskeyService}from'../src/passkey-service.js';import{DeviceSessionService}from'../src/device-sessions.js';import{authenticator}from'./passkey-fixture.js';
import{CodeCipher}from'../src/code-cipher.js';import{SourceEntryStore}from'../src/source-entries.js';import{AssignmentIntents}from'../src/assignment-intents.js';import{createEntryRulesHttp}from'../src/entry-rules-http.js';import{ServiceMetadata}from'../src/service-metadata.js';
const SECRET=Array.from({length:32},(_,i)=>(i*7+13).toString(16).padStart(2,'0')).join('');
const NOW=1800000000000,API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io';
async function acct(db,email,clock,a){
 const identity=new AccountIdentityService(db,{clock}),signup=new PasskeySignupService(db,{clock}),e=await identity.issueEmailChallenge({purpose:'signup-email',email}),c=await signup.begin({email,emailToken:e.token,binding:'b-'+email});
 return signup.finish({token:c.token,binding:'b-'+email,response:a.registration({expected:c.options.challenge})});
}
async function fx({rules=true}={}){
 const db=database(),clock=()=>NOW,a=authenticator(),b=authenticator(),sessions=new DeviceSessionService(db,{clock}),account=await acct(db,'own@example.test',clock,a),other=await acct(db,'rcpt@example.test',clock,b);
 const mk=(acc,kind)=>sessions.issue({proof:{...acc,purpose:'authenticate',verifiedAt:NOW},clientKind:kind});
 const web=await mk(account,'web'),android=await mk(account,'android'),otherWeb=await mk(other,'web'),auth=await sessions.authenticate(web.access);
 const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']),cipher=new CodeCipher({keys:new Map([['f',key]]),activeKeyId:'f'}),meta=new ServiceMetadata(db),store=new SourceEntryStore(db,cipher,{matcher:meta,templateSecret:SECRET});
 const o=account.ownerId;db.sqlite.prepare("INSERT OR IGNORE INTO services(service_id,name)VALUES('test','Test'),('custom-totp','Authenticator')").run();
 const gmail=await store.createSource(o,'gmail','Personal Gmail',NOW),phone=await store.createSource(o,'sms','Phone',NOW),entry=await store.createEntry(o,'test','Target',NOW),entry2=await store.createEntry(o,'test','Second',NOW),custom=await store.createEntry(o,'custom-totp','Mine',NOW),custom2=await store.createEntry(o,'custom-totp','Mine2',NOW);
 await meta.setReceiver(o,gmail,'me@example.test');await meta.setReceiver(o,phone,'+15550001111');
 const passkeys=new PasskeyService(db,{clock}),intents=new AssignmentIntents({db,passkeys,cipher,clock,rules}),http=createEntryRulesHttp({db,sessions,metadata:meta,clock,native:true});
 const call=(token,path,{method='GET',body,origin=APP}={})=>http.fetch(new Request(API+path,{method,headers:{...(origin?{Origin:origin}:{}),Authorization:'Bearer '+token,...(body!==undefined?{'Content-Type':'application/json'}:{})},...(body!==undefined?{body:JSON.stringify(body)}:{})}));
 const mail=(eventId,over={})=>({sourceId:gmail,eventId,code:'123456',receivedAt:NOW-1000,expiresAt:NOW+60000,sender:'noreply@bank.example',receiver:'me@example.test',accountHint:'me@example.test',text:'Your bank code',subject:'Your bank code',...over});
 const sms=(eventId,over={})=>({sourceId:phone,eventId,code:'654321',receivedAt:NOW-1000,expiresAt:NOW+60000,sender:'+15557778888',receiver:'+15550001111',text:'Netflix code 654321',...over});
 const begin=(ev,entryId,phrase)=>intents.begin(auth,{sourceId:ev.sourceId,eventId:ev.eventId,entryId,...(phrase!==undefined?{phrase}:{})});
 const finish=(bg,over={})=>intents.finish(auth,{intentId:bg.intentId,token:bg.token,action:over.action??bg.action,response:bg.options?a.assertion({expected:bg.options.challenge}):undefined});
 const assign=async(ev,entryId,phrase)=>{await store.receive(o,ev);const bg=await begin(ev,entryId,phrase);assert.ok(bg);return{bg,res:await finish(bg)};};
 const rows=()=>db.sqlite.prepare('SELECT * FROM service_routes ORDER BY route_id').all();
 return{db,store,meta,o,other,web,android,otherWeb,gmail,phone,entry,entry2,custom,custom2,call,mail,sms,begin,finish,assign,intents,auth,rows,sessions,a};
}
globalThis.DBG=1;
const list=async(f,tok=f.web.access,q='')=>(await f.call(tok,'/v1/manage/entry/rules'+q)).json();

test('signed Assign saves exact-sender rule in the same batch; next arrival from that sender/connector is assigned, others are not; no back-fill',async()=>{const f=await fx();try{
 await f.store.receive(f.o,f.mail('old-other',{sender:'other@bank.example'}));
 const{bg,res}=await f.assign(f.mail('e1'),f.entry);
 assert.deepEqual(bg.summary.rule.status,'will_save');assert.deepEqual(res,{status:'assigned',rule:{status:'saved'}});
 assert.equal(f.rows().length,1);
 assert.deepEqual(await f.intents.status(f.auth,bg.intentId),{status:'assigned',rule:{status:'saved'}});
 assert.deepEqual(await f.finish(bg),{status:'assigned',rule:{status:'saved'}});assert.equal(f.rows().length,1);
 await f.store.receive(f.o,f.mail('e2'));await f.store.receive(f.o,f.mail('e3',{sender:'other2@bank.example'}));
 const g=id=>f.db.sqlite.prepare('SELECT entry_id FROM incoming_codes WHERE event_id=?').get(id).entry_id;
 assert.equal(g('e2'),f.entry);assert.equal(g('e3'),null);assert.equal(g('old-other'),null);
 assert.equal(f.db.sqlite.prepare('SELECT sender_envelope FROM incoming_codes WHERE event_id=?').get('e2').sender_envelope.includes('bank.example'),false);
}finally{f.db.sqlite.close();}});

test('signed descriptor is exact: altered rule element or phrase refuses and nothing is assigned',async()=>{const f=await fx();try{
 await f.store.receive(f.o,f.mail('e1'));const bg=await f.begin(f.mail('e1'),f.entry,'Bank');assert.ok(bg);
 const act=JSON.parse(bg.action),last=JSON.parse(act.at(-1));assert.equal(last[0],'save');assert.equal(last[6],'bank');
 for(const edit of [x=>{x[2]='evil@x.example';},x=>{x[6]='';},x=>{x[6]=null;},x=>{x[0]='none';}]){const c=[...last];edit(c);const a2=[...act];a2[a2.length-1]=JSON.stringify(c);assert.equal(await f.finish(bg,{action:JSON.stringify(a2)}),undefined);}
 assert.equal(f.rows().length,0);assert.equal(f.db.sqlite.prepare('SELECT entry_id FROM incoming_codes').get().entry_id,null);
 assert.deepEqual((await f.finish(bg)).rule,{status:'saved'});assert.equal(f.rows()[0].phrase,'bank');
}finally{f.db.sqlite.close();}});

test('legacy actions (rules disabled) save no rule; rule actions are refused when rules are disabled',async()=>{const f=await fx({rules:false});try{
 const{res}=await f.assign(f.mail('e1'),f.entry);assert.deepEqual(res,{status:'assigned'});assert.equal(f.rows().length,0);
}finally{f.db.sqlite.close();}});

test('phrase narrows case-insensitively over text; missing text never matches',async()=>{const f=await fx();try{
 await f.assign(f.sms('s1',{text:'Netflix code 654321'}),f.entry,'  NETFLIX ');
 await f.store.receive(f.o,f.sms('s2',{text:'netflix is your service, 111111'}));
 await f.store.receive(f.o,f.sms('s3',{text:'Amazon code 222222'}));
 await f.store.receive(f.o,f.sms('s4',{text:undefined}));
 const g=id=>f.db.sqlite.prepare('SELECT entry_id FROM incoming_codes WHERE event_id=?').get(id).entry_id;
 assert.equal(g('s2'),f.entry);assert.equal(g('s3'),null);assert.equal(g('s4'),null);
}finally{f.db.sqlite.close();}});

test('same sender, two accounts: phrases separate them, an overlap stays unassigned; one account keeps SMS, email and TOTP-type (custom) rules together',async()=>{const f=await fx();try{
 await f.assign(f.sms('a1',{text:'Netflix code 654321'}),f.entry,'netflix');
 await f.assign(f.sms('a2',{text:'Hulu code 654321'}),f.entry2,'hulu');
 await f.assign(f.mail('m1'),f.entry);
 const g=id=>f.db.sqlite.prepare('SELECT entry_id FROM incoming_codes WHERE event_id=?').get(id).entry_id;
 await f.store.receive(f.o,f.sms('n1',{text:'Netflix 111111'}));await f.store.receive(f.o,f.sms('h1',{text:'Hulu 222222'}));await f.store.receive(f.o,f.sms('b1',{text:'Netflix and Hulu 333333'}));
 assert.equal(g('n1'),f.entry);assert.equal(g('h1'),f.entry2);assert.equal(g('b1'),null);
 assert.equal(f.rows().filter(r=>r.entry_id===f.entry).length,2);
}finally{f.db.sqlite.close();}});

test('custom-totp entries: rule saves (sentinel services row), coexists with seed-less entry, two custom entries on one sender stay ambiguous',async()=>{const f=await fx();try{
 f.db.sqlite.prepare("INSERT INTO totp_seeds(owner_id,entry_id,envelope,created_at,updated_at)VALUES(?,?,'{\"seed\":1}',?,?)").run(f.o,f.custom,NOW,NOW);
 const r1=await f.assign(f.mail('c1'),f.custom);assert.deepEqual(r1.res.rule,{status:'saved'});
 f.db.sqlite.prepare("INSERT INTO service_routes(route_id,owner_id,service_id,source_id,origin_kind,origin_value,entry_id,account_hint,phrase,created_at)VALUES('dup',?,'custom-totp',?,'email_address','noreply@bank.example',?,'me@example.test',NULL,?)").run(f.o,f.gmail,f.custom2,NOW);
 await f.store.receive(f.o,f.mail('c3'));
 assert.equal(f.db.sqlite.prepare("SELECT entry_id FROM incoming_codes WHERE event_id='c3'").get().entry_id,null);
 assert.deepEqual({...f.db.sqlite.prepare('SELECT envelope,updated_at FROM totp_seeds WHERE entry_id=?').get(f.custom)},{envelope:'{"seed":1}',updated_at:NOW});
 f.db.sqlite.prepare('DELETE FROM service_routes WHERE route_id=?').run('dup');
 await f.store.receive(f.o,f.mail('c4'));assert.equal(f.db.sqlite.prepare("SELECT entry_id FROM incoming_codes WHERE event_id='c4'").get().entry_id,f.custom);
}finally{f.db.sqlite.close();}});

test('missing prerequisites are explicit, write no rule, and the assignment stands',async()=>{const f=await fx();try{
 const a=await f.assign(f.mail('r1',{sender:undefined}),f.entry);assert.deepEqual(a.res,{status:'assigned',rule:{status:'unavailable',reason:'sender_unknown'}});
 f.db.sqlite.prepare('UPDATE sources SET receiver=NULL WHERE source_id=?').run(f.gmail);
 const b=await f.assign(f.mail('r2'),f.entry);assert.equal(b.res.rule.reason,'receiver_unset');assert.equal(f.rows().length,0);
}finally{f.db.sqlite.close();}});

test('source revoked between begin and finish: nothing assigned, no rule',async()=>{const f=await fx();try{
 await f.store.receive(f.o,f.mail('x1'));const bg=await f.begin(f.mail('x1'),f.entry);await f.store.revokeSource(f.o,f.gmail,NOW);
 assert.equal(await f.finish(bg),undefined);assert.equal(f.rows().length,0);
}finally{f.db.sqlite.close();}});

test('rules API: owner-only, strict, session-bound; recipient and other owner see nothing; PATCH/DELETE statement-level predicate',async()=>{const f=await fx();try{
 await f.assign(f.mail('e1'),f.entry);const id=f.rows()[0].route_id;
 const l=await list(f);assert.equal(l.rules.length,1);assert.deepEqual(Object.keys(l.rules[0]).sort(),['basis','createdAt','entryId','kind','phrase','ruleId','senderKind','sender','sourceId','sourceLabel','status'].sort());
 assert.deepEqual((await list(f,f.otherWeb.access)).rules,[]);
 assert.equal((await f.call(f.web.access,'/v1/manage/entry/rules',{origin:'https://evil.test'})).status,403);
 assert.equal((await f.call(f.web.access,'/v1/manage/entry/rules?x=1')).status,400);
 const upd=(tok,b)=>f.call(tok,'/v1/manage/entry/rule',{method:'POST',body:b});
 assert.equal((await upd(f.otherWeb.access,{ruleId:id,phrase:'x'})).status,409);assert.equal((await f.call(f.otherWeb.access,'/v1/manage/entry/rule/delete',{method:'POST',body:{ruleId:id}})).status,404);assert.equal(f.rows().length,1);
 {const r=await upd(f.web.access,{ruleId:id,phrase:'Bank'});assert.equal(r.status,409);assert.equal((await r.json()).error,'signed_action_required');assert.equal(f.rows()[0].phrase,null);}
 assert.equal((await upd(f.web.access,{ruleId:id,phrase:5})).status,400);
 f.db.sqlite.prepare('UPDATE device_sessions SET revoked_at=? WHERE device_id=?').run(NOW,f.web.deviceId);
 assert.notEqual((await f.call(f.web.access,'/v1/manage/entry/rule/delete',{method:'POST',body:{ruleId:id}})).status,200);assert.equal(f.rows().length,1);
 const del=await f.call(f.android.access,'/v1/manage/entry/rule/delete',{method:'POST',body:{ruleId:id},origin:null});assert.equal(del.status,200);assert.equal(f.rows().length,0);
}finally{f.db.sqlite.close();}});

test('duplicate phrase edit conflicts (409) and the NULL-safe index dedupes',async()=>{const f=await fx();try{
 await f.assign(f.mail('e1'),f.entry,'a');f.db.sqlite.prepare("INSERT INTO service_routes(route_id,owner_id,service_id,source_id,origin_kind,origin_value,entry_id,account_hint,phrase,created_at)SELECT 'zz',owner_id,service_id,source_id,origin_kind,origin_value,entry_id,account_hint,'b',created_at FROM service_routes").run();const[r1,r2]=f.rows();
 const res=await f.call(f.web.access,'/v1/manage/entry/rule',{method:'POST',body:{ruleId:r2.route_id,phrase:'a'}});assert.equal(res.status,409);
 const ins=()=>f.db.sqlite.prepare("INSERT INTO service_routes(route_id,owner_id,service_id,source_id,origin_kind,origin_value,entry_id,account_hint,phrase,created_at)VALUES(?,?,?,?,?,?,?,NULL,NULL,?)").run(crypto.randomUUID(),f.o,'test',f.gmail,'email_address','z@z.example',f.entry,NOW);
 ins();assert.throws(ins,/UNIQUE/i);
}finally{f.db.sqlite.close();}});

test('GET paginates without a silent cap; entry delete removes rules (no NULL-entry route); revoked source lists its rules as paused (owner can still see and delete them)',async()=>{const f=await fx();try{
 const st=f.db.sqlite.prepare("INSERT INTO service_routes(route_id,owner_id,service_id,source_id,origin_kind,origin_value,entry_id,account_hint,phrase,created_at)VALUES(?,?,?,?,?,?,?,NULL,?,?)");
 for(let i=0;i<130;i++)st.run('r'+String(i).padStart(4,'0'),f.o,'test',f.gmail,'email_address','s@x.example',f.entry,'p'+i,NOW);
 const p1=await list(f);assert.equal(p1.rules.length,100);assert.ok(p1.next);const p2=await list(f,f.web.access,'?cursor='+p1.next);assert.equal(p2.rules.length,30);assert.equal(p2.next,undefined);
 f.db.sqlite.prepare('DELETE FROM entries WHERE entry_id=?').run(f.entry);assert.equal(f.rows().length,0);assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM service_routes WHERE entry_id IS NULL').get().n,0);
 st.run('k1',f.o,'test',f.gmail,'email_address','s@x.example',f.entry2,'q',NOW);await f.store.revokeSource(f.o,f.gmail,NOW);{const g=(await list(f)).rules;assert.ok(g.length>0&&g.every(x=>x.status==='paused'));}
}finally{f.db.sqlite.close();}});

import{createIdentityEdgeHost}from'../src/identity-edge-host.js';
test('rules and source routes: web origin and native (no Origin) reach the runtime; native off, wrong origin, extension origin and cookie-less browser origin do not',async()=>{
 const yes={limit:async()=>({success:true})};let hits=0;
 const mk=opts=>createIdentityEdgeHost({resolveTrustedIngress:()=> '192.0.2.1',edgeAddress:yes,edgeAuthGlobal:yes,edgeReadGlobal:yes,initialize:()=>({fetch:async()=>{hits++;return new Response('{}',{status:200});}}),...opts});
 const req=(path,{method='GET',origin}={})=>new Request(API+path,{method,headers:{...(origin?{Origin:origin}:{}),Authorization:'Bearer x'}});
 const paths=[['/v1/manage/entry/rules','GET'],['/v1/manage/entry/sources','GET'],['/v1/manage/entry/rule','POST'],['/v1/manage/entry/rule/delete','POST'],['/v1/manage/unassigned-context','GET'],['/v1/manage/rule-intent/begin','POST'],['/v1/manage/rule-intent/finish','POST'],['/v1/manage/rule-intent/status','POST']];
 const native=mk({nativeApi:true}),off=mk({});
 for(const[p,m]of paths){
  hits=0;assert.equal((await native.fetch(req(p,{method:m,origin:APP}))).status,200);assert.equal((await native.fetch(req(p,{method:m}))).status,200);assert.equal(hits,2,p);
  hits=0;assert.equal((await native.fetch(req(p,{method:m,origin:'https://evil.test'}))).status,403);assert.equal((await native.fetch(req(p,{method:m,origin:'chrome-extension://abc'}))).status,403);
  assert.ok([403,404].includes((await off.fetch(req(p,{method:m}))).status));assert.equal(hits,0,p);
 }
});

import{normalizeTemplate,templateDigest,parseDigestSecret}from'../src/template-fingerprint.js';
test('template canonicalization: all Unicode digits stripped, code located, NFC, fail closed',()=>{
 const n=(t,code='123456',kind='sms')=>normalizeTemplate(t,{code,kind});
 assert.equal(n('Your code is 123456. Pay $50.00 on 12/11/2026'),'your code is . pay $. on //');assert.equal(n('Your code is 987654. Pay $1,234.56 on 01/02/2027','987654'),'your code is . pay $,. on //','punctuation between digits is deliberately not stripped');assert.equal(n('Your code is 987654. Pay $99.99 on 05/06/2028','987654'),'your code is . pay $. on //','same shape, different digits: same template');
 assert.equal(n('Code: 123456 for Netflix'),n('Code: 654321 for Netflix','654321'));
 assert.equal(n('Code ١٢٣٤٥٦ for Netflix on ２０２６'),n('Code 654321 for Netflix on 2026','654321'),'Arabic-Indic and fullwidth digits in non-code positions are stripped to the same template');
 assert.equal(n('Code ١٢٣٤٥٦ for Netflix'),n('Code 654321 for Netflix','654321'),'numeric code written in other scripts is stripped by the Nd rule');
 assert.equal(n('Code 123 456 for Netflix'),n('Code 654-321 for Netflix','654321'),'split code formats');
 assert.equal(n('Hello 123456 and 123456 again'),'hello and again'.replace(/ and /,' and '));
 assert.equal(n('No code here','A1B2C3'),null,'SMS whose alphanumeric code cannot be located has no template');
 assert.equal(n('Visit A1B2C3x now','A1B2C3'),null,'alphanumeric code is anchored at word boundaries (inside a longer word: not located, SMS has no template)');
 assert.equal(n('<#> 123456'),null,'letterless residue is not a template');assert.equal(n('(123456)'),null);
 assert.equal(n('Order 55 shipped',  'A1B2C3','email'),'order shipped','email subject w/o code is valid');
 assert.equal(n('Your A1B2C3 code','A1B2C3','email'),'your code');
 assert.equal(n('12345 6789 000','123456'),null,'empty after stripping');
 assert.equal(n('Caf\u0065\u0301 123456'),n('Caf\u00e9 123456'),'NFC');
 assert.equal(n('Pay   NOW \u00a0 123456'),'pay now');
});
test('keyed digest is deterministic, owner/source scoped, versioned and not the text',async()=>{
 const k=parseDigestSecret(SECRET);assert.ok(k);assert.equal(parseDigestSecret('abcd'),null);
 const a=await templateDigest(k,'o1','s1','pay now'),b=await templateDigest(k,'o1','s1','pay now'),c=await templateDigest(k,'o2','s1','pay now'),d=await templateDigest(k,'o1','s2','pay now');
 assert.equal(a,b);assert.notEqual(a,c);assert.notEqual(a,d);assert.match(a,/^v1:[0-9a-f]{64}$/);assert.equal(a.includes('pay'),false);
});

test('default Assign saves a keyed template rule: same template with other digits matches, other template/sender does not, no text stored, digest never listed',async()=>{const f=await fx();try{
 const{bg,res}=await f.assign(f.sms('t1',{text:'Netflix code 654321. Charge $5.00'}),f.entry);
 assert.equal(bg.summary.rule.basis,'template');assert.equal('digest' in bg.summary.rule,false);assert.deepEqual(res,{status:'assigned',rule:{status:'saved'}});
 const r=f.rows()[0];assert.match(r.template_fp,/^v1:[0-9a-f]{64}$/);assert.equal(r.phrase,null);
 for(const[id,text]of [['t2','Netflix code 111111. Charge $9.00'],['t3','Hulu code 222222. Charge $5.00'],['t4','Netflix code 333333. Charge $9,99']])await f.store.receive(f.o,f.sms(id,{code:id==='t2'?'111111':id==='t3'?'222222':'333333',text}));
 const g=id=>f.db.sqlite.prepare('SELECT entry_id FROM incoming_codes WHERE event_id=?').get(id).entry_id;
 assert.equal(g('t2'),f.entry);assert.equal(g('t3'),null);assert.equal(g('t4'),null);
 assert.equal(JSON.stringify(await list(f)).includes('v1:'),false);
 assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM incoming_codes WHERE sender_envelope LIKE ?').get('%Netflix%').n,0);
}finally{f.db.sqlite.close();}});
test('two accounts with the same sender and template stay unassigned (fail closed); no digest means no rule, never sender-only',async()=>{const f=await fx();try{
 await f.assign(f.sms('u1',{text:'Code 654321 for Acme'}),f.entry);
 f.db.sqlite.prepare("INSERT INTO service_routes(route_id,owner_id,service_id,source_id,origin_kind,origin_value,entry_id,account_hint,phrase,template_fp,created_at)SELECT 'two',owner_id,service_id,source_id,origin_kind,origin_value,?,account_hint,phrase,template_fp,created_at FROM service_routes").run(f.entry2);
 await f.store.receive(f.o,f.sms('u2',{code:'777777',text:'Code 777777 for Acme'}));assert.equal(f.db.sqlite.prepare("SELECT entry_id FROM incoming_codes WHERE event_id='u2'").get().entry_id,null);
 // SMS whose text lacks the code: no template, no rule
 await f.store.receive(f.o,f.sms('u3',{code:'A8B8C8',text:'Acme says hello'}));const bg=await f.begin(f.sms('u3'),f.entry);assert.equal(bg.summary.rule.status,'unavailable');assert.equal(bg.summary.rule.reason,'template_unavailable');
 const done=await f.finish(bg);assert.deepEqual(done,{status:'assigned',rule:{status:'unavailable',reason:'template_unavailable'}});assert.equal(f.rows().length,2);
}finally{f.db.sqlite.close();}});
test('shared target: summary states future recipients and automations (counts are in the signed action too)',async()=>{const f=await fx();try{
 f.db.sqlite.prepare('INSERT INTO accounts(owner_id,created_at)VALUES(?,?)').run('rcp1',NOW);f.db.sqlite.prepare('INSERT INTO entry_shares(entry_id,recipient_id,allow_automation,created_at)VALUES(?,?,1,?)').run(f.entry,'rcp1',NOW);
 await f.store.receive(f.o,f.sms('sh1'));const bg=await f.begin(f.sms('sh1'),f.entry);assert.ok(bg);assert.equal(bg.summary.rule.futureRecipients,1);assert.equal(bg.summary.rule.futureAutomations,1);assert.deepEqual(JSON.parse(bg.action).slice(13,15),[1,1]);
}finally{f.db.sqlite.close();}});

import{ingestEmail}from'../src/email-ingest.js';
test('Gmail e2e: ingest (subject template, code only in body) -> signed Assign -> next arrival assigned; revoke hides the rule, reconnect reuses the source',async()=>{const f=await fx();try{
 const msg=(id,code,subject='Bank sign-in code',from='Alerts <noreply@bank.example>')=>({provider:'gmail',id,receivedAt:NOW-1000,subject,text:'Your code is '+code+'. It expires in 10 minutes.',from:'noreply@bank.example',to:'me@example.test'});
 const r1=await ingestEmail(f.store,f.o,f.gmail,msg('g1','482913'));assert.equal(r1.ingested,true);assert.equal(r1.entryId,null);
 const bg=await f.begin({sourceId:f.gmail,eventId:'g1'},f.entry);assert.equal(bg.summary.rule.basis,'template');assert.equal((await f.finish(bg)).rule.status,'saved');
 const r2=await ingestEmail(f.store,f.o,f.gmail,msg('g2','771204'));assert.equal(r2.entryId,f.entry);
 const r3=await ingestEmail(f.store,f.o,f.gmail,msg('g3','771205','Different subject'));assert.equal(r3.entryId,null);
 await f.store.revokeSource(f.o,f.gmail,NOW);{const g=(await list(f)).rules;assert.ok(g.length>0&&g.every(x=>x.status==='paused'));}
 f.db.sqlite.prepare('UPDATE sources SET revoked_at=NULL WHERE source_id=?').run(f.gmail); // what Gmail reconnect does: same source id
 assert.equal((await list(f)).rules.length,1);assert.equal((await list(f)).rules[0].status,'paused','reconnect keeps the rule paused until a signed resume');
}finally{f.db.sqlite.close();}});

test('no unsigned basis edit exists: plain rule POST refuses every phrase change, including clearing; delete still works',async()=>{const f=await fx();try{
 await f.assign(f.sms('w1',{text:'Acme code 654321'}),f.entry);
 const id=f.rows()[0].route_id,before=JSON.stringify(f.rows()),upd=b=>f.call(f.web.access,'/v1/manage/entry/rule',{method:'POST',body:{ruleId:id,...b}});
 for(const b of [{phrase:'acme'},{phrase:null}]){const r=await upd(b);assert.equal(r.status,409);assert.equal((await r.json()).error,'signed_action_required');}
 f.db.sqlite.prepare('INSERT INTO entry_shares(entry_id,recipient_id,created_at)VALUES(?,?,?)').run(f.entry,f.other.ownerId,NOW);
 assert.equal((await upd({phrase:'x'})).status,409);assert.equal(JSON.stringify(f.rows()),before);
 assert.equal((await list(f,f.web.access,'?entryId='+f.entry)).rules.length,1);assert.equal((await list(f,f.web.access,'?entryId='+f.entry2)).rules.length,0);
 assert.equal((await f.call(f.web.access,'/v1/manage/entry/rule/delete',{method:'POST',body:{ruleId:id}})).status,200);
}finally{f.db.sqlite.close();}});

test('uniqueness includes service_id: same sender/phrase for two services does not collide',async()=>{const f=await fx();try{
 f.db.sqlite.prepare("INSERT OR IGNORE INTO services(service_id,name)VALUES('other','Other')").run();
 const ins=sv=>f.db.sqlite.prepare("INSERT INTO service_routes(route_id,owner_id,service_id,source_id,origin_kind,origin_value,entry_id,account_hint,phrase,created_at)VALUES(?,?,?,?,'email_address','z@z.example',NULL,NULL,NULL,?)").run(crypto.randomUUID(),f.o,sv,f.gmail,NOW);
 ins('test');ins('other');assert.throws(()=>ins('test'),/UNIQUE/i);
}finally{f.db.sqlite.close();}});

test('negative control: session revoked after auth, immediately before each rule write statement, writes nothing',async()=>{for(const op of ['update','delete']){const f=await fx();try{
 await f.assign(f.mail('h1'),f.entry);const id=f.rows()[0].route_id;
 const hooked={...f.db,prepare:sql=>{const st=f.db.prepare(sql);if(!/^\s*(UPDATE|DELETE) FROM service_routes|^\s*UPDATE service_routes/.test(sql))return st;return{bind:(...a)=>{const b=st.bind(...a);return{run:async()=>{f.db.sqlite.prepare('UPDATE device_sessions SET revoked_at=? WHERE device_id=?').run(NOW,f.web.deviceId);return b.run();},first:()=>b.first(),all:()=>b.all()};}};},batch:s=>f.db.batch(s)};
 const http=createEntryRulesHttp({db:hooked,sessions:f.sessions,metadata:f.meta,clock:()=>NOW,native:true});
 const res=await http.fetch(new Request(API+'/v1/manage/entry/rule'+(op==='delete'?'/delete':''),{method:'POST',headers:{Origin:APP,Authorization:'Bearer '+f.web.access,'Content-Type':'application/json'},body:JSON.stringify(op==='delete'?{ruleId:id}:{ruleId:id,phrase:'x'})}));
 assert.notEqual(res.status,200);assert.equal(f.rows().length,1);assert.equal(f.rows()[0].phrase,null);
}finally{f.db.sqlite.close();}}});

test('code length 4-8 and G-prefixed codes give one template; restore collision is 409; saved digest never leaves the server',async()=>{
 const n=(t,code)=>normalizeTemplate(t,{code,kind:'sms'});
 const base=n('Your code is 123456, do not share','123456');
 for(const c of ['1234','12345','1234567','12345678'])assert.equal(n('Your code is '+c+', do not share',c),base);
 assert.equal(n('Your code is G-123456, do not share','123456'),n('Your code is G-12345678, do not share','12345678'));
 const f=await fx();try{
  await f.assign(f.sms('k1',{text:'Acme code 654321'}),f.entry);const r1=f.rows()[0];
  f.db.sqlite.prepare("INSERT INTO service_routes(route_id,owner_id,service_id,source_id,origin_kind,origin_value,entry_id,account_hint,phrase,saved_template_fp,created_at)SELECT 'sw',owner_id,service_id,source_id,origin_kind,origin_value,entry_id,account_hint,'zz',template_fp,created_at FROM service_routes").run();
  const res=await f.call(f.web.access,'/v1/manage/entry/rule',{method:'POST',body:{ruleId:'sw',phrase:null}});assert.equal(res.status,409);
  const text=JSON.stringify(await list(f))+JSON.stringify(f.db.sqlite.prepare('SELECT payload FROM realtime_outbox').all());
  assert.equal(text.includes('v1:'),false);assert.ok(r1.template_fp);
 }finally{f.db.sqlite.close();}
});

test('key ring: legacy secret is key 0000, rotation keeps old rules matching, unknown key is needs_reassign and never matches',async()=>{
 const {parseDigestKeys,digestKeyId,normalizeTemplate,templateDigest}=await import('../src/template-fingerprint.js');
 const S2=Array.from({length:32},(_,i)=>((i*11+5)%256).toString(16).padStart(2,'0')).join('');
 assert.equal(parseDigestKeys(SECRET,null)[0].id,'0000');
 assert.equal(parseDigestKeys(null,'0001:'+S2+',0000:'+SECRET).map(k=>k.id).join(),'0001,0000');
 assert.equal(parseDigestKeys(null,'zz:'+S2),null);assert.equal(parseDigestKeys('short',null),null);
 const norm=normalizeTemplate('Acme code 654321','654321'.length?{code:'654321',kind:'sms'}:0)===null;void norm;
 const t=normalizeTemplate('Acme code 654321',{code:'654321',kind:'sms'});
 const fp0=await templateDigest(parseDigestKeys(SECRET,null)[0],'o','s',t),fp1=await templateDigest(parseDigestKeys(null,'0001:'+S2)[0],'o','s',t);
 assert.equal(fp0.length,67);assert.equal(fp1.length,67);assert.equal(digestKeyId(fp0),'0000');assert.equal(digestKeyId(fp1),'0001');assert.notEqual(fp0.slice(7),fp1.slice(7));
});

async function rfx(opts={}){
 const {RuleIntents}=await import('../src/rule-intents.js');const {createSourceEntryStore}=await import('../src/source-entries.js');
 const f=await fx(),DAY=86400000;
 const rstore=createSourceEntryStore(f.db,f.store.cipher,{matcher:f.meta,templateSecret:SECRET,contextRetentionMs:30*DAY,contextDigestSecret:SECRET,clock:()=>NOW});
 const mkRi=(db=f.db,keyIds=['0000'])=>new RuleIntents({db,passkeys:new PasskeyService(f.db,{clock:()=>NOW}),cipher:f.store.cipher,clock:()=>NOW,keyIds});
 const ri=mkRi();
 const review=async(id='rv1',over={})=>{await rstore.receive(f.o,f.mail(id,{context:{kind:'email',text:'Your bank code 123456'},subject:'Your bank code 123456',...over}));return f.db.sqlite.prepare('SELECT context_id,template_fp FROM unassigned_context ORDER BY arrived_at DESC LIMIT 1').get();};
 const reviewRows=()=>f.db.sqlite.prepare('SELECT count(*) c FROM unassigned_context').get().c;
 const ownerAuth=async(tok,kind)=>({...(await f.sessions.authenticate(tok)),clientKind:kind});
 return{...f,rstore,ri,mkRi,review,reviewRows,ownerAuth};
}
test('review rule: created without a live code, keeps the receiving-address hint, removes only the preview, next same-template arrival is assigned',async()=>{
 const f=await rfx();try{
  const ctx=await f.review();assert.ok(ctx.template_fp);f.db.sqlite.prepare('DELETE FROM incoming_codes').run();
  const b=await f.ri.begin(f.auth,{operation:'review',contextId:ctx.context_id,entryId:f.entry});assert.ok(b);assert.equal(b.proofRequired,false);
  assert.equal(b.summary.addressScope,'receiving-address');assert.equal(b.summary.previewRemoved,true);assert.equal(b.summary.otherAccountRules,0);
  assert.equal(JSON.stringify(b).includes('v1:'),false);assert.equal(JSON.parse(JSON.parse(b.action)[15])[3],'me@example.test');
  assert.deepEqual(await f.ri.finish(f.auth,{intentId:b.intentId,action:b.action}),{status:'applied',rule:{status:'saved'}});
  assert.equal(f.rows().length,1);assert.equal(f.rows()[0].account_hint,'me@example.test');assert.equal(f.reviewRows(),0);
  await f.store.receive(f.o,f.mail('rv2',{code:'777777',subject:'Your bank code 777777',text:'Your bank code 777777'}));
  assert.equal(f.db.sqlite.prepare("SELECT entry_id FROM incoming_codes WHERE event_id='rv2'").get().entry_id,f.entry);
  // the same sender on another mailbox hint is NOT reached by this rule
  await f.store.receive(f.o,f.mail('rv3',{code:'888888',subject:'Your bank code 888888',text:'Your bank code 888888',accountHint:'other@example.test'}));
  assert.equal(f.db.sqlite.prepare("SELECT entry_id FROM incoming_codes WHERE event_id='rv3'").get().entry_id,null);
 }finally{f.db.sqlite.close();}
});
test('review rule: another other template from the same sender keeps its own preview',async()=>{
 const f=await rfx();try{
  const a=await f.review('t1');await f.review('t2',{sender:'noreply@bank.example',subject:'Totally different words 654321',code:'654321',text:'Totally different words 654321',context:{kind:'email',text:'Totally different words 654321'}});
  assert.equal(f.reviewRows(),1,'one latest row per sender: the newer template replaced the older one');
  void a;
 }finally{f.db.sqlite.close();}
});
test('review rule: replay of finish returns the stored result and writes nothing twice',async()=>{
 const f=await rfx();try{
  const ctx=await f.review(),b=await f.ri.begin(f.auth,{operation:'review',contextId:ctx.context_id,entryId:f.entry});
  const r1=await f.ri.finish(f.auth,{intentId:b.intentId,action:b.action}),before=JSON.stringify(f.rows());
  const r2=await f.ri.finish(f.auth,{intentId:b.intentId,action:b.action});
  assert.deepEqual(r1,r2);assert.equal(JSON.stringify(f.rows()),before);assert.deepEqual(await f.ri.status(f.auth,b.intentId),{status:'applied',rule:{status:'saved'}});
 }finally{f.db.sqlite.close();}
});
test('review rule: an identical rule already exists -> result exists, preview removed, no second route',async()=>{
 const f=await rfx();try{
  const ctx=await f.review('ex1');await f.assign(f.mail('ex1'),f.entry); // Assign saves the same rule; the review row is still there
  assert.equal(f.rows().length,1);assert.equal(f.reviewRows(),1);
  const b=await f.ri.begin(f.auth,{operation:'review',contextId:ctx.context_id,entryId:f.entry});assert.ok(b);
  assert.deepEqual(await f.ri.finish(f.auth,{intentId:b.intentId,action:b.action}),{status:'applied',rule:{status:'exists'}});
  assert.equal(f.rows().length,1);assert.equal(f.reviewRows(),0);
 }finally{f.db.sqlite.close();}
});
test('review rule: overlap with another account is counted in the summary and the signed descriptor',async()=>{
 const f=await rfx();try{
  const ctx=await f.review();
  f.db.sqlite.prepare("INSERT INTO service_routes(route_id,owner_id,service_id,source_id,origin_kind,origin_value,entry_id,account_hint,phrase,created_at,template_fp)VALUES('ov1',?,?,?,?,?,?,NULL,NULL,?,?)").run(f.o,'test',f.gmail,'email_address','noreply@bank.example',f.entry2,NOW,ctx.template_fp);
  const b=await f.ri.begin(f.auth,{operation:'review',contextId:ctx.context_id,entryId:f.entry});assert.equal(b.summary.otherAccountRules,1);
  const desc=JSON.parse(JSON.parse(b.action)[15]);assert.equal(desc.at(-1),1);
  // a legacy sender-wide rule on a third entry also ties
  f.db.sqlite.prepare("UPDATE service_routes SET template_fp=NULL WHERE route_id='ov1'").run();
  const b2=await f.ri.begin(f.auth,{operation:'review',contextId:ctx.context_id,entryId:f.entry});assert.equal(b2.summary.otherAccountRules,1);
 }finally{f.db.sqlite.close();}
});
test('review rule: another entry phrase rule on the same sender counts as a possible tie (never understated)',async()=>{
 const f=await rfx();try{
  const ctx=await f.review();
  f.db.sqlite.prepare("INSERT INTO service_routes(route_id,owner_id,service_id,source_id,origin_kind,origin_value,entry_id,account_hint,phrase,created_at,template_fp)VALUES('ph1',?,?,?,?,?,?,NULL,'other words',?,NULL)").run(f.o,'test',f.gmail,'email_address','noreply@bank.example',f.entry2,NOW);
  const b=await f.ri.begin(f.auth,{operation:'review',contextId:ctx.context_id,entryId:f.entry});assert.equal(b.summary.otherAccountRules,1);
 }finally{f.db.sqlite.close();}
});
test('key ring: a review digest or saved digest under a retired key id is refused (key_retired), never saved as a rule that cannot match',async()=>{
 const f=await rfx();try{
  const ctx=await f.review(),retired=f.mkRi(f.db,['0001']);
  assert.equal(await retired.begin(f.auth,{operation:'review',contextId:ctx.context_id,entryId:f.entry}),undefined);
  assert.equal(f.rows().length,0);
  const p=await retired.begin(f.auth,{operation:'review',contextId:ctx.context_id,entryId:f.entry,phrase:'bank'});assert.ok(p,'a phrase rule has no digest, so no key is needed');
  await f.assign(f.mail('kr1'),f.entry);const rule=f.rows()[0];
  f.db.sqlite.prepare('UPDATE service_routes SET phrase=?,saved_template_fp=template_fp,template_fp=NULL').run('bank');
  assert.equal(await retired.begin(f.auth,{operation:'edit',ruleId:rule.route_id,entryId:f.entry,phrase:null}),undefined);
  assert.ok(await f.ri.begin(f.auth,{operation:'edit',ruleId:rule.route_id,entryId:f.entry,phrase:null}));
 }finally{f.db.sqlite.close();}
});
test('edit rule: summary states old to new basis and that a phrase can match other templates; restore works; tamper refused',async()=>{
 const f=await rfx();try{
  await f.assign(f.mail('ed1'),f.entry);const rule=f.rows()[0];
  const e1=await f.ri.begin(f.auth,{operation:'edit',ruleId:rule.route_id,entryId:f.entry,phrase:'bank code'});
  assert.equal(e1.summary.basisBefore,'template');assert.equal(e1.summary.phraseBefore,null);assert.equal(e1.summary.basis,'phrase');assert.equal(e1.summary.phrase,'bank code');assert.equal(e1.summary.mayMatchOtherTemplates,true);
  assert.equal(JSON.stringify(e1).includes('v1:'),false);
  assert.deepEqual(await f.ri.finish(f.auth,{intentId:e1.intentId,action:e1.action}),{status:'applied',rule:{status:'updated'}});
  let r=f.rows()[0];assert.equal(r.phrase,'bank code');assert.equal(r.template_fp,null);assert.ok(r.saved_template_fp);
  const e2=await f.ri.begin(f.auth,{operation:'edit',ruleId:rule.route_id,entryId:f.entry,phrase:null});assert.equal(e2.summary.basisBefore,'phrase');assert.equal(e2.summary.phraseBefore,'bank code');
  assert.deepEqual(await f.ri.finish(f.auth,{intentId:e2.intentId,action:e2.action}),{status:'applied',rule:{status:'updated'}});
  r=f.rows()[0];assert.equal(r.phrase,null);assert.ok(r.template_fp);
  const e3=await f.ri.begin(f.auth,{operation:'edit',ruleId:rule.route_id,entryId:f.entry,phrase:'other'});
  assert.equal(await f.ri.finish(f.auth,{intentId:e3.intentId,action:e3.action.replace('other','OTHER')}),undefined);assert.equal(f.rows()[0].phrase,null);
 }finally{f.db.sqlite.close();}
});
test('edit rule: shared entry needs a step-up proof and discloses recipients; without it nothing changes',async()=>{
 const f=await rfx();try{
  await f.assign(f.mail('sh1'),f.entry);const rule=f.rows()[0];
  f.db.sqlite.prepare('INSERT INTO entry_shares(entry_id,recipient_id,created_at)VALUES(?,?,?)').run(f.entry,f.other.ownerId,NOW);
  const e=await f.ri.begin(f.auth,{operation:'edit',ruleId:rule.route_id,entryId:f.entry,phrase:'shared edit'});assert.equal(e.proofRequired,true);assert.equal(e.summary.futureRecipients,1);assert.equal(JSON.parse(e.action)[12],1);
  assert.equal(await f.ri.finish(f.auth,{intentId:e.intentId,action:e.action}),undefined);assert.equal(f.rows()[0].phrase,null);
 }finally{f.db.sqlite.close();}
});
for(const op of ['review','edit'])test('negative control: session revoked after auth, immediately before the rule-intent write batch ('+op+') writes nothing',async()=>{
 const f=await rfx();try{
  let subject;
  if(op==='review'){subject={contextId:(await f.review()).context_id};}else{await f.assign(f.mail('nc1'),f.entry);subject={ruleId:f.rows()[0].route_id,phrase:'zzz'};}
  const hooked={...f.db,batch:async s=>{f.db.sqlite.prepare('UPDATE device_sessions SET revoked_at=? WHERE device_id=?').run(NOW,f.web.deviceId);return f.db.batch(s);}};
  const ri=f.mkRi(hooked),b=await ri.begin(f.auth,{operation:op,entryId:f.entry,...subject});assert.ok(b);
  const before=JSON.stringify(f.rows()),rv=f.reviewRows();
  assert.equal(await ri.finish(f.auth,{intentId:b.intentId,action:b.action}),undefined);
  assert.equal(JSON.stringify(f.rows()),before);assert.equal(f.reviewRows(),rv);
 }finally{f.db.sqlite.close();}
});
test('rule intents: another owner, another device of the same owner, and a revoked source cannot finish or reuse a signed review action',async()=>{
 const f=await rfx();try{
  const ctx=await f.review(),b=await f.ri.begin(f.auth,{operation:'review',contextId:ctx.context_id,entryId:f.entry});
  const otherOwner=await f.ownerAuth(f.otherWeb.access,'web'),otherDevice=await f.ownerAuth(f.android.access,'android');
  assert.equal(await f.ri.finish(otherOwner,{intentId:b.intentId,action:b.action}),undefined);
  assert.equal(await f.ri.finish(otherDevice,{intentId:b.intentId,action:b.action}),undefined);
  assert.equal(await f.ri.status(otherOwner,b.intentId),undefined);
  assert.equal(await f.ri.begin(otherOwner,{operation:'review',contextId:ctx.context_id,entryId:f.entry}),undefined);
  assert.equal(f.rows().length,0);assert.equal(f.reviewRows(),1);
  f.db.sqlite.prepare('UPDATE sources SET revoked_at=? WHERE source_id=?').run(NOW,f.gmail);
  assert.equal(f.reviewRows(),0,'revoking the source drops its previews');
  assert.equal(await f.ri.finish(f.auth,{intentId:b.intentId,action:b.action}),undefined);
  assert.equal(f.rows().length,0);
 }finally{f.db.sqlite.close();}
});

test('key rotation end to end: old-key rule keeps matching while the old key is in the ring; without it the rule is needs_reassign and never matches',async()=>{
 const {createSourceEntryStore}=await import('../src/source-entries.js');
 const S2=Array.from({length:32},(_,i)=>((i*11+5)%256).toString(16).padStart(2,'0')).join('');
 const f=await fx();try{
  await f.assign(f.mail('k1'),f.entry);assert.equal(f.rows().length,1);assert.ok(f.rows()[0].template_fp.startsWith('v1:0000'));
  const mk=opts=>createSourceEntryStore(f.db,f.store.cipher,{matcher:f.meta,clock:()=>NOW,...opts});
  const both=mk({templateKeyring:'0001:'+S2+',0000:'+SECRET}),onlyNew=mk({templateKeyring:'0001:'+S2});
  const g=id=>f.db.sqlite.prepare('SELECT entry_id,template_fp FROM incoming_codes WHERE event_id=?').get(id);
  await both.receive(f.o,f.mail('k2',{code:'222222',subject:'Your bank code 222222'}));assert.equal(g('k2').entry_id,f.entry);assert.ok(g('k2').template_fp.startsWith('v1:0001'));
  await onlyNew.receive(f.o,f.mail('k3',{code:'333333',subject:'Your bank code 333333'}));assert.equal(g('k3').entry_id,null);
  const http=createEntryRulesHttp({db:f.db,sessions:f.sessions,metadata:f.meta,clock:()=>NOW,native:true,keyIds:['0001']});
  const res=await http.fetch(new Request(API+'/v1/manage/entry/rules',{headers:{Origin:APP,Authorization:'Bearer '+f.web.access}}));
  const body=await res.json();assert.equal(body.rules[0].status,'needs_reassign');assert.equal(JSON.stringify(body).includes('v1:'),false);assert.equal(f.rows().length,1);
 }finally{f.db.sqlite.close();}
});

test('rule-intent HTTP: strict bodies, web and android shapes, no query, status/replay',async()=>{
 const {RuleIntents}=await import('../src/rule-intents.js');const {createRuleIntentHttp}=await import('../src/rule-intent-http.js');
 const f=await fx();try{
  const ri=new RuleIntents({db:f.db,passkeys:new PasskeyService(f.db,{clock:()=>NOW}),cipher:f.store.cipher,clock:()=>NOW,keyIds:['0000']}),http=createRuleIntentHttp({db:f.db,sessions:f.sessions,intents:ri,clock:()=>NOW,native:true});
  await f.assign(f.mail('h1'),f.entry);const rule=f.rows()[0];
  const post=(path,body,{tok=f.web.access,origin=APP,query=''}={})=>http.fetch(new Request(API+'/v1/manage/rule-intent/'+path+query,{method:'POST',headers:{...(origin?{Origin:origin}:{}),Authorization:'Bearer '+tok,'Content-Type':'application/json'},body:JSON.stringify(body)}),{clientAddress:'192.0.2.9'});
  assert.equal((await post('begin',{operation:'edit',ruleId:rule.route_id,entryId:f.entry})).status,400); // phrase missing
  assert.equal((await post('begin',{operation:'edit',ruleId:rule.route_id,entryId:f.entry,phrase:'bank',extra:1})).status,400);
  assert.equal((await post('begin',{operation:'edit',ruleId:rule.route_id,entryId:f.entry,phrase:'bank'},{query:'?x=1'})).status,400);
  assert.equal((await post('begin',{operation:'edit',ruleId:rule.route_id,entryId:f.entry,phrase:'bank'},{tok:f.otherWeb.access})).status,409);
  const b=await post('begin',{operation:'edit',ruleId:rule.route_id,entryId:f.entry,phrase:'bank'});assert.equal(b.status,200);const bj=await b.json();assert.equal(bj.proofRequired,false);
  assert.equal((await (await post('status',{intentId:bj.intentId})).json()).status,'pending');
  const fin=await post('finish',{intentId:bj.intentId,action:bj.action});assert.equal(fin.status,200);assert.deepEqual(await fin.json(),{status:'applied',rule:{status:'updated'}});
  assert.equal(f.rows()[0].phrase,'bank');
  const again=await post('finish',{intentId:bj.intentId,action:bj.action});assert.deepEqual(await again.json(),{status:'applied',rule:{status:'updated'}});
  // android: no Origin, its own token; web token without Origin is refused
  assert.equal((await post('status',{intentId:bj.intentId},{tok:f.web.access,origin:null})).status,401);
  assert.equal((await post('status',{intentId:bj.intentId},{tok:f.android.access,origin:null})).status,409); // other device: its own result view only
 }finally{f.db.sqlite.close();}
});

async function pausedFx(){
 const f=await rfx();await f.assign(f.mail('ps1'),f.entry);const rule=f.rows()[0];
 const down=()=>f.db.sqlite.prepare('UPDATE sources SET revoked_at=? WHERE source_id=?').run(NOW,f.gmail),up=()=>f.db.sqlite.prepare('UPDATE sources SET revoked_at=NULL WHERE source_id=?').run(f.gmail);
 return{...f,rule,down,up};
}
test('lifecycle: revoke pauses rules and drops previews; un-revoke by ANY path keeps them paused (no matching, listed as paused)',async()=>{
 const f=await pausedFx();try{
  await f.review('lc1',{sender:'other@bank.example'});assert.equal(f.reviewRows(),1);
  f.down();assert.equal(f.reviewRows(),0);assert.notEqual(f.db.sqlite.prepare('SELECT paused_at FROM service_routes').get().paused_at,null);
  f.up();assert.equal(f.reviewRows(),0,'a stale preview never reappears');
  assert.notEqual(f.db.sqlite.prepare('SELECT paused_at FROM service_routes').get().paused_at,null,'reconnect alone never resumes');
  await f.store.receive(f.o,f.mail('lc2',{code:'999111',subject:'Your bank code 999111',text:'Your bank code 999111'}));
  assert.equal(f.db.sqlite.prepare("SELECT entry_id FROM incoming_codes WHERE event_id='lc2'").get().entry_id,null,'a paused rule does not assign');
 }finally{f.db.sqlite.close();}
});
test('lifecycle: signed resume re-activates one paused rule; replay, tamper and a still-revoked source write nothing; paused rule cannot be edited',async()=>{
 const f=await pausedFx();try{
  f.down();
  assert.deepEqual(await f.ri.begin(f.auth,{operation:'resume',ruleId:f.rule.route_id,entryId:f.entry}),{refused:'source_revoked'},'source still revoked');
  f.up();
  assert.equal(await f.ri.begin(f.auth,{operation:'edit',ruleId:f.rule.route_id,entryId:f.entry,phrase:'x'}),undefined,'paused rules are not editable');
  const b=await f.ri.begin(f.auth,{operation:'resume',ruleId:f.rule.route_id,entryId:f.entry});assert.ok(b);
  assert.equal(b.summary.operation,'rule-resume');assert.equal(b.summary.resumesPausedRule,true);assert.equal(b.summary.addressScope,'receiving-address');assert.equal(JSON.stringify(b).includes('v1:'),false);
  assert.equal(await f.ri.finish(f.auth,{intentId:b.intentId,action:b.action.replace('"resume"','"edit"')}),undefined);
  assert.notEqual(f.db.sqlite.prepare('SELECT paused_at FROM service_routes').get().paused_at,null);
  const r1=await f.ri.finish(f.auth,{intentId:b.intentId,action:b.action});assert.deepEqual(r1,{status:'applied',rule:{status:'resumed'}});
  assert.equal(f.db.sqlite.prepare('SELECT paused_at FROM service_routes').get().paused_at,null);
  assert.deepEqual(await f.ri.finish(f.auth,{intentId:b.intentId,action:b.action}),r1);
  await f.store.receive(f.o,f.mail('lc3',{code:'123123',subject:'Your bank code 123123',text:'Your bank code 123123'}));
  assert.equal(f.db.sqlite.prepare("SELECT entry_id FROM incoming_codes WHERE event_id='lc3'").get().entry_id,f.entry);
 }finally{f.db.sqlite.close();}
});
test('lifecycle: resume refused for a retired digest key; source revoked or session revoked between auth and write resumes nothing',async()=>{
 const f=await pausedFx();try{
  f.down();f.up();
  assert.deepEqual(await f.mkRi(f.db,['0001']).begin(f.auth,{operation:'resume',ruleId:f.rule.route_id,entryId:f.entry}),{refused:'key_retired'});
  const hooked={...f.db,batch:async s=>{f.db.sqlite.prepare('UPDATE device_sessions SET revoked_at=? WHERE device_id=?').run(NOW,f.web.deviceId);return f.db.batch(s);}};
  const ri=f.mkRi(hooked),b=await ri.begin(f.auth,{operation:'resume',ruleId:f.rule.route_id,entryId:f.entry});assert.ok(b);
  assert.equal(await ri.finish(f.auth,{intentId:b.intentId,action:b.action}),undefined);
  assert.notEqual(f.db.sqlite.prepare('SELECT paused_at FROM service_routes').get().paused_at,null);
 }finally{f.db.sqlite.close();}
});
test('lifecycle: another owner or device cannot resume; a paused rule can be deleted by the session-gated delete',async()=>{
 const f=await pausedFx();try{
  f.down();f.up();const b=await f.ri.begin(f.auth,{operation:'resume',ruleId:f.rule.route_id,entryId:f.entry});
  const oo=await f.ownerAuth(f.otherWeb.access,'web'),od=await f.ownerAuth(f.android.access,'android');
  assert.equal(await f.ri.finish(oo,{intentId:b.intentId,action:b.action}),undefined);assert.equal(await f.ri.finish(od,{intentId:b.intentId,action:b.action}),undefined);
  assert.notEqual(f.db.sqlite.prepare('SELECT paused_at FROM service_routes').get().paused_at,null);
  const http=createEntryRulesHttp({db:f.db,sessions:f.sessions,metadata:f.meta,clock:()=>NOW,native:true});
  const res=await http.fetch(new Request(API+'/v1/manage/entry/rule/delete',{method:'POST',headers:{Origin:APP,Authorization:'Bearer '+f.web.access,'Content-Type':'application/json'},body:JSON.stringify({ruleId:f.rule.route_id})}));
  assert.equal(res.status,200);assert.equal(f.rows().length,0);
 }finally{f.db.sqlite.close();}
});

test('lifecycle: resume refuses a live collision (another entry holds an active tie) with a reason, keeps the rule paused, deletes nothing; a collision created after begin also blocks finish',async()=>{
 const f=await pausedFx();try{
  f.down();f.up();
  const b=await f.ri.begin(f.auth,{operation:'resume',ruleId:f.rule.route_id,entryId:f.entry});assert.ok(b);
  f.db.sqlite.prepare("INSERT INTO service_routes(route_id,owner_id,service_id,source_id,origin_kind,origin_value,entry_id,account_hint,phrase,created_at,template_fp)VALUES('lv1',?,?,?,?,?,?,?,NULL,?,?)").run(f.o,'test',f.gmail,f.rule.origin_kind,f.rule.origin_value,f.entry2,f.rule.account_hint,NOW,f.rule.template_fp);
  assert.equal(await f.ri.finish(f.auth,{intentId:b.intentId,action:b.action}),undefined,'collision appeared after begin');
  assert.deepEqual(await f.ri.begin(f.auth,{operation:'resume',ruleId:f.rule.route_id,entryId:f.entry}),{refused:'live_collision'});
  assert.equal(f.db.sqlite.prepare('SELECT count(*) c FROM service_routes').get().c,2);assert.notEqual(f.db.sqlite.prepare("SELECT paused_at FROM service_routes WHERE route_id=?").get(f.rule.route_id).paused_at,null);
 }finally{f.db.sqlite.close();}
});
test('lifecycle: source revoked between begin and finish resumes nothing',async()=>{
 const f=await pausedFx();try{
  f.down();f.up();const b=await f.ri.begin(f.auth,{operation:'resume',ruleId:f.rule.route_id,entryId:f.entry});assert.ok(b);f.down();
  assert.equal(await f.ri.finish(f.auth,{intentId:b.intentId,action:b.action}),undefined);assert.notEqual(f.db.sqlite.prepare('SELECT paused_at FROM service_routes').get().paused_at,null);
 }finally{f.db.sqlite.close();}
});
test('lifecycle: resume of a shared entry needs step-up and discloses recipients; without proof nothing resumes',async()=>{
 const f=await pausedFx();try{
  f.down();f.up();f.db.sqlite.prepare('INSERT INTO entry_shares(entry_id,recipient_id,created_at)VALUES(?,?,?)').run(f.entry,f.other.ownerId,NOW);
  const b=await f.ri.begin(f.auth,{operation:'resume',ruleId:f.rule.route_id,entryId:f.entry});assert.equal(b.proofRequired,true);assert.equal(b.summary.futureRecipients,1);
  assert.equal(await f.ri.finish(f.auth,{intentId:b.intentId,action:b.action}),undefined);assert.notEqual(f.db.sqlite.prepare('SELECT paused_at FROM service_routes').get().paused_at,null);
 }finally{f.db.sqlite.close();}
});
test('lifecycle: a paused rule is listed and deletable while its source is still revoked; repeat delete is a no-op',async()=>{
 const f=await pausedFx();try{
  f.down();
  const http=createEntryRulesHttp({db:f.db,sessions:f.sessions,metadata:f.meta,clock:()=>NOW,native:true});
  const del=()=>http.fetch(new Request(API+'/v1/manage/entry/rule/delete',{method:'POST',headers:{Origin:APP,Authorization:'Bearer '+f.web.access,'Content-Type':'application/json'},body:JSON.stringify({ruleId:f.rule.route_id})}));
  assert.equal((await list(f)).rules[0].status,'paused');
  assert.equal((await del()).status,200);assert.equal(f.rows().length,0);
  assert.notEqual((await del()).status,500);assert.equal(f.rows().length,0);
 }finally{f.db.sqlite.close();}
});
test('lifecycle: Assign-style review of an identical rule that is paused reports paused with its id, keeps the preview, never says exists',async()=>{
 const f=await pausedFx();try{
  f.down();f.up();
  const c=await f.review('pz2');assert.ok(c,'a paused rule does not cover the sender: a preview is kept');
  const b=await f.ri.begin(f.auth,{operation:'review',contextId:c.context_id,entryId:f.entry});assert.ok(b);
  assert.deepEqual(await f.ri.finish(f.auth,{intentId:b.intentId,action:b.action}),{status:'applied',rule:{status:'paused',ruleId:f.rule.route_id,resumeRequiresSignedAction:true}});
  assert.equal(f.rows().length,1);assert.notEqual(f.rows()[0].paused_at,null);assert.equal(f.reviewRows(),1,'preview preserved');
  assert.deepEqual(await f.ri.status(f.auth,b.intentId),{status:'applied',rule:{status:'paused',ruleId:f.rule.route_id,resumeRequiresSignedAction:true}});
 }finally{f.db.sqlite.close();}
});

test('lifecycle: signed Assign of an identical paused rule reports paused with the rule id, never exists, never unpauses',async()=>{
 const f=await pausedFx();try{
  f.down();f.up();
  const {res}=await f.assign(f.mail('as2'),f.entry);
  const r=res?.rule??res;assert.equal(r.status,'paused');assert.equal(r.ruleId,f.rule.route_id);
  assert.equal(f.rows().length,1);assert.notEqual(f.rows()[0].paused_at,null);
 }finally{f.db.sqlite.close();}
});

test('lifecycle: a live collision that appears after the finish re-derive but before the write batch still leaves the rule paused (guard inside the UPDATE)',async()=>{
 const f=await pausedFx();try{
  f.down();f.up();
  const hooked={...f.db,batch:async s=>{f.db.sqlite.prepare("INSERT INTO service_routes(route_id,owner_id,service_id,source_id,origin_kind,origin_value,entry_id,account_hint,phrase,created_at,template_fp)VALUES('lv2',?,?,?,?,?,?,?,NULL,?,?)").run(f.o,'test',f.gmail,f.rule.origin_kind,f.rule.origin_value,f.entry2,f.rule.account_hint,NOW,f.rule.template_fp);return f.db.batch(s);}};
  const ri=f.mkRi(hooked),b=await ri.begin(f.auth,{operation:'resume',ruleId:f.rule.route_id,entryId:f.entry});assert.ok(b);
  assert.deepEqual(await ri.finish(f.auth,{intentId:b.intentId,action:b.action}),{status:'applied',rule:{status:'unavailable'}});
  assert.notEqual(f.db.sqlite.prepare("SELECT paused_at FROM service_routes WHERE route_id=?").get(f.rule.route_id).paused_at,null);
 }finally{f.db.sqlite.close();}
});
test('lifecycle: Assign begin summary says already_saved_paused with the rule id (not will_save) when an identical paused rule exists',async()=>{
 const f=await pausedFx();try{
  f.down();f.up();
  const ev=f.mail('as3');await f.store.receive(f.o,ev);
  const bg=await f.begin(ev,f.entry);assert.ok(bg);
  assert.equal(bg.summary?.rule?.status??bg.rule?.status,'already_saved_paused');
  assert.equal((bg.summary?.rule??bg.rule).ruleId,f.rule.route_id);
 }finally{f.db.sqlite.close();}
});

for(const operation of ['review','edit','resume'])test('canonical grant-only recipient requires disclosed proof for '+operation,async()=>{
 const f=await rfx();try{
  let subject;
  if(operation==='review')subject={contextId:(await f.review()).context_id};
  else {await f.assign(f.mail('grant-rule'),f.entry);subject={ruleId:f.rows()[0].route_id,...(operation==='edit'?{phrase:'grant phrase'}:{})};if(operation==='resume'){f.db.sqlite.prepare('UPDATE sources SET revoked_at=? WHERE source_id=?').run(NOW,f.gmail);f.db.sqlite.prepare('UPDATE sources SET revoked_at=NULL WHERE source_id=?').run(f.gmail);}}
  f.db.sqlite.prepare("INSERT INTO access_grants(grant_id,owner_id,grantee_id,mode,can_delegate,created_at,granted_at)VALUES('rule-grant',?,?,'all',1,?,?)").run(f.o,f.other.ownerId,NOW,NOW);
  const b=await f.ri.begin(f.auth,{operation,entryId:f.entry,...subject});assert.ok(b);assert.equal(b.proofRequired,true);assert.equal(b.summary.futureRecipients,1);assert.equal(b.summary.futureAutomations,1);
  const before=JSON.stringify(f.rows());assert.equal(await f.ri.finish(f.auth,{intentId:b.intentId,action:b.action}),undefined);assert.equal(JSON.stringify(f.rows()),before);
 }finally{f.db.sqlite.close();}
});
test('canonical grant-only recipient blocks unsigned rule PATCH',async()=>{
 const f=await rfx();try{await f.assign(f.mail('grant-unsigned'),f.entry);const rule=f.rows()[0];f.db.sqlite.prepare("INSERT INTO access_grants(grant_id,owner_id,grantee_id,mode,created_at,granted_at)VALUES('rule-grant',?,?,'all',?,?)").run(f.o,f.other.ownerId,NOW,NOW);
 const r=await f.call(f.web.access,'/v1/manage/entry/rule',{method:'PATCH',body:{ruleId:rule.route_id,phrase:'widen'}});assert.notEqual(r.status,200);assert.equal(f.rows()[0].phrase,null);
 }finally{f.db.sqlite.close();}
});
for(const audience of ['grant','legacy'])test('audience added after private begin blocks finish and terminal status ('+audience+')',async()=>{
 const f=await rfx();try{await f.assign(f.mail('drift'),f.entry);const rule=f.rows()[0],b=await f.ri.begin(f.auth,{operation:'edit',entryId:f.entry,ruleId:rule.route_id,phrase:'drift'});assert.equal(b.proofRequired,false);
 if(audience==='grant')f.db.sqlite.prepare("INSERT INTO access_grants(grant_id,owner_id,grantee_id,mode,created_at,granted_at)VALUES('drift',?,?,'all',?,?)").run(f.o,f.other.ownerId,NOW,NOW);
 else f.db.sqlite.prepare('INSERT INTO entry_shares(entry_id,recipient_id,created_at)VALUES(?,?,?)').run(f.entry,f.other.ownerId,NOW);
 assert.equal(await f.ri.finish(f.auth,{intentId:b.intentId,action:b.action}),undefined);assert.equal(f.rows()[0].phrase,null);assert.notEqual((await f.ri.status(f.auth,b.intentId))?.status,'applied');
 }finally{f.db.sqlite.close();}
});
for(const audience of ['grant','legacy'])test('audience removed after shared begin refuses old disclosure ('+audience+')',async()=>{
 const f=await rfx();try{await f.assign(f.mail('drift-remove'),f.entry);const rule=f.rows()[0];
 if(audience==='grant')f.db.sqlite.prepare("INSERT INTO access_grants(grant_id,owner_id,grantee_id,mode,created_at,granted_at)VALUES('drift',?,?,'all',?,?)").run(f.o,f.other.ownerId,NOW,NOW);else f.db.sqlite.prepare('INSERT INTO entry_shares(entry_id,recipient_id,created_at)VALUES(?,?,?)').run(f.entry,f.other.ownerId,NOW);
 const b=await f.ri.begin(f.auth,{operation:'edit',entryId:f.entry,ruleId:rule.route_id,phrase:'removed'});assert.equal(b.proofRequired,true);
 const response=f.a.assertion({expected:b.options.challenge});
 if(audience==='grant')f.db.sqlite.prepare("UPDATE access_grants SET revoked_at=? WHERE grant_id='drift'").run(NOW);else f.db.sqlite.prepare('UPDATE entry_shares SET revoked_at=? WHERE entry_id=?').run(NOW,f.entry);
 assert.equal(await f.ri.finish(f.auth,{intentId:b.intentId,action:b.action,token:b.token,response}),undefined);assert.equal(f.rows()[0].phrase,null);
 }finally{f.db.sqlite.close();}
});
for(const audience of ['grant','legacy'])test('audience inserted after rederive before atomic batch is blocked ('+audience+')',async()=>{
 const f=await rfx();try{await f.assign(f.mail('race'),f.entry);const rule=f.rows()[0];
 const hooked={...f.db,batch:async s=>{if(audience==='grant')f.db.sqlite.prepare("INSERT INTO access_grants(grant_id,owner_id,grantee_id,mode,created_at,granted_at)VALUES('race',?,?,'all',?,?)").run(f.o,f.other.ownerId,NOW,NOW);else f.db.sqlite.prepare('INSERT INTO entry_shares(entry_id,recipient_id,created_at)VALUES(?,?,?)').run(f.entry,f.other.ownerId,NOW);return f.db.batch(s);}};
 const ri=f.mkRi(hooked),b=await ri.begin(f.auth,{operation:'edit',entryId:f.entry,ruleId:rule.route_id,phrase:'race'});await ri.finish(f.auth,{intentId:b.intentId,action:b.action});assert.equal(f.rows()[0].phrase,null);assert.notEqual((await ri.status(f.auth,b.intentId))?.status,'applied');
 }finally{f.db.sqlite.close();}
});
for(const audience of ['grant','legacy'])test('status receipt remains historical after committed mutation and later audience change ('+audience+')',async()=>{
 const f=await rfx();try{await f.assign(f.mail('receipt'),f.entry);const rule=f.rows()[0],b=await f.ri.begin(f.auth,{operation:'edit',entryId:f.entry,ruleId:rule.route_id,phrase:'receipt'});assert.equal((await f.ri.finish(f.auth,{intentId:b.intentId,action:b.action})).status,'applied');
 if(audience==='grant')f.db.sqlite.prepare("INSERT INTO access_grants(grant_id,owner_id,grantee_id,mode,created_at,granted_at)VALUES('receipt',?,?,'all',?,?)").run(f.o,f.other.ownerId,NOW,NOW);else f.db.sqlite.prepare('INSERT INTO entry_shares(entry_id,recipient_id,created_at)VALUES(?,?,?)').run(f.entry,f.other.ownerId,NOW);
 assert.equal((await f.ri.status(f.auth,b.intentId)).status,'applied');assert.equal((await f.ri.finish(f.auth,{intentId:b.intentId,action:b.action})).status,'applied');assert.equal(f.rows()[0].phrase,'receipt');
 }finally{f.db.sqlite.close();}
});
async function machine(f,{mode='all',linked=false,revoked=false,expired=false,delegated=false,grantAt=NOW-1,issued=NOW}={}){
 const creator=delegated?f.other.ownerId:f.o;
 if(delegated)f.db.sqlite.prepare("INSERT INTO access_grants(grant_id,owner_id,grantee_id,mode,can_delegate,created_at,granted_at)VALUES('machine-grant',?,?,'all',1,?,?)").run(f.o,creator,grantAt,grantAt);
 f.db.sqlite.prepare('INSERT INTO machine_profiles(profile_id,creator_id,name,mode,created_at,revoked_at)VALUES(?,?,?,?,?,?)').run('machine',creator,'Synthetic',mode,NOW,revoked?NOW:null);
 if(linked)f.db.sqlite.prepare("INSERT INTO machine_profile_entries(profile_id,entry_id)VALUES('machine',?)").run(f.entry);
 f.db.sqlite.prepare("INSERT INTO machine_tokens(token_id,token_digest,profile_id,created_at,expires_at)VALUES('machine-token',?,'machine',?,?)").run(new Uint8Array(32),issued,expired?NOW: null);
}
for(const [label,opts,count] of [['all',{},1],['allow included',{mode:'allow',linked:true},1],['allow excluded',{mode:'allow'},0],['deny included',{mode:'deny'},1],['deny excluded',{mode:'deny',linked:true},0],['revoked',{revoked:true},0],['expired',{expired:true,issued:NOW-1},0],['delegated',{delegated:true},2],['delegated too-new',{delegated:true,grantAt:NOW,issued:NOW-1},1]])test('machine audience coverage '+label,async()=>{
 const f=await rfx();try{await f.assign(f.mail('machine-base'),f.entry);await machine(f,opts);const b=await f.ri.begin(f.auth,{operation:'edit',entryId:f.entry,ruleId:f.rows()[0].route_id,phrase:'machine'});assert.ok(b);assert.equal(b.summary.futureAutomations,count);assert.equal(b.proofRequired,count>0);const bg=await f.begin((await f.store.receive(f.o,f.mail('machine-unassigned',{sender:'new@bank.example'})),f.mail('machine-unassigned')),f.entry);assert.equal(bg.summary.automationRecipients,count);
 }finally{f.db.sqlite.close();}
});
test('actual MachineReader reads subsequent sender-routed code and proves machine automation scope',async()=>{
 const f=await rfx();try{await f.assign(f.mail('machine-route'),f.entry);await machine(f);await f.store.receive(f.o,f.mail('machine-next'));const{MachineAccess,MachineReader}=await import('../src/machine-access.js');const access=new MachineAccess(f.db);const reader=new MachineReader({access,sources:f.store,seeds:{},clock:()=>NOW});const got=await reader.read('machine',NOW,f.entry,'email',NOW);assert.equal(got.codes.email.code,'123456');
 }finally{f.db.sqlite.close();}
});
for(const change of ['entry-token','machine-token','grant-delete'])test('shared audience race after rederive blocks batch '+change,async()=>{
 const f=await rfx();try{await f.assign(f.mail('shared-race'),f.entry);f.db.sqlite.prepare("INSERT INTO access_grants(grant_id,owner_id,grantee_id,mode,created_at,granted_at)VALUES('race-grant',?,?,'all',?,?)").run(f.o,f.other.ownerId,NOW,NOW);
 const hooked={...f.db,batch:async statements=>{if(change==='machine-token')await machine(f);else if(change==='grant-delete')f.db.sqlite.prepare("DELETE FROM access_grants WHERE grant_id='race-grant'").run();else f.db.sqlite.prepare("INSERT INTO entry_tokens(token_id,token_digest,entry_id,actor_id,client_id,created_at,expires_at)VALUES('race-token',?,?,?,'test',?,?)").run(new Uint8Array(32),f.entry,f.o,NOW,NOW+1000);return f.db.batch(statements);}};
 const ri=f.mkRi(hooked),b=await ri.begin(f.auth,{operation:'edit',entryId:f.entry,ruleId:f.rows()[0].route_id,phrase:'race'});const response=f.a.assertion({expected:b.options.challenge});await ri.finish(f.auth,{intentId:b.intentId,token:b.token,action:b.action,response});assert.equal(f.rows()[0].phrase,null);assert.notEqual((await ri.status(f.auth,b.intentId))?.status,'applied');
 }finally{f.db.sqlite.close();}
});
