import {runGmailDevMaintenance} from '../src/gmail-dev-maintenance.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { SourceEntryStore } from '../src/source-entries.js';
import { ServiceMetadata } from '../src/service-metadata.js';
import { CodeCipher } from '../src/code-cipher.js';
import { GmailTokenCipher } from '../src/gmail-token-cipher.js';
import { GmailSourceStore } from '../src/gmail-source-store.js';
import { GmailSync } from '../src/gmail-sync.js';
import { GmailSourceOauth } from '../src/gmail-source-oauth.js';
import { createGmailPushHttp } from '../src/gmail-push-http.js';
import { createGoogleOidcVerifier } from '../src/google-oidc.js';
import { createRequestBudget, budgetedDb, budgetedFetch } from '../src/request-budget.js';
import { MESSAGE_COST } from '../src/gmail-sync.js';
import { GMAIL_POLICY } from '../src/gmail-message.js';
import { GMAIL_CODE_FILTER, GMAIL_SCOPES_LABEL_FILTER } from '../src/gmail-label-filter.js';
import { DEFERRED_CAP } from '../src/gmail-source-store.js';
const NOW=1800000000000, AUD='https://api.test/sources/gmail/push', SA='push@proj.iam.gserviceaccount.com', SUB='projects/p/subscriptions/s';
const b64u=b=>btoa(typeof b==='string'?b:String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const enc=s=>b64u(new TextEncoder().encode(s));
const rsa=await crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['sign','verify']);
const jwk=await crypto.subtle.exportKey('jwk',rsa.publicKey);
async function jwt(claims,{kid='k1',key=rsa.privateKey}={}){const h=enc(JSON.stringify({alg:'RS256',kid})),p=enc(JSON.stringify(claims));return h+'.'+p+'.'+b64u(await crypto.subtle.sign('RSASSA-PKCS1-v1_5',key,new TextEncoder().encode(h+'.'+p)));}
const goodClaims=(o={})=>({iss:'https://accounts.google.com',aud:AUD,email:SA,email_verified:true,exp:NOW/1000+300,iat:NOW/1000,...o});
// Gmail API format=raw JSON of a plain message. Nothing is signed: the sender is only what the From header says.
const rawMail=({from='Example <noreply@example.test>',to='me@gmail.test',subject='Your code',body='Your verification code is 482913\r\n',head=[]}={})=>[...(from===null?[]:['From: '+from]),'To: '+to,'Subject: '+subject,'Date: Wed, 25 Nov 2026 01:00:00 +0000','Message-ID: <a@x>','Content-Type: text/plain; charset=utf-8',...head].join('\r\n')+'\r\n\r\n'+body;
const gmailRaw=(id,raw,internalDate=NOW)=>({id,internalDate:String(internalDate),raw:b64u(raw)});
const gmailMsg=(id,o={})=>gmailRaw(id,rawMail(o));
function fakeGoogle(state){
 return async(url,init={})=>{
  url=String(url);const ok=(o,s=200)=>new Response(JSON.stringify(o),{status:s});
  state.calls.push(url.replace(/\?.*/,''));
  (state.reqs??=[]).push({m:init.method??'GET',p:url.replace(/\?.*/,'').replace('https://gmail.googleapis.com/gmail/v1/users/me',''),b:init.body});
  { const P=url.replace('https://gmail.googleapis.com/gmail/v1/users/me','').replace(/\?.*/,''),M=init.method??'GET',L=(state.labels??=new Map()),F=(state.filters??=new Map());
   if(P==='/labels'&&M==='POST'&&state.labelRaw!==undefined)return new Response(state.labelRaw,{status:200});
   if(P==='/settings/filters'&&M==='POST'&&state.filterRaw!==undefined)return new Response(state.filterRaw,{status:200});
   if(P==='/labels'&&M==='POST'){const n=JSON.parse(init.body).name;if(state.labelStatus)return ok({},state.labelStatus);if([...L.values()].includes(n))return ok({},409);const id='Label_'+(state.seq=(state.seq??10)+1);L.set(id,n);return ok({id,name:n});}
   if(P==='/settings/filters'&&M==='POST'){if(state.filterFail)return ok({},500);const id='Filter_'+(state.seq=(state.seq??10)+1);F.set(id,JSON.parse(init.body));return ok({id});}
   const dm=P.match(/^\/(labels|settings\/filters)\/([^/]+)$/);
   if(dm){if(M==='DELETE'&&state.beforeDelete)await state.beforeDelete();const T=dm[1]==='labels'?L:F;if(M==='DELETE'){if(state.deleteThrow)throw new Error('net');if(state.deleteFail)return ok({},500);return T.delete(dm[2])?new Response(null,{status:204}):ok({},404);}return T.has(dm[2])?ok({id:dm[2]}):ok({},404);}
  }
  if(url==='https://oauth2.googleapis.com/revoke'){(state.revokes??=[]).push(new URLSearchParams(init.body).get('token'));if(state.revokeThrow)throw new Error('net');return ok({},state.revokeStatus??200);}
  if(url==='https://oauth2.googleapis.com/token'){const p=new URLSearchParams(init.body);
   if(p.get('grant_type')==='authorization_code'){if(p.get('code')!=='good-code'||!p.get('code_verifier'))return ok({error:'invalid_grant'},400);return ok({access_token:'at1',refresh_token:'rt-secret',scope:state.scope??(state.labelFilter?GMAIL_SCOPES_LABEL_FILTER.join(' '):'https://www.googleapis.com/auth/gmail.readonly')});}
   if(state.revoked)return ok({error:'invalid_grant'},400);return ok({access_token:'at2'});}
  if(url.endsWith('/profile'))return ok({emailAddress:state.mailbox??'Me@Gmail.test',historyId:state.profileHistory??'900'});
  if(url.endsWith('/watch')){await state.onWatch?.();state.watchBodies=(state.watchBodies??[]).concat(init.body);if(state.watchFail)return ok({},500);}
  if(url.endsWith('/watch')&&state.watchRaw!==undefined)return new Response(state.watchRaw,{status:200});
  if(url.endsWith('/watch'))return ok({historyId:'100',expiration:String(NOW+7*86400000)});
  if(url.includes('/history')){if(state.history404)return ok({},404);if(state.historyFail)return ok({},500);
   const q=new URL(url).searchParams;state.histQueries.push(q.get('startHistoryId'));(state.histParams??=[]).push(q);
   const recs=state.hist.filter(h=>BigInt(h.id)>=BigInt(q.get('startHistoryId')));
   const off=Number(q.get('pageToken')||0),size=Number(q.get('maxResults')),pg=recs.slice(off,off+size);
   return ok({history:pg.map(h=>({id:h.id,messagesAdded:h.ids.map(id=>({message:{id}})),...(h.labeled?{labelsAdded:h.labeled.map(x=>({message:{id:x.id},labelIds:x.labelIds}))}:{})})),historyId:state.latest??'1000',...(off+size<recs.length?{nextPageToken:String(off+size)}:{})});}
  if(url.endsWith('/messages')||url.includes('/messages?')){const q=new URL(url).searchParams;if(q.get('pageToken')==='bad'){return ok({},400);}const all=state.recent??[],off=Number(q.get('pageToken')||0),size=Number(q.get('maxResults'));state.lists=(state.lists??0)+1;return ok({messages:all.slice(off,off+size).map(id=>({id})),...(off+size<all.length?{nextPageToken:String(off+size)}:{})});}
  const m=url.match(/\/messages\/([^?]+)/);if(m){if(state.fetchDown)return ok({},503);if(state.hang)return new Promise((_,rej)=>init.signal?.addEventListener('abort',()=>rej(Object.assign(new Error('aborted'),{name:'AbortError'}))));if(state.forbidden)return ok({},403);const v=state.messages[m[1]];return typeof v==='function'?v():v?ok(v):ok({},404);}
  throw new Error('unexpected '+url);
 };
}
async function setup(extra={}){
 const raw=database();for(const o of ['a','b'])await raw.prepare('INSERT INTO accounts VALUES (?,?)').bind(o,NOW).run();
 raw.sqlite.exec('CREATE TABLE test_sessions(owner_id TEXT,device_id TEXT,generation TEXT,active INTEGER)');
 for(const o of ['a','b'])for(const g of ['g1','0'])raw.sqlite.prepare('INSERT INTO test_sessions VALUES (?,?,?,1)').run(o,'dev1',g);
 const budget=createRequestBudget(extra.budget??50);const db=budgetedDb(raw,budget);db.sqlite=raw.sqlite;
 const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);
 const keys=new Map([['t',key]]);
 const sources=new SourceEntryStore(db,new CodeCipher({keys,activeKeyId:'t'}),extra.matcher?{matcher:new ServiceMetadata(db)}:undefined);
 const store=new GmailSourceStore(db,new GmailTokenCipher({keys,activeKeyId:'t'}));
 const state={calls:[],hist:[],histQueries:[],messages:{},...extra};
 const sess={steps:new Set(['ok']),revoke:()=>raw.sqlite.prepare('UPDATE test_sessions SET active=0').run(),setGen:g=>raw.sqlite.prepare('UPDATE test_sessions SET generation=?').run(g)};
 const f=budgetedFetch(fakeGoogle(state),budget);
 const sync=new GmailSync({store,sources,fetchImpl:f,clientId:'cid',clientSecret:'csecret',topicName:'projects/p/topics/t',clock:()=>NOW,budget,...(extra.labelFilter?{labelFilter:extra.labelFilter}:{})});
 const live=c=>raw.sqlite.prepare('SELECT 1 x FROM test_sessions WHERE owner_id=? AND device_id=? AND generation=? AND active=1').get(c.ownerId,c.deviceId,c.generation)!==undefined;
 const oauth=new GmailSourceOauth({store,sync,fetchImpl:f,clientId:'cid',clientSecret:'csecret',redirectUri:'https://api.test/cb',clock:()=>NOW,...(extra.labelFilter&&!extra.noDev?{devMailbox:extra.devMailbox??'me@gmail.test'}:{}),
  verifyStepUp:async c=>{state.stepCtx=c;return c.proof==='ok'&&sess.steps.has('ok')&&c.action==='gmail-source-connect'&&(sess.steps.delete('ok'),true);},
  isCurrent:async c=>live(c),
  sessionGuard:async c=>({sql:'SELECT 1 FROM test_sessions WHERE owner_id=? AND device_id=? AND generation=? AND active=1',params:[c.ownerId,c.deviceId,c.generation]})});
 const verifier=createGoogleOidcVerifier({audience:AUD,serviceAccountEmail:SA,fetchKeys:async()=>({keys:[{...jwk,kid:'k1',alg:'RS256'}]}),clock:()=>NOW});
 const push=createGmailPushHttp({verifier,sync,expectedSubscription:SUB});
 return {db,sources,store,sync,oauth,push,state,sess,budget,metadata:extra.matcher?new ServiceMetadata(db):undefined};
}
const S={deviceId:'dev1',generation:'g1'};
const sessOf=(o='a',g='g1')=>({ownerId:o,deviceId:'dev1',generation:g});
async function begin(s,owner='a',generation='g1'){s.budget.reset();s.sess.steps.add('ok');return s.oauth.start({ownerId:owner,deviceId:'dev1',generation,stepUp:'ok'});}
async function connect(s,owner='a'){const {authorizationUrl}=await begin(s,owner);const state=new URL(authorizationUrl).searchParams.get('state');s.budget.reset();return {state,res:await s.oauth.callback({code:'good-code',state,session:sessOf(owner)})};}
async function pushReq(s,{token,body,hist='105',mailbox='me@gmail.test',sub=SUB,ct='application/json'}={}){
 s.budget.reset();token??=await jwt(goodClaims());
 body??=JSON.stringify({subscription:sub,message:{messageId:'m1',data:btoa(JSON.stringify({emailAddress:mailbox,historyId:hist}))}});
 return s.push.fetch(new Request('https://api.test/sources/gmail/push',{method:'POST',headers:{authorization:'Bearer '+token,'content-type':ct},body}));
}
test('oauth: state is single use, owner-bound, scope and mailbox come from Google, token stored encrypted',async()=>{
 const s=await setup();
 const {authorizationUrl}=await begin(s,'a');const u=new URL(authorizationUrl);
 assert.equal(u.searchParams.get('scope'),'https://www.googleapis.com/auth/gmail.readonly');assert.equal(u.searchParams.get('code_challenge_method'),'S256');
 const state=u.searchParams.get('state');
 const r=await s.oauth.callback({code:'good-code',state,session:sessOf()});assert.equal(r.ok,true);assert.equal(r.mailbox,'me@gmail.test');
 assert.equal((await s.oauth.callback({code:'good-code',state,session:sessOf()})).reason,'invalid_state');
 const row=s.db.sqlite.prepare('SELECT * FROM gmail_connections').get();assert.equal(row.owner_id,'a');assert.ok(!row.refresh_envelope.includes('rt-secret'));
 assert.equal(s.db.sqlite.prepare("SELECT count(*) n FROM sources WHERE kind='gmail' AND owner_id='a'").get().n,1);
 assert.equal((await s.oauth.callback({code:'good-code',state:'0'.repeat(64),session:sessOf()})).reason,'invalid_state');
 const t=await begin(s,'a');assert.equal((await s.oauth.callback({code:'bad',state:new URL(t.authorizationUrl).searchParams.get('state'),session:sessOf()})).reason,'exchange_failed');
 s.db.sqlite.close();
});
test('oauth: missing scope, denied, and a mailbox owned by another account are refused',async()=>{
 const s=await setup({scope:'openid'});
 assert.equal((await connect(s)).res.reason,'scope_missing');
 const d=await begin(s,'a');assert.equal((await s.oauth.callback({error:'access_denied',state:new URL(d.authorizationUrl).searchParams.get('state'),session:sessOf()})).reason,'denied');
 s.state.scope=undefined;assert.equal((await connect(s,'a')).res.ok,true);
 assert.equal((await connect(s,'b')).res.reason,'mailbox_in_use');
 assert.equal((await connect(s,'a')).res.ok,true);
 assert.equal(s.db.sqlite.prepare('SELECT count(*) n FROM gmail_connections').get().n,1);
 s.db.sqlite.close();
});
test('refresh envelope cannot be moved to another owner or source',async()=>{
 const s=await setup();await connect(s);const row=s.db.sqlite.prepare('SELECT * FROM gmail_connections').get();
 assert.equal(await s.store.refreshToken(row),'rt-secret');
 await assert.rejects(s.store.refreshToken({...row,owner_id:'b'}));await assert.rejects(s.store.refreshToken({...row,source_id:'x'}));
 s.db.sqlite.close();
});
test('end to end: authenticated push stores code for the connected owner, replay and stale are safe',async()=>{
 const s=await setup();await connect(s);
 const entry=await s.sources.createEntry('a','example','Example',NOW);
 const src=(await s.sources.sourcesForOwner('a'))[0].source_id;
 await s.sources.addRule('a',{sourceId:src,entryId:entry,sender:'noreply@example.test',accountHint:'me@gmail.test'},NOW);
 s.state.hist=[{id:'101',ids:['g1']}];s.state.latest='105';s.state.messages.g1=gmailMsg('g1');
 assert.equal((await pushReq(s)).status,204);
 assert.equal((await s.sources.latestOwned('a',entry,NOW+1)).code,'482913');
 assert.equal(s.db.sqlite.prepare('SELECT history_id h FROM gmail_connections').get().h,'105');
 const before=s.state.calls.length;assert.equal((await pushReq(s)).status,204);assert.equal(s.state.calls.length,before);
 s.state.latest='106';s.state.hist.push({id:'106',ids:[]});assert.equal((await pushReq(s,{hist:'106'})).status,204);
 assert.equal(s.db.sqlite.prepare('SELECT count(*) n FROM incoming_codes').get().n,1);
 assert.equal(s.db.sqlite.prepare("SELECT count(*) n FROM incoming_codes WHERE owner_id='b'").get().n,0);
 s.db.sqlite.close();
});
test('push authentication fails closed before the body is read or any Google call',async()=>{
 const s=await setup();await connect(s);const n=s.state.calls.length;
 const other=await crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['sign','verify']);
 for(const token of [await jwt(goodClaims({aud:'https://evil.test'})),await jwt(goodClaims({email:'other@proj.iam.gserviceaccount.com'})),await jwt(goodClaims({email_verified:false})),await jwt(goodClaims({exp:NOW/1000-3600})),await jwt(goodClaims({iss:'https://evil.test'})),await jwt(goodClaims(),{key:other.privateKey}),await jwt(goodClaims(),{kid:'unknown'}),'garbage','a.b.c']){
  assert.equal((await pushReq(s,{token,body:'not json at all'})).status,401);
 }
 const noAuth=await s.push.fetch(new Request('https://api.test/sources/gmail/push',{method:'POST',body:'{}'}));assert.equal(noAuth.status,401);
 assert.equal(s.state.calls.length,n);
 assert.equal((await pushReq(s,{sub:'projects/p/subscriptions/other'})).status,400);
 assert.equal((await pushReq(s,{body:'{"x":'})).status,400);
 assert.equal((await pushReq(s,{ct:'text/plain'})).status,400);
 assert.equal((await s.push.fetch(new Request('https://api.test/sources/gmail/push',{method:'GET'}))).status,405);
 s.db.sqlite.close();
});
test('unknown mailbox is acknowledged without work; mail without a code or a From is skipped, not stored',async()=>{
 const s=await setup();await connect(s);const n=s.state.calls.length;
 assert.equal((await pushReq(s,{mailbox:'stranger@gmail.test'})).status,204);assert.equal(s.state.calls.length,n);
 s.state.hist=[{id:'101',ids:['g2','g3']}];s.state.latest='105';
 s.state.messages.g2=gmailMsg('g2',{body:'hello world'});
 s.state.messages.g3=gmailMsg('g3',{from:null});
 assert.equal((await pushReq(s)).status,204);
 assert.equal(s.db.sqlite.prepare('SELECT count(*) n FROM incoming_codes').get().n,0);assert.equal(s.sync.counts.from_invalid,1);assert.deepEqual(handled(s),['g2','g3']);
 s.db.sqlite.close();
});
test('failure mid-sync keeps the cursor at the last handled record; retry completes with no duplicate',async()=>{
 const s=await setup();await connect(s);
 s.state.hist=[{id:'101',ids:['g1']},{id:'102',ids:['g5']}];s.state.latest='105';s.state.messages.g1=gmailMsg('g1');s.state.messages.g5=gmailMsg('g5');
 const orig=s.sync.get.bind(s.sync);let boom=true;
 s.sync.get=async(p,t)=>{if(p.startsWith('/messages/g5')&&boom)return new Response('{}',{status:403});return orig(p,t);};
 assert.equal((await pushReq(s)).status,503);
 assert.equal(cursor(s),'101');
 boom=false;assert.equal((await pushReq(s)).status,204);
 assert.equal(cursor(s),'105');assert.equal(count(s),2);
 s.db.sqlite.close();
});
const cursor=s=>s.db.sqlite.prepare('SELECT history_id h FROM gmail_connections').get().h;
const count=s=>s.db.sqlite.prepare('SELECT count(*) n FROM incoming_codes').get().n;
function many(s,n,start=101,per=1){const ids=[];s.state.hist=[];for(let i=0;i<n;i++){const row=[];for(let k=0;k<per;k++){const id='m'+i+'x'+k;row.push(id);ids.push(id);s.state.messages[id]=gmailMsg(id,{body:'Your verification code is '+String(100000+ids.length)});}s.state.hist.push({id:String(start+i),ids:row});}return ids;}
test('>50 messages over many pages: nothing skipped; budget stop is resumable and cursor only moves over handled records',async()=>{
 const s=await setup({budget:30});await connect(s);many(s,60);s.state.latest='5000';
 let n=0,last='100';
 for(;n<40;n++){const r=await pushReq(s,{hist:'5000'});const c=cursor(s);assert.ok(BigInt(c)>=BigInt(last));last=c;if(r.status===204)break;assert.equal(r.status,503);}
 assert.equal(cursor(s),'5000');assert.equal(count(s),60);assert.ok(n>3&&n<40);
 s.db.sqlite.close();
});
test('budget is per call: no call exceeds it',async()=>{
 const s=await setup({budget:30});await connect(s);many(s,30);s.state.latest='5000';
 await pushReq(s,{hist:'5000'});
 assert.ok(s.budget.used<=30);assert.ok(count(s)<30&&count(s)>=1);
 s.db.sqlite.close();
});
test('duplicate message ids across records, repeated and out-of-order pushes produce one entry each',async()=>{
 const s=await setup();await connect(s);
 s.state.hist=[{id:'101',ids:['g1']},{id:'102',ids:['g1','g5']}];s.state.latest='110';s.state.messages.g1=gmailMsg('g1');s.state.messages.g5=gmailMsg('g5');
 assert.equal((await pushReq(s,{hist:'110'})).status,204);
 assert.equal((await pushReq(s,{hist:'105'})).status,204);assert.equal((await pushReq(s,{hist:'110'})).status,204);
 assert.equal(count(s),2);assert.equal(cursor(s),'110');
 s.db.sqlite.close();
});
test('concurrent pushes cannot move the cursor backwards or duplicate',async()=>{
 const s=await setup({budget:100000});await connect(s);many(s,5);s.state.latest='300';
 const rs=await Promise.all([pushReq(s,{hist:'300'}),pushReq(s,{hist:'300'}),pushReq(s,{hist:'250'})]);
 for(const r of rs)assert.equal(r.status,204);
 assert.equal(count(s),5);assert.equal(cursor(s),'300');
 assert.equal(await s.store.advance({source_id:s.db.sqlite.prepare('SELECT source_id i FROM gmail_connections').get().i},'7',NOW),false);assert.equal(cursor(s),'300');
 s.db.sqlite.close();
});
test('history 404 recovers recent inbox mail (bounded) and restarts from the pre-list mailbox history id',async()=>{
 const s=await setup();await connect(s);
 s.state.history404=true;s.state.profileHistory='900';s.state.recent=['r1','r2'];s.state.messages.r1=gmailMsg('r1');s.state.messages.r2=gmailMsg('r2');
 assert.equal((await pushReq(s,{hist:'950'})).status,204);
 assert.equal(count(s),2);assert.equal(cursor(s),'900');
 s.state.history404=false;s.state.hist=[{id:'920',ids:['r9']}];s.state.messages.r9=gmailMsg('r9');s.state.latest='950';
 assert.equal((await pushReq(s,{hist:'950'})).status,204);assert.equal(count(s),3);assert.equal(cursor(s),'950');
 s.db.sqlite.close();
});
test('recovery failure leaves the cursor untouched so the push is retried',async()=>{
 const s=await setup();await connect(s);s.state.history404=true;s.state.recent=['r1'];
 const orig=s.sync.get.bind(s.sync);s.sync.get=async(p,t)=>p.startsWith('/messages/r1')?new Response('{}',{status:403}):orig(p,t);
 assert.equal((await pushReq(s,{hist:'950'})).status,503);assert.equal(cursor(s),'100');assert.equal(count(s),0);
 s.db.sqlite.close();
});
test('history API failure on a later page keeps handled progress and returns 503',async()=>{
 const s=await setup();await connect(s);s.state.historyFail=true;s.state.hist=[];
 assert.equal((await pushReq(s,{hist:'150'})).status,503);assert.equal(cursor(s),'100');
 s.db.sqlite.close();
});
test('revoked grant needs reauth and later pushes do no Google work',async()=>{
 const s=await setup();await connect(s);s.state.revoked=true;
 assert.equal((await pushReq(s,{hist:'300'})).status,204);
 assert.equal(s.db.sqlite.prepare('SELECT status s FROM gmail_connections').get().s,'reauth_required');
 const n=s.state.calls.length;assert.equal((await pushReq(s,{hist:'400'})).status,204);assert.equal(s.state.calls.length,n);
 s.db.sqlite.close();
});
test('connect binding: step-up required and single use; state bound to device and generation; revocation rechecked before storing',async()=>{
 const s=await setup();
 assert.equal((await s.oauth.start({ownerId:'a',...S,stepUp:'nope'})).reason,'step_up_required');
 assert.equal((await s.oauth.start({ownerId:'a',deviceId:'dev1',stepUp:'ok'})).reason,'session_required');
 s.sess.steps.add('ok');assert.equal((await s.oauth.start({ownerId:'a',...S,stepUp:'ok'})).ok,true);assert.equal(s.state.stepCtx.action,'gmail-source-connect');
 assert.equal((await s.oauth.start({ownerId:'a',...S,stepUp:'ok'})).reason,'step_up_required');
 const st=u=>new URL(u.authorizationUrl).searchParams.get('state');
 let u=await begin(s);assert.equal((await s.oauth.callback({code:'good-code',state:st(u),session:{ownerId:'a',deviceId:'dev2',generation:'g1'}})).reason,'session_mismatch');
 assert.equal((await s.oauth.callback({code:'good-code',state:st(u),session:sessOf()})).reason,'invalid_state');
 u=await begin(s);assert.equal((await s.oauth.callback({code:'good-code',state:st(u),session:{ownerId:'a',deviceId:'dev1',generation:'g2'}})).reason,'session_mismatch');
 u=await begin(s);assert.equal((await s.oauth.callback({code:'good-code',state:st(u)})).reason,'session_mismatch');
 u=await begin(s);s.sess.revoke();s.budget.reset();assert.equal((await s.oauth.callback({code:'good-code',state:st(u),session:sessOf()})).reason,'session_revoked');
 assert.equal(s.db.sqlite.prepare('SELECT count(*) n FROM gmail_connections').get().n,0);
 u=await begin(s);s.sess.setGen('g9');s.budget.reset();assert.equal((await s.oauth.callback({code:'good-code',state:st(u),session:sessOf()})).reason,'session_revoked');
 assert.equal(s.db.sqlite.prepare('SELECT count(*) n FROM gmail_connections').get().n,0);
 s.db.sqlite.close();
});
test('push body is read with a streaming bound',async()=>{
 const s=await setup();await connect(s);const n=s.state.calls.length;let pulled=0;
 const body=new ReadableStream({pull(c){pulled+=8192;c.enqueue(new Uint8Array(8192));if(pulled>1e7)c.close();}});
 const r=await s.push.fetch(new Request('https://api.test/sources/gmail/push',{method:'POST',headers:{authorization:'Bearer '+await jwt(goodClaims()),'content-type':'application/json'},body,duplex:'half'}));
 assert.equal(r.status,413);assert.ok(pulled<=16384+3*8192);
 const r2=await s.push.fetch(new Request('https://api.test/sources/gmail/push',{method:'POST',headers:{authorization:'Bearer '+await jwt(goodClaims()),'content-type':'application/json','content-length':'999999'},body:'{}'}));
 assert.equal(r2.status,413);assert.equal(s.state.calls.length,n);
 s.db.sqlite.close();
});
test('oidc: adversarial time claims, key TTL and refresh cooldown',async()=>{
 let t=NOW,fetches=0;const mk=()=>createGoogleOidcVerifier({audience:AUD,serviceAccountEmail:SA,clock:()=>t,fetchKeys:async()=>{fetches++;return {keys:[{...jwk,kid:'k1',alg:'RS256'}]};}});
 const v=mk(),sec=NOW/1000;
 assert.ok(await v(await jwt(goodClaims())));
 for(const c of [{exp:undefined},{iat:undefined},{exp:String(sec+300)},{exp:null},{exp:NaN},{exp:sec+300,iat:'x'},{iat:sec+3600},{iat:sec+3600,exp:sec+3700},{exp:sec-61},{exp:sec+999999,iat:sec},{exp:sec+100,iat:sec+200},{nbf:sec+3600},{nbf:'0'},{exp:sec-3600,iat:sec-7200}]) assert.equal(await v(await jwt(goodClaims(c))),undefined,JSON.stringify(c));
 assert.equal(fetches,1);
 // forged kid: at most one early refresh per cooldown
 for(let i=0;i<5;i++)assert.equal(await v(await jwt(goodClaims(),{kid:'zz'+i})),undefined);
 t+=61000;assert.equal(await v(await jwt(goodClaims({exp:sec+400,iat:sec+61}),{kid:'zz9'})),undefined);
 const f=fetches;assert.ok(f<=3);
 // TTL: keys older than the TTL are refetched even for a known kid
 t+=3600*1000;const before=fetches;assert.ok(await v(await jwt(goodClaims({exp:t/1000+300,iat:t/1000}))));assert.equal(fetches,before+1);
});
test('watch renewal only touches connections near expiry',async()=>{
 const s=await setup();await connect(s);assert.equal(await s.sync.renewWatches(),0);
 s.db.sqlite.prepare('UPDATE gmail_connections SET watch_expires_at=?').run(NOW+1000);
 assert.equal(await s.sync.renewWatches(),1);
 assert.ok(s.db.sqlite.prepare('SELECT watch_expires_at w FROM gmail_connections').get().w>NOW+86400000);
 s.db.sqlite.close();
});
test('revocation racing the final write is caught atomically by the guarded commit (no preflight can see it)',async()=>{
 const s=await setup();s.state.onWatch=()=>s.sess.revoke(); // after both preflights, before the write
 const orig=s.oauth.isCurrent;let preflights=0;s.oauth.isCurrent=async c=>{preflights++;return orig(c);};
 const u=await begin(s);s.budget.reset();const r=await s.oauth.callback({code:'good-code',state:new URL(u.authorizationUrl).searchParams.get('state'),session:sessOf()});
 assert.equal(r.reason,'session_revoked');assert.equal(preflights,1);
 for(const t of ['gmail_connections','sources'])assert.equal(s.db.sqlite.prepare(`SELECT count(*) n FROM ${t}`).get().n,0);
 s.db.sqlite.close();
});
test('generation 0 (integer) can start and finish a connection; wrong or non-integer generations cannot',async()=>{
 const s=await setup();s.sess.steps.add('ok');
 const u=await s.oauth.start({ownerId:'a',deviceId:'dev1',generation:0,stepUp:'ok'});assert.equal(u.ok,true);assert.equal(s.state.stepCtx.generation,'0');
 s.budget.reset();const r=await s.oauth.callback({code:'good-code',state:new URL(u.authorizationUrl).searchParams.get('state'),session:{ownerId:'a',deviceId:'dev1',generation:0}});assert.equal(r.ok,true);
 for(const g of [-1,1.5,NaN,undefined,null,'']){s.sess.steps.add('ok');assert.equal((await s.oauth.start({ownerId:'a',deviceId:'dev1',generation:g,stepUp:'ok'})).reason,'session_required');}
 s.db.sqlite.close();
});
test('callback session must match the owner too (cookie of another account cannot finish the flow)',async()=>{
 const s=await setup();const u=await begin(s,'a');s.budget.reset();
 assert.equal((await s.oauth.callback({code:'good-code',state:new URL(u.authorizationUrl).searchParams.get('state'),session:sessOf('b')})).reason,'session_mismatch');
 s.db.sqlite.close();
});
test('connect requires a guard and never writes without it',async()=>{
 const s=await setup();await assert.rejects(s.store.connect('a',{mailbox:'x@y.test',refreshToken:'t',historyId:'5',watchExpiresAt:NOW+1}, NOW));
 await assert.rejects(s.store.connect('a',{mailbox:'x@y.test',refreshToken:'t',historyId:'5',watchExpiresAt:NOW+1,guard:{sql:'DELETE FROM accounts',params:[]}}, NOW));
 s.db.sqlite.close();
});
test('worst-case work to handle one message fits MESSAGE_COST (fetch + every D1 query, including rule match)',async()=>{
 const s=await setup();await connect(s);
 const entry=await s.sources.createEntry('a','example','Example',NOW);const src=(await s.sources.sourcesForOwner('a'))[0].source_id;
 await s.sources.addRule('a',{sourceId:src,entryId:entry,sender:'noreply@example.test',accountHint:'me@gmail.test'},NOW);
 s.state.messages.w1=gmailMsg('w1');const conn=await s.store.byMailbox('me@gmail.test');
 s.budget.reset();await s.sync.handleAll(conn,['w1'],'tok');const used=s.budget.used;
 assert.equal(count(s),1);assert.ok(used<=MESSAGE_COST,'used '+used+' > '+MESSAGE_COST);
 console.log('# measured requests for one matching message:',used,'of reserve',MESSAGE_COST);
 s.db.sqlite.close();
});
test('one history record with more messages than a single call can handle still makes durable progress and finishes',async()=>{
 const s=await setup({budget:40});await connect(s);const ids=[];s.state.hist=[{id:'101',ids}];
 for(let i=0;i<30;i++){ids.push('b'+i);s.state.messages['b'+i]=gmailMsg('b'+i,{body:'Your verification code is '+(200000+i)});}
 s.state.latest='101';let calls=0,last=0;
 for(;calls<30;calls++){const r=await pushReq(s,{hist:'200'});const c=count(s);assert.ok(c>last||r.status===204,'no progress at call '+calls);last=c;if(r.status===204)break;assert.equal(r.status,503);}
 assert.equal(count(s),30);assert.ok(calls>=1&&calls<30);assert.equal(cursor(s),'101');
 assert.equal(s.db.sqlite.prepare('SELECT count(*) n FROM gmail_handled').get().n,30);
 // already-handled messages are not refetched on later windows
 const fetched=s.state.calls.filter(c=>c.includes('/messages/')).length;assert.equal(fetched,30);
 s.db.sqlite.close();
});
test('404 recovery pages through the whole day window across calls, then resumes normal history from the earlier mailbox id',async()=>{
 const s=await setup({budget:40});await connect(s);
 s.state.history404=true;s.state.profileHistory='900';s.state.recent=[];
 for(let i=0;i<80;i++){s.state.recent.push('r'+i);s.state.messages['r'+i]=gmailMsg('r'+i,{body:'Your verification code is '+(300000+i)});}
 let calls=0;for(;calls<30;calls++){const r=await pushReq(s,{hist:'950'});if(r.status===204)break;assert.equal(r.status,503);const row=s.db.sqlite.prepare('SELECT recovery_hid h FROM gmail_connections').get();assert.equal(row.h,'900');}
 assert.equal(count(s),80);assert.ok(calls>=1);assert.equal(cursor(s),'900');assert.equal(s.db.sqlite.prepare('SELECT recovery_hid h FROM gmail_connections').get().h,null);
 assert.equal(s.db.sqlite.prepare('SELECT recovery_hid h FROM gmail_connections').get().h,null);
 s.db.sqlite.close();
});
test('404 recovery has no message cap: a 300-message day completes across calls with nothing dropped',async()=>{
 const s=await setup({budget:50});await connect(s);
 s.state.history404=true;s.state.profileHistory='900';s.state.recent=[];
 for(let i=0;i<300;i++){s.state.recent.push('r'+i);s.state.messages['r'+i]=gmailMsg('r'+i,{body:'Your verification code is '+(300000+i)});}
 let k=0;for(;k<200;k++){const r=await pushReq(s,{hist:'950'});if(r.status===204)break;assert.equal(r.status,503);}
 const row=s.db.sqlite.prepare('SELECT history_id h,recovery_hid r FROM gmail_connections').get();
 assert.equal(row.h,'900');assert.equal(row.r,null);assert.equal(count(s),300);assert.ok(k>3&&k<200);
 s.db.sqlite.close();
});
test('stale recovery page token restarts the idempotent listing instead of failing forever',async()=>{
 const s=await setup({budget:40});await connect(s);s.state.history404=true;s.state.recent=['r1'];s.state.messages.r1=gmailMsg('r1');
 s.db.sqlite.prepare("UPDATE gmail_connections SET recovery_hid='900',recovery_page='bad',recovery_count=5").run();
 assert.equal((await pushReq(s,{hist:'950'})).status,204);assert.equal(count(s),1);assert.equal(cursor(s),'900');
 s.db.sqlite.close();
});
test('all work is counted: JWKS fetch, D1 and Google share one budget and an exhausted budget returns 503 without data loss',async()=>{
 const s=await setup({budget:6});await connect(s);s.state.hist=[{id:'101',ids:['g1']}];s.state.latest='105';s.state.messages.g1=gmailMsg('g1');
 assert.equal((await pushReq(s)).status,503);assert.equal(count(s),0);assert.equal(cursor(s),'100');
 s.budget.limit;s.db.sqlite.close();
});
test('request budget hard-stops fetch, D1 queries and batches (a batch counts once)',async()=>{
 const raw=database();const b=createRequestBudget(3);const db=budgetedDb(raw,b);const f=budgetedFetch(async()=>new Response('x'),b);
 await db.prepare('SELECT 1 x').bind().first();await f('https://x.test');
 await db.batch([db.prepare('SELECT 1 x').bind(),db.prepare('SELECT 2 x').bind()]);
 assert.equal(b.used,3);
 await assert.rejects(async()=>db.prepare('SELECT 1').bind().first(),/budget/);await assert.rejects(async()=>f('https://x.test'),/budget/);await assert.rejects(async()=>db.batch([]),/budget/);
 raw.sqlite.close();
});

test('composition with the real ServiceMetadata matcher: a mixed-case mailbox still routes to the entry',async()=>{
 const s=await setup({matcher:true,mailbox:'Me@Gmail.test'});await connect(s);
 const row=s.db.sqlite.prepare("SELECT source_id,receiver FROM sources WHERE kind='gmail'").get();
 assert.equal(row.receiver,'me@gmail.test');
 const entry=await s.sources.createEntry('a','example.test','Acct',NOW);
 await s.metadata.addRoute('a',{serviceId:'example.test',sourceId:row.source_id,originKind:'email_address',originValue:'noreply@example.test',entryId:entry});
 s.state.hist=[{id:'101',ids:['g1']}];s.state.latest='105';s.state.messages.g1=gmailMsg('g1');
 assert.equal((await pushReq(s)).status,204);
 const c=s.db.sqlite.prepare('SELECT entry_id,assignment FROM incoming_codes').get();
 assert.equal(c.entry_id,entry);assert.equal(c.assignment,'rule');
 // reconnecting an existing source keeps the canonical receiver
 s.db.sqlite.prepare("UPDATE sources SET receiver=NULL").run();
 await connect(s);assert.equal(s.db.sqlite.prepare("SELECT receiver FROM sources WHERE kind='gmail'").get().receiver,'me@gmail.test');
 s.db.sqlite.close();
});
test('revoking the source by any path disconnects the connection atomically and sync acknowledges without a token refresh',async()=>{
 const s=await setup();await connect(s);
 const id=s.db.sqlite.prepare("SELECT source_id FROM sources WHERE kind='gmail'").get().source_id;
 await s.sources.revokeSource('a',id,NOW); // the generic path, not a Gmail-specific one
 const c=s.db.sqlite.prepare('SELECT status,refresh_envelope e FROM gmail_connections').get();
 assert.equal(c.status,'disconnected');assert.equal(c.e,'');
 s.state.calls.length=0;s.state.hist=[{id:'101',ids:['g1']}];
 assert.equal((await pushReq(s)).status,204);
 assert.deepEqual(s.state.calls,[]); // no token refresh, no Google call at all
 assert.equal((await s.sync.renewWatches()),0);
 // belt and braces: a connection still marked active under a revoked source is ignored too
 s.db.sqlite.prepare("UPDATE gmail_connections SET status='active'").run();
 s.state.calls.length=0;assert.equal((await pushReq(s)).status,204);assert.deepEqual(s.state.calls,[]);
 s.db.sqlite.close();
});
test('disconnect: local state is the authority, nothing is revoked at Google, idempotent, owner-scoped',async()=>{
 const s=await setup();await connect(s);
 const id=s.db.sqlite.prepare("SELECT source_id FROM sources WHERE kind='gmail'").get().source_id;
 s.state.calls.length=0;s.budget.reset();
 assert.deepEqual(await s.sync.disconnect('b',id),{disconnected:false}); // not b's source
 assert.equal(s.db.sqlite.prepare('SELECT status FROM gmail_connections').get().status,'active');
 const r=await s.sync.disconnect('a',id);assert.deepEqual(r,{disconnected:true,remoteRevoked:false,googlePermissionRemains:true});
 assert.equal(s.state.calls.length,0); // no Google contact at all, not even a grant revoke
 const c=s.db.sqlite.prepare('SELECT status,refresh_envelope e FROM gmail_connections').get();assert.equal(c.status,'disconnected');assert.equal(c.e,'');
 assert.ok(s.db.sqlite.prepare("SELECT revoked_at r FROM sources WHERE source_id=?").get(id).r);
 assert.equal((await s.sync.disconnect('a',id)).disconnected,true);assert.equal(s.state.calls.length,0);
 s.db.sqlite.close();
});
test('watch renewal: one failing mailbox does not block others, and work stops at the budget',async()=>{
 const s=await setup();await connect(s);
 // second mailbox for owner b
 s.state.mailbox='Other@Gmail.test';await connect(s,'b');
 s.db.sqlite.prepare('UPDATE gmail_connections SET watch_expires_at=?').run(NOW+1000);
 s.db.sqlite.prepare("UPDATE gmail_connections SET watch_expires_at=? WHERE owner_id='a'").run(NOW+500); // a is first in line
 s.state.onWatch=null;const orig=s.sync.startWatch.bind(s.sync);let n=0;
 s.sync.startWatch=async t=>{n++;if(n===1)throw new Error('boom');return orig(t);};
 s.budget.reset();assert.equal(await s.sync.renewWatches(),1);assert.deepEqual(s.sync.lastRenewal,{renewed:1,failed:1,partial:false});
 // budget: with room for one renewal only, the rest is reported partial, not attempted
 s.db.sqlite.prepare('UPDATE gmail_connections SET watch_expires_at=?').run(NOW+1000);s.sync.startWatch=orig;
 s.budget.reset();s.budget.spend(s.budget.limit-5);
 assert.equal(await s.sync.renewWatches(),1);assert.equal(s.sync.lastRenewal.partial,true);
 s.db.sqlite.close();
});
test('expired OAuth states are pruned in bounded batches',async()=>{
 const s=await setup();
 for(let i=0;i<3;i++)await s.store.createState('a',{deviceId:'dev1',generation:'g1'},NOW-3600000);
 await s.store.createState('a',{deviceId:'dev1',generation:'g1'},NOW);
 assert.equal(await s.store.pruneStates(NOW,2),2);assert.equal(await s.store.pruneStates(NOW,100),1);
 assert.equal(s.db.sqlite.prepare('SELECT count(*) n FROM gmail_oauth_states').get().n,1);
 s.db.sqlite.close();
});
test('redirects are never followed: budgeted fetch forces redirect:error and a redirecting endpoint fails before an unbudgeted hop',async()=>{
 const budget=createRequestBudget(50);const seen=[];
 const f=budgetedFetch(async(u,i)=>{seen.push(i.redirect);if(i.redirect!=='error')throw new Error('would follow');throw new TypeError('redirect blocked');},budget);
 await assert.rejects(f('https://x.test/',{redirect:'follow'}),/redirect blocked/); // a caller cannot opt back in
 await assert.rejects(f('https://x.test/'),/redirect blocked/);
 assert.deepEqual(seen,['error','error']);assert.equal(budget.used,2);
 // Google calls made by sync/oauth also pass redirect:error even without the wrapper
 const s=await setup();const calls=[];
 const sync=new GmailSync({store:s.store,sources:s.sources,fetchImpl:async(u,i)=>{calls.push(i.redirect);return new Response('{}',{status:500});},clientId:'c',clientSecret:'s',topicName:'t',budget:createRequestBudget(50)});
 await sync.get('/profile','tok');await sync.f('https://oauth2.googleapis.com/token',{method:'POST'});
 assert.deepEqual(calls,['error','error']);
 s.db.sqlite.close();
});
test('raw path: sender is only a match key (provider headers are ignored); malformed responses are counted and skipped; cost stays inside MESSAGE_COST',async()=>{
 const s=await setup();await connect(s);const {entry}=await ruled(s);
 s.state.messages.f1=gmailMsg('f1',{from:null});
 s.state.messages.f2={...gmailMsg('f2'),id:'other'};
 s.state.messages.f3=gmailMsg('f3',{head:['Authentication-Results: mx.google.com; dkim=pass; dmarc=pass header.from=evil.test','X-Note: ignored']});
 const conn=await s.store.byMailbox('me@gmail.test');
 s.budget.reset();await s.sync.handleAll(conn,['f1','f2'],'tok');
 assert.equal(count(s),0);assert.deepEqual([s.sync.counts.from_invalid,s.sync.counts.bad_response],[1,1]);
 s.budget.reset();await s.sync.handleAll(conn,['f3'],'tok');
 assert.equal(count(s),1);assert.ok(s.budget.used<=MESSAGE_COST,'used '+s.budget.used);
 // the assignment is by sender as written (not verified): an entry rule on that sender matches
 assert.equal(s.db.sqlite.prepare('SELECT entry_id e FROM incoming_codes').get().e,entry);
 s.db.sqlite.close();
});
test('oversize raw is dropped (permanent) and marked handled, cursor moves',async()=>{
 const o=await setup();await connect(o);
 o.state.hist=[{id:'101',ids:['big']}];o.state.latest='105';
 o.state.messages.big={id:'big',internalDate:String(NOW),raw:'A'.repeat(1_000_000)};
 assert.equal((await pushReq(o)).status,204);assert.equal(o.sync.counts.too_large,1);assert.equal(count(o),0);assert.equal(cursor(o),'105');
 assert.equal(deferred(o).length,0);o.db.sqlite.close();
});
test('the raw response is read with a hard cap: an endless body stops early and the message is dropped',async()=>{
 const s=await setup();await connect(s);
 s.state.hist=[{id:'101',ids:['inf']}];s.state.latest='105';
 let pulled=0;s.state.messages.inf=()=>new Response(new ReadableStream({pull(c){pulled+=1;c.enqueue(new Uint8Array(65536).fill(65));}}),{status:200});
 assert.equal((await pushReq(s)).status,204);
 assert.ok(pulled<=Math.ceil(GMAIL_POLICY.maxBytes*4/3/65536)+4,'pulled '+pulled);
 assert.equal(s.sync.counts.too_large,1);assert.equal(count(s),0);
 s.db.sqlite.close();
});
const deferred=s=>s.db.sqlite.prepare('SELECT * FROM gmail_deferred ORDER BY message_id').all();
const handled=s=>s.db.sqlite.prepare('SELECT message_id FROM gmail_handled ORDER BY message_id').all().map(r=>r.message_id);
async function ruled(s){const entry=await s.sources.createEntry('a','example','Example',NOW);const src=(await s.sources.sourcesForOwner('a'))[0].source_id;await s.sources.addRule('a',{sourceId:src,entryId:entry,sender:'noreply@example.test',accountHint:'me@gmail.test'},NOW);return {entry,src};}
test('deferred queue: fetch outage queues (no drop, no ingest), cursor advances, backoff skips refetch, due retry ingests and clears the row',async()=>{
 const s=await setup();await connect(s);await ruled(s);
 s.state.fetchDown=true;s.state.hist=[{id:'101',ids:['t1']}];s.state.latest='105';s.state.messages.t1=gmailMsg('t1');
 const fetches=()=>s.state.calls.filter(c=>c.endsWith('/messages/t1')).length;
 assert.equal((await pushReq(s)).status,204);
 assert.equal(cursor(s),'105');assert.equal(count(s),0);assert.deepEqual(handled(s),[]);
 const row=deferred(s)[0];assert.deepEqual([row.message_id,row.attempts,row.last_reason,row.first_seen_at,row.next_attempt_at],['t1',1,'fetch_error',NOW,NOW+60000]);
 assert.deepEqual(Object.keys(row).sort(),['attempts','first_seen_at','last_reason','message_id','next_attempt_at','source_id']); // ids and timestamps only
 assert.equal(fetches(),1);
 // not due: a later push that revisits it does not refetch; the drain after forward sync finds nothing due
 s.state.fetchDown=false;s.state.hist=[{id:'101',ids:['t1']},{id:'106',ids:['t2']}];s.state.latest='110';s.state.messages.t2=gmailMsg('t2');
 s.sync.clock=()=>NOW+30000;assert.equal((await pushReq(s,{hist:'110'})).status,204);
 assert.equal(fetches(),1);assert.equal(count(s),1);assert.equal(deferred(s).length,1);
 // due: the next push drains it
 s.sync.clock=()=>NOW+61000;s.state.latest='120';assert.equal((await pushReq(s,{hist:'120'})).status,204);
 assert.equal(fetches(),2);assert.equal(count(s),2);assert.equal(deferred(s).length,0);assert.deepEqual(handled(s),['t1','t2']);
 s.db.sqlite.close();
});
test('deferred queue: still failing doubles the delay up to one hour; attempts count; a row is updated even when the queue is full',async()=>{
 const s=await setup();await connect(s);const id=(await s.store.byMailbox('me@gmail.test')).source_id;
 const want=[1,2,4,8,16,32,60,60];let t=NOW;
 for(let i=0;i<want.length;i++){assert.equal(await s.store.deferFetch(id,'x','fetch_timeout',t),'queued');const r=deferred(s)[0];assert.equal(r.attempts,i+1);assert.equal(r.next_attempt_at-t,want[i]*60000,'attempt '+(i+1));assert.equal(r.first_seen_at,NOW);t=r.next_attempt_at;}
 assert.equal(await s.store.deferFetch(id,'x','fetch_error',t),'queued');assert.equal(deferred(s)[0].last_reason,'fetch_error');
 await assert.rejects(s.store.deferFetch(id,'y','bogus',t),TypeError);
 s.db.sqlite.close();
});
test('deferred queue cap: a full queue holds the cursor (503) and evicts nothing; existing rows still update; resolving frees it',async()=>{
 const s=await setup();await connect(s);await ruled(s);const id=(await s.store.byMailbox('me@gmail.test')).source_id;
 const ins=s.db.sqlite.prepare("INSERT INTO gmail_deferred VALUES (?,?,?,?,1,'fetch_timeout')");
 for(let i=0;i<DEFERRED_CAP;i++)ins.run(id,'f'+i,NOW-1000,NOW+3600000);
 s.state.fetchDown=true;s.state.hist=[{id:'101',ids:['n1']}];s.state.latest='105';s.state.messages.n1=gmailMsg('n1');
 assert.equal((await pushReq(s)).status,503);assert.equal(cursor(s),'100');assert.equal(deferred(s).length,DEFERRED_CAP);assert.equal(deferred(s).filter(r=>r.message_id==='n1').length,0);
 assert.equal(await s.store.deferFetch(id,'f5','fetch_timeout',NOW),'queued'); // existing row updates
 const st=await s.store.deferredStatus('a',id);assert.deepEqual([st.pending,st.full],[DEFERRED_CAP,true]);
 await s.store.finishMessage(id,'f0',NOW);assert.equal(await s.store.deferFetch(id,'n1','fetch_timeout',NOW),'queued');
 s.db.sqlite.close();
});
test('deferred queue atomicity: verdict marks handled and dequeues in one batch; a crash before the cursor move, or inside ingest, loses nothing and duplicates nothing',async()=>{
 const s=await setup();await connect(s);await ruled(s);const id=(await s.store.byMailbox('me@gmail.test')).source_id;
 await s.store.deferFetch(id,'a1','fetch_timeout',NOW);
 // batch: a failing second statement rolls back the first
 const orig=s.db.batch;s.db.batch=async(st)=>{throw new Error('crash mid-batch');};
 await assert.rejects(s.store.finishMessage(id,'a1',NOW));s.db.batch=orig;
 assert.deepEqual([handled(s),deferred(s).length],[[],1]);
 await s.store.finishMessage(id,'a1',NOW);assert.deepEqual([handled(s),deferred(s).length],[['a1'],0]);
 // crash after the message was queued but before the cursor advanced: redelivery does not refetch, requeue or duplicate
 s.state.fetchDown=true;s.state.hist=[{id:'101',ids:['c1']}];s.state.latest='105';s.state.messages.c1=gmailMsg('c1');
 const adv=s.store.advance.bind(s.store);let boom=true;s.store.advance=async(...a)=>{if(boom)throw new Error('crash before cursor');return adv(...a);};
 assert.equal((await pushReq(s)).status,503);assert.equal(cursor(s),'100');assert.equal(deferred(s).length,1);
 boom=false;const before=s.state.calls.filter(c=>c.endsWith('/messages/c1')).length;
 assert.equal((await pushReq(s)).status,204);assert.equal(cursor(s),'105');
 assert.equal(s.state.calls.filter(c=>c.endsWith('/messages/c1')).length,before);assert.equal(deferred(s)[0].attempts,1);
 // crash inside ingest on a due retry: row stays queued, nothing handled
 s.state.fetchDown=false;s.sync.clock=()=>NOW+120000;const rec=s.sources.receive.bind(s.sources);s.sources.receive=async()=>{throw new Error('crash in ingest');};
 const conn=await s.store.byMailbox('me@gmail.test');s.budget.reset();
 await assert.rejects(s.sync.handleAll(conn,['c1'],'tok',{force:true}));assert.equal(deferred(s).length,1);assert.ok(!handled(s).includes('c1'));
 s.sources.receive=rec;s.budget.reset();await s.sync.handleAll(conn,['c1'],'tok',{force:true});
 assert.equal(count(s),1);assert.deepEqual([deferred(s).length,handled(s).includes('c1')],[0,true]);
 s.db.sqlite.close();
});
test('deferred queue: backfill during an outage keeps every message; a permanent verdict or a 404 on retry also clears the row',async()=>{
 const s=await setup();await connect(s);await ruled(s);
 s.state.fetchDown=true;s.state.history404=true;s.state.profileHistory='900';s.state.recent=['r1','r2','r3'];
 for(const id of ['r1','r2','r3'])s.state.messages[id]=gmailMsg(id,{body:'Your verification code is '+(id==='r1'?'111111':id==='r2'?'222222':'333333')+'\r\n'});
 // messages are hours old: a receipt-based grace would have dropped them on the first failure
 for(const id of ['r1','r2','r3'])s.state.messages[id].internalDate=String(NOW-5*3600000);
 assert.equal((await pushReq(s,{hist:'950'})).status,204);
 assert.equal(count(s),0);assert.deepEqual(deferred(s).map(r=>r.message_id),['r1','r2','r3']);assert.equal(cursor(s),'900');
 s.state.fetchDown=false;s.sync.clock=()=>NOW+70000;
 s.state.messages.r2=gmailMsg('r2',{from:null});delete s.state.messages.r3; // r2 now has no From (skipped), r3 was deleted
 s.state.hist=[];s.state.latest='960';s.state.history404=false;
 assert.equal((await pushReq(s,{hist:'960'})).status,204);
 assert.equal(count(s),1);assert.equal(deferred(s).length,0);assert.deepEqual(handled(s),['r1','r2','r3']);
 s.db.sqlite.close();
});
test('deferred queue: revoke or disconnect clears pending checks; status is owner-scoped; drainDueAll is budget-bounded and handles only due, active mailboxes',async()=>{
 const s=await setup();await connect(s);await ruled(s);const id=(await s.store.byMailbox('me@gmail.test')).source_id;
 await s.store.deferFetch(id,'d1','fetch_error',NOW);await s.store.deferFetch(id,'d2','fetch_timeout',NOW+5);
 const st=await s.store.deferredStatus('a',id);assert.deepEqual([st.pending,st.oldestFirstSeenAt,st.nextAttemptAt,st.reasons,st.full],[2,NOW,NOW+60000,{fetch_error:1,fetch_timeout:1},false]);
 assert.equal((await s.store.deferredStatus('b',id)).pending,0);
 s.state.messages.d1=gmailMsg('d1');s.state.messages.d2=gmailMsg('d2');
 s.sync.clock=()=>NOW;s.budget.reset();assert.deepEqual(await s.sync.drainDueAll(),{mailboxes:0,failed:0,partial:false}); // nothing due yet
 s.sync.clock=()=>NOW+61000;s.budget.reset();const r=await s.sync.drainDueAll();assert.equal(r.mailboxes,1);assert.ok(s.budget.used<=50);
 assert.equal(count(s),2);assert.equal(deferred(s).length,0);
 await s.store.deferFetch(id,'d3','fetch_timeout',NOW);
 s.budget.reset();await s.sync.disconnect('a',id);assert.equal(deferred(s).length,0);
 assert.deepEqual(await s.store.connectionsWithDue(NOW+10**9,5),[]);
 s.db.sqlite.close();
});
test('deferred path costs no more than MESSAGE_COST (raw fetch + one queue write)',async()=>{
 const s=await setup();await connect(s);const conn=await s.store.byMailbox('me@gmail.test');
 s.state.fetchDown=true;s.state.messages.q1=gmailMsg('q1');s.budget.reset();await s.sync.handleAll(conn,['q1'],'tok');
 assert.ok(s.budget.used<=MESSAGE_COST+2,'used '+s.budget.used); // +2 for the handled and deferred lookups that precede the message
 assert.equal(deferred(s).length,1);
 s.db.sqlite.close();
});
test('a stalled raw message body times out and is deferred (not dropped); the push still succeeds and the cursor moves',async()=>{
 const s=await setup({});await connect(s);s.sync.policy={...s.sync.policy,fetchTimeoutMs:50};await ruled(s);
 s.state.hist=[{id:'101',ids:['st']}];s.state.latest='105';
 s.state.messages.st=()=>new Response(new ReadableStream({start(c){c.enqueue(new TextEncoder().encode('{"id"'));},pull(){return new Promise(()=>{});}}),{status:200});
 assert.equal((await pushReq(s)).status,204);assert.equal(cursor(s),'105');assert.deepEqual(handled(s),[]);
 assert.deepEqual(deferred(s).map(r=>[r.message_id,r.last_reason]),[['st','fetch_timeout']]);
 s.db.sqlite.close();
});
test('a request that never answers is aborted at fetchTimeoutMs and deferred; a 403 is not transient and holds the cursor (503)',async()=>{
 const s=await setup({});await connect(s);s.sync.policy={...s.sync.policy,fetchTimeoutMs:50};
 s.state.hist=[{id:'101',ids:['h1']}];s.state.latest='105';s.state.hang=true;
 assert.equal((await pushReq(s)).status,204);assert.deepEqual(deferred(s).map(r=>[r.message_id,r.last_reason]),[['h1','fetch_timeout']]);
 s.state.hang=false;s.state.forbidden=true;s.state.hist=[{id:'106',ids:['h2']}];s.state.latest='110';
 assert.equal((await pushReq(s,{hist:'110'})).status,503);assert.equal(cursor(s),'105');assert.equal(deferred(s).length,1);
 s.db.sqlite.close();
});
test('realtime stays push-driven: a push with nothing queued makes no list or poll call and the drain makes no Google call when nothing is due',async()=>{
 const s=await setup();await connect(s);s.state.hist=[{id:'101',ids:['p1']}];s.state.latest='105';s.state.messages.p1=gmailMsg('p1');
 assert.equal((await pushReq(s)).status,204);assert.ok(!s.state.calls.some(c=>c.endsWith('/messages')));
 const n=s.state.calls.length;s.budget.reset();assert.deepEqual(await s.sync.drainDueAll(),{mailboxes:0,failed:0,partial:false});assert.equal(s.state.calls.length,n);
 s.db.sqlite.close();
});
test('one-auth-unit invocation stops before second raw fetch and resumes without duplicate ingest',async()=>{
 const s=await setup();await connect(s);s.sync.maxMessageUnits=1;s.state.hist=[{id:'105',ids:['u1','u2']}];s.state.messages.u1=gmailMsg('u1');s.state.messages.u2=gmailMsg('u2');
 const first=await pushReq(s);assert.equal(first.status,503);assert.equal(s.sync.units,1);assert.equal(s.state.calls.filter(u=>u.includes('/messages/u2')).length,0);
 s.sync.units=0;const second=await pushReq(s);assert.equal(second.status,204);assert.equal(s.state.calls.filter(u=>u.includes('/messages/u1')).length,1);assert.equal(s.state.calls.filter(u=>u.includes('/messages/u2')).length,1);s.db.sqlite.close();
});

// ---- label mode ----
const LF=GMAIL_CODE_FILTER;
const lrow=s=>s.db.sqlite.prepare('SELECT label_id l, filter_id f, status st FROM gmail_connections').get();
const lreqs=(s,m,pre)=>s.state.reqs.filter(r=>r.m===m&&r.p.startsWith(pre));
test('label mode consent: readonly + labels + settings.basic are requested, a partial grant is refused before any write',async()=>{
 const s=await setup({labelFilter:LF});const {authorizationUrl}=await begin(s);
 assert.deepEqual(new URL(authorizationUrl).searchParams.get('scope').split(' ').sort(),[...GMAIL_SCOPES_LABEL_FILTER].sort());
 s.state.scope='https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.labels'; // user left settings.basic unchecked
 assert.equal((await connect(s)).res.reason,'scope_missing');
 assert.equal(lreqs(s,'POST','/labels').length+lreqs(s,'POST','/settings').length,0);assert.equal(lrow(s),undefined);s.db.sqlite.close();
});
test('label mode setup: one label, one add-label-only filter with the tested query, watch and row follow that label; inbox mode touches no settings',async()=>{
 const i=await setup();assert.equal((await connect(i)).res.ok,true);
 assert.equal(i.state.reqs.filter(r=>/\/labels|\/settings/.test(r.p)).length,0);assert.deepEqual([lrow(i).l,lrow(i).f],[null,null]);assert.equal(JSON.parse(i.state.watchBodies[0]).labelIds[0],'INBOX');i.db.sqlite.close();
 const s=await setup({labelFilter:LF});const r=(await connect(s)).res;assert.equal(r.ok,true);
 assert.equal(lreqs(s,'POST','/labels').length,1);assert.equal(lreqs(s,'POST','/settings/filters').length,1);
 const lid=[...s.state.labels.keys()][0],fb=[...s.state.filters.values()][0];
 assert.equal(s.state.labels.get(lid),LF.labelName);
 assert.deepEqual(fb,{criteria:{query:LF.query},action:{addLabelIds:[lid]}}); // exactly this: no archive, mark-read, forward or delete action
 assert.deepEqual(JSON.parse(s.state.watchBodies[0]),{topicName:'projects/p/topics/t',labelIds:[lid],labelFilterBehavior:'INCLUDE'});
 assert.deepEqual([lrow(s).l,lrow(s).f],[lid,[...s.state.filters.keys()][0]]);s.db.sqlite.close();
});
test('label mode history: asks for messageAdded+labelAdded on the label; a message seen twice is fetched once; other labels are ignored; label-only arrival is collected',async()=>{
 const s=await setup({labelFilter:LF});await connect(s);await ruled(s);const lid=lrow(s).l;
 s.state.hist=[{id:'101',ids:['a1']},{id:'102',ids:[],labeled:[{id:'a1',labelIds:[lid]},{id:'a2',labelIds:['Label_other']},{id:'a3',labelIds:[lid]}]}];s.state.latest='105';
 for(const id of ['a1','a2','a3'])s.state.messages[id]=gmailMsg(id,{body:'Your verification code is '+(id==='a1'?'111111':id==='a2'?'222222':'333333')+'\r\n'});
 assert.equal((await pushReq(s)).status,204);
 const q=s.state.histParams[0];assert.equal(q.get('labelId'),lid);assert.deepEqual(q.getAll('historyTypes'),['messageAdded','labelAdded']);
 const f=id=>s.state.calls.filter(c=>c.endsWith('/messages/'+id)).length;assert.deepEqual([f('a1'),f('a2'),f('a3')],[1,0,1]);assert.equal(count(s),2);assert.equal(cursor(s),'105');
 // replaying the same history changes nothing
 s.state.hist=[{id:'101',ids:['a1']},{id:'102',ids:[],labeled:[{id:'a3',labelIds:[lid]}]}];s.sync.clock=()=>NOW+1;assert.equal((await pushReq(s,{hist:'110'})).status,204);assert.equal(count(s),2);assert.deepEqual([f('a1'),f('a3')],[1,1]);
 s.db.sqlite.close();
});
test('label mode: recovery lists the label, renewal re-watches the label, inbox mode still uses INBOX only',async()=>{
 const s=await setup({labelFilter:LF});await connect(s);const lid=lrow(s).l;
 s.state.history404=true;s.state.recent=[];assert.equal((await pushReq(s,{hist:'950'})).status,204);
 const lst=s.state.calls.filter(c=>c.endsWith('/messages')).length;assert.ok(lst>=1);
 s.sync.clock=()=>NOW+6*86400000;s.budget.reset();s.state.watchBodies=[];assert.equal(await s.sync.renewWatches(),1);assert.equal(JSON.parse(s.state.watchBodies[0]).labelIds[0],lid);
 const i=await setup();await connect(i);i.state.hist=[];i.state.latest='105';await pushReq(i);assert.deepEqual([i.state.histParams[0].getAll('historyTypes'),i.state.histParams[0].get('labelId')],[['messageAdded'],'INBOX']);i.db.sqlite.close();s.db.sqlite.close();
});
test('label mode partial setup failures leave nothing this call created: label exists, filter fails, watch fails, session revoked, mailbox owned by another account',async()=>{
 // existing label of that name is never adopted or deleted
 let s=await setup({labelFilter:LF});s.state.labels=new Map([['Label_user',LF.labelName]]);
 assert.equal((await connect(s)).res.reason,'label_exists');assert.equal(lreqs(s,'POST','/settings').length,0);assert.equal(lreqs(s,'DELETE','/').length,0);assert.ok(s.state.labels.has('Label_user'));assert.equal(lrow(s),undefined);s.db.sqlite.close();
 // filter creation fails: the label just created is removed
 s=await setup({labelFilter:LF,filterFail:true});assert.equal((await connect(s)).res.reason,'filter_failed');assert.equal(s.state.labels.size,0);assert.equal(lrow(s),undefined);s.db.sqlite.close();
 // watch fails: both removed, error surfaces
 s=await setup({labelFilter:LF,watchFail:true});await assert.rejects(connect(s));assert.equal(s.state.labels.size,0);assert.equal(s.state.filters.size,0);assert.equal(lrow(s),undefined);s.db.sqlite.close();
 // session revoked between setup and the guarded write
 s=await setup({labelFilter:LF});s.state.onWatch=()=>s.sess.revoke();assert.equal((await connect(s)).res.reason,'session_revoked');assert.equal(s.state.labels.size,0);assert.equal(s.state.filters.size,0);assert.equal(lrow(s),undefined);s.db.sqlite.close();
 // mailbox belongs to another owner: refused before any write to the mailbox
 s=await setup({labelFilter:LF});assert.equal((await connect(s,'a')).res.ok,true);const before=s.state.reqs.length;
 assert.equal((await connect(s,'b')).res.reason,'mailbox_in_use');assert.equal(s.state.reqs.slice(before).filter(r=>/\/labels|\/settings|\/watch/.test(r.p)&&r.m!=='GET').length,0);
 s.db.sqlite.close();
});
test('label mode reconnect never reuses: it removes this app\'s earlier label and filter and creates new ones',async()=>{
 const s=await setup({labelFilter:LF});await connect(s);const first=lrow(s);
 await connect(s);const second=lrow(s);
 assert.equal(lreqs(s,'POST','/labels').length,2);assert.notEqual(second.l,first.l);assert.notEqual(second.f,first.f);assert.equal(second.st,'active');
 assert.deepEqual([...s.state.labels.keys()],[second.l]);assert.deepEqual([...s.state.filters.keys()],[second.f]);
 s.db.sqlite.close();
});
const clearOp=(s)=>s.db.sqlite.prepare('DELETE FROM gmail_op').run(); // the operator step: only after a definite answer about the earlier request
const tokenPosts=(s)=>s.state.calls.filter(u=>u==='https://oauth2.googleapis.com/token').length;
test('label mode reconnect that fails after the old label was removed marks the connection as needing reconnect; a 5xx on the filter blocks until an operator clears it',async()=>{
 const s=await setup({labelFilter:LF});await connect(s);s.state.filterFail=true;
 assert.equal((await connect(s)).res.reason,'filter_failed');assert.equal(lrow(s).st,'reauth_required');assert.equal(s.state.labels.size+s.state.filters.size,0);
 assert.equal((await s.store.opFor('me@gmail.test')).state,'indeterminate'); // the 500 may still have created a filter
 s.state.filterFail=false;s.state.calls.length=0;assert.equal((await connect(s)).res.reason,'lifecycle_blocked');assert.equal(tokenPosts(s),0);assert.equal(lreqs(s,'POST','/labels').length,2); // blocked before the code exchange, no new write
 clearOp(s);assert.equal((await connect(s)).res.ok,true);assert.equal(lrow(s).st,'active');assert.equal(s.state.labels.size,1);
 const t=await setup({labelFilter:LF});await connect(t);t.state.watchFail=true;await assert.rejects(connect(t));assert.equal(lrow(t).st,'reauth_required');assert.equal(t.state.labels.size+t.state.filters.size,0);assert.equal((await t.store.opFor('me@gmail.test')).state,'indeterminate');
 s.db.sqlite.close();t.db.sqlite.close();
});
test('single-flight: a definite failure (409, 403) releases, a transport error or crash row blocks, nothing is taken over',async()=>{
 let s=await setup({labelFilter:LF});await connect(s);s.state.labelStatus=403;assert.equal((await connect(s)).res.reason,'label_failed');assert.equal(await s.store.opFor('me@gmail.test'),undefined);
 s.state.labelStatus=undefined;s.state.labels.set('Label_foreign','OTPanda codes');assert.equal((await connect(s)).res.reason,'label_exists');assert.equal(await s.store.opFor('me@gmail.test'),undefined);s.db.sqlite.close();
 // transport error on a DELETE: the delete may still land
 s=await setup({labelFilter:LF});await connect(s);s.state.deleteThrow=true;const id=(await s.store.byMailbox('me@gmail.test')).source_id;s.budget.reset();
 let r=await s.sync.disconnect('a',id);assert.deepEqual([r.disconnected,r.artifactsRemoved],[true,false]);assert.equal((await s.store.opFor('me@gmail.test')).state,'indeterminate');
 // later: local disconnect is still possible and idempotent, Google is not touched, connect and renewal are refused
 s.state.deleteThrow=false;s.state.calls.length=0;s.state.reqs.length=0;r=await s.sync.disconnect('a',id);assert.deepEqual([r.disconnected,r.lifecycleBlocked],[true,true]);assert.equal(s.state.calls.length,0);
 assert.equal((await connect(s)).res.reason,'lifecycle_blocked');assert.equal(s.state.calls.filter(u=>u!=='https://oauth2.googleapis.com/token').length,0);
 assert.equal((await s.store.ownerArtifactStatus('a')).lifecycleBlocked,true);s.db.sqlite.close();
 // a crash leaves a running row: it blocks the same way, an in-flight-looking op makes disconnect retryable and renewal skips
 s=await setup({labelFilter:LF});await connect(s);const id2=(await s.store.byMailbox('me@gmail.test')).source_id;
 assert.equal(await s.store.acquireOp('Me@Gmail.test','connect','crashed-op-1',NOW,'a'),true);s.db.sqlite.prepare("UPDATE gmail_connections SET watch_expires_at=1").run();
 r=await s.sync.disconnect('a',id2);assert.deepEqual([r.disconnected,r.lifecycleBlocked],[false,true]);assert.equal(lrow(s).st,'active');
 s.state.calls.length=0;s.budget.reset();assert.equal(await s.sync.renewWatches(),0);assert.equal(s.sync.lastRenewal.blocked,1);assert.ok(!s.state.calls.some(u=>u.endsWith('/watch')));assert.equal((await connect(s)).res.reason,'lifecycle_blocked');
 s.db.sqlite.close();
});
test('single-flight: overlapping connects, connect during disconnect, disconnect during connect: one winner, the loser does nothing',async()=>{
 // second connect inside the first one (during its watch): refused before its code exchange, no Google write
 let s=await setup({labelFilter:LF});let inner;s.state.onWatch=async()=>{s.state.onWatch=undefined;const before=tokenPosts(s);const reqs=s.state.reqs.length;inner=await connect(s);inner.posts=tokenPosts(s)-before;inner.reqs=s.state.reqs.length-reqs;};
 const first=await connect(s);assert.equal(first.res.ok,true);assert.equal(inner.res.reason,'lifecycle_blocked');assert.deepEqual([inner.posts,inner.reqs],[0,0]);assert.equal(await s.store.opFor('me@gmail.test'),undefined);assert.equal(s.state.labels.size,1);assert.equal(lrow(s).st,'active');
 // disconnect while a connect is in flight: retryable, nothing changes
 s.state.onWatch=async()=>{s.state.onWatch=undefined;inner=await s.sync.disconnect('a',(await s.store.byMailbox('me@gmail.test')).source_id);};
 await connect(s);assert.deepEqual([inner.disconnected,inner.lifecycleBlocked],[false,true]);assert.equal(lrow(s).st,'active');assert.equal(s.state.labels.size,1);s.db.sqlite.close();
 // connect while a disconnect is deleting: refused before exchange, the disconnect removes exactly its ids and the row ends disconnected
 s=await setup({labelFilter:LF});await connect(s);const id=(await s.store.byMailbox('me@gmail.test')).source_id;let res,posts;
 s.state.beforeDelete=async()=>{s.state.beforeDelete=undefined;const b=tokenPosts(s);res=await connect(s);posts=tokenPosts(s)-b;};
 s.budget.reset();const r=await s.sync.disconnect('a',id);assert.equal(res.res.reason,'lifecycle_blocked');assert.equal(posts,0);
 assert.deepEqual([r.disconnected,r.artifactsRemoved],[true,true]);assert.deepEqual([lrow(s).st,lrow(s).l,lrow(s).f],['disconnected',null,null]);assert.equal(s.state.labels.size+s.state.filters.size,0);assert.equal(await s.store.opFor('me@gmail.test'),undefined);
 assert.equal((await connect(s)).res.ok,true);s.db.sqlite.close();
});
test('a 2xx whose body cannot be used after a possible write is indeterminate: malformed JSON or missing ids on label, filter or watch',async()=>{
 const cases=[['labelRaw','not json','label_failed'],['labelRaw','{}','label_failed'],['filterRaw','not json','filter_failed'],['filterRaw','{"id":""}','filter_failed'],['watchRaw','not json',null],['watchRaw','{"historyId":"x"}',null]];
 for(const [k,v,reason] of cases){
  const s=await setup({labelFilter:LF});s.state[k]=v;
  if(reason)assert.equal((await connect(s)).res.reason,reason);else await assert.rejects(connect(s));
  const op=await s.store.opFor('me@gmail.test');assert.equal(op?.state,'indeterminate',k+' '+v);assert.equal(op.owner_id,'a');
  s.state[k]=undefined;assert.equal((await connect(s)).res.reason,'lifecycle_blocked',k+' '+v);s.db.sqlite.close();}
 // a clean 4xx on the same calls stays definite (covered by label 403 above); a 200 with good bodies releases
 const g=await setup({labelFilter:LF});assert.equal((await connect(g)).res.ok,true);assert.equal(await g.store.opFor('me@gmail.test'),undefined);g.db.sqlite.close();
});
test('generic source revoke or owner disconnect landing while a reconnect prepares its write is never undone (generation compare-and-set)',async()=>{
 for(const mode of ['inbox','label']){for(const how of ['generic','owner']){
  const s=await setup(mode==='label'?{labelFilter:LF}:{});await connect(s);const id=(await s.store.byMailbox('me@gmail.test')).source_id;const g0=s.db.sqlite.prepare('SELECT gen g FROM gmail_connections').get().g;
  const realEnc=s.store.cipher.encrypt.bind(s.store.cipher);let fired=false;
  s.store.cipher.encrypt=async(...a)=>{if(!fired){fired=true;if(how==='generic')await s.sources.revokeSource('a',id,NOW);else await s.store.disconnect('a',id,NOW);}return realEnc(...a);}; // the revoke lands after connect read the row, before its write
  s.budget.reset();const c=await connect(s);
  const row=s.db.sqlite.prepare('SELECT status,refresh_envelope e,gen g FROM gmail_connections').get();const src=s.db.sqlite.prepare('SELECT revoked_at r FROM sources WHERE source_id=?').get(id);
  assert.equal(c.res.reason,'source_changed',mode+how);assert.equal(row.status,'disconnected');assert.equal(row.e,'');assert.equal(src.r,NOW);assert.equal(row.g,g0+1); // revoke moved the generation, connect wrote nothing
  if(mode==='label'){assert.equal(s.state.labels.size+s.state.filters.size,0);const o=await s.store.opFor('me@gmail.test');assert.equal(o,undefined);} // artifacts this connect created were removed, op released
  // a later, deliberate reconnect still works and moves the generation again
  s.store.cipher.encrypt=realEnc;assert.equal((await connect(s)).res.ok,true);const after=s.db.sqlite.prepare('SELECT status,gen g FROM gmail_connections').get();assert.deepEqual([after.status,after.g],['active',g0+2]);
  s.db.sqlite.close();}}
});
test('op status is owner-bound: only the owner that started a blocked operation sees lifecycleBlocked, including a first connect with no connection row',async()=>{
 const s=await setup({labelFilter:LF});s.state.filterRaw='not json';await connect(s);assert.equal(lrow(s),undefined); // first connect crashed/indeterminate before any connection row
 assert.equal((await s.store.ownerArtifactStatus('a')).lifecycleBlocked,true);assert.equal((await s.store.ownerArtifactStatus('b')).lifecycleBlocked,false);
 s.db.sqlite.close();
 const t=await setup({labelFilter:LF});await connect(t);await t.store.acquireOp('someone-else@gmail.test','renew','op-dddddddd',NOW,'b');
 assert.equal((await t.store.ownerArtifactStatus('a')).lifecycleBlocked,false);assert.equal((await t.store.ownerArtifactStatus('b')).lifecycleBlocked,true);t.db.sqlite.close();
});
test('dev mailbox: label mode needs devMailbox before any exchange, and another mailbox is refused with no Gmail write',async()=>{
 let s=await setup({labelFilter:LF,noDev:true});assert.equal((await connect(s)).res.reason,'dev_mailbox_required');assert.equal(tokenPosts(s),0);assert.equal((s.state.reqs??[]).length,0);s.db.sqlite.close();
 s=await setup({labelFilter:LF,devMailbox:'someone-else@gmail.test'});const c=await connect(s);assert.equal(c.res.reason,'mailbox_not_allowed');
 assert.equal((s.state.reqs??[]).filter(x=>x.m!=='GET'&&!x.p.includes('oauth2.googleapis.com')).length,0);assert.equal(lrow(s),undefined);assert.equal(await s.store.opFor('someone-else@gmail.test'),undefined);s.db.sqlite.close();
});
test('gmail_op single-flight store: one winner, release only by owner, release ignored once indeterminate, keyed by canonical mailbox',async()=>{
 const s=await setup({labelFilter:LF});
 assert.equal(await s.store.acquireOp('Me@Gmail.test','connect','op-aaaaaaaa',NOW,'a'),true);assert.equal(await s.store.acquireOp('me@gmail.test','disconnect','op-bbbbbbbb',NOW,'b'),false);
 await s.store.releaseOp('me@gmail.test','op-bbbbbbbb');assert.equal((await s.store.opFor('me@gmail.test')).op_id,'op-aaaaaaaa'); // not the owner
 await s.store.markOpIndeterminate('me@gmail.test','op-aaaaaaaa');await s.store.releaseOp('me@gmail.test','op-aaaaaaaa');assert.equal((await s.store.opFor('me@gmail.test')).state,'indeterminate'); // never released by normal code
 assert.equal(await s.store.acquireOp('other@gmail.test','renew','op-cccccccc',NOW,'a'),true);s.db.sqlite.close();
});
test('artifact id clearing and reauth marking are compare-and-set',async()=>{
 const s=await setup({labelFilter:LF});await connect(s);const id=(await s.store.byMailbox('me@gmail.test')).source_id;const cur=lrow(s);
 await s.store.clearArtifacts(id,{filter:true,label:true},{filterId:cur.f,labelId:cur.l});assert.deepEqual([lrow(s).l,lrow(s).f],[cur.l,cur.f]); // active row: untouched
 await s.store.markReauthIfArtifacts(id,'Label_other',NOW);assert.equal(lrow(s).st,'active'); // ids differ: untouched
 await s.store.disconnect('a',id,NOW);
 await s.store.clearArtifacts(id,{filter:true,label:true},{filterId:'Filter_other',labelId:'Label_other'});assert.deepEqual([lrow(s).l,lrow(s).f],[cur.l,cur.f]); // different ids: untouched
 await s.store.clearArtifacts(id,{filter:true,label:false},{filterId:cur.f,labelId:cur.l});assert.deepEqual([lrow(s).l,lrow(s).f],[cur.l,null]);
 s.db.sqlite.close();
});
test('label mode disconnect removes only the stored label and filter and never revokes the grant; a 5xx on a delete leaves the op indeterminate',async()=>{
 const s=await setup({labelFilter:LF});await connect(s);s.state.labels.set('Label_foreign','Users own');s.state.filters.set('Filter_foreign',{criteria:{query:'x'}});
 const id=(await s.store.byMailbox('me@gmail.test')).source_id;const mine=[lrow(s).l,lrow(s).f];
 s.budget.reset();const r=await s.sync.disconnect('a',id);
 assert.deepEqual([r.disconnected,r.artifactsRemoved,r.remoteRevoked,r.googlePermissionRemains],[true,true,false,true]);assert.ok(!s.state.calls.includes('https://oauth2.googleapis.com/revoke'));
 assert.deepEqual([...s.state.labels.keys()],['Label_foreign']);assert.deepEqual([...s.state.filters.keys()],['Filter_foreign']);
 assert.deepEqual(lreqs(s,'DELETE','/').map(x=>x.p).sort(),['/labels/'+mine[0],'/settings/filters/'+mine[1]].sort());
 assert.deepEqual([lrow(s).l,lrow(s).f,lrow(s).st],[null,null,'disconnected']);assert.equal(await s.store.opFor('me@gmail.test'),undefined); // definite answers: released
 const t=await setup({labelFilter:LF});await connect(t);t.state.deleteFail=true;const id2=(await t.store.byMailbox('me@gmail.test')).source_id;t.budget.reset();
 const r2=await t.sync.disconnect('a',id2);assert.deepEqual([r2.disconnected,r2.artifactsRemoved],[true,false]);
 assert.equal((await t.store.opFor('me@gmail.test')).state,'indeterminate'); // a 500 on a DELETE may still land
 s.db.sqlite.close();t.db.sqlite.close();
});
test('label mode lifecycle: a caller-supplied guarded revoke gates all remote writes; leftovers stay visible to the owner and nowhere else',async()=>{
 const s=await setup({labelFilter:LF});await connect(s);const id=(await s.store.byMailbox('me@gmail.test')).source_id;const mine=[lrow(s).l,lrow(s).f];
 // guard refuses: nothing is deleted or revoked at Google, ids stay
 s.budget.reset();let r=await s.sync.disconnect('a',id,{revoke:async()=>false});
 assert.equal(r.disconnected,false);assert.equal(lreqs(s,'DELETE','/').length,0);assert.deepEqual([lrow(s).l,lrow(s).f,lrow(s).st],[...mine,'active']);assert.equal(await s.store.opFor('me@gmail.test'),undefined);
 // guard passes, Google deletes fail: disconnected locally, ids stay, owner sees counts, another owner sees none
 s.state.deleteFail=true;const guarded=()=>s.store.disconnect('a',id,NOW);
 s.budget.reset();r=await s.sync.disconnect('a',id,{revoke:guarded});
 assert.deepEqual([r.disconnected,r.artifactsRemoved],[true,false]);assert.deepEqual([lrow(s).l,lrow(s).f,lrow(s).st],[...mine,'disconnected']);
 assert.deepEqual(await s.store.ownerArtifactStatus('a'),{leftoverLabels:1,leftoverFilters:1,lifecycleBlocked:true});assert.deepEqual(await s.store.ownerArtifactStatus('b'),{leftoverLabels:0,leftoverFilters:0,lifecycleBlocked:false});
 s.db.sqlite.close();
 // guard passes and Google succeeds: ids cleared, nothing left over
 const t=await setup({labelFilter:LF});await connect(t);const id2=(await t.store.byMailbox('me@gmail.test')).source_id;t.budget.reset();
 r=await t.sync.disconnect('a',id2,{revoke:()=>t.store.disconnect('a',id2,NOW)});
 assert.deepEqual([r.disconnected,r.artifactsRemoved],[true,true]);assert.equal(t.state.labels.size+t.state.filters.size,0);assert.deepEqual(await t.store.ownerArtifactStatus('a'),{leftoverLabels:0,leftoverFilters:0,lifecycleBlocked:false});
 t.db.sqlite.close();
 // generic source revoke (no Google contact possible): the artifacts are reported as left behind
 const u=await setup({labelFilter:LF});await connect(u);const id3=(await u.store.byMailbox('me@gmail.test')).source_id;await u.sources.revokeSource('a',id3,NOW);
 assert.deepEqual(await u.store.ownerArtifactStatus('a'),{leftoverLabels:1,leftoverFilters:1,lifecycleBlocked:false});u.db.sqlite.close();
});

test('dev maintenance: scoped to the one mailbox, only due rows, no inbox polling, renewal respects the single-flight, tasks isolated',async()=>{
 const s=await setup();await connect(s);s.state.mailbox='Other@Gmail.test';await connect(s,'b');
 const run=(o={})=>{s.budget.reset();return runGmailDevMaintenance({sync:s.sync,store:s.store,budget:s.budget,clock:()=>NOW,mailbox:'ME@gmail.test',...o});};
 const google=()=>s.state.calls.filter(u=>!u.includes('oauth2.googleapis.com/token')).length+s.state.calls.filter(u=>u.includes('oauth2.googleapis.com/token')).length;
 // nothing due: no Google call at all (no polling), only D1 work
 s.state.calls.length=0;let r=await run();assert.equal(google(),0);assert.deepEqual([r.mailbox,r.failed,r.renewal.renewed,r.retries.mailboxes],['me@gmail.test',[],0,0]);assert.ok(s.budget.used<=4);
 // both mailboxes due: only the dev mailbox is renewed; the other keeps its old expiry
 s.db.sqlite.prepare('UPDATE gmail_connections SET watch_expires_at=?').run(NOW+1000);
 s.state.calls.length=0;r=await run();assert.equal(r.renewal.renewed,1);const rows=s.db.sqlite.prepare('SELECT mailbox,watch_expires_at w FROM gmail_connections ORDER BY mailbox').all();
 assert.deepEqual(rows.map(x=>x.mailbox),['me@gmail.test','other@gmail.test']);assert.ok(rows[0].w>NOW+86400000);assert.equal(rows[1].w,NOW+1000);
 // not active rows are not selected
 s.db.sqlite.prepare("UPDATE gmail_connections SET watch_expires_at=?,status='reauth_required' WHERE mailbox='me@gmail.test'").run(NOW+1000);s.state.calls.length=0;r=await run();assert.equal(r.renewal.renewed,0);assert.equal(google(),0);
 s.db.sqlite.prepare("UPDATE gmail_connections SET status='active' WHERE mailbox='me@gmail.test'").run();
 // a blocked single-flight skips renewal without any Google call
 assert.equal(await s.store.acquireOp('me@gmail.test','connect','crashed-op-2',NOW,'a'),true);s.state.calls.length=0;r=await run();assert.equal(r.renewal.blocked,1);assert.equal(r.renewal.renewed,0);assert.equal(google(),0);
 s.db.sqlite.prepare('DELETE FROM gmail_op').run();
 // tasks are selectable and isolated: a failing renew does not skip prune
 const real=s.sync.renewWatches;s.sync.renewWatches=async()=>{throw new Error('x');};
 s.db.sqlite.prepare('INSERT INTO gmail_oauth_states(state_hash,owner_id,verifier,device_id,generation,created_at,expires_at) VALUES (?,?,?,?,?,?,?)').run('h1','a','v','d','g',NOW-5000,NOW-1000);
 r=await run();assert.deepEqual(r.failed,['renew']);assert.equal(r.pruned,1);s.sync.renewWatches=real;
 r=await run({tasks:['prune']});assert.deepEqual([r.retries,r.renewal,r.pruned],[undefined,undefined,0]);
 // an unscoped call is refused
 await assert.rejects(runGmailDevMaintenance({sync:s.sync,store:s.store,budget:s.budget}),TypeError);
 // due retries are scoped too: the other mailbox's due row is not selected
 for(const mb of ['me@gmail.test','other@gmail.test'])s.db.sqlite.prepare("INSERT INTO gmail_deferred(source_id,message_id,first_seen_at,next_attempt_at,attempts,last_reason) SELECT source_id,'m-'||mailbox,?,?,1,'fetch_error' FROM gmail_connections WHERE mailbox=?").run(NOW-9000,NOW-1000,mb);
 assert.deepEqual((await s.store.connectionsWithDue(NOW,5)).map(x=>x.mailbox).sort(),['me@gmail.test','other@gmail.test']);
 assert.deepEqual((await s.store.connectionsWithDue(NOW,5,'Me@Gmail.test')).map(x=>x.mailbox),['me@gmail.test']);
 s.db.sqlite.close();
});

const revokesOf=s=>s.state.revokes??[];
test('post-exchange refusal of a mailbox with no stored connection revokes only the newly issued grant, with no Gmail write',async()=>{
 const s=await setup({labelFilter:LF,devMailbox:'someone-else@gmail.test'});const c=await connect(s);
 assert.equal(c.res.reason,'mailbox_not_allowed');assert.equal(c.res.grantRevoked,true);assert.deepEqual(revokesOf(s),['rt-secret']);
 assert.equal((s.state.reqs??[]).filter(x=>x.m!=='GET'&&!x.p.includes('oauth2.googleapis.com')).length,0);assert.equal(lrow(s),undefined);assert.equal(await s.store.opFor('someone-else@gmail.test'),undefined);s.db.sqlite.close();
});
test('a failed reconnect never revokes the grant while a stored connection holds an envelope for the mailbox',async()=>{
 const s=await setup({labelFilter:LF});const first=await connect(s);assert.equal(first.res.ok,true);assert.deepEqual(revokesOf(s),[]);
 s.state.filterFail=true;const second=await connect(s);assert.equal(second.res.ok,false);assert.notEqual(second.res.grantRevoked,true);assert.deepEqual(revokesOf(s),[]);
 const row=s.db.sqlite.prepare('SELECT refresh_envelope e FROM gmail_connections').get();assert.ok(row);s.db.sqlite.close();
});
test('another owner holding the mailbox is never revoked (mailbox_in_use)',async()=>{
 const s=await setup({labelFilter:LF});assert.equal((await connect(s,'a')).res.ok,true);const r=await connect(s,'b');
 assert.equal(r.res.reason,'mailbox_in_use');assert.notEqual(r.res.grantRevoked,true);assert.deepEqual(revokesOf(s),[]);s.db.sqlite.close();
});
test('successful connect revokes nothing',async()=>{const s=await setup({labelFilter:LF});assert.equal((await connect(s)).res.ok,true);assert.deepEqual(revokesOf(s),[]);s.db.sqlite.close();});
test('without a dev op or a known mailbox ownership cannot be established, so nothing is revoked',async()=>{
 let s=await setup({});const st=await begin(s,'a');s.sess.revoke();s.budget.reset();
 const r=await s.oauth.callback({code:'good-code',state:new URL(st.authorizationUrl).searchParams.get('state'),session:sessOf('a')});
 assert.equal(r.reason,'session_revoked');assert.deepEqual(revokesOf(s),[]);s.db.sqlite.close();
 s=await setup({labelFilter:LF,scope:'https://www.googleapis.com/auth/gmail.readonly'});const c=await connect(s);assert.equal(c.res.reason,'scope_missing');assert.deepEqual(revokesOf(s),[]);s.db.sqlite.close();
});
test('a failed revoke is reported as not revoked and does not poison the dev lifecycle',async()=>{
 let s=await setup({labelFilter:LF,devMailbox:'someone-else@gmail.test',revokeStatus:503});let c=await connect(s);
 assert.equal(c.res.grantRevoked,false);assert.equal(c.res.reason,'mailbox_not_allowed');assert.equal(await s.store.opFor('someone-else@gmail.test'),undefined);s.db.sqlite.close();
 s=await setup({labelFilter:LF,devMailbox:'someone-else@gmail.test',revokeThrow:true});c=await connect(s);
 assert.equal(c.res.grantRevoked,false);assert.equal(c.res.reason,'mailbox_not_allowed');assert.equal(await s.store.opFor('someone-else@gmail.test'),undefined);s.db.sqlite.close();
});
