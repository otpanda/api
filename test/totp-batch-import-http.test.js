import test from 'node:test';import assert from 'node:assert/strict';
import {database} from './sqlite-helper.js';import {SeedCipher} from '../src/seed-cipher.js';import {createTotpBatchImportHttp,MAX_BATCH_ITEMS} from '../src/totp-batch-import-http.js';
// Synthetic secrets only.
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',NONCE='AAAAAAAAAAAAAAAAAAAAAA',S1='GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const uri=(n,extra='')=>`otpauth://totp/Ex:${n}?secret=${S1}&issuer=Ex${extra}`;
async function fixture({now=59000}={}){
 const db=database();await db.prepare('INSERT INTO accounts VALUES (?,?)').bind('owner',0).run();await db.prepare('INSERT INTO account_security(owner_id) VALUES (?)').bind('owner').run();
 await db.prepare("INSERT INTO provider_identities(identity_id,owner_id,provider,issuer,subject,email,created_at) VALUES ('provider','owner','google','https://accounts.google.com','subject','synthetic@example.test',0)").run();
 await db.prepare("INSERT INTO device_sessions(device_id,owner_id,provider_identity_id,generation,client_kind,created_at,last_used_at,expires_at) VALUES ('device','owner','provider',0,'web',0,0,999999999999)").run();
 await db.prepare("INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) VALUES ('fakecred','owner',x'00',0,'[]','singleDevice',0,0)").run();
 await db.prepare("INSERT INTO account_emails(owner_id,email,verified_at,updated_at) VALUES ('owner','synthetic@example.test',0,0)").run();
 let actor={ownerId:'owner',deviceId:'device',generation:0,clientKind:'web',expiresAt:999999999999},clock=now,hook=()=>{};
 const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']),cipher=new SeedCipher({keys:new Map([['test',key]]),activeKeyId:'test'});
 const seen=[];
 const passkeys={begin:async a=>{seen.push(['begin',a]);return{token:'tok'+seen.length,options:{},expiresAt:1};},finishAuthentication:async a=>{seen.push(['finish',a]);return a.token==='bad'?undefined:{generation:0};}};
 const http=createTotpBatchImportHttp({db,sessions:{authenticate:async t=>t==='access'?actor:undefined},getSeedCipher:async()=>{await hook();return cipher;},clock:()=>clock,passkeys});
 const call=(step,body,headers={})=>http.fetch(new Request(API+'/v1/manage/totp/'+step,{method:'POST',headers:{Origin:APP,Authorization:'Bearer access','Content-Type':'application/json',...headers},body:JSON.stringify(body)}),{clientAddress:'t'+Math.random()});
 const count=async t=>(await db.prepare('SELECT count(*) n FROM '+t).first()).n;
 return{db,cipher,seen,call,count,setActor:v=>actor=v,setHook:v=>hook=v,setClock:v=>clock=v};
}
const items=n=>Array.from({length:n},(_,i)=>({label:'Acct '+i,account:'a'+i+'@example.test',secret:uri('a'+i,i%2?'&digits=7&period=60':'')}));
const fin=(items,extra={})=>({items,batchNonce:NONCE,token:'tok',response:{},...extra});
test('whole batch commits once: entries, seeds, outcome row, ids in request order, no secret in response',async()=>{
 const f=await fixture();try{
  const it=items(5),r=await f.call('batch-finish',fin(it));assert.equal(r.status,201);assert.equal(r.headers.get('cache-control'),'no-store');
  const body=await r.json();assert.deepEqual(Object.keys(body).sort(),['entryIds','status']);assert.equal(body.entryIds.length,5);assert.equal(JSON.stringify(body).includes(S1),false);
  assert.equal(await f.count('entries'),5);assert.equal(await f.count('totp_seeds'),5);assert.equal(await f.count('totp_batch_imports'),1);
  const e=await f.db.prepare('SELECT label,issuer FROM entries WHERE entry_id=?').bind(body.entryIds[3]).first();assert.equal(e.label,'Acct 3');
  const seed=await f.db.prepare('SELECT envelope FROM totp_seeds WHERE entry_id=?').bind(body.entryIds[1]).first(),pl=JSON.parse(await f.cipher.decrypt(JSON.parse(seed.envelope),{ownerId:'owner',entryId:body.entryIds[1]}));
  assert.equal(pl.digits,7);assert.equal(pl.period,60);
  assert.equal(JSON.stringify(await f.db.prepare('SELECT * FROM totp_batch_imports').first()).includes(S1),false);
 }finally{f.db.sqlite.close();}});
test('begin binds owner, device, generation, nonce and every item through the action digest',async()=>{
 const f=await fixture();try{
  const it=items(2);assert.equal((await f.call('batch-begin',{items:it,batchNonce:NONCE})).status,200);
  await f.call('batch-begin',{items:it,batchNonce:'BBBBBBBBBBBBBBBBBBBBBB'});
  await f.call('batch-begin',{items:[it[0],{...it[1],label:'Changed'}],batchNonce:NONCE});
  await f.call('batch-begin',{items:[it[1],it[0]],batchNonce:NONCE});
  const actions=f.seen.filter(s=>s[0]==='begin').map(s=>s[1].action);assert.equal(new Set(actions).size,4);
  for(const a of actions)assert.match(a,/^totp-batch-import:[0-9a-f]{64}$/);
  assert.equal(JSON.stringify(f.seen).includes(S1),false);
 }finally{f.db.sqlite.close();}});
test('finish with changed items or a bad proof commits nothing',async()=>{
 const f=await fixture();try{
  const it=items(3);
  assert.equal((await f.call('batch-finish',fin(it,{token:'bad'}))).status,403);
  const fa=f.seen.filter(s=>s[0]==='finish')[0][1];
  assert.match(fa.action,/^totp-batch-import:/);assert.equal(fa.ownerId,'owner');
  assert.equal(await f.count('entries'),0);assert.equal(await f.count('totp_batch_imports'),0);
 }finally{f.db.sqlite.close();}});
test('invalid items, limits and shapes reject the whole batch without echoing input',async()=>{
 const f=await fixture();try{
  const good=items(2);
  const bads=[[...good,{label:'x',account:'a',secret:'bad'}],[...good,{...good[0],extra:1}],[...good,{...good[0],label:''}],[],items(MAX_BATCH_ITEMS+1),[...good,{...good[0],secret:uri('z','&digits=9')}],[...good,{...good[0],catalogId:'BAD ID'}]];
  for(const b of bads){const r=await f.call('batch-begin',{items:b,batchNonce:NONCE});assert.equal(r.status,400);assert.deepEqual(await r.json(),{error:'invalid_request'});assert.equal((await f.call('batch-finish',fin(b))).status,400);}
  for(const n of ['short','has space has space has space','']) assert.equal((await f.call('batch-begin',{items:good,batchNonce:n})).status,400);
  assert.equal((await f.call('batch-begin',{items:good,batchNonce:NONCE,x:1})).status,400);
  assert.equal(await f.count('entries'),0);
 }finally{f.db.sqlite.close();}});
test('exactly 50 items commit in one transaction',async()=>{
 const f=await fixture();try{const r=await f.call('batch-finish',fin(items(MAX_BATCH_ITEMS)));assert.equal(r.status,201);assert.equal(await f.count('entries'),50);assert.equal(await f.count('totp_seeds'),50);}finally{f.db.sqlite.close();}});
test('a failure in the middle rolls back every row (all or none)',async()=>{
 const f=await fixture();try{
  await f.db.sqlite.exec("CREATE TRIGGER boom BEFORE INSERT ON totp_seeds WHEN (SELECT count(*) FROM totp_seeds)=2 BEGIN SELECT RAISE(ABORT,'boom'); END");
  const r=await f.call('batch-finish',fin(items(5)));assert.equal(r.status,503);
  assert.equal(await f.count('entries'),0);assert.equal(await f.count('totp_seeds'),0);assert.equal(await f.count('totp_batch_imports'),0);
  assert.deepEqual(await(await f.call('batch-outcome',{batchNonce:NONCE})).json(),{status:'none'});
 }finally{f.db.sqlite.close();}});
test('revocation while encrypting wins: nothing is written',async()=>{
 const f=await fixture();try{
  f.setHook(()=>f.db.prepare("UPDATE device_sessions SET revoked_at=59000 WHERE device_id='device'").run());
  assert.equal((await f.call('batch-finish',fin(items(3)))).status,401);assert.equal(await f.count('entries'),0);assert.equal(await f.count('totp_batch_imports'),0);
 }finally{f.db.sqlite.close();}});
test('repeated nonce: same batch returns the first result with no new rows; different batch is refused',async()=>{
 const f=await fixture();try{
  const it=items(3),first=await(await f.call('batch-finish',fin(it))).json();
  const again=await f.call('batch-finish',fin(it,{token:'tok2'}));assert.equal(again.status,200);assert.deepEqual(await again.json(),first);
  const beg=await f.call('batch-begin',{items:it,batchNonce:NONCE});assert.equal(beg.status,200);assert.deepEqual(await beg.json(),first);
  assert.equal((await f.call('batch-begin',{items:items(2),batchNonce:NONCE})).status,409);
  assert.equal((await f.call('batch-finish',fin(items(2)))).status,409);
  assert.equal(await f.count('entries'),3);assert.equal(await f.count('totp_batch_imports'),1);
 }finally{f.db.sqlite.close();}});
test('outcome readback is owner bound and permanent nonce tombstone prevents a late duplicate',async()=>{
 const f=await fixture();try{
  const first=await(await f.call('batch-finish',fin(items(2)))).json();
  const out=await(await f.call('batch-outcome',{batchNonce:NONCE})).json();assert.deepEqual(out,{status:'saved',entryIds:first.entryIds});
  await f.db.prepare("INSERT INTO accounts VALUES ('other',0)").run();await f.db.prepare("INSERT INTO account_security(owner_id) VALUES ('other')").run();
  f.setActor({ownerId:'other',deviceId:'x',generation:0,clientKind:'web',expiresAt:999999999999});
  assert.deepEqual(await(await f.call('batch-outcome',{batchNonce:NONCE})).json(),{status:'none'});
  f.setActor({ownerId:'owner',deviceId:'device',generation:0,clientKind:'web',expiresAt:999999999999});
  f.setClock(59000+24*3600*1000+1);
  assert.deepEqual(await(await f.call('batch-outcome',{batchNonce:NONCE})).json(),{status:'saved',entryIds:first.entryIds});
  assert.equal((await f.call('batch-finish',fin(items(1)))).status,409);assert.equal(await f.count('totp_batch_imports'),1);assert.equal(await f.count('entries'),2);
 }finally{f.db.sqlite.close();}});
test('unauthenticated, foreign origin and wrong method are refused; begin needs a passkey',async()=>{
 const f=await fixture();try{
  assert.equal((await f.call('batch-begin',{items:items(1),batchNonce:NONCE},{Authorization:'Bearer refresh'})).status,401);
  assert.equal((await f.call('batch-begin',{items:items(1),batchNonce:NONCE},{Origin:'https://evil.test'})).status,403);
  await f.db.prepare('UPDATE passkey_credentials SET revoked_at=1').run();
  assert.equal((await f.call('batch-begin',{items:items(1),batchNonce:NONCE})).status,409);
 }finally{f.db.sqlite.close();}});
test('real action-bound passkey ceremony: one prompt commits all, changed items deny, replay denies',async()=>{
 const {authenticator}=await import('./passkey-fixture.js'),{PasskeyService}=await import('../src/passkey-service.js');
 const f=await fixture();try{
  const a=authenticator(),c=a.credential;
  await f.db.prepare("INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) VALUES (?,'owner',?,0,'[]','singleDevice',0,0)").bind(c.id,Array.from(c.publicKey)).run();
  const http=createTotpBatchImportHttp({db:f.db,sessions:{authenticate:async()=>({ownerId:'owner',deviceId:'device',generation:0,clientKind:'web',expiresAt:999999999999})},getSeedCipher:async()=>f.cipher,clock:()=>59000,passkeys:new PasskeyService(f.db,{clock:()=>59000})});
  const send=(s,v)=>http.fetch(new Request(API+'/v1/manage/totp/'+s,{method:'POST',headers:{Origin:APP,Authorization:'Bearer access','Content-Type':'application/json'},body:JSON.stringify(v)}),{clientAddress:'real'+Math.random()});
  const it=items(4),begin=await(await send('batch-begin',{items:it,batchNonce:NONCE})).json();assert.ok(begin.token);
  const response=a.assertion({expected:begin.options.challenge});
  assert.equal((await send('batch-finish',{items:[...it.slice(0,3)],batchNonce:NONCE,token:begin.token,response})).status,403);
  const next=await(await send('batch-begin',{items:it,batchNonce:NONCE})).json(),signed=a.assertion({expected:next.options.challenge,counter:2});
  assert.equal((await send('batch-finish',{items:it,batchNonce:NONCE,token:next.token,response:signed})).status,201);
  assert.equal(await f.count('entries'),4);
  assert.equal((await send('batch-finish',{items:it,batchNonce:NONCE,token:next.token,response:signed})).status,200);// stored outcome, nothing new
  assert.equal(await f.count('entries'),4);
 }finally{f.db.sqlite.close();}});
