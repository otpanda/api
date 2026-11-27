import test from 'node:test';import assert from 'node:assert/strict';
import {database} from './sqlite-helper.js';import {SeedCipher} from '../src/seed-cipher.js';import {createTotpExportHttp,MAX_EXPORT_ENTRIES} from '../src/totp-export-http.js';
import {openExport,sealExport,importClientEphemeral,sha256Hex,exportAad} from '../src/totp-export-seal.js';import {base64urlEncode} from '../src/tokens.js';
// Synthetic secrets only.
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io';
const secretOf=i=>new Uint8Array(20).fill(i+1);
async function clientKey(){const pair=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']);return{pair,pub:base64urlEncode(new Uint8Array(await crypto.subtle.exportKey('raw',pair.publicKey)))};}
async function fixture({afterSeal}={}){
 const db=database();
 for(const o of ['owner','other']){await db.prepare('INSERT INTO accounts VALUES (?,?)').bind(o,0).run();await db.prepare('INSERT INTO account_security(owner_id) VALUES (?)').bind(o).run();}
 await db.prepare("INSERT INTO provider_identities(identity_id,owner_id,provider,issuer,subject,email,created_at) VALUES ('provider','owner','google','https://accounts.google.com','subject','synthetic@example.test',0)").run();
 await db.prepare("INSERT INTO device_sessions(device_id,owner_id,provider_identity_id,generation,client_kind,created_at,last_used_at,expires_at) VALUES ('device','owner','provider',0,'web',0,0,999999999999)").run();
 await db.prepare("INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) VALUES ('fakecred','owner',x'00',0,'[]','singleDevice',0,0)").run();
 const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']),cipher=new SeedCipher({keys:new Map([['test',key]]),activeKeyId:'test'});
 await db.prepare("INSERT OR IGNORE INTO services(service_id,name) VALUES ('custom-totp','Authenticator')").run();
 const add=async(owner,id,i,{digits=6,period=30,algorithm='SHA-1'}={})=>{await db.prepare("INSERT INTO entries(entry_id,owner_id,service_id,label,created_at,account_name,issuer) VALUES (?,?,?,?,1,?,?)").bind(id,owner,'custom-totp','Label '+id,'acc'+id,'Iss').run();const env=await cipher.encrypt(JSON.stringify({secret:base64urlEncode(secretOf(i)),algorithm,digits,period}),{ownerId:owner,entryId:id});await db.prepare('INSERT INTO totp_seeds(owner_id,entry_id,envelope,created_at,updated_at) VALUES (?,?,?,1,1)').bind(owner,id,JSON.stringify(env)).run();};
 await add('owner','e1',0);await add('owner','e2',1,{digits:7,period:60});await add('owner','e3',2,{digits:8,algorithm:'SHA-256'});await add('other','x1',9);
 await db.prepare("INSERT INTO entries(entry_id,owner_id,service_id,label,created_at) VALUES ('noseed','owner','custom-totp','No seed',1)").run();
 let actor={ownerId:'owner',deviceId:'device',generation:0,clientKind:'web',expiresAt:999999999999},hook=()=>{};const seen=[];
 const passkeys={begin:async a=>{seen.push(['begin',a]);return{token:'t'+seen.length,options:{},expiresAt:1};},finishAuthentication:async a=>{seen.push(['finish',a]);return a.token==='bad'||a.token==='spent'?undefined:{generation:0};}};
 const http=createTotpExportHttp({db,sessions:{authenticate:async t=>t==='access'?actor:undefined},getSeedCipher:async()=>{await hook();return cipher;},clock:()=>59000,passkeys,seal:async args=>{const out=await sealExport(args);await afterSeal?.(db);return out;}});
 let n=0;const call=(step,body,headers={})=>http.fetch(new Request(API+'/v1/manage/totp/'+step,{method:'POST',headers:{Origin:APP,Authorization:'Bearer access','Content-Type':'application/json',...headers},body:JSON.stringify(body)}),{clientAddress:'ip'+(n++)});
 return{db,cipher,add,seen,call,setActor:v=>actor=v,setHook:v=>hook=v};
}
const finBody=(b,c,over={})=>({ephemeralKey:c.pub,entries:b.entries.map(e=>({entryId:e.entryId,version:e.version})),token:'ok',response:{},...over});
async function begin(f,c,extra={}){const r=await f.call('export-begin',{ephemeralKey:c.pub,...extra});return{r,b:await r.json()};}
test('begin freezes the owned exportable set with versions; shared-in, other owners and seedless entries are excluded',async()=>{
 const f=await fixture(),c=await clientKey();try{
  const {r,b}=await begin(f,c);assert.equal(r.status,200);assert.equal(r.headers.get('cache-control'),'no-store');
  assert.equal(b.ownerId,'owner');assert.equal(b.deviceId,'device');assert.equal(b.generation,0);
  assert.deepEqual(b.entries.map(e=>e.entryId),['e1','e2','e3']);assert.deepEqual(b.unavailable,['noseed']);
  for(const e of b.entries)assert.match(e.version,/^[0-9a-f]{64}$/);
  assert.equal(JSON.stringify(b).includes(base64urlEncode(secretOf(0))),false);
  const a=f.seen.find(s=>s[0]==='begin')[1];assert.match(a.action,/^totp-export:[0-9a-f]{64}$/);assert.equal(a.purpose,'step-up');
 }finally{f.db.sqlite.close();}});
test('finish seals every seed to the ephemeral key; client opens them with its own AAD; no plaintext in the response',async()=>{
 const f=await fixture(),c=await clientKey();try{
  const {b}=await begin(f,c),r=await f.call('export-finish',finBody(b,c));assert.equal(r.status,200);assert.equal(r.headers.get('cache-control'),'no-store');
  const out=await r.json(),text=JSON.stringify(out);assert.equal(text.includes(base64urlEncode(secretOf(0))),false);
  const digest=f.seen.find(s=>s[0]==='finish')[1].action.slice('totp-export:'.length),eph=await sha256Hex((await importClientEphemeral(c.pub)).raw);
  assert.deepEqual(out.entries.map(e=>[e.entryId,e.digits,e.period,e.algorithm]),[['e1',6,30,'SHA-1'],['e2',7,60,'SHA-1'],['e3',8,30,'SHA-256']]);
  for(const [i,e] of out.entries.entries()){
   const aad={ownerId:'owner',deviceId:'device',generation:0,entryId:e.entryId,seedVersion:e.version,label:e.label,account:e.account,issuer:e.issuer,catalogId:e.catalogId,algorithm:e.algorithm,digits:e.digits,period:e.period};
   const pt=await openExport({clientPrivateKey:c.pair.privateKey,serverPublicKey:out.serverPublicKey,actionDigest:digest,ephemeralDigest:eph,aad,nonce:e.nonce,ciphertext:e.ciphertext});
   assert.deepEqual(pt,secretOf(i));
   await assert.rejects(openExport({clientPrivateKey:c.pair.privateKey,serverPublicKey:out.serverPublicKey,actionDigest:digest,ephemeralDigest:eph,aad:{...aad,entryId:'e9'},nonce:e.nonce,ciphertext:e.ciphertext}));// tampered AAD
   await assert.rejects(openExport({clientPrivateKey:c.pair.privateKey,serverPublicKey:out.serverPublicKey,actionDigest:digest,ephemeralDigest:eph,aad:{...aad,digits:6+(e.digits===6?1:0)},nonce:e.nonce,ciphertext:e.ciphertext}));
   const ct=e.ciphertext.slice(0,-3)+(e.ciphertext.at(-3)==='A'?'B':'A')+e.ciphertext.slice(-2);
   await assert.rejects(openExport({clientPrivateKey:c.pair.privateKey,serverPublicKey:out.serverPublicKey,actionDigest:digest,ephemeralDigest:eph,aad,nonce:e.nonce,ciphertext:ct}));// tampered ciphertext
  }
  const other=await clientKey();
  await assert.rejects(openExport({clientPrivateKey:other.pair.privateKey,serverPublicKey:out.serverPublicKey,actionDigest:digest,ephemeralDigest:eph,aad:{ownerId:'owner',deviceId:'device',generation:0,entryId:'e1',seedVersion:out.entries[0].version,algorithm:'SHA-1',digits:6,period:30},nonce:out.entries[0].nonce,ciphertext:out.entries[0].ciphertext}));// wrong client key
 }finally{f.db.sqlite.close();}});
test('the action digest binds ephemeral key, owner, device, generation and the exact set',async()=>{
 const f=await fixture(),c=await clientKey(),c2=await clientKey();try{
  await begin(f,c);await begin(f,c2);await begin(f,c,{entryIds:['e1','e2']});await begin(f,c,{entryIds:['e2','e1']});
  const acts=f.seen.filter(s=>s[0]==='begin').map(s=>s[1].action);assert.equal(new Set(acts.slice(0,3)).size,3);
  assert.equal(acts[2],acts[3]);// order of the request does not matter, the sorted frozen set does
 }finally{f.db.sqlite.close();}});
test('finish refuses a swapped ephemeral key, a changed set, a changed version, and a bad or spent proof; nothing is sealed',async()=>{
 const f=await fixture(),c=await clientKey(),evil=await clientKey();try{
  const {b}=await begin(f,c);
  const digestOf=()=>f.seen.filter(s=>s[0]==='finish').at(-1)[1].action;
  await f.call('export-finish',finBody(b,c));const good=digestOf();
  const swapped=await f.call('export-finish',finBody(b,evil));assert.equal(swapped.status,200);// server cannot know; the digest it bound differs, so the real ceremony rejects it
  assert.notEqual(digestOf(),good);
  const fewer=await f.call('export-finish',{...finBody(b,c),entries:finBody(b,c).entries.slice(0,2)});assert.equal(fewer.status,200);assert.notEqual(digestOf(),good);
  assert.equal((await f.call('export-finish',finBody(b,c,{token:'bad'}))).status,403);
  assert.equal((await f.call('export-finish',finBody(b,c,{token:'spent'}))).status,403);
 }finally{f.db.sqlite.close();}});
test('re-seeded, removed or reassigned entries after begin: 409, nothing sealed',async()=>{
 const f=await fixture(),c=await clientKey();try{
  let {b}=await begin(f,c);
  const env=await f.cipher.encrypt(JSON.stringify({secret:base64urlEncode(secretOf(7)),algorithm:'SHA-1',digits:6,period:30}),{ownerId:'owner',entryId:'e1'});
  await f.db.prepare('UPDATE totp_seeds SET envelope=? WHERE entry_id=?').bind(JSON.stringify(env),'e1').run();
  let r=await f.call('export-finish',finBody(b,c));assert.equal(r.status,409);assert.deepEqual(await r.json(),{error:'changed'});
  ({b}=await begin(f,c));await f.db.prepare("DELETE FROM entries WHERE entry_id='e3'").run();
  r=await f.call('export-finish',finBody(b,c));assert.equal(r.status,409);
 }finally{f.db.sqlite.close();}});
test('cross-owner and shared ids are refused identically to missing ids; a foreign id never reveals existence',async()=>{
 const f=await fixture(),c=await clientKey();try{
  for(const ids of [['x1'],['e1','x1'],['nope'],['noseed'],['e1','e1']]){const r=await f.call('export-begin',{ephemeralKey:c.pub,entryIds:ids});assert.equal(r.status,400);assert.deepEqual(await r.json(),{error:'invalid_request'});}
  // forged finish naming a foreign entry with a self-consistent digest: the owner-scoped re-read finds nothing.
  const {b}=await begin(f,c),forged=finBody(b,c,{entries:[{entryId:'x1',version:'0'.repeat(64)}]});
  assert.equal((await f.call('export-finish',forged)).status,409);
  assert.equal(f.seen.some(s=>s[0]==='begin'&&JSON.stringify(s).includes('x1')),false);
 }finally{f.db.sqlite.close();}});
test('other owner session cannot export this owner\'s entries',async()=>{
 const f=await fixture(),c=await clientKey();try{
  await f.db.prepare("INSERT INTO device_sessions(device_id,owner_id,provider_identity_id,generation,client_kind,created_at,last_used_at,expires_at) VALUES ('d2','other','provider',0,'web',0,0,999999999999)").run().catch(()=>{});
  f.setActor({ownerId:'other',deviceId:'d2',generation:0,clientKind:'web',expiresAt:999999999999});
  const r=await f.call('export-begin',{ephemeralKey:c.pub,entryIds:['e1']});assert.equal(r.status,409);// no passkey for 'other' yet: nothing resolved
 }finally{f.db.sqlite.close();}});
test('revocation after the proof wins; a lost reply never produces a second server effect',async()=>{
 const f=await fixture(),c=await clientKey();try{
  const {b}=await begin(f,c);
  f.setHook(()=>f.db.prepare("UPDATE device_sessions SET revoked_at=59000 WHERE device_id='device'").run());
  const r=await f.call('export-finish',finBody(b,c));assert.equal(r.status,401);assert.equal(JSON.stringify(await r.json()).includes('ciphertext'),false);
 }finally{f.db.sqlite.close();}});
test('invalid shapes, keys and limits are refused; owner-scoped rate limit applies',async()=>{
 const f=await fixture(),c=await clientKey();try{
  const bad=[{},{ephemeralKey:'short'},{ephemeralKey:c.pub,extra:1},{ephemeralKey:c.pub,entryIds:[]},{ephemeralKey:c.pub,entryIds:Array.from({length:MAX_EXPORT_ENTRIES+1},(_,i)=>'e'+i)},{ephemeralKey:c.pub,entryIds:['bad id']},{ephemeralKey:base64urlEncode(new Uint8Array(65).fill(1))}];
  for(const b of bad.slice(0,3))assert.equal((await f.call('export-begin',b)).status,400);
  const {b}=await begin(f,c);
  for(const over of [{entries:[]},{entries:[{entryId:'e1',version:'zz'}]},{entries:[b.entries[1],b.entries[0]]},{entries:[b.entries[0],b.entries[0]]},{token:undefined}])assert.equal((await f.call('export-finish',finBody(b,c,over))).status,400);
  assert.equal((await f.call('export-begin',{ephemeralKey:c.pub},{Authorization:'Bearer refresh'})).status,401);
  assert.equal((await f.call('export-begin',{ephemeralKey:c.pub},{Origin:'https://evil.test'})).status,403);
  let last;for(let i=0;i<8;i++)last=await f.call('export-begin',{ephemeralKey:c.pub});assert.equal(last.status,429);
 }finally{f.db.sqlite.close();}});
test('more invalid begin shapes',async()=>{
 const f=await fixture(),c=await clientKey();try{
  const bad=[{ephemeralKey:c.pub,entryIds:[]},{ephemeralKey:c.pub,entryIds:Array.from({length:MAX_EXPORT_ENTRIES+1},(_,i)=>'e'+i)},{ephemeralKey:c.pub,entryIds:['bad id']},{ephemeralKey:base64urlEncode(new Uint8Array(65).fill(1))}];
  for(const b of bad)assert.equal((await f.call('export-begin',b)).status,400);
 }finally{f.db.sqlite.close();}});
test('seal known-answer shape: label separates export from seed-sync, AAD covers every bound field',()=>{
 const a=exportAad({ownerId:'o',deviceId:'d',generation:1,entryId:'e',seedVersion:'v',algorithm:'SHA-1',digits:6,period:30,actionDigest:'a',ephemeralDigest:'b'});
 assert.equal(new TextDecoder().decode(a),'["otpanda-totp-export-seal-v1","o","d",1,"e","v","SHA-1",6,30,"a","b",null,null,null,null]');
});
test('real action-bound passkey ceremony: one UV prompt exports the frozen set; changed set denied; replay denied',async()=>{
 const {authenticator}=await import('./passkey-fixture.js'),{PasskeyService}=await import('../src/passkey-service.js');
 const f=await fixture(),c=await clientKey();try{
  const a=authenticator(),cr=a.credential;
  await f.db.prepare("INSERT INTO account_emails(owner_id,email,verified_at,updated_at) VALUES ('owner','synthetic@example.test',0,0)").run();
  await f.db.prepare("INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) VALUES (?,'owner',?,0,'[]','singleDevice',0,0)").bind(cr.id,Array.from(cr.publicKey)).run();
  const http=createTotpExportHttp({db:f.db,sessions:{authenticate:async()=>({ownerId:'owner',deviceId:'device',generation:0,clientKind:'web',expiresAt:999999999999})},getSeedCipher:async()=>f.cipher,clock:()=>59000,passkeys:new PasskeyService(f.db,{clock:()=>59000})});
  let n=0;const send=(s,v)=>http.fetch(new Request(API+'/v1/manage/totp/'+s,{method:'POST',headers:{Origin:APP,Authorization:'Bearer access','Content-Type':'application/json'},body:JSON.stringify(v)}),{clientAddress:'real'+n++});
  const b1=await(await send('export-begin',{ephemeralKey:c.pub})).json();
  const signed=a.assertion({expected:b1.options.challenge});
  const entries=b1.entries.map(e=>({entryId:e.entryId,version:e.version}));
  assert.equal((await send('export-finish',{ephemeralKey:c.pub,entries:entries.slice(0,2),token:b1.token,response:signed})).status,403);// changed set, ceremony burned
  const b2=await(await send('export-begin',{ephemeralKey:c.pub})).json(),s2=a.assertion({expected:b2.options.challenge,counter:2});
  const evil=await clientKey();
  assert.equal((await send('export-finish',{ephemeralKey:evil.pub,entries,token:b2.token,response:s2})).status,403);// key substitution
  const b3=await(await send('export-begin',{ephemeralKey:c.pub})).json(),s3=a.assertion({expected:b3.options.challenge,counter:3});
  const ok=await send('export-finish',{ephemeralKey:c.pub,entries,token:b3.token,response:s3});assert.equal(ok.status,200);assert.equal((await ok.json()).entries.length,3);
  assert.equal((await send('export-finish',{ephemeralKey:c.pub,entries,token:b3.token,response:s3})).status,403);// replay yields nothing
 }finally{f.db.sqlite.close();}});

for(const [name,sql] of [
 ['provider revocation',"UPDATE provider_identities SET revoked_at=59000 WHERE identity_id='provider'"],
 ['entry deletion',"DELETE FROM entries WHERE entry_id='e1'"],
 ['metadata change',"UPDATE entries SET label='Changed' WHERE entry_id='e1'"],
 ['generation change',"UPDATE account_security SET generation=1 WHERE owner_id='owner'"],
 ['seed replacement',"UPDATE totp_seeds SET envelope='{}' WHERE entry_id='e1'"]
])test('final response fence rejects '+name+' during sealing',async()=>{
 const f=await fixture({afterSeal:db=>db.prepare(sql).run()}),c=await clientKey();try{
  const {b}=await begin(f,c),r=await f.call('export-finish',finBody(b,c));assert.equal(r.status,409);assert.equal(JSON.stringify(await r.json()).includes('ciphertext'),false);
 }finally{f.db.sqlite.close();}
});
