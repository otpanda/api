import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {database} from './sqlite-helper.js';
import {SeedCipher} from '../src/seed-cipher.js';
import {TotpSeedStore} from '../src/totp-seeds.js';
import {SeedSync,MAX_BATCH,seedSyncEnrollAction,entriesDigest} from '../src/seed-sync.js';
import {seedSyncProofMessage,verifySeedSyncProof,PURPOSE_FIELDS} from '../src/seed-sync-proof.js';
import {sealBatch,openSealed,sealAad,importClientEphemeral,sha256Hex} from '../src/seed-sync-seal.js';
import {createSeedSyncHttp} from '../src/seed-sync-http.js';
import {base64urlEncode,base64urlDecode} from '../src/tokens.js';
import {hashText} from '../src/sessions.js';
const kid=()=>[...crypto.getRandomValues(new Uint8Array(16))].map(b=>b.toString(16).padStart(2,'0')).join('');
const NOW=1800000000000,INSTALL='i'.repeat(22),API='https://otpanda-api.abrahammurciano.workers.dev';
const cipher=new SeedCipher({keys:new Map([['t',await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt'])]]),activeKeyId:'t'});
const pubJwk=async k=>{const j=await crypto.subtle.exportKey('jwk',k);return {kty:j.kty,crv:j.crv,x:j.x,y:j.y};};
async function fixture(){
 const db=database(),sq=db.sqlite;let now=NOW;
 sq.prepare('INSERT INTO accounts(owner_id,created_at) VALUES(?,?)').run('owner',NOW);sq.prepare('INSERT INTO account_security(owner_id) VALUES(?)').run('owner');
 sq.prepare('INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) VALUES(?,?,?,?,?,?,?,?)').run('cred','owner',new Uint8Array([1]),0,'[]','singleDevice',0,NOW);
 sq.prepare("INSERT INTO device_sessions(device_id,owner_id,credential_id,provider_identity_id,generation,client_kind,created_at,last_used_at,expires_at) VALUES('dev','owner','cred',NULL,0,'android',0,0,9999999999999)").run();
 const svc=new SeedSync({db,cipher,clock:()=>now}),seeds=new TotpSeedStore(db,cipher),user={ownerId:'owner',deviceId:'dev',generation:0};
 const kp=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']),jwk=await pubJwk(kp.publicKey);
 const sign=async(p,c)=>base64urlEncode(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},kp.privateKey,seedSyncProofMessage(p,c))));
 const addEntry=async(id,secretLen=20,over={})=>{sq.prepare("INSERT OR IGNORE INTO services(service_id,name) VALUES('custom-totp','A')").run();sq.prepare("INSERT INTO entries(entry_id,owner_id,service_id,label,created_at) VALUES(?,?,?,?,?)").run(id,'owner','custom-totp','L',NOW);return seeds.putSeed('owner',id,{secret:Uint8Array.from({length:secretLen},(_,i)=>i+1),algorithm:'SHA-1',digits:6,period:30,...over},NOW);};
 const enroll=async(k=kp,j=jwk,install=INSTALL,keyId=kid())=>{const action=await seedSyncEnrollAction({ownerId:'owner',installId:install,keyId,publicJwk:j,generation:0}),c=await svc.enrollBegin({user,installId:install,keyId,publicJwk:j,strongProof:{purpose:'step-up',ownerId:'owner',generation:0,credentialId:'cred',actionDigest:action,verifiedAt:now}});if(!c)return;const sig=base64urlEncode(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},k.privateKey,seedSyncProofMessage('seed-sync-enroll',c.challenge))));return svc.enrollFinish({user,token:c.token,signature:sig});};
 const snapshot=async(keyId,epoch=1,sig)=>{const c=await svc.snapshotBegin({user,keyId,epoch});return svc.snapshotFinish({user,token:c.token,signature:sig??await sign('seed-sync-snapshot',c.challenge)});};
 // Native simulation: ephemeral key, signed batch, then open with the AAD built from the device's OWN ticket-checked context.
 const batch=async(keyId,entries,{epoch=1,tamper}={})=>{const eph=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']),raw=base64urlEncode(new Uint8Array(await crypto.subtle.exportKey('raw',eph.publicKey)));
  const c=await svc.batchBegin({user,keyId,epoch,ephemeralKey:raw,entries});if(!c)return {};
  if(tamper)tamper(c);
  const r=await svc.batchFinish({user,token:c.token,signature:await sign('seed-sync-batch',c.challenge)});return {c,r,eph,raw};};
 return {db,sq,svc,seeds,user,jwk,kp,sign,enroll,snapshot,batch,addEntry,setNow:n=>now=n,close:()=>sq.close()};
}
test('triggers: version, revision and tombstones move inside the writing statement; cascades and account deletion work',async()=>{
 const f=await fixture();try{
  assert.equal(await f.addEntry('e1'),true);
  const row=()=>f.sq.prepare('SELECT seed_version v,algorithm a,seed_bytes b FROM totp_seeds WHERE entry_id=?').get('e1'),rev=()=>f.sq.prepare("SELECT revision r FROM seed_sync_owner WHERE owner_id='owner'").get().r;
  assert.deepEqual({...row()},{v:1,a:'SHA-1',b:20});assert.equal(rev(),1);
  assert.equal(await f.seeds.putSeed('owner','e1',{secret:new Uint8Array(20).fill(9),algorithm:'SHA-256',digits:8,period:60},NOW+1),true);
  assert.deepEqual({...row()},{v:2,a:'SHA-256',b:20});assert.equal(rev(),2);
  assert.equal(await f.seeds.removeSeed('owner','e1'),true);assert.equal(rev(),3);
  assert.deepEqual({...f.sq.prepare('SELECT entry_id e,revision r FROM seed_sync_tombstones').get()},{e:'e1',r:3});
  await f.addEntry('e2');f.sq.prepare("DELETE FROM entries WHERE entry_id='e2'").run();assert.equal(rev(),5);assert.equal(f.sq.prepare("SELECT count(*) n FROM seed_sync_tombstones").get().n,2);
  await f.addEntry('e3');f.sq.prepare("DELETE FROM accounts WHERE owner_id='owner'").run();assert.equal(f.sq.prepare('SELECT count(*) n FROM seed_sync_owner').get().n,0);
 }finally{f.close();}});
test('three purposes are separate: a signature for one never verifies as another, every field is bound',async()=>{
 const v=JSON.parse(readFileSync(new URL('./seed-sync-vector.json',import.meta.url)));
 for(const [p,x] of Object.entries(v.proofs)){
  assert.equal(await verifySeedSyncProof({jwk:v.signing.publicJwk,purpose:p,challenge:x.challenge,signature:x.signature,now:1800000000000}),true,p);
  assert.equal(Buffer.from(seedSyncProofMessage(p,x.challenge)).toString('base64'),x.message,p);
  for(const q of Object.keys(PURPOSE_FIELDS))if(q!==p)assert.equal(await verifySeedSyncProof({jwk:v.signing.publicJwk,purpose:q,challenge:x.challenge,signature:x.signature,now:1800000000000}),false,p+' as '+q);
  for(const field of PURPOSE_FIELDS[p]){const c={...x.challenge},o=c[field];c[field]=typeof o==='number'?o+1:typeof o==='string'&&o.length===64?(o[0]==='a'?'b':'a')+o.slice(1):o.length===43?'B'+o.slice(1):o+'x';assert.equal(await verifySeedSyncProof({jwk:v.signing.publicJwk,purpose:p,challenge:c,signature:x.signature,now:1800000000000}),false,p+' field '+field);}
  assert.equal(await verifySeedSyncProof({jwk:v.signing.publicJwk,purpose:p,challenge:x.challenge,signature:x.signature,now:1800000120000}),false,'expired');
  assert.throws(()=>seedSyncProofMessage(p,{...x.challenge,extra:1}));
 }});
test('seal: shared known-answer vector, round trip, and any AAD or key change fails',async()=>{
 const v=JSON.parse(readFileSync(new URL('./seed-sync-vector.json',import.meta.url))).seal;
 const priv=await crypto.subtle.importKey('jwk',v.clientPrivateJwk,{name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
 const open=(over={})=>openSealed({clientPrivateKey:priv,serverPublicKey:v.serverPublicKey,challengeDigest:v.challengeDigest,ephemeralDigest:v.ephemeralDigest,aad:v.aad,nonce:v.nonce,ciphertext:v.ciphertext,...over});
 assert.equal(Buffer.from(await open()).toString('base64'),v.secret);
 assert.equal(Buffer.from(sealAad({...v.aad,challengeDigest:v.challengeDigest,ephemeralDigest:v.ephemeralDigest})).toString('base64'),v.aadBytes);
 for(const aad of [{ownerId:'x'},{deviceId:'x'},{epoch:8},{entryId:'x'},{seedVersion:4},{algorithm:'SHA-256'},{digits:7},{period:31}])await assert.rejects(open({aad:{...v.aad,...aad}}));
 await assert.rejects(open({challengeDigest:'f'.repeat(64)}));await assert.rejects(open({ephemeralDigest:'f'.repeat(64)}));
 const other=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);await assert.rejects(open({clientPrivateKey:other.privateKey}));
 assert.equal(await importClientEphemeral('A'.repeat(87)),undefined);
 const all=JSON.parse(readFileSync(new URL('./seed-sync-vector.json',import.meta.url)));
 assert.ok(await importClientEphemeral(v.clientPublicRaw));
 for(const [name,bad] of Object.entries(all.badPoints))assert.equal(await importClientEphemeral(bad),undefined,name);
 for(const [a,b64] of Object.entries(all.algorithmAads))assert.equal(Buffer.from(sealAad({...v.aad,algorithm:a,challengeDigest:v.challengeDigest,ephemeralDigest:v.ephemeralDigest})).toString('base64'),b64,a);
});
test('enrollment needs the exact action-bound passkey proof, a fresh key, and supersedes the previous key of the same install',async()=>{
 const f=await fixture();try{
  const K0=kid(),action=await seedSyncEnrollAction({ownerId:'owner',installId:INSTALL,keyId:K0,publicJwk:f.jwk,generation:0}),proof={purpose:'step-up',ownerId:'owner',generation:0,credentialId:'cred',actionDigest:action,verifiedAt:NOW};
  for(const bad of [{actionDigest:'0'.repeat(64)},{purpose:'recover-access'},{ownerId:'x'},{generation:1},{verifiedAt:NOW-120000},{credentialId:undefined}])assert.equal(await f.svc.enrollBegin({user:f.user,installId:INSTALL,keyId:K0,publicJwk:f.jwk,strongProof:{...proof,...bad}}),undefined,JSON.stringify(bad));
  assert.equal(await f.svc.enrollBegin({user:f.user,installId:INSTALL,keyId:kid(),publicJwk:f.jwk,strongProof:proof}),undefined,'proof for another key id (v2 digest binds the id)');
  for(const badId of [undefined,'',K0.toUpperCase(),K0.slice(1),K0+'0','g'.repeat(32),crypto.randomUUID()])assert.equal(await f.svc.enrollBegin({user:f.user,installId:INSTALL,keyId:badId,publicJwk:f.jwk,strongProof:proof}),undefined,'bad key id '+badId);
  assert.equal(await f.svc.enrollBegin({user:f.user,installId:'short',keyId:K0,publicJwk:f.jwk,strongProof:proof}),undefined);
  const first=await f.enroll(undefined,undefined,undefined,K0);assert.equal(first?.keyId,K0,'the client id is the server id');
  assert.equal(await f.enroll(),undefined,'same public key is never re-enrolled');
  const kp2=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']),second=await f.enroll(kp2,await pubJwk(kp2.publicKey));
  assert.ok(second.keyId);
  assert.equal(f.sq.prepare('SELECT revoked_reason r FROM seed_sync_keys WHERE key_id=?').get(first.keyId).r,'superseded');
  assert.equal(f.sq.prepare("SELECT count(*) n FROM seed_sync_keys WHERE revoked_at IS NULL").get().n,1);
  assert.equal(f.sq.prepare("SELECT count(*) n FROM seed_sync_events WHERE kind='enrolled'").get().n,2);
 }finally{f.close();}});
test('enroll finish: wrong signature burns the challenge and inserts nothing; session loss denies',async()=>{
 const f=await fixture();try{
  const action=await seedSyncEnrollAction({ownerId:'owner',installId:INSTALL,keyId:'a'.repeat(32),publicJwk:f.jwk,generation:0}),mk=()=>f.svc.enrollBegin({user:f.user,installId:INSTALL,keyId:'a'.repeat(32),publicJwk:f.jwk,strongProof:{purpose:'step-up',ownerId:'owner',generation:0,credentialId:'cred',actionDigest:action,verifiedAt:NOW}});
  const c=await mk(),other=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign']),bad=base64urlEncode(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},other.privateKey,seedSyncProofMessage('seed-sync-enroll',c.challenge))));
  assert.equal(await f.svc.enrollFinish({user:f.user,token:c.token,signature:bad}),undefined);
  assert.equal(await f.svc.enrollFinish({user:f.user,token:c.token,signature:await f.sign('seed-sync-enroll',c.challenge)}),undefined,'burned');
  const d=await mk();f.sq.exec("UPDATE device_sessions SET revoked_at=1 WHERE device_id='dev'");
  assert.equal(await f.svc.enrollFinish({user:f.user,token:d.token,signature:await f.sign('seed-sync-enroll',d.challenge)}),undefined);
  assert.equal(f.sq.prepare('SELECT count(*) n FROM seed_sync_keys').get().n,0);
 }finally{f.close();}});
test('snapshot: atomic revision with data, removal by absence, unsupported entries, echoes, one-use challenge, no secrets',async()=>{
 const f=await fixture();try{
  const {keyId}=await f.enroll();await f.addEntry('a');await f.addEntry('b');await f.addEntry('c');f.sq.exec("UPDATE totp_seeds SET seed_bytes=9 WHERE entry_id='b'");f.sq.exec("UPDATE totp_seeds SET algorithm='MD5' WHERE entry_id='c'");await f.addEntry('d');f.sq.exec("UPDATE totp_seeds SET algorithm=NULL WHERE entry_id='d'");
  const s=await f.snapshot(keyId,5);
  assert.equal(s.epoch,5);assert.equal(s.ownerId,'owner');assert.equal(s.deviceId,'dev');assert.equal(s.complete,true);assert.equal(s.revision,4);assert.equal(s.maxBatch,MAX_BATCH);
  assert.deepEqual(s.entries,[{entryId:'a',seedVersion:1,algorithm:'SHA-1',digits:6,period:30}]);
  assert.deepEqual(s.unsupported.map(u=>u.entryId+':'+u.reason).sort(),['b:unsupported','c:unsupported','d:metadata_pending']);
  assert.ok(/^[a-f0-9]{64}$/.test(s.challengeDigest));assert.equal(JSON.stringify(s).includes(base64urlEncode(Uint8Array.from({length:20},(_,i)=>i+1))),false);
  const c=await f.svc.snapshotBegin({user:f.user,keyId,epoch:1}),sig=await f.sign('seed-sync-snapshot',c.challenge);
  assert.ok(await f.svc.snapshotFinish({user:f.user,token:c.token,signature:sig}));assert.equal(await f.svc.snapshotFinish({user:f.user,token:c.token,signature:sig}),undefined,'replay');
  const d=await f.svc.snapshotBegin({user:f.user,keyId,epoch:1}),batchLike=await f.sign('seed-sync-snapshot',{...d.challenge,epoch:2});
  assert.equal(await f.svc.snapshotFinish({user:f.user,token:d.token,signature:batchLike}),undefined,'epoch is signature-bound');
  await f.seeds.removeSeed('owner','a');f.sq.exec(`UPDATE seed_sync_tombstones SET created_at=${NOW}`);const t=await f.snapshot(keyId,1);assert.equal(t.entries.length,0);assert.deepEqual(t.tombstones.map(x=>x.entryId),['a']);assert.ok(t.revision>s.revision);
 }finally{f.close();}});
test('batch: sealed round trip with native-built AAD; stale and removed are reported without sealing; no plaintext on the wire',async()=>{
 const f=await fixture();try{
  const {keyId}=await f.enroll();await f.addEntry('a');await f.addEntry('b');
  const {c,r,eph,raw}=await f.batch(keyId,[{entryId:'a',seedVersion:1},{entryId:'b',seedVersion:1}]);
  assert.equal(r.results.length,2);const a=r.results.find(x=>x.entryId==='a');
  const ephemeralDigest=await sha256Hex(base64urlDecode(raw,65)),challengeDigest=await hashText(c.challenge.challenge);
  assert.equal(r.challengeDigest,challengeDigest);assert.equal(c.challenge.entriesDigest,await entriesDigest([{entryId:'a',seedVersion:1},{entryId:'b',seedVersion:1}]));
  const opened=await openSealed({clientPrivateKey:eph.privateKey,serverPublicKey:r.serverPublicKey,challengeDigest,ephemeralDigest,aad:{ownerId:'owner',deviceId:'dev',epoch:1,entryId:'a',seedVersion:1,algorithm:a.algorithm,digits:a.digits,period:a.period},nonce:a.nonce,ciphertext:a.ciphertext});
  assert.deepEqual([...opened],Array.from({length:20},(_,i)=>i+1));
  const wire=JSON.stringify(r);for(const needle of [base64urlEncode(opened),Buffer.from(opened).toString('base64'),Buffer.from(opened).toString('hex')])assert.equal(wire.includes(needle),false);
  await assert.rejects(openSealed({clientPrivateKey:eph.privateKey,serverPublicKey:r.serverPublicKey,challengeDigest,ephemeralDigest,aad:{ownerId:'owner',deviceId:'dev',epoch:1,entryId:'a',seedVersion:2,algorithm:a.algorithm,digits:a.digits,period:a.period},nonce:a.nonce,ciphertext:a.ciphertext}));
  await f.seeds.putSeed('owner','a',{secret:new Uint8Array(20).fill(7),algorithm:'SHA-1',digits:6,period:30},NOW+1);await f.seeds.removeSeed('owner','b');
  const s=await f.batch(keyId,[{entryId:'a',seedVersion:1},{entryId:'b',seedVersion:1}]);
  assert.deepEqual(s.r.results.map(x=>x.entryId+':'+x.status).sort(),['a:stale','b:removed']);assert.equal(s.r.serverPublicKey,null);
 }finally{f.close();}});
test('batch: set bound by signature, size limit, one use, key and generation state only after a verified signature',async()=>{
 const f=await fixture();try{
  const {keyId}=await f.enroll();for(const id of ['a','b','c','d'])await f.addEntry(id);
  assert.equal((await f.batch(keyId,['a','b','c','d'].map(entryId=>({entryId,seedVersion:1})))).c,undefined,'over maxBatch');
  assert.equal((await f.batch(keyId,[{entryId:'a',seedVersion:1},{entryId:'a',seedVersion:1}])).c,undefined,'duplicates');
  const swapped=await f.batch(keyId,[{entryId:'a',seedVersion:1}],{tamper:c=>f.sq.exec(`UPDATE seed_sync_challenges SET entries='[{"entryId":"b","seedVersion":1}]' WHERE nonce='${c.challenge.challenge}'`)});
  assert.equal(swapped.r,undefined,'signed entry set is bound');
  const eph=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']),raw=base64urlEncode(new Uint8Array(await crypto.subtle.exportKey('raw',eph.publicKey)));
  const c=await f.svc.batchBegin({user:f.user,keyId,epoch:1,ephemeralKey:raw,entries:[{entryId:'a',seedVersion:1}]}),sig=await f.sign('seed-sync-batch',c.challenge);
  assert.ok((await f.svc.batchFinish({user:f.user,token:c.token,signature:sig})).serverPublicKey);assert.equal(await f.svc.batchFinish({user:f.user,token:c.token,signature:sig}),undefined);
  // Revoked key: an unsigned or badly signed request learns nothing; a verified one gets the definitive code.
  await f.svc.revoke({ownerId:'owner',keyId});
  const r1=await f.svc.batchBegin({user:f.user,keyId,epoch:1,ephemeralKey:raw,entries:[{entryId:'a',seedVersion:1}]});assert.ok(r1,'begin is opaque about key state');
  assert.equal(await f.svc.batchFinish({user:f.user,token:r1.token,signature:'A'.repeat(86)}),undefined);
  const r2=await f.svc.batchBegin({user:f.user,keyId,epoch:1,ephemeralKey:raw,entries:[{entryId:'a',seedVersion:1}]});
  assert.deepEqual(await f.svc.batchFinish({user:f.user,token:r2.token,signature:await f.sign('seed-sync-batch',r2.challenge)}),{error:'key-revoked'});
  assert.equal(f.sq.prepare("SELECT count(*) n FROM seed_sync_events WHERE kind='denied' AND reason='key-revoked'").get().n,1);
 }finally{f.close();}});
test('generation bump is per request: definitive code only after a verified signature; snapshot too',async()=>{
 const f=await fixture();try{
  const {keyId}=await f.enroll(),c=await f.svc.snapshotBegin({user:f.user,keyId,epoch:1});
  f.sq.exec('UPDATE account_security SET generation=1');
  assert.equal(await f.svc.snapshotFinish({user:f.user,token:c.token,signature:'A'.repeat(86)}),undefined,'unsigned caller gets no code');
  const d=await f.svc.snapshotBegin({user:f.user,keyId,epoch:1});
  // The caller's session (generation 0) no longer exists after a bump, so begin is opaque; simulate a session at the new generation.
  assert.equal(d,undefined);
  f.sq.exec("UPDATE device_sessions SET generation=1 WHERE device_id='dev'");const u={...f.user,generation:1};
  const e=await f.svc.snapshotBegin({user:u,keyId,epoch:1});
  assert.deepEqual(await f.svc.snapshotFinish({user:u,token:e.token,signature:await f.sign('seed-sync-snapshot',e.challenge)}),{error:'generation-changed'});
 }finally{f.close();}});
test('proof expiry is the stored challenge expiry: a client cannot supply or extend it',async()=>{
 const f=await fixture();try{
  const {keyId}=await f.enroll(),c=await f.svc.snapshotBegin({user:f.user,keyId,epoch:1});
  const later=await f.sign('seed-sync-snapshot',{...c.challenge,expiresAt:c.challenge.expiresAt+1000});
  assert.equal(await f.svc.snapshotFinish({user:f.user,token:c.token,signature:later}),undefined);
  const d=await f.svc.snapshotBegin({user:f.user,keyId,epoch:1});f.setNow(NOW+120000);
  assert.equal(await f.svc.snapshotFinish({user:f.user,token:d.token,signature:await f.sign('seed-sync-snapshot',d.challenge)}),undefined,'expired');
 }finally{f.close();}});
test('challenge caps, sweep, and another owner or session cannot use a challenge',async()=>{
 const f=await fixture();try{
  const {keyId}=await f.enroll();for(let i=0;i<8;i++)assert.ok(await f.svc.snapshotBegin({user:f.user,keyId,epoch:i}));
  assert.equal(await f.svc.snapshotBegin({user:f.user,keyId,epoch:9}),undefined);
  f.setNow(NOW+200000);const c=await f.svc.snapshotBegin({user:f.user,keyId,epoch:1});assert.ok(c);
  assert.equal(await f.svc.snapshotFinish({user:{...f.user,deviceId:'other'},token:c.token,signature:await f.sign('seed-sync-snapshot',c.challenge)}),undefined);
  assert.equal(await f.svc.snapshotBegin({user:f.user,keyId:'unknown',epoch:1}),undefined);
 }finally{f.close();}});
test('backfill fills non-secret metadata for old rows',async()=>{
 const f=await fixture();try{
  await f.addEntry('a');f.sq.exec('UPDATE totp_seeds SET algorithm=NULL,digits=NULL,period=NULL,seed_bytes=NULL');
  assert.equal(await f.svc.backfillMetadata(),1);assert.deepEqual({...f.sq.prepare('SELECT algorithm a,digits d,period p,seed_bytes b,seed_version v FROM totp_seeds').get()},{a:'SHA-1',d:6,p:30,b:20,v:1});
 }finally{f.close();}});
test('http: flag off is a 404 before any limiter; android-only, exact keys, definitive codes; happy path',async()=>{
 const f=await fixture();try{
  const sessions={authenticate:async()=>({ownerId:'owner',deviceId:'dev',generation:0,clientKind:'android',expiresAt:9999999999999})};
  let touched=0;const spy={prepare(){touched++;throw new Error('db')}};
  const off=createSeedSyncHttp({db:spy,sessions,service:f.svc});
  const post=(h,path,body,hd={})=>h.fetch(new Request(API+'/v1/manage/seed-sync/'+path,{method:'POST',headers:{Authorization:'Bearer a','Content-Type':'application/json',...hd},body:JSON.stringify(body)}),{clientAddress:'a'+Math.random()});
  assert.equal((await post(off,'snapshot-begin',{keyId:'k',epoch:1})).status,404);assert.equal(touched,0);
  const passkeys={begin:async()=>({token:'t'}),finishAuthentication:async({action})=>({ownerId:'owner',credentialId:'cred',generation:0,verifiedAt:NOW,purpose:'step-up',actionDigest:await hashText(action)})};
  const on=createSeedSyncHttp({db:f.db,sessions,service:f.svc,passkeys,enabled:true,clock:()=>NOW});
  assert.equal((await post(on,'snapshot-begin',{keyId:'k',epoch:1},{Origin:'https://otpanda.github.io'})).status,403);
  assert.equal((await post(on,'snapshot-begin',{keyId:'k',epoch:1,extra:1})).status,400);
  assert.equal((await post(on,'snapshot-begin',{keyId:'unknown',epoch:1})).status,409);
  const HK=kid();assert.equal((await post(on,'enroll-begin',{installId:INSTALL,publicJwk:f.jwk,token:'x',response:{}})).status,400,'keyId is required');assert.equal((await post(on,'enroll-begin',{installId:INSTALL,keyId:'bad',publicJwk:f.jwk,token:'x',response:{}})).status,400);
  assert.equal((await post(on,'stepup-begin',{installId:INSTALL,publicJwk:f.jwk})).status,400);
  const ctx=await post(on,'context',{});assert.equal(ctx.status,200);assert.deepEqual(await ctx.json(),{generation:0});assert.equal((await post(on,'context',{x:1})).status,400);assert.equal(ctx.headers.get('cache-control'),'no-store');
  const enrollBegin=await (await post(on,'enroll-begin',{installId:INSTALL,keyId:HK,publicJwk:f.jwk,token:'x',response:{}})).json();assert.ok(enrollBegin.token);assert.equal(enrollBegin.challenge.keyId,HK);
  const fin=await post(on,'enroll-finish',{token:enrollBegin.token,signature:await f.sign('seed-sync-enroll',enrollBegin.challenge)});assert.equal(fin.status,200);
  const {keyId}=await fin.json();await f.addEntry('a');
  const sb=await (await post(on,'snapshot-begin',{keyId,epoch:3})).json(),sf=await post(on,'snapshot-finish',{token:sb.token,signature:await f.sign('seed-sync-snapshot',sb.challenge)});
  assert.equal(sf.status,200);assert.equal((await sf.json()).entries[0].entryId,'a');assert.equal(sf.headers.get('cache-control'),'no-store');
  await f.svc.revoke({ownerId:'owner',keyId});
  const sb2=await (await post(on,'snapshot-begin',{keyId,epoch:3})).json(),rv=await post(on,'snapshot-finish',{token:sb2.token,signature:await f.sign('seed-sync-snapshot',sb2.challenge)});
  assert.equal(rv.status,409);assert.deepEqual(await rv.json(),{error:'key-revoked'});
 }finally{f.close();}});
test('seed_version is strictly monotonic across delete and re-create of the same entry id',async()=>{
 const f=await fixture();try{
  const {keyId}=await f.enroll();await f.addEntry('a');
  const v1=(await f.snapshot(keyId,1)).entries[0].seedVersion;
  await f.seeds.removeSeed('owner','a');
  assert.equal(await f.seeds.putSeed('owner','a',{secret:new Uint8Array(20).fill(5),algorithm:'SHA-1',digits:6,period:30},NOW+1),true);
  const s=await f.snapshot(keyId,1);assert.ok(s.entries[0].seedVersion>v1,`${s.entries[0].seedVersion} > ${v1}`);
  assert.deepEqual(s.tombstones.map(t=>t.entryId),[],'re-create clears the tombstone');
  await f.seeds.putSeed('owner','a',{secret:new Uint8Array(20).fill(6),algorithm:'SHA-1',digits:6,period:30},NOW+2);
  assert.ok((await f.snapshot(keyId,1)).entries[0].seedVersion>s.entries[0].seedVersion);
  // A pre-migration row (version 1) is also superseded by the next change.
  await f.addEntry('b');f.sq.exec("UPDATE totp_seeds SET seed_version=1 WHERE entry_id='b'");await f.seeds.putSeed('owner','b',{secret:new Uint8Array(20).fill(8),algorithm:'SHA-1',digits:6,period:30},NOW+3);
  assert.ok((await f.snapshot(keyId,1)).entries.find(e=>e.entryId==='b').seedVersion>1);
 }finally{f.close();}});
test('backfill moves the owner revision so a client sees the entry become representable; pending count reaches zero',async()=>{
 const f=await fixture();try{
  const {keyId}=await f.enroll();await f.addEntry('a');f.sq.exec('UPDATE totp_seeds SET algorithm=NULL,digits=NULL,period=NULL,seed_bytes=NULL');
  const before=await f.snapshot(keyId,1);assert.equal(before.entries.length,0);assert.equal(before.unsupported[0].reason,'metadata_pending');assert.equal(await f.svc.metadataPending(),1);
  assert.equal(await f.svc.backfillMetadata(),1);assert.equal(await f.svc.metadataPending(),0);
  const after=await f.snapshot(keyId,1);assert.equal(after.entries.length,1);assert.ok(after.revision>before.revision);
 }finally{f.close();}});
test('own-install revoke is key-signed with a derived reason; there is no session-only revoke; list shows last use; definitive code afterwards',async()=>{
 const f=await fixture();try{
  const {keyId}=await f.enroll();await f.snapshot(keyId,1);
  assert.equal(typeof f.svc.revokeKey,'undefined','no bearer-only revoke exists');
  assert.equal(await f.svc.revokeBegin({user:f.user,keyId:'unknown'}),undefined);
  f.sq.prepare('INSERT INTO accounts(owner_id,created_at) VALUES(?,?)').run('other',NOW);f.sq.prepare('INSERT INTO account_security(owner_id) VALUES(?)').run('other');
  assert.equal(await f.svc.revokeBegin({user:{ownerId:'other',deviceId:'dev',generation:0},keyId}),undefined,'another owner cannot begin');
  const l=await f.svc.listKeys({user:f.user});assert.equal(l.keys.length,1);assert.equal(l.keys[0].lastUsedAt,NOW);assert.equal(l.keys[0].revokedAt,null);
  const c=await f.svc.revokeBegin({user:f.user,keyId});
  assert.equal(await f.svc.revokeFinish({user:f.user,token:c.token,signature:await f.sign('seed-sync-snapshot',{...c.challenge,epoch:0})}),undefined,'wrong purpose signature is rejected');
  assert.equal(f.sq.prepare('SELECT revoked_at r FROM seed_sync_keys').get().r,null);
  const c2=await f.svc.revokeBegin({user:f.user,keyId});
  assert.deepEqual(await f.svc.revokeFinish({user:f.user,token:c2.token,signature:await f.sign('seed-sync-revoke',c2.challenge)}),{revoked:true});
  assert.equal(await f.svc.revokeFinish({user:f.user,token:c2.token,signature:await f.sign('seed-sync-revoke',c2.challenge)}),undefined,'one use');
  assert.equal(f.sq.prepare('SELECT revoked_reason r FROM seed_sync_keys').get().r,'disabled');
  const s=await f.svc.snapshotBegin({user:f.user,keyId,epoch:1});
  assert.deepEqual(await f.svc.snapshotFinish({user:f.user,token:s.token,signature:await f.sign('seed-sync-snapshot',s.challenge)}),{error:'key-revoked'});
  assert.equal(f.sq.prepare('SELECT last_device_id d FROM seed_sync_keys').get().d,f.user.deviceId,'last device recorded');
 }finally{f.close();}});
test('a session revoked while the batch is being read gets nothing, and no purge code',async()=>{
 const f=await fixture();try{
  const {keyId}=await f.enroll();await f.addEntry('a');
  const spy={decrypt:async(...a)=>{f.sq.exec("UPDATE device_sessions SET revoked_at=1");return cipher.decrypt(...a);},encrypt:(...a)=>cipher.encrypt(...a)};
  const svc=new SeedSync({db:f.db,cipher:spy,clock:()=>NOW}),eph=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']),raw=base64urlEncode(new Uint8Array(await crypto.subtle.exportKey('raw',eph.publicKey)));
  const c=await svc.batchBegin({user:f.user,keyId,epoch:1,ephemeralKey:raw,entries:[{entryId:'a',seedVersion:f.sq.prepare("SELECT seed_version v FROM totp_seeds").get().v}]});
  assert.equal(await svc.batchFinish({user:f.user,token:c.token,signature:await f.sign('seed-sync-batch',c.challenge)}),undefined);
 }finally{f.close();}});
test('per-key pull limit bounds an enrolled key even when per-owner limits are not reached',async()=>{
 const f=await fixture();try{
  const {keyId}=await f.enroll();let ok=0;for(let i=0;i<20;i++){f.sq.exec('DELETE FROM seed_sync_challenges');if(await f.svc.snapshotBegin({user:f.user,keyId,epoch:i}))ok++;}
  assert.equal(ok,12);
 }finally{f.close();}});
test('http revoke-begin/finish and list routes: exact keys, android session, no Origin',async()=>{
 const f=await fixture();try{
  const sessions={authenticate:async()=>({ownerId:'owner',deviceId:'dev',generation:0,clientKind:'android',expiresAt:9999999999999})};
  const on=createSeedSyncHttp({db:f.db,sessions,service:f.svc,enabled:true,clock:()=>NOW});
  const post=(path,body,hd={})=>on.fetch(new Request(API+'/v1/manage/seed-sync/'+path,{method:'POST',headers:{Authorization:'Bearer a','Content-Type':'application/json',...hd},body:JSON.stringify(body)}),{clientAddress:'a'+Math.random()});
  const {keyId}=await f.enroll();
  assert.equal((await post('list',{x:1})).status,400);
  assert.equal((await post('revoke',{keyId,reason:'remote'})).status,404);
  const l=await (await post('list',{})).json();assert.equal(l.keys[0].keyId,keyId);
  assert.equal((await post('revoke-begin',{keyId,reason:'x'})).status,400);
  assert.equal((await post('revoke-begin',{keyId},{Origin:'https://otpanda.github.io'})).status,403);
  const c=await (await post('revoke-begin',{keyId})).json();assert.ok(c.token);
  assert.equal((await post('revoke-finish',{token:c.token,signature:await f.sign('seed-sync-revoke',c.challenge)})).status,200);
  assert.equal(f.sq.prepare('SELECT revoked_reason r FROM seed_sync_keys').get().r,'disabled');
 }finally{f.close();}});
test('a session revoked between claim and link gets nothing and the key is not linked to the dead session',async()=>{
 const f=await fixture();try{
  const {keyId}=await f.enroll();await f.snapshot(keyId,1);
  const before=f.sq.prepare('SELECT last_device_id d FROM seed_sync_keys').get().d;
  const c=await f.svc.snapshotBegin({user:f.user,keyId,epoch:1}),sig=await f.sign('seed-sync-snapshot',c.challenge);
  const real=f.db.prepare.bind(f.db);let fired=false;
  f.db.prepare=q=>{if(!fired&&/SET last_device_id/.test(q)){fired=true;f.sq.exec('UPDATE device_sessions SET revoked_at=1');}return real(q);};
  assert.equal(await f.svc.snapshotFinish({user:f.user,token:c.token,signature:sig}),undefined);
  f.db.prepare=real;assert.ok(fired);assert.equal(f.sq.prepare('SELECT last_device_id d FROM seed_sync_keys').get().d,before);
 }finally{f.close();}});
test('status proof without a session: key-signed, one-use, same-shape begin, survives session cleanup, never purges on unknown/expired/bad/replay',async()=>{
 const f=await fixture();try{
  const {keyId}=await f.enroll();
  const shape=o=>[Object.keys(o).sort().join(),Object.keys(o.challenge).sort().join(),o.token.length,o.challenge.challenge.length];
  const real=await f.svc.statusBegin({keyId}),unk=await f.svc.statusBegin({keyId:'00000000-0000-4000-8000-000000000000'}),bad=await f.svc.statusBegin({keyId:7});
  assert.deepEqual(shape(real),shape(unk));assert.deepEqual(shape(real),shape(bad));
  const fin=async(c,purpose='seed-sync-status',over={})=>f.svc.statusFinish({token:c.token,signature:await f.sign(purpose,{...c.challenge,...over})});
  assert.deepEqual(await fin(real),{state:'active'});
  assert.equal(await fin(real),undefined,'replay');
  assert.equal(await fin(unk),undefined,'unknown key');
  const w=await f.svc.statusBegin({keyId});assert.equal(await f.svc.statusFinish({token:w.token,signature:await f.sign('seed-sync-revoke',{ownerId:'owner',keyId,deviceId:'x',generation:0,challenge:w.challenge.challenge,expiresAt:w.challenge.expiresAt})}),undefined,'wrong purpose');
  const e=await f.svc.statusBegin({keyId});assert.equal(await f.svc.statusFinish({token:e.token,signature:'A'.repeat(86)}),undefined,'bad signature');
  // Remote sign-out: revoke the key, delete every session row (cleanup), the status still answers key-revoked from the key row.
  f.sq.exec("UPDATE seed_sync_keys SET revoked_at=5,revoked_reason='remote'");f.sq.exec('DELETE FROM device_sessions');
  assert.deepEqual(await fin(await f.svc.statusBegin({keyId})),{state:'key-revoked'});
  f.sq.exec('UPDATE seed_sync_keys SET revoked_at=NULL,revoked_reason=NULL');f.sq.exec('UPDATE account_security SET generation=generation+1');
  assert.deepEqual(await fin(await f.svc.statusBegin({keyId})),{state:'generation-changed'});
  const x=await f.svc.statusBegin({keyId});f.clock&&0;f.sq.exec('UPDATE seed_sync_challenges SET expires_at=1');assert.equal(await fin(x),undefined,'expired');
  f.sq.exec('DELETE FROM seed_sync_keys');assert.equal(await fin(await f.svc.statusBegin({keyId})),undefined,'missing row is non-purging');
 }finally{f.close();}});
test('http status routes need no bearer, exact keys, no Origin; other routes still do',async()=>{
 const f=await fixture();try{
  const sessions={authenticate:async()=>undefined};
  const on=createSeedSyncHttp({db:f.db,sessions,service:f.svc,enabled:true,clock:()=>NOW});
  const post=(path,body,hd={})=>on.fetch(new Request(API+'/v1/manage/seed-sync/'+path,{method:'POST',headers:{'Content-Type':'application/json',...hd},body:JSON.stringify(body)}),{clientAddress:'a'+Math.random()});
  const {keyId}=await f.enroll();
  assert.equal((await post('snapshot-begin',{keyId,epoch:1})).status,401);
  assert.equal((await post('status-begin',{keyId,x:1})).status,400);
  assert.equal((await post('status-begin',{keyId},{Origin:'https://otpanda.github.io'})).status,403);
  const c=await (await post('status-begin',{keyId})).json();
  const r=await post('status-finish',{token:c.token,signature:await f.sign('seed-sync-status',c.challenge)});assert.equal(r.status,200);assert.deepEqual(await r.json(),{state:'active'});
  assert.equal((await post('status-finish',{token:c.token,signature:await f.sign('seed-sync-status',c.challenge)})).status,409);
 }finally{f.close();}});
test('challenge tokens are purpose-bound across all five finishes, in both directions',async()=>{
 const f=await fixture();try{
  const {keyId}=await f.enroll();
  const st=async()=>f.svc.statusBegin({keyId});
  const s1=await st();
  const sig=(c,extra={})=>f.sign('seed-sync-status',{keyId:c.keyId,challenge:c.challenge,expiresAt:c.expiresAt});
  // status token refused by every session finish (valid status signature, and valid signature for that finish's own purpose)
  const statusAs=async(c,purpose,fields)=>f.sign(purpose,{...fields,challenge:c.challenge,expiresAt:c.expiresAt});
  const own={ownerId:'owner',keyId,deviceId:'status',generation:0};
  assert.equal(await f.svc.snapshotFinish({user:f.user,token:s1.token,signature:await sig(s1.challenge)}),undefined);
  assert.equal(await f.svc.snapshotFinish({user:f.user,token:s1.token,signature:await statusAs(s1.challenge,'seed-sync-snapshot',{...own,epoch:0})}),undefined);
  assert.equal(await f.svc.revokeFinish({user:f.user,token:s1.token,signature:await statusAs(s1.challenge,'seed-sync-revoke',own)}),undefined);
  assert.equal(await f.svc.batchFinish({user:f.user,token:s1.token,signature:await sig(s1.challenge)}),undefined);
  assert.equal(await f.svc.enrollFinish({user:f.user,token:s1.token,signature:await sig(s1.challenge)}),undefined);
  assert.equal(f.sq.prepare("SELECT used_at u FROM seed_sync_challenges WHERE purpose='seed-sync-status'").get().u,null,'a refused finish does not spend a challenge of another purpose');
  // other tokens refused by status-finish, even with a valid status signature
  const used=()=>f.sq.prepare("SELECT count(*) n FROM seed_sync_challenges WHERE used_at IS NOT NULL AND purpose<>'seed-sync-status'").get().n,usedBefore=used();
  const snap=await f.svc.snapshotBegin({user:f.user,keyId,epoch:1}),rev=await f.svc.revokeBegin({user:f.user,keyId});
  for(const c of [snap,rev])assert.equal(await f.svc.statusFinish({token:c.token,signature:await sig({keyId,challenge:c.challenge.challenge,expiresAt:c.challenge.expiresAt})}),undefined);
  assert.equal(used(),usedBefore,'status-finish spends no other purpose');
  assert.deepEqual(await f.svc.statusFinish({token:s1.token,signature:await sig(s1.challenge)}),{state:'active'});
 }finally{f.close();}});
test('status begin: filling the outstanding-challenge cap or the key limit only blocks until the TTL passes; fake and failed answers are never "active"',async()=>{
 const f=await fixture();try{
  const {keyId}=await f.enroll();
  const sig=c=>f.sign('seed-sync-status',{keyId:c.keyId,challenge:c.challenge,expiresAt:c.expiresAt});
  const first=[];for(let i=0;i<8;i++)first.push(await f.svc.statusBegin({keyId}));
  const blocked=await f.svc.statusBegin({keyId});
  assert.equal(await f.svc.statusFinish({token:blocked.token,signature:await sig(blocked.challenge)}),undefined,'attacker-filled cap: the real begin gets a fake and finish is opaque, not active');
  assert.deepEqual(await f.svc.statusFinish({token:first[0].token,signature:await sig(first[0].challenge)}),{state:'active'},'an outstanding real challenge still works');
  f.setNow(NOW+120_000+61_000);
  const later=await f.svc.statusBegin({keyId});
  assert.deepEqual(await f.svc.statusFinish({token:later.token,signature:await sig(later.challenge)}),{state:'active'},'recovers after the TTL and the minute window');
 }finally{f.close();}});
test('account deletion cascades the key rows away, so status stays opaque and non-purging afterwards',async()=>{
 const f=await fixture();try{
  const {keyId}=await f.enroll();
  f.sq.exec('PRAGMA foreign_keys=ON');f.sq.prepare('DELETE FROM accounts WHERE owner_id=?').run('owner');
  assert.equal(f.sq.prepare('SELECT count(*) n FROM seed_sync_keys').get().n,0,'rows are removed with the account, with no tombstone and no revoke step');
  const c=await f.svc.statusBegin({keyId});assert.equal(await f.svc.statusFinish({token:c.token,signature:await f.sign('seed-sync-status',{keyId:c.challenge.keyId,challenge:c.challenge.challenge,expiresAt:c.challenge.expiresAt})}),undefined);
 }finally{f.close();}});
import {deliverSeedSyncNotices,seedSyncNoticeHealth} from '../src/seed-sync-notices.js';
import {notificationEmail} from '../src/email-templates.js';
test('new-device notice: written atomically with the key, delivered to the stored mailbox with a fixed template, retried then terminal; nothing for a failed enrollment',async()=>{
 const f=await fixture();try{
  f.sq.prepare('INSERT INTO account_emails(owner_id,email,verified_at,updated_at) VALUES(?,?,?,?)').run('owner','o@example.test',1,1);
  assert.equal(f.sq.prepare('SELECT count(*) n FROM seed_sync_notices').get().n,0);
  const {keyId}=await f.enroll();
  const rows=f.sq.prepare('SELECT * FROM seed_sync_notices').all();assert.equal(rows.length,1);assert.equal(rows[0].key_id,keyId);assert.equal(rows[0].kind,'enrolled');
  // a refused enrollment (same public key again) leaves no second notice
  assert.equal(await f.enroll(f.kp,f.jwk,'j'.repeat(22)),undefined);
  assert.equal(f.sq.prepare('SELECT count(*) n FROM seed_sync_notices').get().n,1);
  const sent=[];let now=NOW;
  assert.deepEqual(await deliverSeedSyncNotices({db:f.db,deliver:async m=>{sent.push(m);},clock:()=>now}),{delivered:1,failed:0,healed:0,pruned:0});
  assert.deepEqual(sent.map(m=>m.to),['o@example.test']);assert.equal(sent[0].kind,'seed-sync-enrolled');
  assert.deepEqual(await deliverSeedSyncNotices({db:f.db,deliver:async()=>{throw new Error('x');},clock:()=>now}),{delivered:0,failed:0,healed:0,pruned:0},'delivered notices are not sent again');
  // body is fixed and carries no identifiers
  const mail=notificationEmail('seed-sync-enrolled');const text=JSON.stringify(mail);
  assert.ok(!text.includes(keyId)&&!text.includes(INSTALL)&&/passkey/i.test(text));
  // transport accepts the kind
 }catch(e){throw e;}finally{f.close();}});
test('notice delivery: backoff, terminal failed_at after 5 attempts, missing mailbox never silent, lease prevents double claim',async()=>{
 const f=await fixture();try{
  await f.enroll();let now=NOW;const fail=async()=>{throw new Error('down');};
  for(let i=0;i<5;i++){const r=await deliverSeedSyncNotices({db:f.db,deliver:fail,clock:()=>now});assert.equal(r.failed,1,'attempt '+i);now+=60_000*2**(i+1)+1;}
  const row=f.sq.prepare('SELECT attempts,failed_at,delivered_at FROM seed_sync_notices').get();assert.equal(row.attempts,5);assert.ok(row.failed_at);assert.equal(row.delivered_at,null);
  assert.deepEqual(await deliverSeedSyncNotices({db:f.db,deliver:async()=>{},clock:()=>now}),{delivered:0,failed:0,healed:0,pruned:0},'terminal rows are left for operators');
 }finally{f.close();}});

test('notice monitoring: a failure-path write that fails is healed to failed_at and visible; health alert, overdue, prune after retention; wording is not a local-disable promise',async()=>{
 const f=await fixture();try{
  await f.enroll();let now=NOW;const fail=async()=>{throw new Error('down');};
  assert.equal((await seedSyncNoticeHealth({db:f.db,clock:()=>now})).alert,false);
  // pending and never run: overdue after 15 minutes
  assert.equal((await seedSyncNoticeHealth({db:f.db,clock:()=>now+16*60_000})).alert,true);
  // the failure-path UPDATE itself fails on every attempt: attempts reach 5, failed_at stays NULL
  const broken={prepare:sql=>sql.includes('failed_at=CASE')?{bind:()=>({run:async()=>{throw new Error('d1 down');}})}:f.db.prepare(sql)};
  for(let i=0;i<5;i++){const r=await deliverSeedSyncNotices({db:broken,deliver:fail,clock:()=>now});assert.equal(r.failed,1);assert.equal(r.unmarked,1);now+=61*60_000;}
  let row=f.sq.prepare('SELECT attempts,failed_at,claimed_until FROM seed_sync_notices').get();assert.equal(row.attempts,5);assert.equal(row.failed_at,null);
  const h=await seedSyncNoticeHealth({db:f.db,clock:()=>now});assert.equal(h.exhaustedUnmarked,1);assert.equal(h.alert,true);
  // the next healthy run marks it terminal; health then reports failed=1
  assert.equal((await deliverSeedSyncNotices({db:f.db,deliver:async()=>{},clock:()=>now})).healed,1);
  row=f.sq.prepare('SELECT failed_at FROM seed_sync_notices').get();assert.ok(row.failed_at);
  const h2=await seedSyncNoticeHealth({db:f.db,clock:()=>now});assert.deepEqual([h2.failed,h2.exhaustedUnmarked,h2.alert],[1,0,true]);
  // retention: delivered rows go after 30 days, failed rows stay
  f.sq.prepare("INSERT INTO seed_sync_notices(notice_id,owner_id,key_id,kind,created_at,delivered_at) VALUES('old','owner','k','enrolled',1,1000)").run();
  const r=await deliverSeedSyncNotices({db:f.db,deliver:async()=>{},clock:()=>now+31*24*60*60*1000});assert.equal(r.pruned,1);
  assert.equal(f.sq.prepare('SELECT count(*) n FROM seed_sync_notices').get().n,1);
  const w=JSON.stringify(notificationEmail('seed-sync-enrolled'));assert.ok(!/turn offline codes off|already holds/i.test(w)&&/authorized to save/.test(w)&&/cannot erase keys already saved/.test(w));
 }finally{f.close();}});

test('notice recipient: the schema itself refuses an unverified mailbox row, so the deliverer can only ever see a verified address',async()=>{
 const f=await fixture();try{
  assert.throws(()=>f.sq.prepare('INSERT INTO account_emails(owner_id,email,verified_at,updated_at) VALUES(?,?,?,?)').run('owner','x@example.test',null,1),/NOT NULL|constraint/i);
  assert.equal(f.sq.prepare('SELECT count(*) n FROM account_emails').get().n,0);
  await f.enroll();let sent=[];
  assert.deepEqual(await deliverSeedSyncNotices({db:f.db,deliver:async m=>{sent.push(m);},clock:()=>NOW}),{delivered:0,failed:1,healed:0,pruned:0},'no verified mailbox: counted as failure, never sent');
  assert.equal(sent.length,0);
 }finally{f.close();}});
// ---- Install-state fence and client key id (v2 enrollment) ----
const newKey=async()=>{const k=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);return {k,j:await pubJwk(k.publicKey)};};
const begin=async(f,{j,install=INSTALL,keyId=kid()})=>{const action=await seedSyncEnrollAction({ownerId:'owner',installId:install,keyId,publicJwk:j,generation:0});const c=await f.svc.enrollBegin({user:f.user,installId:install,keyId,publicJwk:j,strongProof:{purpose:'step-up',ownerId:'owner',generation:0,credentialId:'cred',actionDigest:action,verifiedAt:NOW}});return c&&{...c,keyId};};
const finish=async(f,c,k)=>f.svc.enrollFinish({user:f.user,token:c.token,signature:base64urlEncode(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},(k.k??k).privateKey,seedSyncProofMessage('seed-sync-enroll',c.challenge))))});
const state=f=>f.sq.prepare('SELECT key_id,revoked_reason r,revoked_at a FROM seed_sync_keys ORDER BY rowid').all().map(r=>[r.key_id,r.a==null?'active':r.r]);
test('fence: a late finish of an older challenge never supersedes a newer enrollment (same millisecond, claimed-before-commit order)',async()=>{
 const f=await fixture();try{
  const a=await newKey(),b=await newKey(),c1=await begin(f,{j:a.j}),c2=await begin(f,{j:b.j});
  assert.ok(c1&&c2);
  const r2=await finish(f,c2,b);assert.equal(r2.keyId,c2.keyId);
  assert.equal(await finish(f,c1,a),undefined,'late K1 fails');
  assert.deepEqual(state(f),[[c2.keyId,'active']],'K2 stays active; K1 was never inserted');
  assert.equal(f.sq.prepare("SELECT count(*) n FROM seed_sync_notices").get().n,1,'one notice, for K2 only');
 }finally{f.close();}});
test('fence: a predecessor revoked after begin (disable, remote, internal revoke) blocks the late finish even in the same millisecond',async()=>{
 const f=await fixture();try{
  const a=await newKey(),b=await newKey(),k0=await f.enroll(a.k,a.j);
  const c1=await begin(f,{j:b.j});assert.ok(c1);
  assert.equal(await f.svc.revoke({ownerId:'owner',keyId:k0.keyId,reason:'disabled'}),true); // same fixed clock instant as the begin
  assert.equal(await finish(f,c1,b),undefined,'late finish after disable fails');
  assert.deepEqual(state(f),[[k0.keyId,'disabled']]);
  // re-enable: a fresh begin after the disable commits and is a fresh state
  const d=await newKey(),c2=await begin(f,{j:d.j});assert.ok(c2);assert.ok(await finish(f,c2,d));
  assert.deepEqual(state(f),[[k0.keyId,'disabled'],[c2.keyId,'active']]);
  assert.equal(await finish(f,c1,b),undefined,'the old challenge is burned and its state is stale');
 }finally{f.close();}});
test('fence: begun on a revoked install, a later enrollment moves the state and the older challenge fails (no ABA after revoke)',async()=>{
 const f=await fixture();try{
  const a=await newKey(),b=await newKey(),d=await newKey();
  const c1=await begin(f,{j:a.j}),c2=await begin(f,{j:b.j});
  assert.ok(await finish(f,c2,b));assert.equal(await f.svc.revoke({ownerId:'owner',keyId:c2.keyId,reason:'remote'}),true);
  assert.equal(await finish(f,c1,a),undefined,'state (0, none) came back as active-none but the row count moved');
  assert.deepEqual(state(f),[[c2.keyId,'remote']]);
  const c3=await begin(f,{j:d.j});assert.ok(await finish(f,c3,d));assert.deepEqual(state(f),[[c2.keyId,'remote'],[c3.keyId,'active']]);
 }finally{f.close();}});
test('fence: a predecessor is superseded by the same batch; a second finish from the same pre-state fails and leaves the winner',async()=>{
 const f=await fixture();try{
  const a=await newKey(),b=await newKey(),c=await newKey(),k0=await f.enroll(a.k,a.j);
  const c1=await begin(f,{j:b.j}),c2=await begin(f,{j:c.j});
  assert.ok(await finish(f,c1,b));
  assert.equal(await finish(f,c2,c),undefined);
  assert.deepEqual(state(f),[[k0.keyId,'superseded'],[c1.keyId,'active']]);
  const c3=await begin(f,{j:c.j});assert.ok(await finish(f,c3,c),'a fresh begin supersedes the winner');
  assert.deepEqual(state(f),[[k0.keyId,'superseded'],[c1.keyId,'superseded'],[c3.keyId,'active']]);
 }finally{f.close();}});
test('key id: a taken id (any owner, any state) is refused at begin, and a collision at finish fails without revoking the winner',async()=>{
 const f=await fixture();try{
  const a=await newKey(),b=await newKey(),c=await newKey(),ID=kid();
  f.sq.prepare("INSERT INTO accounts(owner_id,created_at) VALUES('other',?)").run(NOW);
  f.sq.prepare("INSERT INTO seed_sync_keys(key_id,owner_id,install_id,public_jwk,public_key_digest,generation,created_at,revoked_at,revoked_reason) VALUES(?,?,?,?,?,0,1,2,'disabled')").run(ID,'other','O'.repeat(22),'{}','x');
  assert.equal(await begin(f,{j:a.j,keyId:ID}),undefined,'id taken by another owner (revoked) is refused');
  const k0=await f.enroll(a.k,a.j),ID2=kid();
  const c1=await begin(f,{j:b.j,keyId:ID2}),c2=await begin(f,{j:c.j,keyId:ID2});assert.ok(c1&&c2,'two begins can share an unused id');
  assert.ok(await finish(f,c1,b));
  assert.equal(await finish(f,c2,c),undefined,'collision at finish');
  assert.deepEqual(state(f).slice(1),[[k0.keyId,'superseded'],[ID2,'active']],'winner is untouched, its predecessor was superseded by its own batch');
  assert.equal(f.sq.prepare("SELECT count(*) n FROM seed_sync_keys WHERE revoked_at IS NULL").get().n,1);
  // same public key never re-enrolled, even with a different id
  assert.equal(await begin(f,{j:b.j}),undefined);
  void k0;
 }finally{f.close();}});
test('context: the live android session gets its generation; nothing else; a revoked session gets nothing',async()=>{
 const f=await fixture();try{
  assert.deepEqual(await f.svc.context({user:f.user}),{generation:0});
  assert.equal(await f.svc.context({user:{...f.user,generation:1}}),undefined,'stale generation');
  assert.equal(await f.svc.context({user:{...f.user,deviceId:'nope'}}),undefined);
  f.sq.exec("UPDATE device_sessions SET revoked_at=1 WHERE device_id='dev'");
  assert.equal(await f.svc.context({user:f.user}),undefined);
 }finally{f.close();}});
test('enroll v2 digest vector and key rows are never deleted by source',async()=>{
 const v=JSON.parse(readFileSync(new URL('./seed-sync-enroll-v2-vector.json',import.meta.url)));
 for(const t of v.cases){const d=await seedSyncEnrollAction(t.input);assert.equal(d,t.digest);assert.equal(await hashText(t.preimage),t.digest);}
 const {readdirSync}=await import('node:fs');
 for(const n of readdirSync(new URL('../src/',import.meta.url)))assert.ok(!/DELETE\s+FROM\s+seed_sync_keys/i.test(readFileSync(new URL('../src/'+n,import.meta.url),'utf8')),n+' must not delete key rows: the install fence counts rows (insert-only)');
});
test('guard parity: whatever blocks the key INSERT also blocks the supersede, so a predecessor is never revoked without the new key; no notice then',async()=>{
 const blockers={
  'passkey revoked':f=>f.sq.exec("UPDATE passkey_credentials SET revoked_at=5 WHERE credential_id='cred'"),
  'session revoked':f=>f.sq.exec("UPDATE device_sessions SET revoked_at=1 WHERE device_id='dev'"),
  'generation changed':f=>f.sq.exec('UPDATE account_security SET generation=generation+1'),
  'active key cap (20 other installs)':f=>{for(let i=0;i<20;i++)f.sq.prepare("INSERT INTO seed_sync_keys(key_id,owner_id,install_id,public_jwk,public_key_digest,generation,created_at) VALUES(?,?,?,?,?,0,1)").run('c'.repeat(31)+i.toString(16),'owner','X'.repeat(21)+i.toString(16),'{}','cap'+i);},
  'enrollment since begin (count moved)':f=>f.sq.prepare("INSERT INTO seed_sync_keys(key_id,owner_id,install_id,public_jwk,public_key_digest,generation,created_at,revoked_at,revoked_reason) VALUES('d'||'0'||'0','owner',?,?,?,0,1,2,'disabled')").run(INSTALL,'{}','moved'),
  'new id taken':(f,c)=>f.sq.prepare("INSERT INTO seed_sync_keys(key_id,owner_id,install_id,public_jwk,public_key_digest,generation,created_at,revoked_at,revoked_reason) VALUES(?,?,?,?,?,0,1,2,'disabled')").run(c.keyId,'owner','T'.repeat(22),'{}','taken'),
  'public key already enrolled':(f,c,b)=>f.sq.prepare("INSERT INTO seed_sync_keys(key_id,owner_id,install_id,public_jwk,public_key_digest,generation,created_at,revoked_at,revoked_reason) VALUES(?,?,?,?,?,0,1,2,'disabled')").run('e'.repeat(32),'owner','U'.repeat(22),'{}',c.digest),
 };
 for(const [name,block] of Object.entries(blockers)){
  const f=await fixture();try{
   const a=await newKey(),b=await newKey(),k0=await f.enroll(a.k,a.j),c=await begin(f,{j:b.j});assert.ok(c,name);
   const notices=()=>f.sq.prepare('SELECT count(*) n FROM seed_sync_notices').get().n,n0=notices(),digest=await hashText(JSON.stringify({kty:b.j.kty,crv:b.j.crv,x:b.j.x,y:b.j.y}));
   block(f,{...c,digest},b);
   assert.equal(await finish(f,c,b),undefined,name);
   const active=f.sq.prepare("SELECT key_id FROM seed_sync_keys WHERE owner_id='owner' AND install_id=? AND revoked_at IS NULL").all(INSTALL).map(k=>k.key_id);
   assert.deepEqual(active,[k0.keyId],name+': predecessor still active, no new active key');
   assert.equal(notices(),n0,name+': no notice for a failed insert');
  }finally{f.close();}
 }
});
test('key table writes are limited: no delete, no OR REPLACE, only audited UPDATE column sets (none clears revoked_at, so revocation is permanent)',async()=>{
 const {readdirSync}=await import('node:fs');const allowed=new Set(['revoked_at=?5,revoked_reason=\'superseded\'',"revoked_at=?5,revoked_reason='remote'","revoked_at=?4,revoked_reason='remote'","revoked_at=?1,revoked_reason='disabled'",'revoked_at=?1,revoked_reason=?4','last_device_id=?2','last_used_at=?2']);
 let seen=0;
 for(const n of readdirSync(new URL('../src/',import.meta.url))){
  const t=readFileSync(new URL('../src/'+n,import.meta.url),'utf8');
  assert.ok(!/INSERT\s+OR\s+(REPLACE|IGNORE)\s+INTO\s+seed_sync_keys/i.test(t)&&!/REPLACE\s+INTO\s+seed_sync_keys/i.test(t),n+': no replace into key rows');
  assert.ok(!/UPDATE\s+OR\s+\w+\s+seed_sync_keys/i.test(t),n);
  for(const m of t.matchAll(/UPDATE\s+seed_sync_keys\s+SET\s+([^W]*?)\s+WHERE/g)){seen++;const set=m[1].replace(/\\'/g,"'").trim();assert.ok(allowed.has(set),n+': unaudited UPDATE of key columns: '+set);}
  for(const m of t.matchAll(/INSERT\s+INTO\s+seed_sync_keys/gi))assert.equal(n,'seed-sync.js','key rows are inserted only by enrollFinish');
 }
 assert.ok(seen>=8,'found the audited UPDATEs ('+seen+')');
});
test('generation change: finish with a bumped account generation inserts nothing, leaves the predecessor and writes no notice',async()=>{
 const f=await fixture();try{
  const a=await newKey(),b=await newKey(),k0=await f.enroll(a.k,a.j),c=await begin(f,{j:b.j});
  f.sq.exec('UPDATE account_security SET generation=generation+1');
  assert.equal(await finish(f,c,b),undefined);
  assert.equal(f.sq.prepare('SELECT count(*) n FROM seed_sync_keys').get().n,1);assert.equal(f.sq.prepare('SELECT count(*) n FROM seed_sync_notices').get().n,1);
 }finally{f.close();}});
// ---- Resume of an unconfirmed (signed) enrollment: same key id, same public key, fresh challenge ----
test('resume: an uncommitted attempt can be retried for the SAME key id after its challenge expired; the old token is dead and exactly one key results',async()=>{
 const f=await fixture();try{
  const a=await newKey(),keyId=kid(),c1=await begin(f,{j:a.j,keyId});assert.ok(c1);
  f.setNow(NOW+120000);
  assert.equal(await finish(f,c1,a),undefined,'expired token never commits');
  assert.deepEqual(state(f),[]);
  f.setNow(NOW+121000);
  const action=await seedSyncEnrollAction({ownerId:'owner',installId:INSTALL,keyId,publicJwk:a.j,generation:0});
  const c2=await f.svc.enrollBegin({user:f.user,installId:INSTALL,keyId,publicJwk:a.j,strongProof:{purpose:'step-up',ownerId:'owner',generation:0,credentialId:'cred',actionDigest:action,verifiedAt:NOW+121000}}); // a fresh passkey step-up, as in the real flow
  assert.ok(c2,'same key id and public key may begin again while nothing was committed');
  assert.equal(c2.challenge.keyId,keyId);
  assert.ok(await finish(f,{...c2,keyId},a));
  assert.deepEqual(state(f),[[keyId,'active']]);
  assert.equal(f.sq.prepare("SELECT count(*) n FROM seed_sync_notices").get().n,1);
 }finally{f.close();}});
test('resume: a committed key refuses a second begin for its id; replaying the same token and signature changes nothing',async()=>{
 const f=await fixture();try{
  const a=await newKey(),keyId=kid(),c1=await begin(f,{j:a.j,keyId});
  const sig=base64urlEncode(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},a.k.privateKey,seedSyncProofMessage('seed-sync-enroll',c1.challenge))));
  assert.ok(await f.svc.enrollFinish({user:f.user,token:c1.token,signature:sig}));
  assert.equal(await f.svc.enrollFinish({user:f.user,token:c1.token,signature:sig}),undefined,'no idempotent replay: the token is single use');
  assert.equal(await begin(f,{j:a.j,keyId}),undefined,'committed id is refused at begin');
  assert.deepEqual(state(f),[[keyId,'active']]);
  assert.equal(f.sq.prepare("SELECT count(*) n FROM seed_sync_notices").get().n,1);
 }finally{f.close();}});
test('resume: a claimed token with a bad signature is burned; a fresh challenge for the same key id still commits',async()=>{
 const f=await fixture();try{
  const a=await newKey(),b=await newKey(),keyId=kid(),c1=await begin(f,{j:a.j,keyId});
  assert.equal(await finish(f,c1,b),undefined,'wrong key signature');
  assert.equal(await finish(f,c1,a),undefined,'burned even with the right signature now');
  const c2=await begin(f,{j:a.j,keyId});assert.ok(c2);
  assert.ok(await finish(f,c2,a));
  assert.deepEqual(state(f),[[keyId,'active']]);
 }finally{f.close();}});
test('resume: two live challenges for the same key id and key commit exactly once',async()=>{
 const f=await fixture();try{
  const a=await newKey(),keyId=kid(),c1=await begin(f,{j:a.j,keyId}),c2=await begin(f,{j:a.j,keyId});
  assert.ok(c1&&c2);
  const [r1,r2]=await Promise.all([finish(f,c1,a),finish(f,c2,a)]);
  assert.equal([r1,r2].filter(Boolean).length,1);
  assert.deepEqual(state(f),[[keyId,'active']]);
  assert.equal(f.sq.prepare("SELECT count(*) n FROM seed_sync_notices").get().n,1);
 }finally{f.close();}});
test('status has no definite absence: a never-committed key id answers like any transient failure, so a client cannot prove "not committed" from status',async()=>{
 const f=await fixture();try{
  const keyId=kid(),c=await f.svc.statusBegin({keyId});
  assert.ok(c&&c.token&&c.challenge.keyId===keyId,'a fake challenge of the normal shape');
  assert.equal(await f.svc.statusFinish({token:c.token,signature:'A'.repeat(86)}),undefined);
 }finally{f.close();}});
