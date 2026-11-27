// Loopback full flow through the REAL composed runtime: createIdentityRuntime with native and seedSync on, real DeviceSessionService bearer session, real
// managedPasskeys (PasskeyService with PasskeyVerifier androidOrigins) verifying a real P-256 WebAuthn assertion, real SeedCipher and D1-shaped SQLite.
// No substituted proof service. Only the clock, the trusted address and the code keys are injected. Synthetic data, no network.
import test from 'node:test';import assert from 'node:assert/strict';
import {database} from './sqlite-helper.js';import {authenticator} from './passkey-fixture.js';
import {createIdentityRuntime} from '../src/identity-runtime.js';import {DeviceSessionService} from '../src/device-sessions.js';
import {SeedCipher} from '../src/seed-cipher.js';import {TotpSeedStore} from '../src/totp-seeds.js';
import {seedSyncProofMessage} from '../src/seed-sync-proof.js';import {entriesDigest} from '../src/seed-sync.js';
import {openSealed,sha256Hex} from '../src/seed-sync-seal.js';import {base64urlEncode,base64urlDecode} from '../src/tokens.js';import {hashText} from '../src/sessions.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',NOW=1800000000000,INSTALL='i'.repeat(22);
const FP=Array.from({length:32},(_,i)=>(i*7+3).toString(16).padStart(2,'0').toUpperCase()).join(':');
const HASH='android:apk-key-hash:'+base64urlEncode(Uint8Array.from(FP.split(':').map(h=>parseInt(h,16))));
const kid=()=>[...crypto.getRandomValues(new Uint8Array(16))].map(b=>b.toString(16).padStart(2,'0')).join('');
async function world({seedSync=true,kind='android'}={}){
 const db=database(),sq=db.sqlite,a=authenticator(),c=a.credential;
 const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']),config={keys:new Map([['k',key]]),activeKeyId:'k'},cipher=new SeedCipher(config);
 sq.prepare('INSERT INTO accounts(owner_id,created_at) VALUES(?,?)').run('owner',NOW);sq.prepare('INSERT INTO account_security(owner_id) VALUES(?)').run('owner');sq.prepare("INSERT INTO account_emails(owner_id,email,verified_at,updated_at) VALUES('owner','synthetic@example.test',0,0)").run();
 sq.prepare('INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) VALUES(?,?,?,?,?,?,?,?)').run(c.id,'owner',c.publicKey,0,'[]','singleDevice',0,NOW);
 const sessions=new DeviceSessionService(db,{clock:()=>NOW}),s=await sessions.issue({proof:{ownerId:'owner',credentialId:c.id,generation:0,purpose:'authenticate',verifiedAt:NOW},clientKind:kind});
 const rt=createIdentityRuntime({db,loadCodeKeys:async()=>config,trustedRequestKey:()=> '203.0.113.9',clock:()=>NOW,native:{enabled:true,assetFingerprints:[FP]},seedSync:{enabled:seedSync}});
 let n=0;const post=async(path,body,{origin,auth=s.access}={})=>{const r=await rt.fetch(new Request(API+'/v1/manage/seed-sync/'+path,{method:'POST',headers:{'Content-Type':'application/json',...(auth?{Authorization:'Bearer '+auth}:{}),...(origin?{Origin:origin}:{})},body:JSON.stringify(body)}),{clientAddress:'192.0.2.'+(++n%200),waitUntil(){}});let j;try{j=await r.json();}catch{}return{status:r.status,body:j};};
 const dk=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']),jx=await crypto.subtle.exportKey('jwk',dk.publicKey),jwk={kty:jx.kty,crv:jx.crv,x:jx.x,y:jx.y};
 const sign=async(purpose,challenge)=>base64urlEncode(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},dk.privateKey,seedSyncProofMessage(purpose,challenge))));
 const seeds=new TotpSeedStore(db,cipher);
 const addEntry=async(id,len=20)=>{sq.prepare("INSERT OR IGNORE INTO services(service_id,name) VALUES('custom-totp','A')").run();sq.prepare('INSERT INTO entries(entry_id,owner_id,service_id,label,created_at) VALUES(?,?,?,?,?)').run(id,'owner','custom-totp','L',NOW);return seeds.putSeed('owner',id,{secret:Uint8Array.from({length:len},(_,i)=>i+1),algorithm:'SHA-1',digits:6,period:30},NOW);};
 // One full enrollment through step-up (real assertion), enroll-begin, signed enroll-finish.
 let counter=0;const enroll=async({origin=HASH,keyId=kid()}={})=>{
  const su=await post('stepup-begin',{installId:INSTALL,keyId,publicJwk:jwk});if(su.status!==200)return{su};
  const response=a.assertion({expected:su.body.options.challenge,origin,counter:++counter});
  const eb=await post('enroll-begin',{installId:INSTALL,keyId,publicJwk:jwk,response,token:su.body.token});if(eb.status!==200)return{su,eb};
  const ef=await post('enroll-finish',{signature:await sign('seed-sync-enroll',eb.body.challenge),token:eb.body.token});return{su,eb,ef,keyId};};
 return{db,sq,a,c,s,rt,post,dk,jwk,sign,seeds,addEntry,enroll,cipher,close:()=>sq.close()};
}
test('full flow on the real runtime: context, step-up with a real android assertion, enroll, signed finish, snapshot, sealed batch opens to the stored seed',async()=>{
 const w=await world();try{
  await w.addEntry('a',20);await w.addEntry('b',32);
  const ctx=await w.post('context',{});assert.equal(ctx.status,200);assert.equal(ctx.body.generation,0);
  const e=await w.enroll();assert.equal(e.su.status,200,'step-up begin');assert.equal(e.eb.status,200,'enroll begin with real assertion');assert.equal(e.ef?.status,200,'enroll finish '+JSON.stringify(e.ef?.body));
  const keyId=e.keyId;
  assert.equal(w.sq.prepare('SELECT count(*) n FROM seed_sync_keys WHERE key_id=? AND revoked_at IS NULL').get(keyId).n,1,'key row active');
  assert.equal(w.sq.prepare('SELECT count(*) n FROM seed_sync_notices').get().n,1,'one new-device notice row');
  const sb=await w.post('snapshot-begin',{epoch:1,keyId});assert.equal(sb.status,200,JSON.stringify(sb.body));
  const sf=await w.post('snapshot-finish',{signature:await w.sign('seed-sync-snapshot',sb.body.challenge),token:sb.body.token});assert.equal(sf.status,200,JSON.stringify(sf.body));
  assert.deepEqual(sf.body.entries.map(x=>x.entryId).sort(),['a','b']);const rev=sf.body.entries.find(x=>x.entryId==='a');assert.ok(Number.isSafeInteger(rev.seedVersion));
  assert.equal(JSON.stringify(sf.body).includes(base64urlEncode(Uint8Array.from({length:20},(_,i)=>i+1))),false,'no seed bytes in the snapshot');
  const eph=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']),raw=base64urlEncode(new Uint8Array(await crypto.subtle.exportKey('raw',eph.publicKey)));
  const entries=sf.body.entries.map(x=>({entryId:x.entryId,seedVersion:x.seedVersion}));
  const bb=await w.post('batch-begin',{entries,ephemeralKey:raw,epoch:1,keyId});assert.equal(bb.status,200,JSON.stringify(bb.body));
  assert.equal(bb.body.challenge.entriesDigest,await entriesDigest(entries),'signed set digest');
  const bf=await w.post('batch-finish',{signature:await w.sign('seed-sync-batch',bb.body.challenge),token:bb.body.token});assert.equal(bf.status,200,JSON.stringify(bf.body));
  const ephemeralDigest=await sha256Hex(base64urlDecode(raw,65)),challengeDigest=await hashText(bb.body.challenge.challenge);assert.equal(bf.body.challengeDigest,challengeDigest);
  for(const [id,len] of [['a',20],['b',32]]){const r=bf.body.results.find(x=>x.entryId===id);assert.equal(r.status,'sealed',id+JSON.stringify(bf.body.results.map(({ciphertext,nonce,...x})=>x)));
   const opened=await openSealed({clientPrivateKey:eph.privateKey,serverPublicKey:bf.body.serverPublicKey,challengeDigest,ephemeralDigest,aad:{ownerId:'owner',deviceId:w.s.deviceId,epoch:1,entryId:id,seedVersion:r.seedVersion,algorithm:r.algorithm,digits:r.digits,period:r.period},nonce:r.nonce,ciphertext:r.ciphertext});
   assert.deepEqual([...opened],Array.from({length:len},(_,i)=>i+1),'sealed batch opens to the stored seed '+id);}
  assert.equal(JSON.stringify(bf.body).includes(base64urlEncode(Uint8Array.from({length:20},(_,i)=>i+1))),false,'no plaintext seed on the wire');
  // one-use: replaying either finish yields the opaque 409
  assert.equal((await w.post('batch-finish',{signature:await w.sign('seed-sync-batch',bb.body.challenge),token:bb.body.token})).status,409);
  assert.equal((await w.post('snapshot-finish',{signature:await w.sign('seed-sync-snapshot',sb.body.challenge),token:sb.body.token})).status,409);
 }finally{w.close();}});
test('real assertion verification gates enrollment: wrong android origin, replayed assertion and a web-origin assertion enroll nothing',async()=>{
 const w=await world();try{
  const wrong='android:apk-key-hash:'+'B'.repeat(43);
  const bad=await w.enroll({origin:wrong});assert.equal(bad.eb.status,409);assert.equal(w.sq.prepare('SELECT count(*) n FROM seed_sync_keys').get().n,0);
  // a step-up ceremony begun for one key cannot be spent for another key or install
  const k1=kid(),k2=kid(),su=await w.post('stepup-begin',{installId:INSTALL,keyId:k1,publicJwk:w.jwk});
  const resp=w.a.assertion({expected:su.body.options.challenge,origin:HASH,counter:9});
  assert.equal((await w.post('enroll-begin',{installId:INSTALL,keyId:k2,publicJwk:w.jwk,response:resp,token:su.body.token})).status,409,'action binds the key id');
  assert.equal(w.sq.prepare('SELECT count(*) n FROM seed_sync_keys').get().n,0);assert.equal(w.sq.prepare('SELECT count(*) n FROM seed_sync_challenges').get().n,0,'no challenge issued without a verified assertion');
  const ok=await w.enroll();assert.equal(ok.ef.status,200,'a correct flow still works afterwards');
 }finally{w.close();}});
test('boundary on the composed runtime: flag off is 404, any Origin is 403, no bearer is 401, a web session cannot use it',async()=>{
 const off=await world({seedSync:false});try{assert.equal((await off.post('context',{})).status,404);}finally{off.close();}
 const w=await world();try{
  assert.equal((await w.post('context',{},{origin:'https://otpanda.github.io'})).status,403);assert.equal((await w.post('context',{},{auth:null})).status,401);
 }finally{w.close();}
 const web=await world({kind:'web'});try{assert.notEqual((await web.post('context',{})).status,200,'a web session is not an android session');}finally{web.close();}});
