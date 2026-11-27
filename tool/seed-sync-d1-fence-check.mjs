// Local workerd D1 (Miniflare) check of the enrollFinish fence and key id rules: atomic batch rollback, changes() attribution between batch statements,
// same-millisecond revoke, late finish, collision and concurrent finishes. SYNTHETIC data only, no network, no Cloudflare account. NOT remote D1: it uses
// the same D1 binding API on local workerd, so it proves API semantics, not Cloudflare's metered behaviour.
import {readdirSync,readFileSync} from 'node:fs';import {createRequire} from 'node:module';
import assert from 'node:assert/strict';
import {SeedCipher} from '../src/seed-cipher.js';import {SeedSync,seedSyncEnrollAction} from '../src/seed-sync.js';
import {seedSyncProofMessage} from '../src/seed-sync-proof.js';import {base64urlEncode} from '../src/tokens.js';
const require=createRequire(import.meta.url);const {Miniflare,convertV4MiniflareOptions}=require('miniflare');
const NOW=1800000000000,INSTALL='i'.repeat(22);
const mf=new Miniflare(await convertV4MiniflareOptions({modules:true,script:'export default{fetch(){return new Response("ok")}}',compatibilityDate:'2026-11-23',d1Databases:['DB']}));
const db=await mf.getD1Database('DB');
for(const f of readdirSync('migrations').sort())for(const sql of readFileSync('migrations/'+f,'utf8').replace(/^--.*$/gm,'').split(/;(?=\s*(?:CREATE|ALTER|PRAGMA|$))/).map(s=>s.trim()).filter(Boolean))await db.prepare(sql).run();
await db.batch([db.prepare('INSERT INTO accounts(owner_id,created_at) VALUES(?,?)').bind('owner',NOW),db.prepare('INSERT INTO account_security(owner_id) VALUES(?)').bind('owner'),
 db.prepare('INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) VALUES(?,?,?,?,?,?,?,?)').bind('cred','owner',new Uint8Array([1]),0,'[]','singleDevice',0,NOW),
 db.prepare("INSERT INTO device_sessions(device_id,owner_id,credential_id,provider_identity_id,generation,client_kind,created_at,last_used_at,expires_at) VALUES('dev','owner','cred',NULL,0,'android',0,0,9999999999999)")]);
const cipher=new SeedCipher({keys:new Map([['t',await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt'])]]),activeKeyId:'t'});
const svc=new SeedSync({db,cipher,clock:()=>NOW}),user={ownerId:'owner',deviceId:'dev',generation:0};
const kid=()=>[...crypto.getRandomValues(new Uint8Array(16))].map(b=>b.toString(16).padStart(2,'0')).join('');
const newKey=async()=>{const k=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']),j=await crypto.subtle.exportKey('jwk',k.publicKey);return {k,j:{kty:j.kty,crv:j.crv,x:j.x,y:j.y}};};
const begin=async({j,keyId=kid()})=>{const action=await seedSyncEnrollAction({ownerId:'owner',installId:INSTALL,keyId,publicJwk:j,generation:0});const c=await svc.enrollBegin({user,installId:INSTALL,keyId,publicJwk:j,strongProof:{purpose:'step-up',ownerId:'owner',generation:0,credentialId:'cred',actionDigest:action,verifiedAt:NOW}});return c&&{...c,keyId};};
const finish=async(c,key)=>svc.enrollFinish({user,token:c.token,signature:base64urlEncode(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key.k.privateKey,seedSyncProofMessage('seed-sync-enroll',c.challenge))))});
const state=async()=>(await db.prepare('SELECT key_id,revoked_at a,revoked_reason r FROM seed_sync_keys ORDER BY rowid').all()).results.map(r=>[r.key_id,r.a==null?'active':r.r]);
const reset=()=>db.batch([db.prepare('DELETE FROM seed_sync_notices'),db.prepare('DELETE FROM seed_sync_keys'),db.prepare('DELETE FROM seed_sync_challenges')]);
const out=[];const ok=(n)=>out.push('ok '+n);
// 1 late finish after newer enrollment
{await reset();const a=await newKey(),b=await newKey(),c1=await begin({j:a.j}),c2=await begin({j:b.j});assert.ok(await finish(c2,b));assert.equal(await finish(c1,a),undefined);assert.deepEqual(await state(),[[c2.keyId,'active']]);ok('late finish after newer enrollment fails, winner active');}
// 2 predecessor revoked after begin, same millisecond; then re-enable
{await reset();const a=await newKey(),b=await newKey(),d=await newKey(),c0=await begin({j:a.j});const k0=await finish(c0,a);assert.ok(k0);
 const c1=await begin({j:b.j});assert.equal(await svc.revoke({ownerId:'owner',keyId:k0.keyId,reason:'disabled'}),true);assert.equal(await finish(c1,b),undefined);assert.deepEqual(await state(),[[k0.keyId,'disabled']]);
 const c2=await begin({j:d.j});assert.ok(await finish(c2,d));assert.deepEqual(await state(),[[k0.keyId,'disabled'],[c2.keyId,'active']]);assert.equal(await finish(c1,b),undefined);ok('revoked predecessor blocks late finish (same ms); re-enable works');}
// 3 supersede in the same batch and key rows/notices consistent
{await reset();const a=await newKey(),b=await newKey(),c0=await begin({j:a.j});const k0=await finish(c0,a);const c1=await begin({j:b.j});assert.ok(await finish(c1,b));
 assert.deepEqual(await state(),[[k0.keyId,'superseded'],[c1.keyId,'active']]);assert.equal((await db.prepare('SELECT count(*) n FROM seed_sync_notices').first()).n,2);ok('supersede + insert + notice commit together (changes() chain)');}
// 4 id collision at finish rolls back with no effect on the winner, and the loser leaves no partial rows
{await reset();const a=await newKey(),b=await newKey(),c=await newKey(),ID=kid();const c0=await begin({j:a.j});const k0=await finish(c0,a);
 const c1=await begin({j:b.j,keyId:ID}),c2=await begin({j:c.j,keyId:ID});assert.ok(await finish(c1,b));assert.equal(await finish(c2,c),undefined);
 assert.deepEqual(await state(),[[k0.keyId,'superseded'],[ID,'active']]);assert.equal((await db.prepare('SELECT count(*) n FROM seed_sync_notices').first()).n,2);ok('id collision at finish: winner untouched, no stray rows');}
// 5 concurrent finishes from the same pre-state: exactly one commits
{await reset();const a=await newKey(),b=await newKey(),c=await newKey(),c0=await begin({j:a.j});const k0=await finish(c0,a);
 const c1=await begin({j:b.j}),c2=await begin({j:c.j});const r=await Promise.all([finish(c1,b),finish(c2,c)]);
 assert.equal(r.filter(Boolean).length,1,'exactly one wins');const st=await state();assert.equal(st.filter(x=>x[1]==='active').length,1);assert.equal(st.length,2);assert.equal(st[0][1],'superseded');ok('concurrent finishes: exactly one commits ('+JSON.stringify(r.map(x=>!!x))+')');}
// 6 raw batch rollback: a failing INSERT inside db.batch rolls back the earlier UPDATE (the premise the guards no longer depend on)
{await reset();const a=await newKey(),c0=await begin({j:a.j});const k0=await finish(c0,a);
 let threw=false;try{await db.batch([db.prepare("UPDATE seed_sync_keys SET revoked_at=1,revoked_reason='disabled' WHERE key_id=?").bind(k0.keyId),db.prepare("INSERT INTO seed_sync_keys(key_id,owner_id,install_id,public_jwk,public_key_digest,generation,created_at) VALUES(?,?,?,?,?,0,1)").bind(k0.keyId,'owner','z'.repeat(22),'{}','dd')]);}catch{threw=true;}
 assert.ok(threw);assert.deepEqual(await state(),[[k0.keyId,'active']]);ok('D1 batch rolls back earlier statements when a later one fails');}
// 7 changes() semantic: after an UPDATE matching 0 rows changes()=0, after matching 1 row changes()=1, inside a batch
{await reset();const a=await newKey(),c0=await begin({j:a.j});const k0=await finish(c0,a);
 const r=await db.batch([db.prepare("UPDATE seed_sync_keys SET last_used_at=5 WHERE key_id='none'"),db.prepare("SELECT changes() AS c"),db.prepare("UPDATE seed_sync_keys SET last_used_at=6 WHERE key_id=?").bind(k0.keyId),db.prepare("SELECT changes() AS c")]);
 assert.equal(r[1].results[0].c,0);assert.equal(r[3].results[0].c,1);ok('changes() after the previous batch statement: 0 then 1');}
console.log(out.join('\n'));await mf.dispose();
