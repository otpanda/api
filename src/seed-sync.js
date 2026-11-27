// Inactive native seed-sync service (own entries only, device-encrypted, download only). Nothing here is mounted; see docs/seed-sync.md.
// Authorities: a live android session (caller), a seed-sync key enrolled under a fresh action-bound passkey proof, one-use challenges
// consumed atomically BEFORE any decrypt or seal, and the account generation checked per request. Definitive purge codes are returned
// only after the request's signature verified; everything else is the opaque undefined.
import {hashText,takeRateLimit} from './sessions.js';
import {generateAccessToken,parseAccessToken,digestSecret,digestToHex,base64urlEncode,base64urlDecode} from './tokens.js';
import {importDevicePublicKey} from './device-key-proof.js';
import {verifySeedSyncProof,PROOF_TTL} from './seed-sync-proof.js';
import {importClientEphemeral,sealBatch,sha256Hex} from './seed-sync-seal.js';
import {SESSION_METHOD_JOIN as MJ,SESSION_METHOD_ACTIVE as MA} from './session-method.js';
export const MAX_BATCH=3,SNAPSHOT_CAP=1000,TOMBSTONE_LIMIT=200,TOMBSTONE_RETENTION=30*86400000,MAX_ACTIVE_KEYS=20,MAX_KEY_CHALLENGES=8,KEY_PULLS_PER_MINUTE=12,MAX_ENROLL_CHALLENGES=32;
export const ALGORITHMS=Object.freeze(['SHA-1','SHA-256','SHA-512']);
const keyText=j=>JSON.stringify({kty:j.kty,crv:j.crv,x:j.x,y:j.y});
const id=v=>typeof v==='string'&&/^[A-Za-z0-9_-]{1,128}$/.test(v);
const keyIdOk=v=>typeof v==='string'&&/^[0-9a-f]{32}$/.test(v);
const installOk=v=>typeof v==='string'&&/^[A-Za-z0-9_-]{22,64}$/.test(v);
const epochOk=v=>Number.isSafeInteger(v)&&v>=0;
const hexBytes=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
// v2: the client-proposed native key id is part of the digest the passkey step-up authorizes. Order: label, owner, install, keyId, key text, generation.
export const seedSyncEnrollAction=async({ownerId,installId,keyId,publicJwk,generation})=>{if(!keyIdOk(keyId))throw new TypeError('32-hex key id required');await importDevicePublicKey(publicJwk);return hashText(JSON.stringify(['seed-sync-enroll-v2',ownerId,installId,keyId,keyText(publicJwk),generation]));};
export const seedSyncEnrollBinding=(ownerId,deviceId,actionDigest)=>hashText(JSON.stringify(['seed-sync-enroll-binding-v1',ownerId,deviceId,actionDigest]));
export const entriesDigest=entries=>hashText(JSON.stringify([...entries].sort((a,b)=>a.entryId<b.entryId?-1:1).map(e=>[e.entryId,e.seedVersion])));
export function representable(r){
 if(r.algorithm==null||r.digits==null||r.period==null||r.seed_bytes==null)return 'metadata_pending';
 if(!ALGORITHMS.includes(r.algorithm)||!Number.isInteger(r.digits)||r.digits<6||r.digits>8||!Number.isSafeInteger(r.period)||r.period<1||r.period>86400||!Number.isInteger(r.seed_bytes)||r.seed_bytes<10||r.seed_bytes>128)return 'unsupported';
 return undefined;
}
// Active android session of the caller (D device, O owner, G generation, N now).
const SESSION=(D,O,G,N)=>`EXISTS(SELECT 1 FROM device_sessions d ${MJ} JOIN account_security s ON s.owner_id=d.owner_id WHERE d.device_id=${D} AND d.owner_id=${O} AND d.client_kind='android' AND d.generation=${G} AND s.generation=${G} AND d.revoked_at IS NULL AND d.expires_at>${N} AND ${MA})`;
export class SeedSync {
 constructor({db,cipher,clock=Date.now}={}){if(!db||!cipher)throw new TypeError('db and seed cipher required');Object.assign(this,{db,cipher,clock});}
 now(){const n=this.clock();if(!Number.isSafeInteger(n)||n<0)throw new TypeError('Valid instant required');return n;}
 // Key active at its generation AND the caller's android session still live: used right before anything is released.
 async #live(row){
  const now=this.now();
  return !!await this.db.prepare(`SELECT 1 x FROM seed_sync_keys k JOIN account_security s ON s.owner_id=k.owner_id AND s.generation=k.generation WHERE k.key_id=?1 AND k.owner_id=?2 AND k.revoked_at IS NULL AND k.generation=?3 AND ${SESSION('?4','?2','?3','?5')}`).bind(row.key_id,row.owner_id,row.generation,row.device_id,now).first();
 }
 async #sweep(now){await this.db.prepare('DELETE FROM seed_sync_challenges WHERE challenge_id IN (SELECT challenge_id FROM seed_sync_challenges WHERE expires_at<=?1 ORDER BY expires_at LIMIT 64)').bind(now).run();}
 async #event(ownerId,keyId,kind,reason){try{await this.db.prepare('INSERT INTO seed_sync_events(owner_id,key_id,kind,reason,created_at) VALUES(?1,?2,?3,?4,?5)').bind(ownerId,keyId??null,kind,reason??null,this.now()).run();}catch{/* audit must not change the outcome */}}
 async #issue(row){
  const now=this.now();await this.#sweep(now);
  const secret=generateAccessToken(),nonce=base64urlEncode(crypto.getRandomValues(new Uint8Array(32))),expiresAt=now+PROOF_TTL;
  const cap=row.purpose==='seed-sync-enroll'?`(SELECT count(*) FROM seed_sync_challenges WHERE owner_id=?3 AND purpose='seed-sync-enroll' AND expires_at>?13 AND used_at IS NULL)<${MAX_ENROLL_CHALLENGES}`:`(SELECT count(*) FROM seed_sync_challenges WHERE key_id=?4 AND expires_at>?13 AND used_at IS NULL)<${MAX_KEY_CHALLENGES}`;
  const r=await this.db.prepare(`INSERT INTO seed_sync_challenges(challenge_id,secret_digest,owner_id,key_id,device_id,install_id,generation,purpose,epoch,nonce,action_digest,public_jwk,credential_id,ephemeral_key,entries,created_at,expires_at,install_key_count,predecessor_key_id) SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?14,?15,?16,?13,?17,CASE WHEN ?8='seed-sync-enroll' THEN (SELECT count(*) FROM seed_sync_keys WHERE owner_id=?3 AND install_id=?6) END,CASE WHEN ?8='seed-sync-enroll' THEN (SELECT key_id FROM seed_sync_keys WHERE owner_id=?3 AND install_id=?6 AND revoked_at IS NULL) END WHERE ${SESSION('?5','?3','?7','?13')} AND ${cap}`)
   .bind(secret.tokenId,digestToHex(await digestSecret(secret.secret)),row.ownerId,row.keyId,row.deviceId,row.installId??null,row.generation,row.purpose,row.epoch??null,nonce,row.actionDigest??null,row.publicJwk??null,now,row.credentialId??null,row.ephemeralKey??null,row.entries??null,expiresAt).run();
  return r.meta.changes>=1?{token:secret.token,nonce,expiresAt}:undefined;
 }
 // Enrollment: one passkey step-up (strongProof from PasskeyService.finishAuthentication, never a body-supplied assertion), then the
 // new key signs a one-use challenge. A new enrollment for the same install atomically supersedes the previous key.
 async enrollBegin({user,installId,keyId,publicJwk,strongProof}){
  try{
   if(!installOk(installId)||!keyIdOk(keyId))return;
   const action=await seedSyncEnrollAction({ownerId:user.ownerId,installId,keyId,publicJwk,generation:user.generation}),p=strongProof,now=this.now();
   if(!p||p.purpose!=='step-up'||p.ownerId!==user.ownerId||p.generation!==user.generation||p.actionDigest!==action||typeof p.credentialId!=='string'||!Number.isSafeInteger(p.verifiedAt)||p.verifiedAt>now||now-p.verifiedAt>=PROOF_TTL)return;
   const digest=await hashText(keyText(publicJwk));
   if(await this.db.prepare('SELECT 1 x FROM seed_sync_keys WHERE (owner_id=?1 AND public_key_digest=?2) OR key_id=?3').bind(user.ownerId,digest,keyId).first())return; // fresh key and fresh id every enrollment (advisory: finish re-checks atomically)
   const c=await this.#issue({purpose:'seed-sync-enroll',ownerId:user.ownerId,keyId,deviceId:user.deviceId,installId,generation:user.generation,actionDigest:action,publicJwk:keyText(publicJwk),credentialId:p.credentialId});
   return c?{token:c.token,challenge:{ownerId:user.ownerId,keyId,installId,generation:user.generation,challenge:c.nonce,actionDigest:action,expiresAt:c.expiresAt}}:undefined;
  }catch{return;}
 }
 // Seed-scoped context for enrollment bootstrap: the caller's own live android session and current account generation, nothing else.
 // A hint only: the v2 action digest, the passkey step-up and the finish guards decide, so a stale value fails closed.
 async context({user}){
  try{
   const g=await this.db.prepare(`SELECT s.generation AS g FROM device_sessions d ${MJ} JOIN account_security s ON s.owner_id=d.owner_id WHERE d.device_id=?1 AND d.owner_id=?2 AND d.client_kind='android' AND d.generation=?3 AND s.generation=?3 AND d.revoked_at IS NULL AND d.expires_at>?4 AND ${MA}`).bind(user.deviceId,user.ownerId,user.generation,this.now()).first();
   return g&&Number.isSafeInteger(g.g)&&g.g>=0?{generation:g.g}:undefined;
  }catch{return;}
 }
 async #claim(purpose,{user,token}){
  const t=parseAccessToken(token);if(!t)return;const now=this.now();
  const row=await this.db.prepare('UPDATE seed_sync_challenges SET used_at=?5 WHERE challenge_id=?1 AND secret_digest=?2 AND purpose=?3 AND owner_id=?4 AND device_id=?6 AND used_at IS NULL AND created_at<=?5 AND expires_at>?5 RETURNING *').bind(t.tokenId,digestToHex(await digestSecret(t.secret)),purpose,user.ownerId,now,user.deviceId).first();
  return row?{row,now}:undefined;
 }
 async enrollFinish({user,token,signature}){
  try{
   const c=await this.#claim('seed-sync-enroll',{user,token});if(!c)return;const {row}=c;
   const ch={ownerId:row.owner_id,keyId:row.key_id,installId:row.install_id,generation:row.generation,challenge:row.nonce,actionDigest:row.action_digest,expiresAt:row.expires_at};
   if(!await verifySeedSyncProof({jwk:JSON.parse(row.public_jwk),purpose:'seed-sync-enroll',challenge:ch,signature,now:this.now()}))return;
   const at=this.now();if(at>=row.expires_at)return;
   const digest=await hashText(row.public_jwk);
   const guard=`${SESSION('?9','?2','?4','?5')} AND EXISTS(SELECT 1 FROM passkey_credentials WHERE credential_id=?6 AND owner_id=?2 AND revoked_at IS NULL) AND (SELECT count(*) FROM seed_sync_keys WHERE owner_id=?2 AND revoked_at IS NULL AND install_id!=?8)<${MAX_ACTIVE_KEYS}`;
   // Install-state fence. The challenge stored (n, a) at begin: n = rows (active or revoked, insert-only) for this (owner, install), a = the active key or NULL.
   // Commit only if n is unchanged (no enrollment since begin), the new id and public key are free, and the install has no active key left after the
   // supersede below. A predecessor must have been revoked by THIS batch's own UPDATE (changes()=1 on the directly preceding statement), never by
   // anything that merely happened earlier: a late finish after a newer enrollment, a disable or a remote revoke cannot commit or supersede.
   const unchanged=`(SELECT count(*) FROM seed_sync_keys WHERE owner_id=?2 AND install_id=?8)=?10 AND NOT EXISTS(SELECT 1 FROM seed_sync_keys WHERE key_id=?1 OR (owner_id=?2 AND public_key_digest=?7))`;
   // ONE shared predicate for the supersede UPDATE and the key INSERT: a guard can never let the revoke run while the insert is blocked (the INSERT only adds
   // conditions). Pinned by a test that blocks each component and checks the predecessor stays active.
   const shared=`${unchanged} AND ${guard}`;
   const n=row.install_key_count,pred=row.predecessor_key_id??null;
   if(!Number.isSafeInteger(n)||n<0)return;
   const [,ins]=await this.db.batch([
    this.db.prepare(`UPDATE seed_sync_keys SET revoked_at=?5,revoked_reason='superseded' WHERE owner_id=?2 AND install_id=?8 AND revoked_at IS NULL AND ?11 IS NOT NULL AND key_id=?11 AND key_id!=?1 AND ${shared}`).bind(row.key_id,row.owner_id,row.public_jwk,row.generation,at,row.credential_id,digest,row.install_id,user.deviceId,n,pred),
    this.db.prepare(`INSERT INTO seed_sync_keys(key_id,owner_id,install_id,public_jwk,public_key_digest,generation,credential_id,created_at,last_device_id) SELECT ?1,?2,?8,?3,?7,?4,?6,?5,?9 WHERE NOT EXISTS(SELECT 1 FROM seed_sync_keys WHERE owner_id=?2 AND install_id=?8 AND revoked_at IS NULL) AND (?11 IS NULL OR changes()=1) AND ${shared}`).bind(row.key_id,row.owner_id,row.public_jwk,row.generation,at,row.credential_id,digest,row.install_id,user.deviceId,n,pred),
    // New-device security notice, atomic with the key: only if the key INSERT directly before it inserted a row. Needs migration 0053.
    this.db.prepare("INSERT INTO seed_sync_notices(notice_id,owner_id,key_id,kind,created_at) SELECT ?3,?2,?1,'enrolled',?4 WHERE changes()=1 AND EXISTS(SELECT 1 FROM seed_sync_keys WHERE key_id=?1 AND owner_id=?2 AND revoked_at IS NULL)").bind(row.key_id,row.owner_id,crypto.randomUUID(),at),
   ]);
   if(ins.meta.changes<1)return;
   await this.#event(row.owner_id,row.key_id,'enrolled');
   return {keyId:row.key_id};
  }catch(e){return;}
 }
 // Begin never reveals key state: a revoked or stale key still gets a challenge, and only the SIGNED finish returns a definitive code.
 async #beginSigned(purpose,{user,keyId,epoch,ephemeralKey,entries}){
  if(!id(keyId)||!epochOk(epoch))return;
  const k=await this.db.prepare('SELECT generation FROM seed_sync_keys WHERE key_id=?1 AND owner_id=?2').bind(keyId,user.ownerId).first();if(!k)return;
  // Per-key pull limit: an enrolled (possibly stolen) key must not be able to drain seeds at the per-owner rate.
  if(!(await takeRateLimit(this.db,'seed-sync-key:'+purpose+':'+keyId,{now:this.now(),limit:KEY_PULLS_PER_MINUTE})).allowed)return;
  return this.#issue({purpose,ownerId:user.ownerId,keyId,deviceId:user.deviceId,generation:user.generation,epoch,ephemeralKey,entries});
 }
 async snapshotBegin({user,keyId,epoch}){
  try{const c=await this.#beginSigned('seed-sync-snapshot',{user,keyId,epoch});
   return c?{token:c.token,challenge:{ownerId:user.ownerId,keyId,deviceId:user.deviceId,generation:user.generation,epoch,challenge:c.nonce,expiresAt:c.expiresAt}}:undefined;}catch{return;}
 }
 // Common signed-finish: claim atomically, verify, and only then report key/generation state.
 async #finishSigned(purpose,{user,token,signature},build){
  const c=await this.#claim(purpose,{user,token});if(!c)return;const {row}=c;
  const key=await this.db.prepare('SELECT k.public_jwk,k.revoked_at,k.generation AS key_generation,s.generation AS account_generation FROM seed_sync_keys k JOIN account_security s ON s.owner_id=k.owner_id WHERE k.key_id=?1 AND k.owner_id=?2').bind(row.key_id,row.owner_id).first();
  if(!key)return;
  const ch=await build(row);
  if(!await verifySeedSyncProof({jwk:JSON.parse(key.public_jwk),purpose,challenge:ch,signature,now:this.now()}))return;
  if(key.revoked_at!=null){await this.#event(row.owner_id,row.key_id,'denied','key-revoked');return {error:'key-revoked'};}
  if(key.key_generation!==key.account_generation||row.generation!==key.account_generation){await this.#event(row.owner_id,row.key_id,'denied','generation-changed');return {error:'generation-changed'};}
  // Link and liveness in ONE statement: a session revoked after the claim cannot be linked, and then nothing is released.
  const linked=await this.db.prepare(`UPDATE seed_sync_keys SET last_device_id=?2 WHERE key_id=?1 AND owner_id=?3 AND ${SESSION('?2','?3','?4','?5')}`).bind(row.key_id,row.device_id,row.owner_id,row.generation,this.now()).run();
  if(linked.meta.changes<1)return;
  return {row,ch};
 }
 // Snapshot: no secrets. One statement reads revision and entries atomically (a revision never newer than the data).
 async snapshotFinish({user,token,signature}){
  try{
   const f=await this.#finishSigned('seed-sync-snapshot',{user,token,signature},r=>({ownerId:r.owner_id,keyId:r.key_id,deviceId:r.device_id,generation:r.generation,epoch:r.epoch,challenge:r.nonce,expiresAt:r.expires_at}));
   if(!f||f.error)return f;
   const {row}=f,now=this.now();
   const rows=(await this.db.prepare(`SELECT COALESCE(o.revision,0) AS revision,s.entry_id,s.seed_version,s.algorithm,s.digits,s.period,s.seed_bytes FROM accounts a LEFT JOIN seed_sync_owner o ON o.owner_id=a.owner_id LEFT JOIN totp_seeds s ON s.owner_id=a.owner_id WHERE a.owner_id=?1 ORDER BY s.entry_id LIMIT ${SNAPSHOT_CAP+1}`).bind(row.owner_id).all()).results;
   const real=rows.filter(r=>r.entry_id!=null),complete=real.length<=SNAPSHOT_CAP,use=real.slice(0,SNAPSHOT_CAP),entries=[],unsupported=[];
   for(const r of use){const why=representable(r);if(why)unsupported.push({entryId:r.entry_id,reason:why});else entries.push({entryId:r.entry_id,seedVersion:r.seed_version,algorithm:r.algorithm,digits:r.digits,period:r.period});}
   const revision=rows.length?rows[0].revision:0;
   const tombstones=(await this.db.prepare('SELECT entry_id,revision FROM seed_sync_tombstones WHERE owner_id=?1 AND created_at>?2 ORDER BY revision DESC LIMIT ?3').bind(row.owner_id,now-TOMBSTONE_RETENTION,TOMBSTONE_LIMIT).all()).results.map(t=>({entryId:t.entry_id,revision:t.revision}));
   if(!await this.#live(row))return undefined;
   await this.db.prepare('UPDATE seed_sync_keys SET last_used_at=?2 WHERE key_id=?1').bind(row.key_id,now).run();
   return {ownerId:row.owner_id,deviceId:row.device_id,epoch:row.epoch,challengeDigest:await hashText(row.nonce),revision,complete,maxBatch:MAX_BATCH,entries,unsupported,tombstones};
  }catch{return;}
 }
 async batchBegin({user,keyId,epoch,ephemeralKey,entries}){
  try{
   if(!Array.isArray(entries)||entries.length<1||entries.length>MAX_BATCH||new Set(entries.map(e=>e?.entryId)).size!==entries.length)return;
   if(!entries.every(e=>e&&Object.keys(e).sort().join(',')==='entryId,seedVersion'&&id(e.entryId)&&Number.isSafeInteger(e.seedVersion)&&e.seedVersion>=1))return;
   if(!await importClientEphemeral(ephemeralKey))return;
   const sorted=[...entries].sort((a,b)=>a.entryId<b.entryId?-1:1);
   const c=await this.#beginSigned('seed-sync-batch',{user,keyId,epoch,ephemeralKey,entries:JSON.stringify(sorted)});
   return c?{token:c.token,challenge:{ownerId:user.ownerId,keyId,deviceId:user.deviceId,generation:user.generation,epoch,challenge:c.nonce,ephemeralDigest:await sha256Hex(base64urlDecode(ephemeralKey,65)),entriesDigest:await entriesDigest(sorted),expiresAt:c.expiresAt}}:undefined;
  }catch{return;}
 }
 async batchFinish({user,token,signature}){
  try{
   const f=await this.#finishSigned('seed-sync-batch',{user,token,signature},async r=>({ownerId:r.owner_id,keyId:r.key_id,deviceId:r.device_id,generation:r.generation,epoch:r.epoch,challenge:r.nonce,ephemeralDigest:await sha256Hex(base64urlDecode(r.ephemeral_key,65)),entriesDigest:await entriesDigest(JSON.parse(r.entries)),expiresAt:r.expires_at}));
   if(!f||f.error)return f;
   const {row}=f,client=await importClientEphemeral(row.ephemeral_key),requested=JSON.parse(row.entries);
   if(!client)return;
   const challengeDigest=await hashText(row.nonce),ephemeralDigest=f.ch.ephemeralDigest;
   const items=[],results=[];
   try{
    for(const e of requested){
     // Version and envelope are read in ONE query, so a rotation between check and decrypt cannot seal a new seed under an old version.
     const r=await this.db.prepare('SELECT envelope,seed_version,algorithm,digits,period,seed_bytes FROM totp_seeds WHERE owner_id=?1 AND entry_id=?2').bind(row.owner_id,e.entryId).first();
     if(!r){results.push({entryId:e.entryId,status:'removed'});continue;}
     if(r.seed_version!==e.seedVersion){results.push({entryId:e.entryId,status:'stale',seedVersion:r.seed_version});continue;}
     if(representable(r)){results.push({entryId:e.entryId,status:'unsupported'});continue;}
     let secret;
     try{
      const p=JSON.parse(await this.cipher.decrypt(JSON.parse(r.envelope),{ownerId:row.owner_id,entryId:e.entryId}));
      if(!p||typeof p!=='object'||p.algorithm!==r.algorithm||p.digits!==r.digits||p.period!==r.period||typeof p.secret!=='string'||p.secret.length>171)throw new Error('bad');
      secret=base64urlDecode(p.secret,Math.floor(p.secret.length*6/8));
      if(!secret||secret.length<10||secret.length>128||secret.length!==r.seed_bytes)throw new Error('bad');
     }catch{secret?.fill(0);results.push({entryId:e.entryId,status:'unsupported'});continue;}
     // Revalidate after decrypt: the exact version and envelope must still be current.
     const live=await this.db.prepare('SELECT 1 x FROM totp_seeds WHERE owner_id=?1 AND entry_id=?2 AND seed_version=?3 AND envelope=?4').bind(row.owner_id,e.entryId,e.seedVersion,r.envelope).first();
     if(!live){secret.fill(0);results.push({entryId:e.entryId,status:'stale'});continue;}
     items.push({entryId:e.entryId,meta:{algorithm:r.algorithm,digits:r.digits,period:r.period},aad:{ownerId:row.owner_id,deviceId:row.device_id,epoch:row.epoch,entryId:e.entryId,seedVersion:e.seedVersion,algorithm:r.algorithm,digits:r.digits,period:r.period},secret});
    }
    // A revoke or generation bump racing the decrypts must not release anything.
    if(!await this.#live(row)){await this.#event(row.owner_id,row.key_id,'denied','revoked-during-read');return undefined;}
    const sealed=items.length?await sealBatch({client,challengeDigest,ephemeralDigest,items:items.map(i=>({aad:i.aad,secret:i.secret}))}):{serverPublicKey:null,entries:[]};
    const entries=items.map((i,n)=>({entryId:i.entryId,status:'sealed',seedVersion:i.aad.seedVersion,...i.meta,...sealed.entries[n]}));
    await this.db.prepare('UPDATE seed_sync_keys SET last_used_at=?2 WHERE key_id=?1').bind(row.key_id,this.now()).run();
    return {ownerId:row.owner_id,deviceId:row.device_id,epoch:row.epoch,challengeDigest,serverPublicKey:sealed.serverPublicKey,results:[...results,...entries]};
   }finally{for(const i of items)i.secret.fill(0);}
  }catch{return;}
 }
 // Definitive key status WITHOUT a live session (a remotely signed-out device has none). Possession of the enrolled key is the only authority.
 // Begin has one shape for every input (unknown, revoked, rate-limited all look the same). Finish spends the one-use challenge first and then
 // answers only after the key's own signature verified; unknown key, expired, bad signature, replay and a missing row are all the same opaque failure.
 // It reads key and account state only: never seeds, never last_used_at, never a session. Key rows outlive session rows (see doc retention policy).
 async statusBegin({keyId}){
  const now=this.now(),fake=()=>({token:generateAccessToken().token,challenge:{keyId:typeof keyId==='string'?keyId:'',challenge:base64urlEncode(crypto.getRandomValues(new Uint8Array(32))),expiresAt:now+PROOF_TTL}});
  try{
   if(!id(keyId))return fake();
   const k=await this.db.prepare('SELECT owner_id,generation FROM seed_sync_keys WHERE key_id=?1').bind(keyId).first();if(!k)return fake();
   if(!(await takeRateLimit(this.db,'seed-sync-key:status:'+keyId,{now,limit:KEY_PULLS_PER_MINUTE})).allowed)return fake();
   await this.#sweep(now);
   const secret=generateAccessToken(),nonce=base64urlEncode(crypto.getRandomValues(new Uint8Array(32))),expiresAt=now+PROOF_TTL;
   const r=await this.db.prepare(`INSERT INTO seed_sync_challenges(challenge_id,secret_digest,owner_id,key_id,device_id,generation,purpose,epoch,nonce,created_at,expires_at) SELECT ?1,?2,?3,?4,'status',?5,'seed-sync-status',0,?6,?7,?8 WHERE (SELECT count(*) FROM seed_sync_challenges WHERE key_id=?4 AND expires_at>?7 AND used_at IS NULL)<${MAX_KEY_CHALLENGES}`)
    .bind(secret.tokenId,digestToHex(await digestSecret(secret.secret)),k.owner_id,keyId,k.generation,nonce,now,expiresAt).run();
   return r.meta.changes>=1?{token:secret.token,challenge:{keyId,challenge:nonce,expiresAt}}:fake();
  }catch{return fake();}
 }
 async statusFinish({token,signature}){
  try{
   const t=parseAccessToken(token);if(!t)return;const now=this.now();
   const row=await this.db.prepare("UPDATE seed_sync_challenges SET used_at=?3 WHERE challenge_id=?1 AND secret_digest=?2 AND purpose='seed-sync-status' AND used_at IS NULL AND created_at<=?3 AND expires_at>?3 RETURNING *").bind(t.tokenId,digestToHex(await digestSecret(t.secret)),now).first();
   if(!row)return;
   const key=await this.db.prepare('SELECT k.public_jwk,k.revoked_at,k.generation AS key_generation,s.generation AS account_generation FROM seed_sync_keys k JOIN account_security s ON s.owner_id=k.owner_id WHERE k.key_id=?1').bind(row.key_id).first();
   if(!key)return;
   if(!await verifySeedSyncProof({jwk:JSON.parse(key.public_jwk),purpose:'seed-sync-status',challenge:{keyId:row.key_id,challenge:row.nonce,expiresAt:row.expires_at},signature,now}))return;
   const state=key.revoked_at!=null?'key-revoked':key.key_generation!==key.account_generation?'generation-changed':'active';
   if(state!=='active')await this.#event(row.owner_id,row.key_id,'denied',state);
   return {state};
  }catch{return;}
 }
 // Own-install revoke (sign-out or disable while online): authenticated by the key itself (signed one-use purpose) plus the owner's live android session.
 // The reason is always 'disabled', derived from this path. Revoking ANOTHER install's key is only done by the existing verified remote session-revoke
 // (recovery-controls), which calls the same SQL; there is no session-only revoke of other keys.
 async revokeBegin({user,keyId}){
  try{const c=await this.#beginSigned('seed-sync-revoke',{user,keyId,epoch:0});
   return c?{token:c.token,challenge:{ownerId:user.ownerId,keyId,deviceId:user.deviceId,generation:user.generation,challenge:c.nonce,expiresAt:c.expiresAt}}:undefined;}catch{return;}
 }
 async revokeFinish({user,token,signature}){
  try{
   const f=await this.#finishSigned('seed-sync-revoke',{user,token,signature},r=>({ownerId:r.owner_id,keyId:r.key_id,deviceId:r.device_id,generation:r.generation,challenge:r.nonce,expiresAt:r.expires_at}),true);
   if(!f)return;if(f.error==='key-revoked')return {revoked:true};if(f.error)return f;
   const r=await this.db.prepare('UPDATE seed_sync_keys SET revoked_at=?1,revoked_reason=\'disabled\' WHERE key_id=?2 AND owner_id=?3 AND revoked_at IS NULL').bind(this.now(),f.row.key_id,user.ownerId).run();
   if(r.meta.changes>=1)await this.#event(user.ownerId,f.row.key_id,'revoked','disabled');
   return {revoked:true};
  }catch{return;}
 }
 async listKeys({user}){
  try{
   const rows=(await this.db.prepare(`SELECT key_id,install_id,created_at,last_used_at,revoked_at,revoked_reason FROM seed_sync_keys WHERE owner_id=?1 AND ${SESSION('?2','?1','?3','?4')} ORDER BY created_at DESC LIMIT 50`).bind(user.ownerId,user.deviceId,user.generation,this.now()).all()).results;
   return {keys:rows.map(r=>({keyId:r.key_id,installId:r.install_id,createdAt:r.created_at,lastUsedAt:r.last_used_at,revokedAt:r.revoked_at,reason:r.revoked_reason}))};
  }catch{return;}
 }
 async metadataPending(){return (await this.db.prepare('SELECT count(*) n FROM totp_seeds WHERE algorithm IS NULL OR digits IS NULL OR period IS NULL OR seed_bytes IS NULL').first()).n;}

 // Internal (security events, generation handling): revoke without a user session.
 async revoke({ownerId,keyId,reason='remote'}){
  const r=await this.db.prepare('UPDATE seed_sync_keys SET revoked_at=?1,revoked_reason=?4 WHERE key_id=?2 AND owner_id=?3 AND revoked_at IS NULL').bind(this.now(),keyId,ownerId,reason).run();
  if(r.meta.changes>=1)await this.#event(ownerId,keyId,'revoked',reason);
  return r.meta.changes>=1;
 }
 // One-time or periodic maintenance (run until metadataPending() is 0 BEFORE mounting; the update bumps the owner revision via trigger): fill non-secret metadata for rows written before this migration (bounded, decrypts in memory).
 async backfillMetadata({limit=20}={}){
  const rows=(await this.db.prepare('SELECT owner_id,entry_id,envelope FROM totp_seeds WHERE algorithm IS NULL OR digits IS NULL OR period IS NULL OR seed_bytes IS NULL LIMIT ?1').bind(Math.min(Math.max(1,limit),50)).all()).results;
  let done=0;
  for(const r of rows){
   let secret;
   try{
    const p=JSON.parse(await this.cipher.decrypt(JSON.parse(r.envelope),{ownerId:r.owner_id,entryId:r.entry_id}));
    secret=base64urlDecode(p.secret,Math.floor(p.secret.length*6/8));
    if(!secret)continue;
    const u=await this.db.prepare('UPDATE totp_seeds SET algorithm=?3,digits=?4,period=?5,seed_bytes=?6 WHERE owner_id=?1 AND entry_id=?2 AND envelope=?7').bind(r.owner_id,r.entry_id,p.algorithm,p.digits,p.period,secret.length,r.envelope).run();
    if(u.meta.changes>=1)done++;
   }catch{/* leave pending */}finally{secret?.fill(0);}
  }
  return done;
 }
}
