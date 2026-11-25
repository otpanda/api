// Internal, unmounted. Approvals by an enrolled phone: passkey-add (web requester) and device-key-add (new phone).
// Proof means possession of an enrolled device key, never "biometric-verified". Every guard failure is opaque (undefined).
import {hashText} from './sessions.js';
import {generateAccessToken,parseAccessToken,digestSecret,digestToHex,base64urlEncode} from './tokens.js';
import {importDevicePublicKey,verifyDeviceKeyProof} from './device-key-proof.js';
import {deviceEnrollmentAction} from './durable-device-keys.js';
import {deviceBind} from './google-device-enrollment.js';
import {SESSION_METHOD_JOIN as MJ,SESSION_METHOD_ACTIVE as MA} from './session-method.js';
export const APPROVAL_TTL=600000,AUTH_TTL=120000,RECEIPT_TTL=600000,MAX_PENDING=8,MAX_KEYS=20;
const keyText=j=>JSON.stringify({kty:j.kty,crv:j.crv,x:j.x,y:j.y});
const id=v=>typeof v==='string'&&/^[A-Za-z0-9_-]{1,128}$/.test(v);
const parse=async t=>{const p=parseAccessToken(t);return p?{id:p.tokenId,hash:digestToHex(await digestSecret(p.secret))}:undefined;};
export const approvalAction=(changeId,kind,target,ownerId,generation)=>hashText(JSON.stringify(['enrolled-approval',changeId,kind,target??null,ownerId,generation]));
export const approveBinding=(ownerId,deviceId,changeId)=>hashText(JSON.stringify(['enrolled-approve',ownerId,deviceId,changeId]));
export const fingerprint=digest=>digest.slice(0,16).match(/.{4}/g).join('-');
// Active session of a given client kind (SQL fragment). D device, O owner, G generation, N now placeholders.
const SESSION=(kind,D,O,G,N)=>`EXISTS(SELECT 1 FROM device_sessions d ${MJ} JOIN account_security s ON s.owner_id=d.owner_id WHERE d.device_id=${D} AND d.owner_id=${O} AND d.client_kind='${kind}' AND d.generation=${G} AND s.generation=${G} AND d.revoked_at IS NULL AND d.expires_at>${N} AND ${MA})`;
// Approver key active at the generation, owned by the owner (K key id, O owner, G generation).
const KEY=(K,O,G)=>`EXISTS(SELECT 1 FROM durable_device_keys k WHERE k.key_id=${K} AND k.owner_id=${O} AND k.revoked_at IS NULL AND k.generation=${G})`;
export class EnrolledApprovals {
 constructor(db,{clock=Date.now,keys}={}){if(!keys)throw new TypeError('Device keys required');Object.assign(this,{db,clock,keys});}
 now(){const n=this.clock();if(!Number.isSafeInteger(n)||n<0)throw new TypeError('Valid instant required');return n;}
 async #open(owner,device,kind,now){return this.db.prepare('SELECT change_id,expires_at,target,approved_at FROM enrolled_approvals WHERE owner_id=?1 AND requester_device_id=?2 AND kind=?3 AND consumed_at IS NULL AND expires_at>?4').bind(owner,device,kind,now).first();}
 // Web session asks for a passkey-add approval. One open request per requester device; a lost response or a race returns the same row.
 async requestPasskeyAdd({user}){
  const now=this.now(),changeId=crypto.randomUUID(),expiresAt=now+APPROVAL_TTL;
  // Same batch: drop this device's expired unconsumed request first (the partial unique index would block the insert), then insert if absent.
  try{await this.db.batch([
   this.db.prepare('DELETE FROM enrolled_approvals WHERE owner_id=?1 AND requester_device_id=?2 AND kind=\'passkey-add\' AND consumed_at IS NULL AND expires_at<=?3').bind(user.ownerId,user.deviceId,now),
   this.db.prepare(`INSERT INTO enrolled_approvals(change_id,owner_id,generation,kind,requester_device_id,requester_label,created_at,expires_at) SELECT ?1,?2,?3,'passkey-add',?4,NULL,?5,?6 WHERE ${SESSION('web','?4','?2','?3','?5')} AND EXISTS(SELECT 1 FROM durable_device_keys WHERE owner_id=?2 AND revoked_at IS NULL AND generation=?3) AND (SELECT count(*) FROM enrolled_approvals WHERE owner_id=?2 AND consumed_at IS NULL AND expires_at>?5)<${MAX_PENDING} ON CONFLICT DO NOTHING`).bind(changeId,user.ownerId,user.generation,user.deviceId,now,expiresAt),
  ]);}catch{/* a racing winner already holds the open row: return it below */}
  const row=await this.#open(user.ownerId,user.deviceId,'passkey-add',now);
  return row?{changeId:row.change_id,expiresAt:row.expires_at}:undefined;
 }
 // New phone (android session) asks to add its own key. Re-requesting with a different key replaces an unapproved request.
 async requestDeviceKeyAdd({user,publicJwk}){
  let text,digest;
  try{await importDevicePublicKey(publicJwk);text=keyText(publicJwk);digest=await hashText(text);}catch{return;}
  const now=this.now(),changeId=crypto.randomUUID(),expiresAt=now+APPROVAL_TTL;
  try{await this.db.batch([
   this.db.prepare('DELETE FROM enrolled_approvals WHERE owner_id=?1 AND requester_device_id=?2 AND kind=\'device-key-add\' AND consumed_at IS NULL AND (expires_at<=?3 OR (approved_at IS NULL AND target!=?4))').bind(user.ownerId,user.deviceId,now,digest),
   this.db.prepare(`INSERT INTO enrolled_approvals(change_id,owner_id,generation,kind,target,target_jwk,requester_device_id,requester_label,created_at,expires_at) SELECT ?1,?2,?3,'device-key-add',?4,?5,?6,NULL,?7,?8 WHERE ${SESSION('android','?6','?2','?3','?7')} AND EXISTS(SELECT 1 FROM durable_device_keys WHERE owner_id=?2 AND revoked_at IS NULL AND generation=?3) AND NOT EXISTS(SELECT 1 FROM durable_device_keys WHERE owner_id=?2 AND public_key_digest=?4) AND (SELECT count(*) FROM durable_device_keys WHERE owner_id=?2 AND revoked_at IS NULL)<${MAX_KEYS} AND (SELECT count(*) FROM enrolled_approvals WHERE owner_id=?2 AND consumed_at IS NULL AND expires_at>?7)<${MAX_PENDING} ON CONFLICT DO NOTHING`).bind(changeId,user.ownerId,user.generation,digest,text,user.deviceId,now,expiresAt),
  ]);}catch{/* a racing winner already holds the open row: return it below */}
  const row=await this.#open(user.ownerId,user.deviceId,'device-key-add',now);
  return row&&row.target===digest?{changeId:row.change_id,expiresAt:row.expires_at,fingerprint:fingerprint(digest)}:undefined;
 }
 // requesterKind is server-derived from the requester session; requestedAt is when the REQUEST was created (not the session). Display only, not in the digest.
 // Approver (android) lists unapproved, unexpired requests of its owner from OTHER devices. Read-only, max 8.
 async status({user}){
  const now=this.now();
  const ok=await this.db.prepare(`SELECT 1 AS ok WHERE ${SESSION('android','?1','?2','?3','?4')}`).bind(user.deviceId,user.ownerId,user.generation,now).first();if(!ok)return;
  const r=await this.db.prepare(`SELECT a.change_id,a.kind,a.target,a.requester_label,a.expires_at,a.created_at,d.client_kind FROM enrolled_approvals a JOIN device_sessions d ON d.device_id=a.requester_device_id WHERE a.owner_id=?1 AND a.generation=?2 AND a.approved_at IS NULL AND a.consumed_at IS NULL AND a.expires_at>?3 AND a.requester_device_id!=?4 ORDER BY a.created_at DESC LIMIT ${MAX_PENDING}`).bind(user.ownerId,user.generation,now,user.deviceId).all();
  return {ownerId:user.ownerId,generation:user.generation,pending:(r.results??[]).map(x=>({changeId:x.change_id,kind:x.kind,target:x.target,requesterLabel:x.requester_label,requesterKind:x.client_kind==='android'?'android':'web',requestedAt:x.created_at,expiresAt:x.expires_at}))};
 }
 async #pending(user,changeId,now){
  if(!id(changeId))return;
  return this.db.prepare('SELECT * FROM enrolled_approvals WHERE change_id=?1 AND owner_id=?2 AND generation=?3 AND approved_at IS NULL AND consumed_at IS NULL AND expires_at>?4 AND requester_device_id!=?5').bind(changeId,user.ownerId,user.generation,now,user.deviceId).first();
 }
 async approveBegin({user,changeId,keyId}){
  const now=this.now(),row=await this.#pending(user,changeId,now);if(!row||typeof keyId!=='string'||!keyId||keyId.length>128)return;
  const ok=await this.db.prepare(`SELECT 1 AS ok WHERE ${SESSION('android','?1','?2','?3','?4')} AND ${KEY('?5','?2','?3')}`).bind(user.deviceId,user.ownerId,user.generation,now,keyId).first();if(!ok)return;
  const c=await this.keys.beginProof({owner:user.ownerId,keyId,purpose:'step-up',actionDigest:await approvalAction(row.change_id,row.kind,row.target,row.owner_id,row.generation),browserBinding:await approveBinding(user.ownerId,user.deviceId,changeId)});
  return c&&c.challenge.generation===user.generation?c:undefined;
 }
 // -> {status:'approved'} | undefined. The challenge is consumed by verification; a failure needs a new approve-begin.
 async approveFinish({user,changeId,token,signature}){
  const now=this.now();if(!id(changeId)||!parseAccessToken(token))return;
  const prior=await this.db.prepare('SELECT 1 AS ok FROM enrolled_approvals WHERE change_id=?1 AND owner_id=?2 AND approver_device_id=?3 AND approved_at IS NOT NULL AND expires_at>?4').bind(changeId,user.ownerId,user.deviceId,now).first();
  if(prior)return {status:'approved'};
  const row=await this.#pending(user,changeId,now);if(!row)return;
  const p=await this.keys.finish({token,browserBinding:await approveBinding(user.ownerId,user.deviceId,changeId),signature});
  if(!p||p.purpose!=='step-up'||p.ownerId!==user.ownerId||p.generation!==user.generation||p.actionDigest!==await approvalAction(row.change_id,row.kind,row.target,row.owner_id,row.generation))return;
  const done=this.now();
  const r=await this.db.prepare(`UPDATE enrolled_approvals SET approved_at=?1,approver_device_id=?2,approver_key_id=?3 WHERE change_id=?4 AND owner_id=?5 AND generation=?6 AND approved_at IS NULL AND consumed_at IS NULL AND expires_at>?1 AND requester_device_id!=?2 AND ${SESSION('android','?2','?5','?6','?1')} AND ${KEY('?3','?5','?6')}`).bind(done,user.deviceId,p.keyId,changeId,user.ownerId,user.generation).run();
  return r.meta.changes===1?{status:'approved'}:undefined;
 }
 // WEB requester redeems an approved passkey-add. Insert the authorization first; the claim writes only when it changed one row. Single use.
 async authorizePasskeyAdd({user,changeId}){
  if(!id(changeId))return;
  const now=this.now(),t=generateAccessToken(),p=await parse(t.token),expiresAt=now+AUTH_TTL;
  const live=`a.change_id=?1 AND a.owner_id=?3 AND a.generation=?5 AND a.kind='passkey-add' AND a.requester_device_id=?4 AND a.approved_at IS NOT NULL AND a.consumed_at IS NULL AND a.expires_at>?6 AND a.approver_device_id!=a.requester_device_id AND ${KEY('a.approver_key_id','a.owner_id','a.generation')} AND ${SESSION('android','a.approver_device_id','a.owner_id','a.generation','?6')}`;
  try{
   await this.db.batch([
    this.db.prepare(`INSERT OR REPLACE INTO passkey_add_authorizations(auth_id,secret_digest,owner_id,device_id,generation,approver_credential_id,approver_key_id,created_at,expires_at) SELECT ?2,?7,?3,?4,?5,NULL,a.approver_key_id,?6,?8 FROM enrolled_approvals a WHERE ${live} AND ${SESSION('web','?4','?3','?5','?6')} AND (SELECT count(*) FROM passkey_credentials WHERE owner_id=?3 AND revoked_at IS NULL)<10`).bind(changeId,p.id,user.ownerId,user.deviceId,user.generation,now,p.hash,expiresAt),
    this.db.prepare(`UPDATE enrolled_approvals AS a SET consumed_at=?6,consume_receipt=?2 WHERE ${live} AND EXISTS(SELECT 1 FROM passkey_add_authorizations WHERE auth_id=?2 AND secret_digest=?7)`).bind(changeId,p.id,user.ownerId,user.deviceId,user.generation,now,p.hash),
   ]);
  }catch{return;}
  const ok=await this.db.prepare('SELECT 1 AS ok FROM enrolled_approvals WHERE change_id=?1 AND consume_receipt=?2 AND consumed_at=?3').bind(changeId,p.id,now).first();
  return ok?{token:t.token,expiresAt}:undefined;
 }
 // NEW phone, after approval: issue an 'enroll' challenge over the stored target key.
 async addBegin({user,changeId}){
  if(!id(changeId))return;const now=this.now();
  const row=await this.db.prepare(`SELECT a.* FROM enrolled_approvals a WHERE a.change_id=?1 AND a.owner_id=?2 AND a.generation=?3 AND a.kind='device-key-add' AND a.requester_device_id=?4 AND a.approved_at IS NOT NULL AND a.consumed_at IS NULL AND a.expires_at>?5 AND ${KEY('a.approver_key_id','a.owner_id','a.generation')}`).bind(changeId,user.ownerId,user.generation,user.deviceId,now).first();
  if(!row)return;
  let jwk;try{jwk=JSON.parse(row.target_jwk);await importDevicePublicKey(jwk);}catch{return;}
  if(row.target!==await hashText(row.target_jwk))return;// stored key must still be exactly the approved digest
  const actionDigest=await deviceEnrollmentAction(jwk),prior=await this.db.prepare('SELECT key_id,revoked_at FROM durable_device_keys WHERE owner_id=?1 AND public_key_digest=?2').bind(user.ownerId,row.target).first();
  if(prior?.revoked_at!=null)return;
  const keyId=prior?.key_id??'k_'+(await hashText(JSON.stringify(['device-key-id-v1',user.ownerId,row.target]))).slice(0,40),secret=generateAccessToken(),t=await parse(secret.token);
  const challenge=base64urlEncode(crypto.getRandomValues(new Uint8Array(32))),expiresAt=Math.min(now+AUTH_TTL,row.expires_at),bd=await hashText(await deviceBind(user.deviceId,changeId));
  const r=await this.db.prepare(`INSERT INTO durable_device_challenges(challenge_id,secret_digest,binding_digest,key_id,owner_id,generation,purpose,action_digest,public_jwk,challenge,created_at,expires_at) SELECT ?1,?2,?3,?4,?5,?6,'enroll',?7,?8,?9,?10,?11 WHERE EXISTS(SELECT 1 FROM enrolled_approvals a WHERE a.change_id=?12 AND a.owner_id=?5 AND a.generation=?6 AND a.approved_at IS NOT NULL AND a.consumed_at IS NULL AND a.expires_at>?10 AND ${KEY('a.approver_key_id','a.owner_id','a.generation')}) AND ${SESSION('android','?13','?5','?6','?10')} AND (SELECT count(*) FROM durable_device_challenges WHERE owner_id=?5 AND purpose='enroll' AND expires_at>?10 AND consumed_at IS NULL)<32 AND (SELECT count(*) FROM durable_device_keys WHERE owner_id=?5 AND revoked_at IS NULL AND key_id!=?4)<${MAX_KEYS}`).bind(t.id,t.hash,bd,keyId,user.ownerId,user.generation,actionDigest,row.target_jwk,challenge,now,expiresAt,changeId,user.deviceId).run();
  return r.meta.changes===1?{token:secret.token,challenge:{ownerId:user.ownerId,keyId,generation:user.generation,purpose:'enroll',actionDigest,challenge,expiresAt}}:undefined;
 }
 // -> {status:'enrolled',keyId} | undefined. Challenge claim, approval claim, key insert and receipt commit in one batch or not at all.
 async addFinish({user,changeId,token,signature}){
  const t=await parse(token);if(!t||!id(changeId))return;const now=this.now();
  const bd=await hashText(await deviceBind(user.deviceId,changeId));
  const replay=async at=>{const rec=await this.db.prepare('SELECT result_json FROM device_key_receipts WHERE challenge_id=?1 AND secret_digest=?2 AND binding_digest=?3 AND session_device_id=?4 AND owner_id=?5 AND purpose=\'enroll\' AND expires_at>?6').bind(t.id,t.hash,bd,user.deviceId,user.ownerId,at).first();return rec?JSON.parse(rec.result_json):undefined;};
  const prev=await replay(now);if(prev)return prev;
  const row=await this.db.prepare('SELECT * FROM durable_device_challenges WHERE challenge_id=?1 AND secret_digest=?2 AND binding_digest=?3 AND owner_id=?4 AND generation=?5 AND purpose=\'enroll\' AND consumed_at IS NULL AND created_at<=?6 AND expires_at>?6').bind(t.id,t.hash,bd,user.ownerId,user.generation,now).first();
  if(!row||!row.public_jwk)return;
  const ap=await this.db.prepare('SELECT target,target_jwk FROM enrolled_approvals WHERE change_id=?1 AND owner_id=?2 AND kind=\'device-key-add\' AND requester_device_id=?3').bind(changeId,user.ownerId,user.deviceId).first();
  // The signed key must be exactly the approved target.
  if(!ap||ap.target_jwk!==row.public_jwk||ap.target!==await hashText(row.public_jwk))return;
  const c={ownerId:row.owner_id,keyId:row.key_id,generation:row.generation,purpose:'enroll',actionDigest:row.action_digest,challenge:row.challenge,expiresAt:row.expires_at};
  if(!await verifyDeviceKeyProof({jwk:JSON.parse(row.public_jwk),challenge:c,signature,now:this.now()}))return;
  const done=this.now();if(done>=row.expires_at)return;
  const result=JSON.stringify({status:'enrolled',keyId:row.key_id});
  try{
   await this.db.batch([
    this.db.prepare('UPDATE durable_device_challenges SET consumed_at=?4 WHERE challenge_id=?1 AND secret_digest=?2 AND binding_digest=?3 AND consumed_at IS NULL AND expires_at>?4').bind(t.id,t.hash,bd,done),
    this.db.prepare(`UPDATE enrolled_approvals AS a SET consumed_at=?1,consume_receipt=?2 WHERE a.change_id=?3 AND a.owner_id=?4 AND a.generation=?5 AND a.kind='device-key-add' AND a.requester_device_id=?6 AND a.target=?7 AND a.target_jwk=?8 AND a.approved_at IS NOT NULL AND a.consumed_at IS NULL AND a.expires_at>?1 AND changes()=1 AND ${KEY('a.approver_key_id','a.owner_id','a.generation')} AND ${SESSION('android','a.approver_device_id','a.owner_id','a.generation','?1')}`).bind(done,t.id,changeId,user.ownerId,user.generation,user.deviceId,ap.target,ap.target_jwk),
    this.db.prepare(`INSERT INTO durable_device_keys(key_id,owner_id,public_jwk,generation,created_at,public_key_digest) SELECT ?1,?2,?3,?4,?5,?6 WHERE changes()=1 AND ${SESSION('android','?7','?2','?4','?5')} AND (SELECT count(*) FROM durable_device_keys WHERE owner_id=?2 AND revoked_at IS NULL AND key_id!=?1)<${MAX_KEYS} ON CONFLICT(owner_id,public_key_digest) DO UPDATE SET last_used_at=?5 WHERE revoked_at IS NULL AND generation=?4 AND key_id=?1`).bind(row.key_id,user.ownerId,row.public_jwk,user.generation,done,ap.target,user.deviceId),
    this.db.prepare('INSERT INTO device_key_receipts(challenge_id,owner_id,session_device_id,key_id,purpose,action_digest,secret_digest,binding_digest,result_json,created_at,expires_at) VALUES(?1,?2,?3,?4,\'enroll\',?5,?6,?7,CASE WHEN changes()=1 THEN ?8 END,?9,?10)').bind(t.id,user.ownerId,user.deviceId,row.key_id,row.action_digest,t.hash,bd,result,done,done+RECEIPT_TTL),
   ]);
  }catch{return await replay(this.now());}
  return {status:'enrolled',keyId:row.key_id};
 }
 // Bounded retention: expired or consumed-and-old approvals.
 async cleanup({limit=100}={}){const now=this.now();const r=await this.db.prepare('DELETE FROM enrolled_approvals WHERE change_id IN(SELECT change_id FROM enrolled_approvals WHERE expires_at<=?1 OR consumed_at<=?2 ORDER BY expires_at LIMIT ?3)').bind(now,now-RECEIPT_TTL,limit).run();return r.meta.changes;}
}
