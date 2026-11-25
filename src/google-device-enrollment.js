// Internal, unmounted. First device-key enrollment for a Google-only account via a
// 120 s server grant, plus adopt and status. Proof means key possession only.
import {hashText} from './sessions.js';
import {generateAccessToken,parseAccessToken,digestSecret,digestToHex,base64urlEncode} from './tokens.js';
import {importDevicePublicKey,verifyDeviceKeyProof} from './device-key-proof.js';
import {deviceEnrollmentAction} from './durable-device-keys.js';
import {SESSION_METHOD_JOIN as MJ,SESSION_METHOD_ACTIVE as MA} from './session-method.js';
const TTL=120000,RECEIPT_TTL=600000,GOOGLE='https://accounts.google.com';
const keyText=j=>JSON.stringify({kty:j.kty,crv:j.crv,x:j.x,y:j.y});
const isDigest=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const parse=async t=>{const p=parseAccessToken(t);return p?{id:p.tokenId,hash:digestToHex(await digestSecret(p.secret))}:undefined;};
export const deviceBind=(deviceId,second)=>hashText(JSON.stringify(['otpanda-device-bind-v1',deviceId,second]));
export const adoptAction=digest=>hashText(JSON.stringify(['adopt-device-key-v1',digest]));
// Active Google-method android session at the given generation (SQL fragment, params: device ?D owner ?O gen ?G now ?N)
const SESSION=(D,O,G,N)=>`EXISTS(SELECT 1 FROM device_sessions d JOIN account_security s ON s.owner_id=d.owner_id JOIN provider_identities i ON i.identity_id=d.provider_identity_id AND i.owner_id=d.owner_id WHERE d.device_id=${D} AND d.owner_id=${O} AND d.client_kind='android' AND d.generation=${G} AND s.generation=${G} AND d.revoked_at IS NULL AND d.expires_at>${N} AND i.revoked_at IS NULL AND i.issuer='${GOOGLE}')`;
export class GoogleDeviceEnrollment {
 constructor(db,{clock=Date.now}={}){this.db=db;this.clock=clock;}
 now(){const n=this.clock();if(!Number.isSafeInteger(n)||n<0)throw new TypeError('Valid instant required');return n;}
 // -> {token,challenge} | {error:'method_exists'} | undefined (opaque)
 async begin({user,publicJwk,grant}){
  let digest,text,actionDigest;
  try{await importDevicePublicKey(publicJwk);text=keyText(publicJwk);digest=await hashText(text);actionDigest=await deviceEnrollmentAction(publicJwk);}catch{return;}
  const g=await parse(grant);if(!g)return;const now=this.now();
  const row=await this.db.prepare(`SELECT g.expires_at FROM google_enrollment_grants g WHERE g.grant_id=?1 AND g.secret_digest=?2 AND g.owner_id=?3 AND g.device_id=?4 AND g.generation=?5 AND g.created_at<=?6 AND g.expires_at>?6 AND g.consumed_at IS NULL AND ${SESSION('?4','?3','?5','?6')}`).bind(g.id,g.hash,user.ownerId,user.deviceId,user.generation,now).first();
  if(!row)return;
  const prior=await this.db.prepare('SELECT key_id,revoked_at FROM durable_device_keys WHERE owner_id=?1 AND public_key_digest=?2').bind(user.ownerId,digest).first();
  if(prior?.revoked_at!=null)return;
  const other=await this.db.prepare('SELECT (EXISTS(SELECT 1 FROM passkey_credentials WHERE owner_id=?1 AND revoked_at IS NULL) OR EXISTS(SELECT 1 FROM durable_device_keys WHERE owner_id=?1 AND revoked_at IS NULL AND public_key_digest!=?2)) AS blocked').bind(user.ownerId,digest).first();
  if(other?.blocked)return {error:'method_exists'};
  const keyId=prior?.key_id??'k_'+(await hashText(JSON.stringify(['device-key-id-v1',user.ownerId,digest]))).slice(0,40),secret=generateAccessToken(),cid=(await parse(secret.token)).id,hash=(await parse(secret.token)).hash;
  const challenge=base64urlEncode(crypto.getRandomValues(new Uint8Array(32))),expiresAt=Math.min(now+TTL,row.expires_at),binding=await deviceBind(user.deviceId,g.id),bindingDigest=await hashText(binding);
  const r=await this.db.prepare(`INSERT INTO durable_device_challenges(challenge_id,secret_digest,binding_digest,key_id,owner_id,generation,purpose,action_digest,public_jwk,challenge,created_at,expires_at) SELECT ?1,?2,?3,?4,?5,?6,'enroll',?7,?8,?9,?10,?11 WHERE EXISTS(SELECT 1 FROM google_enrollment_grants WHERE grant_id=?12 AND owner_id=?5 AND device_id=?13 AND generation=?6 AND consumed_at IS NULL AND expires_at>?10) AND ${SESSION('?13','?5','?6','?10')} AND NOT EXISTS(SELECT 1 FROM passkey_credentials WHERE owner_id=?5 AND revoked_at IS NULL) AND NOT EXISTS(SELECT 1 FROM durable_device_keys WHERE owner_id=?5 AND revoked_at IS NULL AND public_key_digest!=?14) AND (SELECT count(*) FROM durable_device_challenges WHERE owner_id=?5 AND purpose='enroll' AND expires_at>?10 AND consumed_at IS NULL)<32 AND (SELECT count(*) FROM durable_device_keys WHERE owner_id=?5 AND revoked_at IS NULL AND key_id!=?4)<20`).bind(cid,hash,bindingDigest,keyId,user.ownerId,user.generation,actionDigest,text,challenge,now,expiresAt,g.id,user.deviceId,digest).run();
  return r.meta.changes===1?{token:secret.token,challenge:{ownerId:user.ownerId,keyId,generation:user.generation,purpose:'enroll',actionDigest,challenge,expiresAt}}:undefined;
 }
 // -> {status:'enrolled',keyId} | undefined (opaque; client reconciles with status)
 async finish({user,grant,token,signature}){
  const g=await parse(grant),t=await parse(token);if(!g||!t)return;const now=this.now();
  const binding=await deviceBind(user.deviceId,g.id),bd=await hashText(binding);
  const replay=async at=>{const rec=await this.db.prepare('SELECT result_json FROM device_key_receipts WHERE challenge_id=?1 AND secret_digest=?2 AND binding_digest=?3 AND session_device_id=?4 AND owner_id=?5 AND purpose=\'enroll\' AND expires_at>?6').bind(t.id,t.hash,bd,user.deviceId,user.ownerId,at).first();return rec?JSON.parse(rec.result_json):undefined;};
  const prev=await replay(now);if(prev)return prev;
  const row=await this.db.prepare('SELECT * FROM durable_device_challenges WHERE challenge_id=?1 AND secret_digest=?2 AND binding_digest=?3 AND owner_id=?4 AND generation=?5 AND purpose=\'enroll\' AND consumed_at IS NULL AND created_at<=?6 AND expires_at>?6').bind(t.id,t.hash,await hashText(binding),user.ownerId,user.generation,now).first();
  if(!row||!row.public_jwk)return;
  const c={ownerId:row.owner_id,keyId:row.key_id,generation:row.generation,purpose:'enroll',actionDigest:row.action_digest,challenge:row.challenge,expiresAt:row.expires_at};
  if(!await verifyDeviceKeyProof({jwk:JSON.parse(row.public_jwk),challenge:c,signature,now:this.now()}))return;
  const done=this.now();if(done>=row.expires_at)return;
  const digest=await hashText(row.public_jwk),result=JSON.stringify({status:'enrolled',keyId:row.key_id}),binds=[t.id,t.hash,await hashText(binding),done,user.ownerId,user.deviceId,user.generation,g.id,g.hash,row.key_id,row.public_jwk,digest,result,done+RECEIPT_TTL];
  try{
   await this.db.batch([
    this.db.prepare('UPDATE durable_device_challenges SET consumed_at=?4 WHERE challenge_id=?1 AND secret_digest=?2 AND binding_digest=?3 AND consumed_at IS NULL AND expires_at>?4').bind(t.id,t.hash,await hashText(binding),done),
    this.db.prepare('UPDATE google_enrollment_grants SET consumed_at=?1 WHERE grant_id=?2 AND secret_digest=?3 AND owner_id=?4 AND device_id=?5 AND generation=?6 AND consumed_at IS NULL AND expires_at>?1 AND changes()=1').bind(done,g.id,g.hash,user.ownerId,user.deviceId,user.generation),
    this.db.prepare(`INSERT INTO durable_device_keys(key_id,owner_id,public_jwk,generation,created_at,public_key_digest) SELECT ?1,?2,?3,?4,?5,?6 WHERE changes()=1 AND NOT EXISTS(SELECT 1 FROM passkey_credentials WHERE owner_id=?2 AND revoked_at IS NULL) AND NOT EXISTS(SELECT 1 FROM durable_device_keys WHERE owner_id=?2 AND revoked_at IS NULL AND public_key_digest!=?6) AND ${SESSION('?7','?2','?4','?5')} AND (SELECT count(*) FROM durable_device_keys WHERE owner_id=?2 AND revoked_at IS NULL AND key_id!=?1)<20 ON CONFLICT(owner_id,public_key_digest) DO UPDATE SET last_used_at=?5 WHERE revoked_at IS NULL AND generation=?4 AND key_id=?1`).bind(row.key_id,user.ownerId,row.public_jwk,user.generation,done,digest,user.deviceId),
    // A NOT NULL violation (result_json NULL) rolls the whole batch back unless the key statement changed one row.
    this.db.prepare('INSERT INTO device_key_receipts(challenge_id,owner_id,session_device_id,key_id,purpose,action_digest,secret_digest,binding_digest,result_json,created_at,expires_at) VALUES(?1,?2,?3,?4,\'enroll\',?5,?6,?7,CASE WHEN changes()=1 THEN ?8 END,?9,?10)').bind(t.id,user.ownerId,user.deviceId,row.key_id,row.action_digest,t.hash,await hashText(binding),result,done,done+RECEIPT_TTL),
   ]);
  }catch{return await replay(this.now());}
  return {status:'enrolled',keyId:row.key_id};
 }
 // Read/adopt only reveal or prove an EXISTING owner key by possession, so any live android session of the owner at the current generation
 // (passkey OR Google method) may use them. Enrollment (begin/finish) keeps the Google-grant SESSION guard.
 async #active(user){const n=this.now();return !!await this.db.prepare(`SELECT 1 AS ok WHERE EXISTS(SELECT 1 FROM device_sessions d ${MJ} JOIN account_security s ON s.owner_id=d.owner_id WHERE d.device_id=?1 AND d.owner_id=?2 AND d.client_kind='android' AND d.generation=?3 AND s.generation=?3 AND d.revoked_at IS NULL AND d.expires_at>?4 AND ${MA})`).bind(user.deviceId,user.ownerId,user.generation,n).first();}
 async status({user,digest}){
  if(!isDigest(digest)||!await this.#active(user))return;
  const r=await this.db.prepare('SELECT key_id,revoked_at FROM durable_device_keys WHERE owner_id=?1 AND public_key_digest=?2').bind(user.ownerId,digest).first();
  return !r?{status:'absent'}:r.revoked_at!=null?{status:'revoked'}:{status:'enrolled',keyId:r.key_id};
 }
 async adoptBegin({user,digest,keys}){
  if(!isDigest(digest)||!await this.#active(user))return;
  const r=await this.db.prepare('SELECT key_id FROM durable_device_keys WHERE owner_id=?1 AND public_key_digest=?2 AND revoked_at IS NULL AND generation=?3').bind(user.ownerId,digest,user.generation).first();if(!r)return;
  return keys.beginProof({owner:user.ownerId,keyId:r.key_id,purpose:'step-up',actionDigest:await adoptAction(digest),browserBinding:await deviceBind(user.deviceId,digest)});
 }
 async adoptFinish({user,digest,token,signature,keys}){
  if(!isDigest(digest)||!await this.#active(user))return;
  const p=await keys.finish({token,browserBinding:await deviceBind(user.deviceId,digest),signature});
  if(!p||p.ownerId!==user.ownerId||p.generation!==user.generation||p.actionDigest!==await adoptAction(digest))return;
  const r=await this.db.prepare('SELECT key_id FROM durable_device_keys WHERE owner_id=?1 AND public_key_digest=?2 AND key_id=?3 AND revoked_at IS NULL').bind(user.ownerId,digest,p.keyId).first();
  return r?{status:'enrolled',keyId:r.key_id}:undefined;
 }
}
