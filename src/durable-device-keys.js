// Internal only. Caller must supply actual verifier-produced strongProof, never
// a request body's assertion. This returns proofs, not sessions/reset effects.
import {hashText} from './sessions.js';
import {generateAccessToken,parseAccessToken,digestSecret,digestToHex,base64urlEncode} from './tokens.js';
import {importDevicePublicKey,verifyDeviceKeyProof} from './device-key-proof.js';
const TTL=120000;
const binding=v=>typeof v==='string'&&v.length>=32&&v.length<=512;
const digest=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const keyText=j=>JSON.stringify({kty:j.kty,crv:j.crv,x:j.x,y:j.y});
export async function deviceEnrollmentAction(jwk){await importDevicePublicKey(jwk);return hashText(JSON.stringify(['enroll-device-key-v1',keyText(jwk)]));}
export class DurableDeviceKeys {
 constructor(db,{clock=Date.now}={}){this.db=db;this.clock=clock;}
 now(){const n=this.clock();if(!Number.isSafeInteger(n)||n<0)throw TypeError('Valid instant required');return n;}
 async beginEnrollment({jwk,strongProof,browserBinding}) {
  if(!binding(browserBinding))return undefined;
  const actionDigest=await deviceEnrollmentAction(jwk),p=strongProof,now=this.now();
  if(!p||p.purpose!=='step-up'||p.actionDigest!==actionDigest||!Number.isSafeInteger(p.verifiedAt)||p.verifiedAt>now||now-p.verifiedAt>=TTL)return undefined;
  // Reconcile lost confirmations and generation changes only through a new
  // action-bound fresh strong proof. Never replace a public key silently.
  const prior=await this.db.prepare('SELECT key_id,revoked_at FROM durable_device_keys WHERE owner_id=?1 AND public_key_digest=?2').bind(p.ownerId,await hashText(keyText(jwk))).first();
  if(prior?.revoked_at!=null)return undefined; // Revocation is not restoration authority.
  const keyId=prior?.key_id??crypto.randomUUID();return this.issue({keyId,ownerId:p.ownerId,generation:p.generation,purpose:'enroll',actionDigest,publicJwk:keyText(jwk),browserBinding,credentialId:p.credentialId,maxExpiresAt:p.verifiedAt+TTL});
 }
 async beginProof({keyId,purpose,actionDigest,browserBinding,owner}) {
  if(owner!==undefined&&(typeof owner!=='string'||!owner))return undefined;
  if(!['step-up','recover-access'].includes(purpose)||!digest(actionDigest)||!binding(browserBinding)||typeof keyId!=='string'||keyId.length>128)return undefined;
  const row=await this.db.prepare('SELECT k.owner_id,k.generation FROM durable_device_keys k JOIN account_security s ON s.owner_id=k.owner_id WHERE key_id=?1 AND k.revoked_at IS NULL AND s.generation=k.generation AND (?2 IS NULL OR k.owner_id=?2)').bind(keyId,owner??null).first();
  return row?this.issue({keyId,ownerId:row.owner_id,generation:row.generation,purpose,actionDigest,browserBinding}):undefined;
 }
 async issue({keyId,ownerId,generation,purpose,actionDigest,publicJwk=null,browserBinding,credentialId=null,maxExpiresAt=null}) {
  const now=this.now();
  await this.sweepExpired(now);
  const expiresAt=Math.min(now+TTL,maxExpiresAt??now+TTL),secret=generateAccessToken(),challenge=base64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
  const result=await this.db.prepare(`INSERT INTO durable_device_challenges(challenge_id,secret_digest,binding_digest,key_id,owner_id,generation,purpose,action_digest,public_jwk,challenge,created_at,expires_at,credential_id) SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13 WHERE EXISTS(SELECT 1 FROM account_security WHERE owner_id=?5 AND generation=?6) AND (?7='enroll' AND (SELECT count(*) FROM durable_device_challenges WHERE owner_id=?5 AND purpose='enroll' AND expires_at>?11)<32 OR ?7!='enroll' AND (SELECT count(*) FROM durable_device_challenges WHERE key_id=?4 AND expires_at>?11)<8) AND (?7!='enroll' OR (EXISTS(SELECT 1 FROM passkey_credentials WHERE credential_id=?13 AND owner_id=?5 AND revoked_at IS NULL) AND (SELECT count(*) FROM durable_device_keys WHERE owner_id=?5 AND revoked_at IS NULL AND generation=?6 AND key_id!=?4)<20))`).bind(secret.tokenId,digestToHex(await digestSecret(secret.secret)),await hashText(browserBinding),keyId,ownerId,generation,purpose,actionDigest,publicJwk,challenge,now,expiresAt,credentialId).run();
  return result.meta.changes===1?{token:secret.token,challenge:{ownerId,keyId,generation,purpose,actionDigest,challenge,expiresAt}}:undefined;
 }
 async finish({token,browserBinding,signature}) {
  const parsed=parseAccessToken(token);if(!parsed||!binding(browserBinding))return undefined;const now=this.now();
  const row=await this.db.prepare('DELETE FROM durable_device_challenges WHERE challenge_id=?1 AND secret_digest=?2 AND binding_digest=?3 AND created_at<=?4 AND expires_at>?4 AND consumed_at IS NULL RETURNING *').bind(parsed.tokenId,digestToHex(await digestSecret(parsed.secret)),await hashText(browserBinding),now).first();if(!row)return undefined;
  let jwk=row.public_jwk;
  if(row.purpose!=='enroll'){const key=await this.db.prepare('SELECT public_jwk FROM durable_device_keys WHERE key_id=?1 AND owner_id=?2 AND generation=?3 AND revoked_at IS NULL').bind(row.key_id,row.owner_id,row.generation).first();jwk=key?.public_jwk;}
  const challenge={ownerId:row.owner_id,keyId:row.key_id,generation:row.generation,purpose:row.purpose,actionDigest:row.action_digest,challenge:row.challenge,expiresAt:row.expires_at};
  if(!jwk||!await verifyDeviceKeyProof({jwk:JSON.parse(jwk),challenge,signature,now:this.now()}))return undefined;
  const completed=this.now();if(completed<now||completed>=row.expires_at)return undefined;
  let result;
  if(row.purpose==='enroll')result=await this.db.prepare('INSERT INTO durable_device_keys(key_id,owner_id,public_jwk,generation,created_at,public_key_digest) SELECT ?1,?2,?3,?4,?5,?7 WHERE EXISTS(SELECT 1 FROM account_security WHERE owner_id=?2 AND generation=?4) AND (SELECT count(*) FROM durable_device_keys WHERE owner_id=?2 AND revoked_at IS NULL AND generation=?4 AND key_id!=?1)<20 AND EXISTS(SELECT 1 FROM passkey_credentials WHERE credential_id=?6 AND owner_id=?2 AND revoked_at IS NULL) ON CONFLICT(owner_id,public_key_digest) DO UPDATE SET generation=excluded.generation WHERE durable_device_keys.key_id=excluded.key_id AND durable_device_keys.revoked_at IS NULL').bind(row.key_id,row.owner_id,jwk,row.generation,completed,row.credential_id,await hashText(jwk)).run();
  else result=await this.db.prepare('UPDATE durable_device_keys SET last_used_at=?1 WHERE key_id=?2 AND owner_id=?3 AND generation=?4 AND revoked_at IS NULL AND EXISTS(SELECT 1 FROM account_security WHERE owner_id=?3 AND generation=?4)').bind(completed,row.key_id,row.owner_id,row.generation).run();
  return result.meta.changes>=1?{ownerId:row.owner_id,keyId:row.key_id,generation:row.generation,purpose:row.purpose,actionDigest:row.action_digest,verifiedAt:completed}:undefined;
 }
 async sweepExpired(now=this.now()) {
  // Bounded physical cleanup, including consumed historical schema backlog.
  return this.db.prepare('DELETE FROM durable_device_challenges WHERE challenge_id IN (SELECT challenge_id FROM durable_device_challenges WHERE expires_at<=?1 ORDER BY expires_at LIMIT 64)').bind(now).run();
 }
 async readiness(ownerId){
  if(typeof ownerId!=='string'||!/^[A-Za-z0-9_-]{1,128}$/.test(ownerId))throw TypeError('Owner required');
  const row=await this.db.prepare('SELECT count(*) AS key_count FROM durable_device_keys k JOIN account_security s ON s.owner_id=k.owner_id WHERE k.owner_id=?1 AND k.revoked_at IS NULL AND k.generation=s.generation').bind(ownerId).first();
  return {enrolledKeyCount:row?.key_count??0,platformVerified:false,fullLossWarning:true};
 }
 async revoke({ownerId,keyId}){const r=await this.db.prepare('UPDATE durable_device_keys SET revoked_at=?1 WHERE key_id=?2 AND owner_id=?3 AND revoked_at IS NULL').bind(this.now(),keyId,ownerId).run();return r.meta.changes>=1;}
}
