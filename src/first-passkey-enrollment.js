import {generateAccessToken,parseAccessToken,digestSecret,digestToHex} from './tokens.js';
import {PasskeyService,verifiedRegistration} from './passkey-service.js';
import {storeAaguid} from './passkey-providers.js';
const parse=async token=>{const p=parseAccessToken(token);return p?{id:p.tokenId,hash:digestToHex(await digestSecret(p.secret))}:undefined;};
export class FirstPasskeyEnrollment {
 constructor(db,{clock=Date.now,passkeys=new PasskeyService(db,{clock})}={}){Object.assign(this,{db,clock,passkeys});}
 async issue({ownerId,deviceId,generation,issuer,subject,verifiedAt}){
  const now=this.clock();if(issuer!=='https://accounts.google.com'||!Number.isSafeInteger(verifiedAt)||now<verifiedAt||now-verifiedAt>=120000)return;
  const t=generateAccessToken(),p=await parse(t.token),expiresAt=Math.min(verifiedAt+120000,now+120000);
  const r=await this.db.prepare("INSERT INTO google_enrollment_grants(grant_id,secret_digest,owner_id,device_id,generation,issuer,subject,created_at,expires_at) SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9 WHERE EXISTS(SELECT 1 FROM device_sessions d JOIN account_security s ON s.owner_id=d.owner_id JOIN provider_identities i ON i.identity_id=d.provider_identity_id AND i.owner_id=d.owner_id WHERE d.device_id=?4 AND d.owner_id=?3 AND d.generation=?5 AND s.generation=?5 AND d.revoked_at IS NULL AND d.expires_at>?8 AND i.revoked_at IS NULL AND i.issuer=?6 AND i.subject=?7) AND NOT EXISTS(SELECT 1 FROM passkey_credentials WHERE owner_id=?3 AND revoked_at IS NULL) AND NOT EXISTS(SELECT 1 FROM durable_device_keys WHERE owner_id=?3 AND revoked_at IS NULL)").bind(p.id,p.hash,ownerId,deviceId,generation,issuer,subject,now,expiresAt).run();return r.meta.changes===1?{token:t.token,expiresAt}:undefined;
 }
 async begin({user,grant}){
  const p=await parse(grant);if(!p)return;const now=this.clock();
  const row=await this.db.prepare('SELECT grant_id FROM google_enrollment_grants WHERE grant_id=?1 AND secret_digest=?2 AND owner_id=?3 AND device_id=?4 AND generation=?5 AND created_at<=?6 AND expires_at>?6 AND consumed_at IS NULL').bind(p.id,p.hash,user.ownerId,user.deviceId,user.generation,now).first();if(!row)return;
  return this.passkeys.begin({purpose:'register',ownerId:user.ownerId,binding:grant,action:JSON.stringify(['first-passkey',user.ownerId,user.deviceId,p.id])});
 }
 async finish({user,grant,token,response}){
  const p=await parse(grant);if(!p)return false;const now=this.clock();
  const row=await this.db.prepare('DELETE FROM google_enrollment_grants WHERE grant_id=?1 AND secret_digest=?2 AND owner_id=?3 AND device_id=?4 AND generation=?5 AND created_at<=?6 AND expires_at>?6 AND consumed_at IS NULL RETURNING grant_id').bind(p.id,p.hash,user.ownerId,user.deviceId,user.generation,now).first();if(!row)return false;
  const ceremony=await this.passkeys.claim({token,purpose:'register',ownerId:user.ownerId,binding:grant,action:JSON.stringify(['first-passkey',user.ownerId,user.deviceId,p.id])});if(!ceremony||ceremony.generation!==user.generation)return false;
  const record=await verifiedRegistration(this.passkeys.verifier,response,ceremony.challenge);if(!record)return false;
  const completed=this.clock();if(completed<ceremony.created_at||completed>=ceremony.expires_at)return false;
  const {c,transports,deviceType,backedUp}=record;
  const result=await this.db.prepare('INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) SELECT ?1,?2,?3,?4,?5,?6,?7,?8 WHERE NOT EXISTS(SELECT 1 FROM passkey_credentials WHERE owner_id=?2 AND revoked_at IS NULL) AND NOT EXISTS(SELECT 1 FROM durable_device_keys WHERE owner_id=?2 AND revoked_at IS NULL) AND EXISTS(SELECT 1 FROM device_sessions d JOIN account_security s ON s.owner_id=d.owner_id JOIN provider_identities i ON i.identity_id=d.provider_identity_id AND i.owner_id=d.owner_id WHERE i.revoked_at IS NULL AND d.device_id=?9 AND d.owner_id=?2 AND d.revoked_at IS NULL AND d.expires_at>?8 AND d.generation=?10 AND s.generation=?10) ON CONFLICT(credential_id) DO NOTHING').bind(c.id,user.ownerId,Array.from(c.publicKey),c.counter,JSON.stringify(transports),deviceType,backedUp,completed,user.deviceId,user.generation).run();
  if(result.meta.changes<1)return false;await storeAaguid(this.db,{credentialId:c.id,ownerId:user.ownerId,aaguid:record.aaguid});return true;
 }
}
