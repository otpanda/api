// Add ANOTHER passkey to an account that already has one. Never widens the
// first-passkey bootstrap. Flow: (1) fresh passkey step-up proof bound to the
// exact action/device/generation (HTTP layer verifies it) -> authorize() issues
// a single-use, device/owner/generation-bound registration authorization;
// (2) begin() starts a register ceremony bound to that authorization, excluding
// existing keys; (3) finish() consumes the authorization once and inserts the
// credential in a guarded write that rechecks session, generation and the
// approving credential.
import {generateAccessToken,parseAccessToken,digestSecret,digestToHex} from './tokens.js';
import {hashText} from './sessions.js';
import {PasskeyService,verifiedRegistration} from './passkey-service.js';
import {storeAaguid} from './passkey-providers.js';
import {SESSION_METHOD_JOIN as MJ,SESSION_METHOD_ACTIVE as MA} from './session-method.js';
export const ADD_ACTION='passkey:add',MAX_PASSKEYS=10,AUTH_TTL=120_000;
const parse=async token=>{const p=parseAccessToken(token);return p?{id:p.tokenId,hash:digestToHex(await digestSecret(p.secret))}:undefined;};
const action=(owner,device,id)=>JSON.stringify(['add-passkey',owner,device,id]);
export class AddPasskeyEnrollment {
 constructor(db,{clock=Date.now,passkeys=new PasskeyService(db,{clock})}={}){Object.assign(this,{db,clock,passkeys});}
 // proof comes from PasskeyService.finishAuthentication for purpose 'step-up'
 // and action ADD_ACTION. user comes from the authenticated session, never the body.
 async authorize({user,proof}){
  const now=this.clock();
  if(!proof||proof.purpose!=='step-up'||proof.ownerId!==user.ownerId||proof.generation!==user.generation||typeof proof.credentialId!=='string'||!Number.isSafeInteger(proof.verifiedAt)||proof.verifiedAt>now||now-proof.verifiedAt>=AUTH_TTL||proof.actionDigest!==await hashText(ADD_ACTION))return;
  const t=generateAccessToken(),p=await parse(t.token),expiresAt=Math.min(proof.verifiedAt+AUTH_TTL,now+AUTH_TTL);
  const r=await this.db.prepare(`INSERT OR REPLACE INTO passkey_add_authorizations(auth_id,secret_digest,owner_id,device_id,generation,approver_credential_id,created_at,expires_at) SELECT ?1,?2,?3,?4,?5,?6,?7,?8 WHERE EXISTS(SELECT 1 FROM passkey_credentials c JOIN account_security s ON s.owner_id=c.owner_id WHERE c.credential_id=?6 AND c.owner_id=?3 AND c.revoked_at IS NULL AND s.generation=?5) AND EXISTS(SELECT 1 FROM device_sessions d ${MJ} WHERE d.device_id=?4 AND d.owner_id=?3 AND d.generation=?5 AND d.revoked_at IS NULL AND d.expires_at>?7 AND ${MA}) AND (SELECT count(*) FROM passkey_credentials WHERE owner_id=?3 AND revoked_at IS NULL)<${MAX_PASSKEYS}`).bind(p.id,p.hash,user.ownerId,user.deviceId,user.generation,proof.credentialId,now,expiresAt).run();
  return r.meta.changes===1?{token:t.token,expiresAt}:undefined;
 }
 async #live(user,p,now){return this.db.prepare('SELECT approver_credential_id FROM passkey_add_authorizations WHERE auth_id=?1 AND secret_digest=?2 AND owner_id=?3 AND device_id=?4 AND generation=?5 AND created_at<=?6 AND expires_at>?6').bind(p.id,p.hash,user.ownerId,user.deviceId,user.generation,now).first();}
 async begin({user,grant}){
  const p=await parse(grant);if(!p)return;const now=this.clock();
  if(!await this.#live(user,p,now))return;
  const c=await this.passkeys.begin({purpose:'register',ownerId:user.ownerId,binding:grant,action:action(user.ownerId,user.deviceId,p.id)});if(!c)return;
  // PasskeyService already excludes every active credential of the owner.
  return c;
 }
 async finish({user,grant,token,response}){
  const p=await parse(grant);if(!p)return false;const now=this.clock();
  // Single use: consumed before any ceremony work. A failed attempt needs a new step-up.
  const auth=await this.db.prepare('DELETE FROM passkey_add_authorizations WHERE auth_id=?1 AND secret_digest=?2 AND owner_id=?3 AND device_id=?4 AND generation=?5 AND created_at<=?6 AND expires_at>?6 RETURNING approver_credential_id').bind(p.id,p.hash,user.ownerId,user.deviceId,user.generation,now).first();if(!auth)return false;
  const ceremony=await this.passkeys.claim({token,purpose:'register',ownerId:user.ownerId,binding:grant,action:action(user.ownerId,user.deviceId,p.id)});if(!ceremony||ceremony.generation!==user.generation)return false;
  const record=await verifiedRegistration(this.passkeys.verifier,response,ceremony.challenge);if(!record)return false;
  const completed=this.clock();if(completed<ceremony.created_at||completed>=ceremony.expires_at)return false;
  const {c,transports,deviceType,backedUp}=record;
  const r=await this.db.prepare(`INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) SELECT ?1,?2,?3,?4,?5,?6,?7,?8 WHERE EXISTS(SELECT 1 FROM passkey_credentials a JOIN account_security s ON s.owner_id=a.owner_id WHERE a.credential_id=?11 AND a.owner_id=?2 AND a.revoked_at IS NULL AND s.generation=?10) AND EXISTS(SELECT 1 FROM device_sessions d ${MJ} WHERE d.device_id=?9 AND d.owner_id=?2 AND d.generation=?10 AND d.revoked_at IS NULL AND d.expires_at>?8 AND ${MA}) AND (SELECT count(*) FROM passkey_credentials WHERE owner_id=?2 AND revoked_at IS NULL)<${MAX_PASSKEYS} ON CONFLICT(credential_id) DO NOTHING`).bind(c.id,user.ownerId,Array.from(c.publicKey),c.counter,JSON.stringify(transports),deviceType,backedUp,completed,user.deviceId,user.generation,auth.approver_credential_id).run();
  if(r.meta.changes!==1)return false;await storeAaguid(this.db,{credentialId:c.id,ownerId:user.ownerId,aaguid:record.aaguid});return true;
 }
 async cleanup({limit=100}={}){const r=await this.db.prepare('DELETE FROM passkey_add_authorizations WHERE auth_id IN(SELECT auth_id FROM passkey_add_authorizations WHERE expires_at<=?1 ORDER BY expires_at LIMIT ?2)').bind(this.clock(),limit).run();return r.meta.changes;}
}
