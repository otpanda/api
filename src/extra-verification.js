// Optional extra verification for new devices. Service only: no HTTP, cookies
// or UI. Callers (HTTP) pass authenticated owner/device identity, never request
// body fields. Strong proof is a passkey step-up proof bound to the exact
// action. Enabled means fail closed: no verifier present does not bypass it.
import {generateAccessToken,parseAccessToken,digestSecret,digestToHex} from './tokens.js';
import {hashText} from './sessions.js';
import {SESSION_METHOD_JOIN as MJ,SESSION_METHOD_ACTIVE as MA} from './session-method.js';
// Same predicates for a second session alias, so two sessions can be compared.
const MJOTHER=MJ.replaceAll('d.','o.').replace('p ON','po ON').replace('g ON','go ON').replace('p.credential_id=','po.credential_id=').replace('g.identity_id=','go.identity_id=');
const MAOTHER=MA.replaceAll('d.','o.').replaceAll('p.','po.').replaceAll('g.','go.');
const MJA=MJ.replaceAll('d.','a.').replace('p ON','pa ON').replace('g ON','ga ON').replace('p.credential_id=','pa.credential_id=').replace('g.identity_id=','ga.identity_id=');
const MAA=MA.replaceAll('d.','a.').replaceAll('p.','pa.').replaceAll('g.','ga.');
export const PENDING_TTL=10*60_000,PROOF_TTL=120_000,MAX_PENDING=5;
export const ACTION={enable:'extra-verification:enable',disable:'extra-verification:disable',approve:id=>`extra-verification:approve:${id}`};
const HEX=/^[a-f0-9]{64}$/,CHAL=/^[A-Za-z0-9_-]{43}$/;
async function split(token){const p=parseAccessToken(token);return p?{id:p.tokenId,digest:digestToHex(await digestSecret(p.secret))}:undefined;}
async function fresh(){const t=generateAccessToken();return{token:t.token,id:t.tokenId,digest:digestToHex(await digestSecret(t.secret))};}
// Fragment usable inside an issuance batch. Placeholders are SQL parameter
// names such as '?12'. True when the login may proceed without extra proof.
export function protectionGuard({owner,gen,link,recId,recDigest,pendId,pendDigest,challenge,binding,now,requirePending=false}){
 const pending=`EXISTS(SELECT 1 FROM pending_logins pl WHERE pl.pending_id=${pendId} AND pl.secret_digest=${pendDigest} AND pl.owner_id=${owner} AND pl.generation=${gen} AND pl.provider_identity_id=${link} AND pl.challenge=${challenge} AND pl.browser_binding_digest=${binding} AND pl.approved_at IS NOT NULL AND pl.consumed_at IS NULL AND pl.canceled_at IS NULL AND pl.expires_at>${now} AND ((pl.approval_method='passkey' AND EXISTS(SELECT 1 FROM passkey_credentials ap WHERE ap.credential_id=pl.approver_credential_id AND ap.owner_id=${owner} AND ap.revoked_at IS NULL)) OR (pl.approval_method='client' AND pl.local_verified_at IS NOT NULL AND EXISTS(SELECT 1 FROM device_sessions a ${MJA} WHERE a.device_id=pl.approver_device_id AND a.owner_id=${owner} AND a.generation=${gen} AND a.revoked_at IS NULL AND a.expires_at>${now} AND ${MAA}))))`;
 if(requirePending)return pending;
 return `(NOT EXISTS(SELECT 1 FROM new_device_verification v WHERE v.owner_id=${owner}) OR EXISTS(SELECT 1 FROM recognized_browsers r WHERE r.recognition_id=${recId} AND r.secret_digest=${recDigest} AND r.owner_id=${owner} AND r.generation=${gen} AND r.revoked_at IS NULL AND r.provider_identity_id=${link}) OR ${pending})`;
}
export class ExtraVerification {
 // localVerification: injected verifier of FRESH local user verification on the
// approving enrolled client. None exists yet, so client approval fails closed.
 // A bare session or a different browser is never an approval.
 constructor(db,{clock=Date.now,localVerification}={}){this.db=db;this.clock=clock;this.localVerification=typeof localVerification==='function'?localVerification:undefined;}
 get approvalAvailable(){return !!this.localVerification;}
 now(){const n=this.clock();if(!Number.isSafeInteger(n)||n<0)throw new TypeError('Valid instant required');return n;}
 async enabled(ownerId){return!!await this.db.prepare('SELECT 1 x FROM new_device_verification WHERE owner_id=?1').bind(ownerId).first();}
 async #strong(proof,action){
  const now=this.now();
  if(!proof||proof.purpose!=='step-up'||typeof proof.ownerId!=='string'||typeof proof.credentialId!=='string'||!Number.isSafeInteger(proof.generation)||!Number.isSafeInteger(proof.verifiedAt)||proof.verifiedAt>now||now-proof.verifiedAt>=PROOF_TTL)return undefined;
  if(proof.actionDigest!==await hashText(action))return undefined;
  return now;
 }
 // Opt in. One guarded write: the proving passkey must still be active, the
 // generation current, and the user must have accepted the lockout warning.
 async enable({proof,warningAccepted}){
  if(warningAccepted!==true)return undefined;
  const now=await this.#strong(proof,ACTION.enable);if(now===undefined)return undefined;
  await this.db.prepare(`INSERT OR IGNORE INTO new_device_verification(owner_id,enabled_at,generation) SELECT ?1,?2,?3 WHERE EXISTS(SELECT 1 FROM passkey_credentials p JOIN account_security s ON s.owner_id=p.owner_id WHERE p.credential_id=?4 AND p.owner_id=?1 AND p.revoked_at IS NULL AND s.generation=?3)`).bind(proof.ownerId,now,proof.generation,proof.credentialId).run();
  return await this.enabled(proof.ownerId)?{enabled:true}:undefined;
 }
 // Opt out needs the same strong proof it enforces, never a Google-only session.
 async disable({proof}){
  const now=await this.#strong(proof,ACTION.disable);if(now===undefined)return undefined;
  const r=await this.db.prepare(`DELETE FROM new_device_verification WHERE owner_id=?1 AND EXISTS(SELECT 1 FROM passkey_credentials p JOIN account_security s ON s.owner_id=p.owner_id WHERE p.credential_id=?2 AND p.owner_id=?1 AND p.revoked_at IS NULL AND s.generation=?3)`).bind(proof.ownerId,proof.credentialId,proof.generation).run();
  return r.meta.changes===1||!await this.enabled(proof.ownerId)?{enabled:false}:undefined;
 }
 // New unguessable recognition for the caller to set as a cookie. The row is
 // inserted by the issuance batch (recognitionInsert), never here.
 async newRecognition(){const f=await fresh();return{token:f.token,id:f.id,digest:f.digest};}
 async parseToken(token){return split(token);}
 // Waiting login. Requires the setting on and an active provider link for the
 // exact owner/generation. Bounded pending count is checked inside the write.
 async createPending({ownerId,generation,issuer,subject,challenge,browserBindingDigest,remember,context}){
  if(typeof ownerId!=='string'||!Number.isSafeInteger(generation)||typeof issuer!=='string'||typeof subject!=='string'||!CHAL.test(challenge??'')||!HEX.test(browserBindingDigest??'')||typeof remember!=='boolean'||typeof context!=='string'||context.length>4096)return undefined;
  const now=this.now(),f=await fresh();
  const r=await this.db.prepare(`INSERT INTO pending_logins(pending_id,secret_digest,owner_id,provider_identity_id,generation,challenge,browser_binding_digest,remember,context,created_at,expires_at) SELECT ?1,?2,?3,g.identity_id,?4,?5,?6,?7,?8,?9,?10 FROM provider_identities g WHERE g.issuer=?11 AND g.subject=?12 AND g.owner_id=?3 AND g.revoked_at IS NULL AND EXISTS(SELECT 1 FROM new_device_verification v WHERE v.owner_id=?3) AND EXISTS(SELECT 1 FROM account_security s WHERE s.owner_id=?3 AND s.generation=?4) AND (SELECT count(*) FROM pending_logins WHERE owner_id=?3 AND consumed_at IS NULL AND canceled_at IS NULL AND expires_at>?9)<${MAX_PENDING}`).bind(f.id,f.digest,ownerId,generation,challenge,browserBindingDigest,remember?1:0,context,now,now+PENDING_TTL,issuer,subject).run();
  return r.meta.changes===1?{pendingId:f.id,token:f.token,expiresAt:now+PENDING_TTL}:undefined;
 }
 // Metadata for an approving screen: ids and times only, never context.
 async listForApprover({ownerId,generation}){
  const now=this.now(),r=await this.db.prepare('SELECT pending_id,created_at,expires_at FROM pending_logins WHERE owner_id=?1 AND generation=?2 AND approved_at IS NULL AND consumed_at IS NULL AND canceled_at IS NULL AND expires_at>?3 ORDER BY created_at').bind(ownerId,generation,now).all();
  return r.results.map(x=>({pendingId:x.pending_id,createdAt:x.created_at,expiresAt:x.expires_at}));
 }
 // A different already-signed-in client of the same owner approves exactly
 // this attempt. It must predate the attempt and be a different browser, and
 // it is rechecked as an active session inside the write. Never automatic.
 async approveWithClient({ownerId,deviceId,generation,pendingId}){
  if(typeof ownerId!=='string'||typeof deviceId!=='string'||!Number.isSafeInteger(generation)||typeof pendingId!=='string'||!this.localVerification)return undefined;
  if(await this.localVerification({user:{ownerId,deviceId,generation},pendingId})!==true)return undefined;
  const now=this.now();
  const r=await this.db.prepare(`UPDATE pending_logins SET approved_at=?1,approval_method='client',approver_device_id=?2,local_verified_at=?1 WHERE pending_id=?3 AND owner_id=?4 AND generation=?5 AND approved_at IS NULL AND consumed_at IS NULL AND canceled_at IS NULL AND expires_at>?1 AND EXISTS(SELECT 1 FROM device_sessions d ${MJ} WHERE d.device_id=?2 AND d.owner_id=?4 AND d.generation=?5 AND d.revoked_at IS NULL AND d.created_at<=?1 AND d.expires_at>?1 AND d.created_at<pending_logins.created_at AND d.browser_binding_digest IS NOT pending_logins.browser_binding_digest AND ${MA}) AND EXISTS(SELECT 1 FROM account_security s WHERE s.owner_id=?4 AND s.generation=?5)`).bind(now,deviceId,pendingId,ownerId,generation).run();
  return r.meta.changes===1;
 }
 async approveWithPasskey({proof,pendingId}){
  if(typeof pendingId!=='string')return undefined;
  const now=await this.#strong(proof,ACTION.approve(pendingId));if(now===undefined)return undefined;
  const r=await this.db.prepare(`UPDATE pending_logins SET approved_at=?1,approval_method='passkey',approver_credential_id=?5 WHERE pending_id=?2 AND owner_id=?3 AND generation=?4 AND approved_at IS NULL AND consumed_at IS NULL AND canceled_at IS NULL AND expires_at>?1 AND EXISTS(SELECT 1 FROM passkey_credentials p JOIN account_security s ON s.owner_id=p.owner_id WHERE p.credential_id=?5 AND p.owner_id=?3 AND p.revoked_at IS NULL AND s.generation=?4)`).bind(now,pendingId,proof.ownerId,proof.generation,proof.credentialId).run();
  return r.meta.changes===1;
 }
 // Owner rejects an attempt from a signed-in client or after passkey proof.
 async cancel({ownerId,generation,pendingId}){
  const r=await this.db.prepare('UPDATE pending_logins SET canceled_at=?1 WHERE pending_id=?2 AND owner_id=?3 AND generation=?4 AND consumed_at IS NULL AND canceled_at IS NULL').bind(this.now(),pendingId,ownerId,generation).run();return r.meta.changes===1;
 }
 // Poll by the waiting browser. Reveals only status and, once approved, the
 // opaque context. Does not consume; issuance consumes atomically.
 async poll({token,browserBindingDigest}){
  const t=await split(token);if(!t||!HEX.test(browserBindingDigest??''))return{status:'denied'};
  const row=await this.db.prepare('SELECT * FROM pending_logins WHERE pending_id=?1 AND secret_digest=?2 AND browser_binding_digest=?3').bind(t.id,t.digest,browserBindingDigest).first();
  if(!row||row.canceled_at!==null||row.consumed_at!==null)return{status:'denied'};
  if(row.expires_at<=this.now())return{status:'expired'};
  if(row.approved_at===null)return{status:'waiting'};
  return{status:'approved',context:row.context,remember:row.remember===1,pendingId:row.pending_id,digest:t.digest};
 }

 // Signed-in-client path for both directions. A requester (an authenticated
 // active session; ids come from the session, never the body) creates a change
 // for exactly enable or disable. Enabling records the accepted warning. A
 // different preexisting client on a different browser approves that exact
 // change, then the requester consumes it once; everything is revalidated in the
 // consuming write. A lone Google-only session can never toggle by itself.
 async createSettingChange({ownerId,deviceId,generation,enabled,warningAccepted}){
  if(typeof ownerId!=='string'||typeof deviceId!=='string'||!Number.isSafeInteger(generation)||typeof enabled!=='boolean')return undefined;
  if(enabled&&warningAccepted!==true)return undefined;
  const now=this.now(),f=await fresh(),action=enabled?'enable-extra-verification':'disable-extra-verification';
  const r=await this.db.prepare(`INSERT INTO setting_changes(change_id,owner_id,generation,action,requester_device_id,created_at,expires_at) SELECT ?1,?2,?3,?7,?4,?5,?6 WHERE EXISTS(SELECT 1 FROM device_sessions d ${MJ} WHERE d.device_id=?4 AND d.owner_id=?2 AND d.generation=?3 AND d.revoked_at IS NULL AND d.created_at<=?5 AND d.expires_at>?5 AND ${MA}) AND (SELECT count(*) FROM setting_changes WHERE owner_id=?2 AND consumed_at IS NULL AND expires_at>?5)<${MAX_PENDING}`).bind(f.id,ownerId,generation,deviceId,now,now+PENDING_TTL,action).run();
  return r.meta.changes===1?{changeId:f.id,expiresAt:now+PENDING_TTL}:undefined;
 }
 // Open changes this device could approve: not its own, different browser.
 async listSettingChanges({ownerId,deviceId,generation}){
  const now=this.now(),r=await this.db.prepare(`SELECT c.change_id,c.action,c.created_at,c.expires_at FROM setting_changes c JOIN device_sessions q ON q.device_id=c.requester_device_id JOIN device_sessions d ON d.device_id=?2 WHERE c.owner_id=?1 AND c.generation=?3 AND d.owner_id=?1 AND d.revoked_at IS NULL AND d.expires_at>?4 AND c.approved_at IS NULL AND c.consumed_at IS NULL AND c.expires_at>?4 AND c.requester_device_id<>?2 AND d.browser_binding_digest IS NOT q.browser_binding_digest ORDER BY c.created_at`).bind(ownerId,deviceId,generation,now).all();
  return r.results.map(x=>({changeId:x.change_id,enabled:x.action==='enable-extra-verification',createdAt:x.created_at,expiresAt:x.expires_at}));
 }
 async approveSettingChange({ownerId,deviceId,generation,changeId}){
  if(!this.localVerification||typeof changeId!=='string')return undefined;
  if(await this.localVerification({user:{ownerId,deviceId,generation},changeId})!==true)return undefined;
  const now=this.now();
  const r=await this.db.prepare(`UPDATE setting_changes SET approved_at=?1,approver_device_id=?2,local_verified_at=?1 WHERE change_id=?3 AND owner_id=?4 AND generation=?5 AND approved_at IS NULL AND consumed_at IS NULL AND expires_at>?1 AND requester_device_id<>?2 AND EXISTS(SELECT 1 FROM device_sessions d ${MJ} JOIN device_sessions q ON q.device_id=setting_changes.requester_device_id WHERE d.device_id=?2 AND d.owner_id=?4 AND d.generation=?5 AND d.revoked_at IS NULL AND d.created_at<=?1 AND d.expires_at>?1 AND d.browser_binding_digest IS NOT q.browser_binding_digest AND ${MA})`).bind(now,deviceId,changeId,ownerId,generation).run();
  return r.meta.changes===1;
 }
 // Atomic: consume the approved change and apply the toggle in one batch. Both
 // requester and approver must still be active, generation current.
 async consumeSettingChange({ownerId,deviceId,generation,changeId}){
  const now=this.now(),receipt=(await fresh()).id;
  const r=await this.db.batch([
   this.db.prepare(`UPDATE setting_changes SET consumed_at=?1,consume_receipt=?6 WHERE change_id=?2 AND owner_id=?3 AND generation=?4 AND requester_device_id=?5 AND approved_at IS NOT NULL AND local_verified_at IS NOT NULL AND consumed_at IS NULL AND expires_at>?1 AND EXISTS(SELECT 1 FROM account_security s WHERE s.owner_id=?3 AND s.generation=?4) AND EXISTS(SELECT 1 FROM device_sessions d ${MJ} WHERE d.device_id=?5 AND d.owner_id=?3 AND d.generation=?4 AND d.revoked_at IS NULL AND d.expires_at>?1 AND ${MA}) AND EXISTS(SELECT 1 FROM device_sessions a ${MJA} WHERE a.device_id=setting_changes.approver_device_id AND a.owner_id=?3 AND a.generation=?4 AND a.revoked_at IS NULL AND a.expires_at>?1 AND ${MAA})`).bind(now,changeId,ownerId,generation,deviceId,receipt),
   // Only this batch's own consumption (unique random receipt on the row, same
   // owner/generation/id) may apply the toggle; a replay changes nothing.
   this.db.prepare(`INSERT OR IGNORE INTO new_device_verification(owner_id,enabled_at,generation) SELECT ?1,?3,?4 WHERE EXISTS(SELECT 1 FROM setting_changes WHERE change_id=?2 AND owner_id=?1 AND generation=?4 AND consume_receipt=?5 AND action='enable-extra-verification')`).bind(ownerId,changeId,now,generation,receipt),
   this.db.prepare(`DELETE FROM new_device_verification WHERE owner_id=?1 AND EXISTS(SELECT 1 FROM setting_changes WHERE change_id=?2 AND owner_id=?1 AND generation=?3 AND consume_receipt=?4 AND action='disable-extra-verification')`).bind(ownerId,changeId,generation,receipt),
  ]);
  if(r[0].meta.changes!==1)return undefined;
  return {enabled:await this.enabled(ownerId)};
 }
 async cleanup({limit=100}={}){
  if(!Number.isSafeInteger(limit)||limit<1||limit>500)throw new TypeError('Bounded cleanup required');
  const now=this.now(),r=await this.db.prepare('DELETE FROM pending_logins WHERE pending_id IN(SELECT pending_id FROM pending_logins WHERE expires_at<=?1 OR consumed_at IS NOT NULL OR canceled_at IS NOT NULL ORDER BY expires_at LIMIT ?2)').bind(now,limit).run();return r.meta.changes;
 }
}
