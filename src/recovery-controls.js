import {providerName} from './passkey-providers.js';
// Recovery controls for an authenticated web session. Every mutation needs a
// fresh passkey step-up bound to the exact action text, owner and generation.
// Email, Google and remembered cookies are never proof here. All passkeys are
// equal; nothing inspects sync or backup type.
import {hashText} from './sessions.js';
import {generateAccessToken,digestSecret,digestToHex} from './tokens.js';
import {SESSION_METHOD_JOIN as MJ,SESSION_METHOD_ACTIVE as MA} from './session-method.js';
export const PROOF_TTL=120_000,DELAY_MS=604_800_000,CHANGE_TTL=10*60_000,MAX_CHANGES=5;
export const KINDS=['email-escape-on','email-escape-off','passkey-revoke','session-revoke'];
// Passkey step-up only. Deliberately NOT in KINDS: the enrolled-client approval path (createChange/consumeChange) must never apply it.
export const APPLY_KINDS=[...KINDS,'google-unlink'];
export const GOOGLE_ISSUER='https://accounts.google.com';
export const recoveryAction=(kind,target)=>JSON.stringify(['recovery',kind,target??null]);
const ID=/^[A-Za-z0-9_-]{1,512}$/;
export class RecoveryControls {
 // localVerification: verifier-enforced FRESH local user verification (OS PIN or
 // biometric) for an enrolled client, as an async ({user,changeId,proof})=>true.
 // There is no such verifier today (DurableDeviceKeys proves possession only,
 // platformVerified:false), so protected changes FAIL CLOSED: approval is
 // unavailable unless a real verifier is injected. Possession alone is never a fallback.
 constructor(db,{clock=Date.now,localVerification}={}){this.db=db;this.clock=clock;this.localVerification=typeof localVerification==='function'?localVerification:undefined;}
 get approvalAvailable(){return !!this.localVerification;}
 async googleLinked(ownerId){return !!await this.db.prepare("SELECT 1 x FROM provider_identities WHERE owner_id=?1 AND issuer=?2 AND revoked_at IS NULL").bind(ownerId,GOOGLE_ISSUER).first();}
 async hasPasskey(ownerId){return !!await this.db.prepare('SELECT 1 x FROM passkey_credentials WHERE owner_id=?1 AND revoked_at IS NULL').bind(ownerId).first();}
 async status(user){
  const owner=user.ownerId,now=this.clock();
  const escape=!!await this.db.prepare('SELECT 1 x FROM email_recovery_optin WHERE owner_id=?1').bind(owner).first();
  const protection=!!await this.db.prepare('SELECT 1 x FROM new_device_verification WHERE owner_id=?1').bind(owner).first();
  const passkeys=(await this.db.prepare('SELECT p.credential_id id,p.created_at createdAt,p.last_used_at lastUsedAt,m.aaguid,m.label FROM passkey_credentials p LEFT JOIN passkey_metadata m ON m.credential_id=p.credential_id AND m.owner_id=p.owner_id WHERE p.owner_id=?1 AND p.revoked_at IS NULL ORDER BY p.created_at LIMIT 20').bind(owner).all()).results.map(({aaguid,label,...p})=>({...p,provider:providerName(aaguid),label:label??null}));
  const sessions=(await this.db.prepare('SELECT d.device_id id,d.client_kind clientKind,d.created_at createdAt,d.last_used_at lastUsedAt,i.browser,i.os,i.name FROM device_sessions d LEFT JOIN device_session_info i ON i.device_id=d.device_id AND i.owner_id=d.owner_id WHERE d.owner_id=?1 AND d.generation=?2 AND d.revoked_at IS NULL AND d.expires_at>?3 ORDER BY d.created_at LIMIT 50').bind(owner,user.generation,now).all()).results.map(s=>({...s,browser:s.browser??null,os:s.os??null,name:s.name??null,current:s.id===user.deviceId}));
  const changes=await this.listChanges(user);
  return{emailEscape:{enabled:escape,delayDays:DELAY_MS/86_400_000,blockedByGoogleProtection:protection},passkeys,sessions,changes};
 }
 // Client-approval path. A signed-in client asks; a DIFFERENT enrolled client
 // (other session, device key) approves the exact action with a verifier-
 // produced device-key proof; the requester
 // consumes it once. Everything is revalidated in the consuming write.
 async createChange({ownerId,deviceId,generation,kind,target,warningAccepted}){
  if(!KINDS.includes(kind)||typeof ownerId!=='string'||typeof deviceId!=='string'||!Number.isSafeInteger(generation))return;
  const needsTarget=kind==='passkey-revoke'||kind==='session-revoke';
  if(needsTarget!==(typeof target==='string')||(needsTarget&&!ID.test(target)))return;
  if(kind==='email-escape-on'&&(warningAccepted!==true||await this.db.prepare('SELECT 1 x FROM new_device_verification WHERE owner_id=?1').bind(ownerId).first()))return;
  const now=this.clock(),id=generateAccessToken().tokenId;
  const r=await this.db.prepare(`INSERT INTO recovery_changes(change_id,owner_id,generation,kind,target,requester_device_id,created_at,expires_at) SELECT ?1,?2,?3,?4,?5,?6,?7,?8 WHERE EXISTS(SELECT 1 FROM device_sessions d ${MJ} WHERE d.device_id=?6 AND d.owner_id=?2 AND d.generation=?3 AND d.revoked_at IS NULL AND d.created_at<=?7 AND d.expires_at>?7 AND ${MA}) AND (SELECT count(*) FROM recovery_changes WHERE owner_id=?2 AND consumed_at IS NULL AND expires_at>?7)<${MAX_CHANGES}`).bind(id,ownerId,generation,kind,target??null,deviceId,now,now+CHANGE_TTL).run();
  return r.meta.changes===1?{changeId:id,expiresAt:now+CHANGE_TTL}:undefined;
 }
 async listChanges({ownerId,deviceId,generation}){
  const now=this.clock(),r=await this.db.prepare(`SELECT c.change_id,c.kind,c.target,c.created_at,c.expires_at FROM recovery_changes c JOIN device_sessions d ON d.device_id=?2 WHERE c.owner_id=?1 AND c.generation=?3 AND d.owner_id=?1 AND d.generation=?3 AND d.revoked_at IS NULL AND d.expires_at>?4 AND c.approved_at IS NULL AND c.consumed_at IS NULL AND c.expires_at>?4 AND c.requester_device_id<>?2 ORDER BY c.created_at LIMIT 20`).bind(ownerId,deviceId,generation,now).all();
  return r.results.map(x=>({changeId:x.change_id,kind:x.kind,target:x.target,createdAt:x.created_at,expiresAt:x.expires_at}));
 }
 // The exact bytes the approving device key signs over.
 async approvalDigest({changeId,kind,target,ownerId,generation}){return hashText(JSON.stringify(['recovery-change',changeId,kind,target??null,ownerId,generation]));}
 // Server-derived binding: the approver's own session and the change. Nothing
 // the caller supplies chooses it.
 approvalBinding({ownerId,deviceId,changeId}){return hashText(JSON.stringify(['recovery-approve',ownerId,deviceId,changeId]));}
 async #approvable({ownerId,deviceId,generation,changeId}){
  if(typeof changeId!=='string'||changeId.length>128)return;
  const now=this.clock();
  return await this.db.prepare(`SELECT c.kind,c.target FROM recovery_changes c WHERE c.change_id=?1 AND c.owner_id=?2 AND c.generation=?3 AND c.approved_at IS NULL AND c.consumed_at IS NULL AND c.expires_at>?4 AND c.requester_device_id<>?5 AND EXISTS(SELECT 1 FROM device_sessions d ${MJ} WHERE d.device_id=?5 AND d.owner_id=?2 AND d.generation=?3 AND d.revoked_at IS NULL AND d.expires_at>?4 AND ${MA})`).bind(changeId,ownerId,generation,now,deviceId).first()??undefined;
 }
 // Step 1: the enrolled approver client asks for a challenge for ONE change.
 async beginApproval({user,changeId,keyId,deviceKeys}){
  if(!this.localVerification)return;
  const row=await this.#approvable({...user,changeId});if(!row||typeof keyId!=='string')return;
  return deviceKeys.beginProof({keyId,purpose:'step-up',actionDigest:await this.approvalDigest({changeId,kind:row.kind,target:row.target,ownerId:user.ownerId,generation:user.generation}),browserBinding:await this.approvalBinding({ownerId:user.ownerId,deviceId:user.deviceId,changeId})});
 }
 // Step 2: verify the signature server-side, then record the approval.
 async approveChange({user,changeId,token,signature,deviceKeys}){
  if(!this.localVerification)return false;
  const row=await this.#approvable({...user,changeId});if(!row||typeof token!=='string'||typeof signature!=='string')return false;
  const proof=await deviceKeys.finish({token,signature,browserBinding:await this.approvalBinding({ownerId:user.ownerId,deviceId:user.deviceId,changeId})});
  const now=this.clock();
  // Possession proof must be accompanied by verifier-enforced local verification.
  if(proof&&await this.localVerification({user,changeId,proof})!==true)return false;
  if(!proof||proof.purpose!=='step-up'||proof.ownerId!==user.ownerId||proof.generation!==user.generation||now-proof.verifiedAt>=PROOF_TTL||proof.actionDigest!==await this.approvalDigest({changeId,kind:row.kind,target:row.target,ownerId:user.ownerId,generation:user.generation}))return false;
  const r=await this.db.prepare(`UPDATE recovery_changes SET approved_at=?1,approver_device_id=?2,approver_key_id=?6 WHERE change_id=?3 AND owner_id=?4 AND generation=?5 AND approved_at IS NULL AND consumed_at IS NULL AND expires_at>?1 AND requester_device_id<>?2 AND EXISTS(SELECT 1 FROM device_sessions d ${MJ} WHERE d.device_id=?2 AND d.owner_id=?4 AND d.generation=?5 AND d.revoked_at IS NULL AND d.expires_at>?1 AND ${MA}) AND EXISTS(SELECT 1 FROM durable_device_keys k JOIN account_security s ON s.owner_id=k.owner_id WHERE k.key_id=?6 AND k.owner_id=?4 AND k.revoked_at IS NULL AND k.generation=s.generation AND s.generation=?5)`).bind(now,user.deviceId,changeId,user.ownerId,user.generation,proof.keyId).run();
  return r.meta.changes===1;
 }
 // Atomic: consume the approved change and apply it. A replay changes nothing.
 async consumeChange({ownerId,deviceId,generation,changeId}){
  if(typeof changeId!=='string'||changeId.length>128)return;
  const now=this.clock(),receipt=generateAccessToken().tokenId,o=ownerId,g=generation;
  const row=await this.db.prepare('SELECT kind,target FROM recovery_changes WHERE change_id=?1 AND owner_id=?2').bind(changeId,o).first();if(!row)return;
  const mine=`EXISTS(SELECT 1 FROM recovery_changes WHERE change_id=?1 AND owner_id=?2 AND generation=?3 AND consume_receipt=?4)`;
  const approver=`EXISTS(SELECT 1 FROM recovery_changes c JOIN device_sessions d ON d.device_id=c.approver_device_id ${MJ} JOIN durable_device_keys k ON k.key_id=c.approver_key_id JOIN account_security s ON s.owner_id=k.owner_id WHERE c.change_id=?1 AND k.owner_id=?2 AND k.revoked_at IS NULL AND k.generation=s.generation AND s.generation=?3 AND d.owner_id=?2 AND d.generation=?3 AND d.revoked_at IS NULL AND d.expires_at>?5 AND ${MA})`;
  let effect;
  if(row.kind==='email-escape-on')effect=this.db.prepare(`INSERT OR IGNORE INTO email_recovery_optin(owner_id,enabled_at,generation,delay_ms) SELECT ?2,?5,?3,${DELAY_MS} WHERE ${mine}`).bind(changeId,o,g,receipt,now);
  else if(row.kind==='email-escape-off')effect=this.db.prepare(`DELETE FROM email_recovery_optin WHERE owner_id=?2 AND ${mine}`).bind(changeId,o,g,receipt);
  else if(row.kind==='passkey-revoke')effect=this.db.prepare(`UPDATE passkey_credentials SET revoked_at=?5,revision=revision+1 WHERE credential_id=?6 AND owner_id=?2 AND revoked_at IS NULL AND ${mine} AND EXISTS(SELECT 1 FROM passkey_credentials o2 WHERE o2.owner_id=?2 AND o2.credential_id<>?6 AND o2.revoked_at IS NULL)`).bind(changeId,o,g,receipt,now,row.target);
  else effect=this.db.prepare(`UPDATE device_sessions SET revoked_at=?5 WHERE device_id=?6 AND owner_id=?2 AND revoked_at IS NULL AND ${mine}`).bind(changeId,o,g,receipt,now,row.target);
  let r;try{r=await this.db.batch([
   this.db.prepare(`UPDATE recovery_changes SET consumed_at=?5,consume_receipt=?4 WHERE change_id=?1 AND owner_id=?2 AND generation=?3 AND requester_device_id=?6 AND approved_at IS NOT NULL AND consumed_at IS NULL AND expires_at>?5 AND EXISTS(SELECT 1 FROM account_security s WHERE s.owner_id=?2 AND s.generation=?3) AND EXISTS(SELECT 1 FROM device_sessions d ${MJ} WHERE d.device_id=?6 AND d.owner_id=?2 AND d.generation=?3 AND d.revoked_at IS NULL AND d.expires_at>?5 AND ${MA}) AND ${approver}`).bind(changeId,o,g,receipt,now,deviceId),
   effect,
  ]);}catch{return;}
  if(r[0]/*exact-count-ok*/.meta.changes!==1)return;
  if(row.kind==='email-escape-on')return await this.db.prepare('SELECT 1 x FROM email_recovery_optin WHERE owner_id=?1').bind(o).first()?{emailEscape:true}:undefined;
  if(row.kind==='email-escape-off')return{emailEscape:false};
  return r[1].meta.changes>=1?{revoked:row.kind==='passkey-revoke'?'passkey':'session'}:undefined;
 }
 // proof: PasskeyService.finishAuthentication result for purpose 'step-up'. A
 // device-key (possession-only) proof is refused here.
 async apply({user,kind,target,proof,warningAccepted}){
  const now=this.clock();
  if(!APPLY_KINDS.includes(kind)||!proof||proof.purpose!=='step-up'||proof.ownerId!==user.ownerId||proof.generation!==user.generation||typeof proof.credentialId!=='string'||typeof proof.keyId==='string'||!Number.isSafeInteger(proof.verifiedAt)||proof.verifiedAt>now||now-proof.verifiedAt>=PROOF_TTL)return;
  const needsTarget=kind==='passkey-revoke'||kind==='session-revoke';
  if(needsTarget!==(typeof target==='string')||(needsTarget&&!ID.test(target)))return;
  if(kind==='email-escape-on'&&warningAccepted!==true)return;
  if(proof.actionDigest!==await hashText(recoveryAction(kind,target)))return;
  const o=user.ownerId,g=proof.generation,c=proof.credentialId;
  // The proving passkey must still be active and the generation current.
  const live=`EXISTS(SELECT 1 FROM passkey_credentials p JOIN account_security s ON s.owner_id=p.owner_id WHERE p.credential_id=?1 AND p.owner_id=?2 AND p.revoked_at IS NULL AND s.generation=?3)`;
  const keep='';
  try{
   if(kind==='email-escape-on'){
    await this.db.prepare(`INSERT OR IGNORE INTO email_recovery_optin(owner_id,enabled_at,generation,delay_ms) SELECT ?2,?4,?3,${DELAY_MS} WHERE ${live}`).bind(c,o,g,now).run();
    return await this.db.prepare('SELECT 1 x FROM email_recovery_optin WHERE owner_id=?1').bind(o).first()?{emailEscape:true}:undefined;
   }
   if(kind==='email-escape-off'){
    const r=await this.db.prepare(`DELETE FROM email_recovery_optin WHERE owner_id=?2 AND ${live}`).bind(c,o,g).run();
    return r/*exact-count-ok*/.meta.changes===1||!await this.db.prepare('SELECT 1 x FROM email_recovery_optin WHERE owner_id=?1').bind(o).first()?{emailEscape:false}:undefined;
   }
   if(kind==='passkey-revoke'){
    // A different passkey must authorize, so one always remains.
    if(target===c)return;
    const r=await this.db.prepare(`UPDATE passkey_credentials SET revoked_at=?4,revision=revision+1 WHERE credential_id=?5 AND owner_id=?2 AND revoked_at IS NULL AND ${live}${keep}`).bind(c,o,g,now,target).run();
    return r/*exact-count-ok*/.meta.changes===1?{revoked:'passkey'}:undefined;
   }
   if(kind==='google-unlink'){
    // One atomic batch. The proving passkey must be active (so a passkey always remains) and the link still active.
    // Sessions that rest on the link are revoked by writing revoked_at, so the realtime revoke trigger fires too.
    const gone=`(SELECT identity_id FROM provider_identities WHERE owner_id=?2 AND issuer='${GOOGLE_ISSUER}' AND revoked_at=?4)`;
    const r=await this.db.batch([
     this.db.prepare(`UPDATE provider_identities SET revoked_at=?4 WHERE owner_id=?2 AND issuer='${GOOGLE_ISSUER}' AND revoked_at IS NULL AND ${live}`).bind(c,o,g,now),
     this.db.prepare(`UPDATE device_sessions SET revoked_at=?4 WHERE owner_id=?2 AND revoked_at IS NULL AND provider_identity_id IN ${gone}`).bind(c,o,g,now),
     this.db.prepare(`UPDATE recognized_browsers SET revoked_at=?4 WHERE owner_id=?2 AND revoked_at IS NULL AND provider_identity_id IN ${gone}`).bind(c,o,g,now),
     this.db.prepare(`DELETE FROM pending_logins WHERE owner_id=?2 AND provider_identity_id IN ${gone}`).bind(c,o,g,now),
    ]);
    return r[0].meta.changes>=1?{revoked:'google'}:undefined;
   }
   const r=await this.db.prepare(`UPDATE device_sessions SET revoked_at=?4 WHERE device_id=?5 AND owner_id=?2 AND revoked_at IS NULL AND ${live}`).bind(c,o,g,now,target).run();
   return r.meta.changes>=1?{revoked:'session'}:undefined;
  }catch{return;}
 }
}
