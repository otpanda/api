// Opt-in all-loss email recovery. Email is never a sign-in method: a mailbox
// code only moves a request along. Completion needs the 7-day wait, a fresh
// mailbox code AND registering a NEW passkey, and then retires every old
// passkey, device key, session and automation token in one atomic batch.
// Data, entry shares and linked Google identities are not touched. No session
// is issued: the person signs in afterwards with the new passkey.
// Mail is only delivered through the injected server-side deliver(); the caller
// never supplies a proof object. Browser binding is a client-held random secret
// (like a PKCE verifier) bound to the code with the mailbox address.
import {generateAccessToken,parseAccessToken,digestSecret,digestToHex} from './tokens.js';
import {prepareHumanCode,claimHumanCode} from './human-email-code.js';
import {canonicalAccountEmail,mailboxKey} from './account-identity.js';
import {takeRateLimit,hashText} from './sessions.js';
import {deliverRecoveryCodeJob} from './recovery-notifier.js';
import {verifiedRegistration} from './passkey-service.js';
import {storeAaguid} from './passkey-providers.js';
import {SESSION_METHOD_JOIN as MJ,SESSION_METHOD_ACTIVE as MA} from './session-method.js';
export const DELAY_MS=604_800_000,CODE_TTL=30*60_000,GRANT_TTL=10*60_000;
const accepted=Object.freeze({status:'accepted'});
const goodBinding=b=>typeof b==='string'&&b.length>=32&&b.length<=512;
const completeAction=id=>JSON.stringify(['recovery-complete',id]);
export class EmailRecovery {
 constructor(db,{clock=Date.now,deliver,passkeys,getCipher}={}){this.db=db;this.clock=clock;this.deliver=deliver;this.passkeys=passkeys;this.getCipher=getCipher;}
 #binding(binding,email){return JSON.stringify([binding,email]);}
 async #owner(email){const k=await this.db.prepare('SELECT m.owner_id,e.email FROM account_mailbox_keys m JOIN account_emails e ON e.owner_id=m.owner_id WHERE m.mailbox_key=?1').bind(mailboxKey(email)).first();return k??undefined;}
 // purpose: 'request' (start the 7-day wait) or 'complete' (after the wait).
 // Generic response whatever happens. Mail only for an opted-in account.
 #pending=0;
 async requestCode({email,clientAddress,binding,purpose,defer}){
  try{email=canonicalAccountEmail(email);}catch{return accepted;}
  if(!['request','complete'].includes(purpose)||!goodBinding(binding)||typeof clientAddress!=='string'||!clientAddress||typeof this.deliver!=='function'||typeof this.getCipher!=='function')return accepted;
  const now=this.clock();
  if(!(await takeRateLimit(this.db,'recovery-email:address:'+clientAddress,{now,limit:5,windowMs:3600000})).allowed)return accepted;
  if(!(await takeRateLimit(this.db,'recovery-email:recipient:'+mailboxKey(email),{now,limit:3,windowMs:3600000})).allowed)return accepted;
  if(!(await takeRateLimit(this.db,'recovery-email:global',{now,limit:100,windowMs:86400000})).allowed)return accepted;
  // Every valid-shaped request does the same work: owner lookup, a code row, an
  // encrypted durable job row and a deferred send attempt. Unknown mailboxes and
  // accounts without the opt-in get a decoy code and a born-delivered decoy job,
  // never sent, so response time and writes do not reveal the opt-in.
  const a=await this.#owner(email);
  const optin=a&&await this.db.prepare('SELECT 1 x FROM email_recovery_optin WHERE owner_id=?1').bind(a.owner_id).first();
  const open=a&&await this.db.prepare('SELECT available_at FROM email_recovery_requests r JOIN account_security s ON s.owner_id=r.owner_id AND s.generation=r.generation WHERE r.owner_id=?1 AND r.canceled_at IS NULL AND r.completed_at IS NULL').bind(a.owner_id).first();
  const real=!!optin&&(purpose==='request'?!open:!!open&&open.available_at<=now);
  const kind=real?'recovery-'+purpose:'decoy',bindingText=this.#binding(binding,email),expiresAt=now+CODE_TTL,jobId=generateAccessToken().tokenId;
  const {code,codeId,statement:codeStatement}=await prepareHumanCode(this.db,{purpose:real?kind:'recovery-decoy',binding:bindingText,proofId:real?a.owner_id:null,now,expiresAt});
  // Storage failure here is a uniform 503 for every request shape, never a silent drop.
  const cipher=await this.getCipher(),owner=real?a.owner_id:null,bd=await hashText(bindingText);
  const envelope=await cipher.encrypt(JSON.stringify({code,to:real?a.email:'decoy@invalid'}),{ownerId:owner??'decoy',recordId:jobId,serviceId:'recovery-code',receivedAt:now,expiresAt});
  // Atomic: the new code row, retirement of older jobs and the new job (bound to
  // this exact code_id) commit together. A cipher failure above issues nothing, so
  // the previous code and job stay intact.
  await this.db.batch([
   codeStatement,
   // Deterministic supersession: the older undelivered job is retired and its
   // envelope wiped, never deleted, so an already-leased old job sees it before sending.
   this.db.prepare("UPDATE recovery_code_jobs SET superseded_at=?3,envelope='' WHERE binding_digest=?1 AND kind=?2 AND delivered_at IS NULL AND superseded_at IS NULL AND failed_at IS NULL").bind(bd,kind,now),
   this.db.prepare('INSERT INTO recovery_code_jobs(job_id,owner_id,kind,binding_digest,envelope,created_at,expires_at,delivered_at,generation,code_id) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)').bind(jobId,owner,kind,bd,JSON.stringify(envelope),now,expiresAt,real?null:now,real?(await this.db.prepare('SELECT generation g FROM account_security WHERE owner_id=?1').bind(a.owner_id).first())?.g??null:null,codeId),
  ]);
  if(!real)return accepted;
  // Best-effort immediate send. Whatever happens here (no defer, saturation, a
  // throwing defer, provider failure) the durable job is retried by the drain.
  const run=async()=>{try{await deliverRecoveryCodeJob({db:this.db,cipher,deliver:this.deliver,clock:this.clock,jobId});}catch{}finally{this.#pending--;}};
  if(typeof defer!=='function'){this.#pending++;await run();return accepted;}
  if(this.#pending>=4)return accepted;
  this.#pending++;try{defer(run());}catch{/* run() already started and releases its own slot */}
  return accepted;
 }
 async #claim({email,code,binding,purpose}){
  try{email=canonicalAccountEmail(email);}catch{return;}
  if(!goodBinding(binding))return;
  const row=await claimHumanCode(this.db,{purpose:'recovery-'+purpose,binding:this.#binding(binding,email),code,now:this.clock()});
  return row&&typeof row.proof_id==='string'?row.proof_id:undefined;
 }
 // A claimed fresh mailbox code opens a 7-day REQUEST. Nothing else.
 async verifyRequest({email,code,binding}){
  const o=await this.#claim({email,code,binding,purpose:'request'});if(!o)return;
  const now=this.clock(),id=generateAccessToken().tokenId,nid=generateAccessToken().tokenId;
  try{await this.db.batch([
   // A rotated security generation cannot complete an older request. Retire
   // that stale row atomically before opening a fresh full seven-day wait.
   this.db.prepare("UPDATE email_recovery_requests SET canceled_at=?2,canceled_by='generation-changed' WHERE owner_id=?1 AND canceled_at IS NULL AND completed_at IS NULL AND generation<>(SELECT generation FROM account_security WHERE owner_id=?1)").bind(o,now),
   this.db.prepare('INSERT OR IGNORE INTO email_recovery_requests(request_id,owner_id,generation,requested_at,available_at) SELECT ?1,?2,s.generation,?3,?4 FROM account_security s JOIN email_recovery_optin t ON t.owner_id=s.owner_id WHERE s.owner_id=?2').bind(id,o,now,now+DELAY_MS),
   this.db.prepare("INSERT INTO recovery_notifications(notification_id,owner_id,request_id,kind,created_at) SELECT ?1,?2,?3,'requested',?4 WHERE EXISTS(SELECT 1 FROM email_recovery_requests WHERE request_id=?3 AND owner_id=?2)").bind(nid,o,id,now),
  ]);}catch{return;}
  return this.status(o);
 }
 async status(ownerId){
  const now=this.clock(),r=await this.db.prepare('SELECT r.request_id,r.requested_at,r.available_at FROM email_recovery_requests r JOIN account_security s ON s.owner_id=r.owner_id AND s.generation=r.generation WHERE r.owner_id=?1 AND r.canceled_at IS NULL AND r.completed_at IS NULL').bind(ownerId).first();
  return r?{requestId:r.request_id,requestedAt:r.requested_at,availableAt:r.available_at,waiting:now<r.available_at}:undefined;
 }
 // Cancel is the safe direction: any active PASSKEY session of the owner.
 async cancel({ownerId,deviceId,generation,requestId}){
  if(typeof requestId!=='string'||requestId.length>128)return false;
  const now=this.clock(),nid=generateAccessToken().tokenId;
  try{const r=await this.db.batch([
   this.db.prepare(`UPDATE email_recovery_requests SET canceled_at=?1,canceled_by='client' WHERE request_id=?2 AND owner_id=?3 AND canceled_at IS NULL AND completed_at IS NULL AND EXISTS(SELECT 1 FROM device_sessions d ${MJ} WHERE d.device_id=?4 AND d.owner_id=?3 AND d.generation=?5 AND d.credential_id IS NOT NULL AND d.revoked_at IS NULL AND d.expires_at>?1 AND ${MA})`).bind(now,requestId,ownerId,deviceId,generation),
   this.db.prepare("INSERT INTO recovery_notifications(notification_id,owner_id,request_id,kind,created_at) SELECT ?1,?2,?3,'canceled',?4 WHERE EXISTS(SELECT 1 FROM email_recovery_requests WHERE request_id=?3 AND owner_id=?2 AND canceled_at=?4 AND canceled_by='client')").bind(nid,ownerId,requestId,now),
  ]);return r[0].meta.changes===1;}catch{return false;}
 }
 // Completion step 1: after the wait, a fresh mailbox code buys ONE single-use
 // grant to register a NEW passkey. No session, no vault, no data access.
 async beginCompletion({email,code,binding}){
  const o=await this.#claim({email,code,binding,purpose:'complete'});if(!o)return;
  const now=this.clock(),req=await this.db.prepare('SELECT r.request_id,r.generation FROM email_recovery_requests r JOIN account_security s ON s.owner_id=r.owner_id AND s.generation=r.generation JOIN email_recovery_optin t ON t.owner_id=r.owner_id WHERE r.owner_id=?1 AND r.canceled_at IS NULL AND r.completed_at IS NULL AND r.available_at<=?2').bind(o,now).first();if(!req)return;
  const secret=generateAccessToken();
  try{await this.db.batch([
   this.db.prepare('DELETE FROM email_recovery_grants WHERE request_id=?1').bind(req.request_id),
   this.db.prepare('INSERT INTO email_recovery_grants(grant_id,secret_digest,request_id,owner_id,generation,created_at,expires_at) VALUES(?1,?2,?3,?4,?5,?6,?7)').bind(secret.tokenId,digestToHex(await digestSecret(secret.secret)),req.request_id,o,req.generation,now,now+GRANT_TTL),
  ]);}catch{return;}
  const ceremony=await this.passkeys.begin({purpose:'register',ownerId:o,binding:secret.token,action:completeAction(req.request_id)});
  return ceremony?{grant:secret.token,ceremony}:undefined;
 }
 // Completion step 2: verify the NEW passkey and apply everything atomically.
 async finishCompletion({grant,token,response}){
  const p=parseAccessToken(grant);if(!p)return false;const now=this.clock();
  const g=await this.db.prepare('DELETE FROM email_recovery_grants WHERE grant_id=?1 AND secret_digest=?2 AND created_at<=?3 AND expires_at>?3 RETURNING request_id,owner_id,generation').bind(p.tokenId,digestToHex(await digestSecret(p.secret)),now).first();if(!g)return false;
  const ceremony=await this.passkeys.claim({token,purpose:'register',ownerId:g.owner_id,binding:grant,action:completeAction(g.request_id)});
  if(!ceremony||ceremony.generation!==g.generation)return false;
  const record=await verifiedRegistration(this.passkeys.verifier,response,ceremony.challenge);if(!record)return false;
  const at=this.clock();if(at<ceremony.created_at||at>=ceremony.expires_at)return false;
  const {c,transports,deviceType,backedUp}=record,receipt=generateAccessToken().tokenId,nid=generateAccessToken().tokenId,o=g.owner_id,id=g.request_id;
  // E: still eligible (opt-in on, not canceled, wait over, generation unchanged).
  // E2: same without the generation join, so it survives the rotation below.
  // N: the new passkey was inserted by THIS batch (receipt, not a timestamp). Every retirement needs E and N.
  const open=`r.request_id=?1 AND r.owner_id=?2 AND r.canceled_at IS NULL AND r.completed_at IS NULL AND r.available_at<=?3 AND EXISTS(SELECT 1 FROM email_recovery_optin t WHERE t.owner_id=?2)`;
  const E=`EXISTS(SELECT 1 FROM email_recovery_requests r JOIN account_security s ON s.owner_id=r.owner_id AND s.generation=r.generation WHERE ${open})`;
  const E2=`EXISTS(SELECT 1 FROM email_recovery_requests r WHERE ${open})`;
  const N=`EXISTS(SELECT 1 FROM passkey_credentials n WHERE n.credential_id=?5 AND n.owner_id=?2 AND n.revoked_at IS NULL AND n.recovery_receipt=?4)`;
  const b=sql=>this.db.prepare(sql);
  let r;try{r=await this.db.batch([
   b(`INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at,recovery_receipt) SELECT ?5,?2,?6,?7,?8,?9,?10,?3,?4 WHERE ${E} ON CONFLICT(credential_id) DO NOTHING`).bind(id,o,at,receipt,c.id,Array.from(c.publicKey),c.counter,JSON.stringify(transports),deviceType,backedUp),
   b(`UPDATE passkey_credentials SET revoked_at=?3,revision=revision+1 WHERE owner_id=?2 AND credential_id<>?5 AND revoked_at IS NULL AND ${E} AND ${N}`).bind(id,o,at,receipt,c.id),
   b(`UPDATE durable_device_keys SET revoked_at=?3 WHERE owner_id=?2 AND revoked_at IS NULL AND ${E} AND ${N}`).bind(id,o,at,receipt,c.id),
   b(`UPDATE device_sessions SET revoked_at=?3 WHERE owner_id=?2 AND revoked_at IS NULL AND ${E} AND ${N}`).bind(id,o,at,receipt,c.id),
   b(`UPDATE entry_tokens SET revoked_at=?3 WHERE actor_id=?2 AND revoked_at IS NULL AND ${E} AND ${N}`).bind(id,o,at,receipt,c.id),
   b(`UPDATE access_tokens SET revoked_at=?3 WHERE owner_id=?2 AND revoked_at IS NULL AND ${E} AND ${N}`).bind(id,o,at,receipt,c.id),
   b(`DELETE FROM sessions WHERE owner_id=?2 AND ${E} AND ${N}`).bind(id,o,at,receipt,c.id),
   b(`UPDATE account_security SET generation=generation+1 WHERE owner_id=?2 AND ${E} AND ${N}`).bind(id,o,at,receipt,c.id),
   b(`INSERT INTO recovery_notifications(notification_id,owner_id,request_id,kind,created_at) SELECT ?11,?2,?1,'completed',?3 WHERE ${E2} AND ${N}`).bind(id,o,at,receipt,c.id,null,null,null,null,null,nid),
   b(`UPDATE email_recovery_requests SET completed_at=?3,completion_receipt=?4 WHERE request_id=?1 AND owner_id=?2 AND completed_at IS NULL AND ${E2} AND ${N}`).bind(id,o,at,receipt,c.id),
  ]);}catch{return false;}
  if(r[9]/*exact-count-ok*/.meta.changes!==1)return false;
  await storeAaguid(this.db,{credentialId:c.id,ownerId:o,aaguid:record.aaguid});return true;
 }
 async cleanup({limit=100}={}){const r=await this.db.prepare('DELETE FROM email_recovery_grants WHERE grant_id IN(SELECT grant_id FROM email_recovery_grants WHERE expires_at<=?1 ORDER BY expires_at LIMIT ?2)').bind(this.clock(),limit).run();return r.meta.changes;}
}
