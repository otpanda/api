import {claimHumanCode} from './human-email-code.js';
// Internal first-passkey signup to existing cookie-bound login completion.
// No HTTP/runtime mount, mail transport, enrollment of recovery devices or keys.
import{AccountIdentityService,canonicalAccountEmail,mailboxKey}from'./account-identity.js';
import{hashText}from'./sessions.js';
import{generateAccessToken,parseAccessToken,digestSecret,digestToHex}from'./tokens.js';
const REDIRECT='https://otpanda.github.io/app/',OPAQUE=/^[A-Za-z0-9_-]{43}$/;
async function binding(c){return hashText(JSON.stringify(['web-signup-v1',c.cookieDigest,c.challenge,c.state,REDIRECT]));}
export class SignupHandoffService {
 constructor(db,{signup,login,clock=Date.now}={}){if(!db?.prepare||!signup||!login||typeof clock!=='function')throw new TypeError('Signup handoff dependencies required');Object.assign(this,{db,signup,login,clock});this.identity=new AccountIdentityService(db,{clock});}
 now(){const n=this.clock();if(!Number.isSafeInteger(n)||n<0||!Number.isSafeInteger(n+120000))throw new TypeError('Valid instant required');return n;}
 async beginBrowser({email,emailToken,cookieBinding,challenge,state,redirectUri,resolveExisting=false}={}){
  if(typeof cookieBinding!=='string'||cookieBinding.length<32||cookieBinding.length>512||!OPAQUE.test(challenge)||!OPAQUE.test(state)||redirectUri!==REDIRECT)return undefined;
  const now=this.now(),cookieDigest=await hashText(cookieBinding),c={cookieDigest,challenge,state};
  email=canonicalAccountEmail(email);const human=await claimHumanCode(this.db,{purpose:'signup',binding:JSON.stringify([cookieBinding,email]),code:emailToken,now});const ep=human?{tokenId:human.proof_id}:parseAccessToken(emailToken);if(!ep)return undefined;
  const existing=await this.db.prepare('SELECT owner_id FROM account_mailbox_keys WHERE mailbox_key=?1').bind(mailboxKey(email)).first();if(existing&&!resolveExisting)return undefined;
  const receipt=await this.db.prepare('UPDATE signup_mail_bindings SET attempts=attempts+1 WHERE proof_id=?1 AND (?2 IS NULL OR secret_digest=?2) AND cookie_digest=?3 AND email=?4 AND created_at<=?5 AND expires_at>?5 AND attempts<5 RETURNING verified_at,expires_at').bind(ep.tokenId,human?null:digestToHex(await digestSecret(ep.secret)),cookieDigest,email,now).first();if(!receipt)return undefined;
  if(receipt.verified_at===null){
   if(human){await this.db.prepare('DELETE FROM auth_challenges WHERE challenge_id=?1').bind(ep.tokenId).run();}else if(!await this.identity.claim({token:emailToken,purpose:'signup-email',email}))return undefined;
   await this.db.prepare('UPDATE signup_mail_bindings SET verified_at=?1 WHERE proof_id=?2 AND verified_at IS NULL').bind(now,ep.tokenId).run();
  }
  if(existing)return {existing:true};
  // Browser-bound mailbox receipt permits at most five fresh ceremonies. Each
  // receives a new internal one-use proof and a new authenticator challenge.
  const internal=await this.identity.issueEmailChallenge({purpose:'signup-email',email,ttlMs:Math.min(120000,receipt.expires_at-now)});
  const pending=await this.signup.begin({email,emailToken:internal.token,binding:await binding(c)});if(!pending)return undefined;
  const p=parseAccessToken(pending.token);if(!p||!Number.isSafeInteger(pending.expiresAt)||pending.expiresAt<=this.now()||pending.expiresAt>this.now()+120000)return undefined;
  await this.db.prepare('INSERT INTO web_signup_starts (signup_id,secret_digest,cookie_digest,challenge,state,created_at,expires_at) VALUES (?1,?2,?3,?4,?5,?6,?7)').bind(p.tokenId,digestToHex(await digestSecret(p.secret)),cookieDigest,challenge,state,now,pending.expiresAt).run();
  return pending;
 }
 async verifyBrowser({token,response}={}){
  const p=parseAccessToken(token);if(!p)return undefined;const now=this.now();
  const c=await this.db.prepare('DELETE FROM web_signup_starts WHERE signup_id=?1 AND secret_digest=?2 AND created_at<=?3 AND expires_at>?3 RETURNING cookie_digest,challenge,state,expires_at').bind(p.tokenId,digestToHex(await digestSecret(p.secret)),now).first();if(!c)return undefined;
  const proof=await this.signup.finish({token,response,binding:await binding({cookieDigest:c.cookie_digest,challenge:c.challenge,state:c.state})});if(!proof)return undefined;
  // Account now exists: retire all browser receipts for this mailbox. A lost
  // completion is recovered by ordinary passkey login, not another signup.
  await this.db.prepare('DELETE FROM signup_mail_bindings WHERE email=?1').bind(await this.identity.emailForOwner(proof.ownerId)).run();
  const verifiedAt=this.now();if(verifiedAt<now||verifiedAt>=c.expires_at)return undefined;
  const handoff=generateAccessToken(),expiresAt=verifiedAt+60000;
  // Same table/protocol as existing login completion. Generation and credential
  // are checked again by the final insert and by DeviceSessionService.issue().
  const r=await this.db.prepare('INSERT INTO web_login_handoffs (handoff_id,secret_digest,binding_digest,owner_id,credential_id,generation,verified_at,challenge,state,created_at,expires_at) SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?7,?10 WHERE EXISTS (SELECT 1 FROM passkey_credentials p JOIN account_security s ON s.owner_id=p.owner_id WHERE p.credential_id=?5 AND p.owner_id=?4 AND p.revoked_at IS NULL AND s.generation=?6)').bind(handoff.tokenId,digestToHex(await digestSecret(handoff.secret)),await hashText(c.cookie_digest),proof.ownerId,proof.credentialId,proof.generation,verifiedAt,c.challenge,c.state,expiresAt).run();
  return r.meta.changes===1?{handoff:handoff.token,expiresAt}:undefined;
 }
 async completeBrowser(args){return this.login.completeBrowser(args);}
 async cleanup({limit=100}={}){if(!Number.isSafeInteger(limit)||limit<1||limit>500)throw new TypeError('Bounded cleanup required');const r=await this.db.prepare('DELETE FROM web_signup_starts WHERE signup_id IN (SELECT signup_id FROM web_signup_starts WHERE expires_at<=?1 ORDER BY expires_at LIMIT ?2)').bind(this.now(),limit).run();return r.meta.changes;}
}
