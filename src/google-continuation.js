import {issueHumanCode,claimHumanCode} from './human-email-code.js';
// A pending Google transaction has no session authority. It binds one verified
// provider, mailbox or existing-owner proof, original browser and app PKCE.
import {generateAccessToken,parseAccessToken,digestSecret,digestToHex} from './tokens.js';
import {hashText,takeRateLimit} from './sessions.js';
import {AccountIdentityService,mailboxKey} from './account-identity.js';
import {PasskeyService} from './passkey-service.js';
const TTL=600000;
const parse=async token=>{const p=parseAccessToken(token);return p?{id:p.tokenId,hash:digestToHex(await digestSecret(p.secret))}:undefined;};
const context=r=>({ownerId:'google-continuation',recordId:r.continuation_id,serviceId:'https://accounts.google.com',receivedAt:r.created_at,expiresAt:r.expires_at});
export class GoogleContinuation {
 constructor(db,{cipher,clock=Date.now,deliver,allowEmailVerification=false,passkeys=new PasskeyService(db,{clock})}={}){Object.assign(this,{db,cipher,clock,deliver,passkeys,allowEmailVerification});this.identity=new AccountIdentityService(db,{clock});}
 async create({identity,binding,challenge,appState,remember,link}){
  const rows=(await this.db.prepare('SELECT owner_id FROM account_mailbox_keys WHERE mailbox_key=?1 LIMIT 2').bind(mailboxKey(identity.email)).all()).results;if(rows.length>1||(!rows.length&&!this.allowEmailVerification))return;
  // Signed-in link: the bound owner must be the one that owns this mailbox. Never a sign-in, never email verification.
  if(link&&(rows.length!==1||rows[0].owner_id!==link.ownerId))return;
  const now=this.clock(),secret=generateAccessToken(),p=await parse(secret.token),r={continuation_id:p.id,created_at:now,expires_at:now+TTL},data={identity,challenge,appState,remember,ownerId:rows[0]?.owner_id??null,...(link?{linkOnly:{deviceId:link.deviceId,generation:link.generation}}:{})};
  const envelope=await this.cipher.encrypt(JSON.stringify(data),context(r));await this.db.prepare('INSERT INTO google_continuations VALUES(?1,?2,?3,?4,?5,?6)').bind(p.id,p.hash,await hashText(binding),JSON.stringify(envelope),now,now+TTL).run();return{token:secret.token,email:identity.email,kind:link?'link-only':data.ownerId?'link':'email',expiresAt:now+TTL};
 }
 async read(token){const p=await parse(token);if(!p)return;const now=this.clock(),r=await this.db.prepare('SELECT * FROM google_continuations WHERE continuation_id=?1 AND secret_digest=?2 AND created_at<=?3 AND expires_at>?3').bind(p.id,p.hash,now).first();if(!r)return;return{r,p,data:JSON.parse(await this.cipher.decrypt(JSON.parse(r.envelope),context(r)))};}
 async sendEmail({token,clientAddress}){const q=await this.read(token);if(!this.allowEmailVerification||!q||q.data.ownerId||typeof this.deliver!=='function')return false;const now=this.clock();for(const [key,limit,windowMs] of [['google-mail:address:'+clientAddress,5,3600000],['google-mail:recipient:'+mailboxKey(q.data.identity.email),3,3600000],['google-mail:global',100,86400000]])if(!(await takeRateLimit(this.db,key,{now,limit,windowMs})).allowed)return true;
  const proof=await this.identity.issueEmailChallenge({purpose:'signup-email',email:q.data.identity.email,ttlMs:Math.max(1,q.r.expires_at-now)});const code=await issueHumanCode(this.db,{purpose:'google',binding:token,now,expiresAt:proof.expiresAt});await this.deliver({kind:'google-email',to:q.data.identity.email,token:proof.token,code,expiresAt:proof.expiresAt});return true;}
 async beginLink(token){const q=await this.read(token);if(!q?.data.ownerId)return;return this.passkeys.begin({purpose:'step-up',ownerId:q.data.ownerId,binding:token,action:JSON.stringify(['link-google',q.data.identity.issuer,q.data.identity.subject,q.data.identity.email])});}
 async verify({token,emailProof,ceremony,response}){const q=await this.read(token);if(!q)return false;const {data}=q;
  if(data.ownerId){const proof=await this.passkeys.finishAuthentication({token:ceremony,binding:token,response,ownerId:data.ownerId,action:JSON.stringify(['link-google',data.identity.issuer,data.identity.subject,data.identity.email])});if(!proof)return false;data.expectedGeneration=proof.generation;
   // Existing-owner proof and current mailbox identity must still match. Alias
   // collision keys prevent duplicates but never authorize provider linking.
   const account=await this.identity.emailForOwner(data.ownerId);if(mailboxKey(account)!==mailboxKey(data.identity.email))return false;
   const inserted=await this.db.prepare("INSERT INTO provider_identities(identity_id,owner_id,provider,issuer,subject,email,created_at) SELECT ?1,?2,'google',?3,?4,?5,?6 WHERE EXISTS(SELECT 1 FROM account_emails e JOIN account_security s ON s.owner_id=e.owner_id JOIN passkey_credentials p ON p.owner_id=e.owner_id WHERE e.owner_id=?2 AND e.email=?5 AND s.generation=?7 AND p.credential_id=?8 AND p.revoked_at IS NULL AND ?6<?9 AND ?6>=?10 AND ?6<?10+120000) AND (?11 IS NULL OR EXISTS(SELECT 1 FROM device_sessions d WHERE d.device_id=?11 AND d.owner_id=?2 AND d.generation=?7 AND d.revoked_at IS NULL AND d.expires_at>?6)) ON CONFLICT(issuer,subject) WHERE revoked_at IS NULL DO NOTHING").bind(crypto.randomUUID(),data.ownerId,data.identity.issuer,data.identity.subject,account,this.clock(),proof.generation,proof.credentialId,q.r.expires_at,proof.verifiedAt,data.linkOnly?.deviceId??null).run();if(inserted.meta.changes!==1)return false;
   // Link-only is complete here: single use, no verified marker, nothing for consume() or a sign-in to pick up.
   if(data.linkOnly){await this.db.prepare('DELETE FROM google_continuations WHERE continuation_id=?1 AND secret_digest=?2').bind(q.p.id,q.p.hash).run();return true;}
  }else{if(!this.allowEmailVerification)return false;if(!await claimHumanCode(this.db,{purpose:'google',binding:token,code:emailProof,now:this.clock()})&&!await this.identity.claim({token:emailProof,purpose:'signup-email',email:data.identity.email}))return false;data.identity={...data.identity,authoritative:true};}
  // Mark exact transaction verified. Completion still needs original cookie.
  const envelope=await this.cipher.encrypt(JSON.stringify({...data,verifiedAt:this.clock()}),context(q.r));const r=await this.db.prepare('UPDATE google_continuations SET envelope=?1 WHERE continuation_id=?2 AND secret_digest=?3 AND envelope=?4').bind(JSON.stringify(envelope),q.p.id,q.p.hash,q.r.envelope).run();return r.meta.changes===1;
 }
 async consume({token,binding}){const q=await this.read(token);if(!q||q.data.linkOnly||(!q.data.ownerId&&!this.allowEmailVerification)||!Number.isSafeInteger(q.data.verifiedAt)||this.clock()<q.data.verifiedAt||this.clock()-q.data.verifiedAt>=60000||await hashText(binding)!==q.r.binding_digest)return;
 const r=await this.db.prepare('DELETE FROM google_continuations WHERE continuation_id=?1 AND secret_digest=?2 AND envelope=?3 RETURNING continuation_id').bind(q.p.id,q.p.hash,q.r.envelope).first();return r?q.data:undefined;}
}
