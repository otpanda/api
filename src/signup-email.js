// Internal orchestration only. No provider, HTTP route, runtime mount or send.
import {AccountIdentityService,canonicalAccountEmail} from './account-identity.js';
import {takeRateLimit,hashText} from './sessions.js';
import {parseAccessToken,digestSecret,digestToHex} from './tokens.js';
const TTL=10*60*1000;
export class SignupEmailService {
 constructor(db,{deliver,clock=Date.now,signupAllowed=()=>true}={}) {
  if(!db?.prepare||typeof deliver!=='function'||typeof clock!=='function')throw new TypeError('Signup email dependencies required');
  if(typeof signupAllowed!=='function')throw new TypeError('Signup policy required');this.signupAllowed=signupAllowed;
  this.db=db;this.deliver=deliver;this.clock=clock;this.identity=new AccountIdentityService(db,{clock});
 }
 async request({email,clientAddress,cookieBinding}={}) {
  // Never return an account-existence, quota or delivery-result oracle.
  const accepted=Object.freeze({status:'accepted'});
  email=canonicalAccountEmail(email);
  if(this.signupAllowed(email)!==true)return accepted;
  if(typeof cookieBinding!=='string'||cookieBinding.length<32||cookieBinding.length>512)throw new TypeError('Server browser binding required');
  if(typeof clientAddress!=='string'||!clientAddress||clientAddress.length>128)throw new TypeError('Trusted request address required');
  const now=this.clock();if(!Number.isSafeInteger(now)||now<0||!Number.isSafeInteger(now+TTL))throw new TypeError('Valid instant required');
  // Both are consumed before branching. Address data is hashed by takeRateLimit.
  const sender=await takeRateLimit(this.db,'signup-email:address:'+clientAddress,{now,limit:5,windowMs:3600000});
  if(!sender.allowed)return accepted;
  const recipient=await takeRateLimit(this.db,'signup-email:recipient:'+email,{now,limit:3,windowMs:3600000});
  if(!recipient.allowed)return accepted;
  const global=await takeRateLimit(this.db,'signup-email:global',{now,limit:100,windowMs:86400000});
  if(!global.allowed)return accepted;
  const existing=await this.db.prepare('SELECT owner_id FROM account_emails WHERE email=?1').bind(email).first();
  if(existing)return accepted;
  const proof=await this.identity.issueEmailChallenge({purpose:'signup-email',email,ttlMs:TTL});
  const parsed=parseAccessToken(proof.token);
  await this.db.prepare('INSERT INTO signup_mail_bindings (proof_id,secret_digest,cookie_digest,email,created_at,expires_at) VALUES (?1,?2,?3,?4,?5,?6)').bind(parsed.tokenId,digestToHex(await digestSecret(parsed.secret)),await hashText(cookieBinding),email,now,proof.expiresAt).run();
  try{if(this.signupAllowed(email)!==true)throw new Error('Signup policy changed');await this.deliver(Object.freeze({kind:'signup-email',to:email,token:proof.token,expiresAt:proof.expiresAt}));}
  catch{
   // Failed delivery invalidates its proof without returning transport details.
   await this.identity.claim({token:proof.token,purpose:'signup-email',email});
   await this.db.prepare('DELETE FROM signup_mail_bindings WHERE proof_id=?1').bind(parsed.tokenId).run();
  }
  return accepted;
 }
}
