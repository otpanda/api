// Atomic first-credential signup. Internal only; no HTTP or email delivery.
import { AccountIdentityService, canonicalAccountEmail } from './account-identity.js';
import { PasskeyVerifier } from './passkey-verifier.js';
import { verifiedRegistration } from './passkey-service.js';
import { generateAccessToken, parseAccessToken, digestSecret, digestToHex, base64urlEncode } from './tokens.js';
import { hashText } from './sessions.js';
const TTL=120_000;
function bindingText(value) { if (typeof value !== 'string' || !value || value.length > 512) throw new TypeError('Server browser binding required');return value; }
export class PasskeySignupService {
  constructor(db,{clock=Date.now,verifier=new PasskeyVerifier()}={}) { this.db=db;this.clock=clock;this.verifier=verifier;this.identity=new AccountIdentityService(db,{clock}); }
  now(){const n=this.clock();if(!Number.isSafeInteger(n)||n<0)throw new TypeError('Valid instant required');return n;}
  async begin({email,emailToken,binding}){
    email=canonicalAccountEmail(email);bindingText(binding);
    if(!await this.identity.claim({token:emailToken,purpose:'signup-email',email}))return undefined;
    const now=this.now(),ownerId=crypto.randomUUID(),secret=generateAccessToken(),challenge=base64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
    const options=await this.verifier.registrationOptions({ownerId,email,challenge});
    await this.db.prepare('INSERT INTO passkey_signups (signup_id, secret_digest, binding_digest, owner_id, email, challenge, verified_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)')
      .bind(secret.tokenId,digestToHex(await digestSecret(secret.secret)),await hashText(binding),ownerId,email,challenge,now,now+TTL).run();
    return {token:secret.token,options,expiresAt:now+TTL};
  }
  async finish({token,binding,response}){
    const parsed=parseAccessToken(token);if(!parsed)return undefined;bindingText(binding);const now=this.now();
    const pending=await this.db.prepare('DELETE FROM passkey_signups WHERE signup_id = ?1 AND secret_digest = ?2 AND binding_digest = ?3 AND verified_at <= ?4 AND expires_at > ?4 RETURNING owner_id, email, challenge, verified_at, expires_at')
      .bind(parsed.tokenId,digestToHex(await digestSecret(parsed.secret)),await hashText(binding),now).first();
    if(!pending)return undefined;
    const record=await verifiedRegistration(this.verifier,response,pending.challenge);if(!record)return undefined;
    const completedAt=this.now();if(completedAt < pending.verified_at || completedAt >= pending.expires_at)return undefined;
    const {c,transports,deviceType,backedUp}=record;
    // The same transaction creates account, unique email, security state and
    // first credential. Any conflict rolls everything back, never an orphan.
    try{
      await this.db.batch([
        this.db.prepare('INSERT INTO accounts (owner_id, created_at) VALUES (?1, ?2)').bind(pending.owner_id,completedAt),
        this.db.prepare('INSERT INTO account_emails (owner_id, email, verified_at, updated_at) VALUES (?1, ?2, ?3, ?4)').bind(pending.owner_id,pending.email,pending.verified_at,completedAt),
        this.db.prepare('INSERT INTO account_security (owner_id) VALUES (?1)').bind(pending.owner_id),
        this.db.prepare('INSERT INTO passkey_credentials (credential_id, owner_id, public_key, counter, transports, device_type, backed_up, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)').bind(c.id,pending.owner_id,Array.from(c.publicKey),c.counter,JSON.stringify(transports),deviceType,backedUp,completedAt),
      ]);
    }catch{return undefined;}
    return {ownerId:pending.owner_id,credentialId:c.id,generation:0};
  }
  async cleanupExpired({limit=100}={}){
    if(!Number.isSafeInteger(limit)||limit<1||limit>500)throw new TypeError('Bounded cleanup required');
    const result=await this.db.prepare('DELETE FROM passkey_signups WHERE signup_id IN (SELECT signup_id FROM passkey_signups WHERE expires_at <= ?1 ORDER BY expires_at LIMIT ?2)').bind(this.now(),limit).run();return result.meta.changes;
  }
      }
