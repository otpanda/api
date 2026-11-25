// Email-primary account core. Internal API only: no public route, email delivery,
// provider validation, or legacy-session authorization is implied by this module.
import { generateAccessToken, parseAccessToken, digestSecret, digestToHex } from './tokens.js';
import { hashText } from './sessions.js';

const PURPOSES = new Set(['signup-email', 'change-email', 'link-provider']);
const MAX_TTL = 15 * 60 * 1000;
function instant(now) {
  if (!Number.isSafeInteger(now) || now < 0) throw new TypeError('Valid instant required');
  return now;
}
function identifier(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(value)) throw new TypeError('Bounded identifier required');
  return value;
}
// Display/delivery address stays lowercased and otherwise unchanged.
export function canonicalAccountEmail(value) {
  if (typeof value !== 'string' || value.length > 254 || value !== value.trim() || /[^\x21-\x7e]/.test(value)) throw new TypeError('Supported email required');
  const parts = value.split('@');
  if (parts.length !== 2) throw new TypeError('Supported email required');
  const [local, domain] = parts;
  if (!local || local.length > 64 || !/^[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~.]+$/.test(local) || local.startsWith('.') || local.endsWith('.') || local.includes('..')) throw new TypeError('Supported email required');
  const labels = domain.split('.');
  if (labels.length < 2 || labels.some(v => !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(v))) throw new TypeError('Supported email required');
  return value.toLowerCase();
}
export function mailboxKey(value){const email=canonicalAccountEmail(value),[local,domain]=email.split('@');return ['gmail.com','googlemail.com'].includes(domain)?local.split('+')[0].replaceAll('.','')+'@gmail.com':email;}
function providerIdentity(identity) {
  if (!identity || identity.issuer !== 'https://accounts.google.com' || typeof identity.subject !== 'string' || !identity.subject || identity.subject.length > 256 || /[\u0000-\u001f\u007f]/.test(identity.subject)) throw new TypeError('Validated supported provider identity required');
  return { issuer: identity.issuer, subject: identity.subject, email: canonicalAccountEmail(identity.email) };
}
// Call only on an already signature/audience/issuer/nonce-validated Google ID
// token. email_verified alone is not authoritative for arbitrary external mail.
// The Google profile picture is only ever a plain https URL on a googleusercontent.com host, so a stored or returned value can
// never point the client at an arbitrary site. Anything else is dropped, not an error.
export function googlePictureUrl(value) {
  if (typeof value !== 'string' || value.length > 512) return undefined;
  let u; try { u = new URL(value); } catch { return undefined; }
  if (u.protocol !== 'https:' || u.username || u.password || u.port || u.search || u.hash || !/^[a-z0-9-]+\.googleusercontent\.com$/.test(u.hostname)) return undefined;
  return u.href === value ? value : undefined;
}
export function googleEmailEvidence(claims) {
  const identity = providerIdentity({ issuer: claims?.iss, subject: claims?.sub, email: claims?.email });
  if (claims.email_verified !== true) throw new TypeError('Verified provider email required');
  const domain = identity.email.split('@')[1];
  const authoritative = domain === 'gmail.com' || (typeof claims.hd === 'string' && claims.hd.toLowerCase() === domain);
  const picture = googlePictureUrl(claims.picture);
  return Object.freeze({ ...identity, authoritative, ...(picture ? { picture } : {}) });
}
export class AccountIdentityService {
  constructor(db, { clock = Date.now } = {}) { this.db = db; this.clock = clock; }
  async issueEmailChallenge({ purpose, email, ownerId = null, identity = null, ttlMs = MAX_TTL }) {
    if (!PURPOSES.has(purpose) || !Number.isSafeInteger(ttlMs) || ttlMs < 1 || ttlMs > MAX_TTL) throw new TypeError('Bounded challenge required');
    email = canonicalAccountEmail(email);
    if (purpose === 'signup-email' ? ownerId !== null : ownerId === null) throw new TypeError('Challenge owner mismatch');
    if (ownerId !== null) identifier(ownerId);
    if ((purpose === 'link-provider') !== (identity !== null)) throw new TypeError('Provider binding mismatch');
    const provider = identity === null ? null : providerIdentity(identity);
    if (provider && provider.email !== email) throw new TypeError('Provider email mismatch');
    const target = JSON.stringify({ email, provider });
    const now = instant(this.clock()), token = generateAccessToken();
    await this.db.prepare('INSERT INTO auth_challenges (challenge_id, secret_digest, purpose, owner_id, target_digest, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)')
      .bind(token.tokenId, digestToHex(await digestSecret(token.secret)), purpose, ownerId, await hashText(target), now, now + ttlMs).run();
    return { token: token.token, expiresAt: now + ttlMs };
  }
  async claim({ token, purpose, email, ownerId = null, identity = null }) {
    const parsed = parseAccessToken(token);
    if (!parsed || !PURPOSES.has(purpose)) return false;
    email = canonicalAccountEmail(email);
    const provider = identity === null ? null : providerIdentity(identity);
    const now = instant(this.clock());
    const row = await this.db.prepare('DELETE FROM auth_challenges WHERE challenge_id = ?1 AND secret_digest = ?2 AND purpose = ?3 AND owner_id IS ?4 AND target_digest = ?5 AND created_at <= ?6 AND expires_at > ?6 RETURNING challenge_id')
      .bind(parsed.tokenId, digestToHex(await digestSecret(parsed.secret)), purpose, ownerId, await hashText(JSON.stringify({ email, provider })), now).first();
    return Boolean(row);
  }
  async createEmailAccount({ email, token }) {
    email = canonicalAccountEmail(email);
    if (!await this.claim({ token, purpose: 'signup-email', email })) return undefined;
    const ownerId = crypto.randomUUID(), now = instant(this.clock());
    // D1 batch is transactional. A uniqueness failure cannot leave an account
    // without its email/security row. Consumed challenges fail closed on races.
    try {
      await this.db.batch([
        this.db.prepare('INSERT INTO accounts (owner_id, created_at) VALUES (?1, ?2)').bind(ownerId, now),
        this.db.prepare('INSERT INTO account_emails (owner_id, email, verified_at, updated_at) VALUES (?1, ?2, ?3, ?3)').bind(ownerId, email, now),
        this.db.prepare('INSERT INTO account_security (owner_id) VALUES (?1)').bind(ownerId),
      ]);
      return ownerId;
    } catch { return undefined; }
  }
  async emailForOwner(ownerId) {
    identifier(ownerId);
    const row = await this.db.prepare('SELECT email FROM account_emails WHERE owner_id = ?1').bind(ownerId).first();
    return row?.email;
  }
  async linkProvider({ ownerId, identity, token }) {
    identifier(ownerId);
    const provider = providerIdentity(identity);
    if (await this.emailForOwner(ownerId) !== provider.email) return false;
    // HTTP orchestration must separately require action-bound fresh step-up.
    // Challenge proves current mailbox and binds exact provider issuer+subject.
    if (!await this.claim({ token, purpose: 'link-provider', email: provider.email, ownerId, identity })) return false;
    await this.db.prepare(`INSERT INTO provider_identities(identity_id,owner_id,provider,issuer,subject,email,created_at) SELECT ?5,?3,'google',?1,?2,?4,?6 WHERE EXISTS (SELECT 1 FROM account_emails WHERE owner_id = ?3 AND email = ?4) ON CONFLICT(issuer, subject) WHERE revoked_at IS NULL DO NOTHING`)
      .bind(provider.issuer, provider.subject, ownerId, provider.email,crypto.randomUUID(),instant(this.clock())).run();
    const row = await this.db.prepare('SELECT owner_id FROM provider_identities WHERE issuer = ?1 AND subject = ?2 AND revoked_at IS NULL').bind(provider.issuer, provider.subject).first();
    return row?.owner_id === ownerId;
  }
  async ownerForProvider(identity) {
    const provider = providerIdentity(identity);
    // Stable provider subject signs in. Email matching never links a new subject.
    const row = await this.db.prepare('SELECT i.owner_id FROM provider_identities i WHERE i.issuer = ?1 AND i.subject = ?2 AND i.revoked_at IS NULL')
      .bind(provider.issuer, provider.subject).first();
    return row?.owner_id;
  }
}
