import {storeAaguid} from './passkey-providers.js';
// Internal orchestration, not a public route. Authenticated owner/action binding
// comes from the future HTTP layer, never from an untrusted request field.
import { generateAccessToken, parseAccessToken, digestSecret, digestToHex, base64urlEncode, base64urlDecode } from './tokens.js';
import { hashText } from './sessions.js';
import { PasskeyVerifier } from './passkey-verifier.js';
const TTL = 120_000;
const PURPOSES = new Set(['register', 'authenticate', 'step-up']);
function owner(value) { if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(value)) throw new TypeError('Opaque owner required'); return value; }
function bounded(value, limit = 512) { if (typeof value !== 'string' || !value || value.length > limit) throw new TypeError('Bounded binding required'); return value; }
function credentialId(value) { return typeof value === 'string' && value.length >= 2 && value.length <= 1366 && Boolean(base64urlDecode(value, Math.floor(value.length * 6 / 8))); }
function bytes(value) { return value instanceof Uint8Array ? value : new Uint8Array(value); }
// Normalize only cryptographically verified registration material. Not an
// enrollment grant: callers still own identity and transaction authorization.
export async function verifiedRegistration(verifier, response, challenge) {
  let info;
  try { info = await verifier.verifyRegistration({ response, expectedChallenge:challenge }); } catch { return undefined; }
  if (!info || !info.userVerified || !credentialId(info.credential?.id)) return undefined;
  const c = info.credential;
  if (!(c.publicKey instanceof Uint8Array) || c.publicKey.length < 1 || c.publicKey.length > 4096 || !Number.isSafeInteger(c.counter) || c.counter < 0 || !['singleDevice','multiDevice'].includes(info.credentialDeviceType) || typeof info.credentialBackedUp !== 'boolean') return undefined;
  const transports = [...new Set((c.transports ?? []).filter(t => ['ble','cable','hybrid','internal','nfc','smart-card','usb'].includes(t)))];
  return { c, transports, deviceType:info.credentialDeviceType, backedUp:info.credentialBackedUp ? 1 : 0, aaguid:info.aaguid };
}
export class PasskeyService {
  constructor(db, { clock = Date.now, verifier = new PasskeyVerifier() } = {}) { this.db = db; this.clock = clock; this.verifier = verifier; }
  now() { const now = this.clock(); if (!Number.isSafeInteger(now) || now < 0) throw new TypeError('Valid instant required'); return now; }
  async account(ownerId) {
    owner(ownerId);
    return this.db.prepare('SELECT e.email, s.generation FROM account_emails e JOIN account_security s ON s.owner_id = e.owner_id WHERE e.owner_id = ?1').bind(ownerId).first();
  }
  async active(ownerId) {
    owner(ownerId);
    const rows = await this.db.prepare('SELECT credential_id, transports FROM passkey_credentials WHERE owner_id = ?1 AND revoked_at IS NULL ORDER BY created_at, credential_id').bind(ownerId).all();
    return rows.results.map(r => ({ id:r.credential_id, transports:JSON.parse(r.transports) }));
  }
  async begin({ purpose, ownerId = null, binding, action = null }) {
    if (!PURPOSES.has(purpose)) throw new TypeError('Known ceremony required');
    bounded(binding);
    if (purpose === 'register' || purpose === 'step-up') { owner(ownerId); bounded(action); }
    else if (ownerId !== null || action !== null) throw new TypeError('Discoverable authentication required');
    const account = ownerId === null ? null : await this.account(ownerId);
    if (ownerId !== null && !account) return undefined;
    const now = this.now(), secret = generateAccessToken();
    const entropy=crypto.getRandomValues(new Uint8Array(32));
    const challenge = purpose==='step-up'?base64urlEncode(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(JSON.stringify(['otpanda-step-up-v1',base64urlEncode(entropy),action]))))):base64urlEncode(entropy);
    const credentials = ownerId === null ? null : await this.active(ownerId);
    const options = purpose === 'register'
      ? await this.verifier.registrationOptions({ ownerId, email:account.email, challenge, excludeCredentials:credentials })
      : await this.verifier.authenticationOptions({ challenge, ...(credentials ? {allowCredentials:credentials} : {}) });
    await this.db.prepare('INSERT INTO passkey_ceremonies (ceremony_id, secret_digest, binding_digest, challenge, purpose, owner_id, generation, action_digest, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)')
      .bind(secret.tokenId, digestToHex(await digestSecret(secret.secret)), await hashText(binding), challenge, purpose, ownerId, account?.generation ?? null, action === null ? null : await hashText(action), now, now + TTL).run();
    return { token:secret.token, options, expiresAt:now + TTL };
  }
  async claim({ token, purpose, ownerId = null, binding, action = null }) {
    const parsed = parseAccessToken(token);
    if (!parsed || !PURPOSES.has(purpose)) return undefined;
    bounded(binding);
    if (purpose === 'authenticate' ? ownerId !== null || action !== null : ownerId === null || action === null) return undefined;
    const now = this.now();
    // Exactly one attempt with the correctly bound ceremony. Verification failure
    // consumes it too, avoiding concurrent/repeated signature attempts.
    return (await this.db.prepare('DELETE FROM passkey_ceremonies WHERE ceremony_id = ?1 AND secret_digest = ?2 AND binding_digest = ?3 AND purpose = ?4 AND owner_id IS ?5 AND action_digest IS ?6 AND created_at <= ?7 AND expires_at > ?7 RETURNING challenge, owner_id, generation, purpose, action_digest, created_at, expires_at')
      .bind(parsed.tokenId, digestToHex(await digestSecret(parsed.secret)), await hashText(binding), purpose, ownerId, action === null ? null : await hashText(bounded(action)), now).first()) ?? undefined;
  }
  async finishRegistration({ token, ownerId, binding, action, response }) {
    const ceremony = await this.claim({ token, purpose:'register', ownerId, binding, action });
    if (!ceremony) return false;
    const record = await verifiedRegistration(this.verifier, response, ceremony.challenge);
    if (!record) return false;
    const { c, transports, deviceType, backedUp } = record, now = this.now();
    if (now < ceremony.created_at || now >= ceremony.expires_at) return false;
    // Uniqueness never overwrites another credential, including a revoked one.
    const result = await this.db.prepare('INSERT INTO passkey_credentials (credential_id, owner_id, public_key, counter, transports, device_type, backed_up, created_at) SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8 WHERE EXISTS (SELECT 1 FROM account_security WHERE owner_id = ?2 AND generation = ?9) ON CONFLICT(credential_id) DO NOTHING')
      .bind(c.id, ownerId, Array.from(c.publicKey), c.counter, JSON.stringify(transports), deviceType, backedUp, now, ceremony.generation).run();
    if (result.meta.changes !== 1) return false;
    await storeAaguid(this.db,{credentialId:c.id,ownerId,aaguid:record.aaguid});
    return true;
  }
  async finishAuthentication({ token, binding, response, ownerId = null, action = null, onCeremonyClaimed }) {
    const purpose = ownerId === null ? 'authenticate' : 'step-up';
    const ceremony = await this.claim({ token, purpose, ownerId, binding, action });
    if (!ceremony) return undefined;
    // Internal ownership signal, never an authentication result. Only the caller
    // that deleted this one-use ceremony may retire its pending action intent.
    onCeremonyClaimed?.();
    if (!credentialId(response?.id)) return undefined;
    const row = await this.db.prepare('SELECT p.*, s.generation FROM passkey_credentials p JOIN account_security s ON s.owner_id = p.owner_id JOIN account_emails e ON e.owner_id = p.owner_id WHERE p.credential_id = ?1 AND p.revoked_at IS NULL').bind(response.id).first();
    if (!row || (ownerId !== null && (ownerId !== row.owner_id || ceremony.generation !== row.generation))) return undefined;
    // Discoverable authentication must return the exact opaque user handle.
    // Step-up may omit it when allowCredentials selected the credential.
    const handle = response?.response?.userHandle;
    const expectedHandle = base64urlEncode(new TextEncoder().encode(row.owner_id));
    if (purpose === 'authenticate' ? handle !== expectedHandle : handle !== undefined && handle !== null && handle !== expectedHandle) return undefined;
    let info;
    try { info = await this.verifier.verifyAuthentication({ response, expectedChallenge:ceremony.challenge, credential:{ id:row.credential_id, publicKey:bytes(row.public_key), counter:row.counter, transports:JSON.parse(row.transports) } }); } catch { return undefined; }
    if (!info || !info.userVerified || info.credentialDeviceType !== row.device_type || !Number.isSafeInteger(info.newCounter) || info.newCounter < row.counter) return undefined;
    // Revision also serializes authenticators whose signature counter stays 0.
    // A revoke or security-generation change during verification wins the race.
    const now = this.now();
    if (now < ceremony.created_at || now >= ceremony.expires_at) return undefined;
    const updated = await this.db.prepare('UPDATE passkey_credentials SET counter = ?1, revision = revision + 1, last_used_at = ?2, backed_up = ?3 WHERE credential_id = ?4 AND revision = ?5 AND revoked_at IS NULL AND EXISTS (SELECT 1 FROM account_security WHERE owner_id = ?6 AND generation = ?7)')
      .bind(info.newCounter, now, info.credentialBackedUp ? 1 : 0, row.credential_id, row.revision, row.owner_id, row.generation).run();
    if (updated.meta.changes !== 1) return undefined;
    // This is an internal verification result, not a bearer credential or session.
    return { ownerId:row.owner_id, credentialId:row.credential_id, generation:row.generation, verifiedAt:now, purpose, actionDigest:ceremony.action_digest };
  }
  async cleanupExpired({ limit = 100 } = {}) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500) throw new TypeError('Bounded cleanup required');
    const result = await this.db.prepare('DELETE FROM passkey_ceremonies WHERE ceremony_id IN (SELECT ceremony_id FROM passkey_ceremonies WHERE expires_at <= ?1 ORDER BY expires_at LIMIT ?2)').bind(this.now(), limit).run();
    return result.meta.changes;
  }
  async revoke({ ownerId, credentialId: id }) {
    owner(ownerId);
    if (!credentialId(id)) return false;
    // The last passkey stays unless an active Google link remains (no lockout).
    // HTTP layer must require fresh action-bound step-up and recovery-readiness
    // confirmation before calling this mutation. Never accept ownerId from body.
    // The 0025 last-verifier trigger still aborts a protection-on last-key revoke.
    let result;try{result = await this.db.prepare('UPDATE passkey_credentials SET revoked_at = ?1, revision = revision + 1 WHERE credential_id = ?2 AND owner_id = ?3 AND revoked_at IS NULL AND (EXISTS(SELECT 1 FROM passkey_credentials o WHERE o.owner_id = ?3 AND o.credential_id <> ?2 AND o.revoked_at IS NULL) OR EXISTS(SELECT 1 FROM provider_identities g WHERE g.owner_id = ?3 AND g.revoked_at IS NULL))').bind(this.now(), id, ownerId).run();}catch{return false;}
    return result.meta.changes === 1;
  }
}
