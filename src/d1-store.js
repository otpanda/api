// Cloudflare D1 adapter: only bound SQL, no SQL built from request values.
// Account provisioning is internal until an authenticated identity flow exists.
import { digestToHex } from './tokens.js';

function decodeToken(row) {
  if (!row) return undefined;
  const digest = typeof row.token_digest === 'string'
    ? Uint8Array.from(row.token_digest.match(/../g) ?? [], v => parseInt(v, 16))
    : new Uint8Array(row.token_digest);
  return { tokenId: row.token_id, tokenDigest: digest, ownerId: row.owner_id,
    clientId: row.client_id, serviceId: row.service_id, scopes: JSON.parse(row.scopes),
    createdAt: row.created_at, notBefore: row.not_before, expiresAt: row.expires_at, revokedAt: row.revoked_at };
}
function requireId(id) {
  if (typeof id !== 'string' || !id || id.length > 256) throw new TypeError('Bounded identifier required');
  return id;
}
export class D1TokenStore {
  constructor(db) { this.db = db; }
  async getByTokenId(id) {
    return decodeToken(await this.db.prepare('SELECT token_id, hex(token_digest) AS token_digest, owner_id, client_id, service_id, scopes, created_at, not_before, expires_at, revoked_at FROM access_tokens WHERE token_id = ?1').bind(id).first());
  }
  async insert(r) {
    if (!(r.tokenDigest instanceof Uint8Array) || r.tokenDigest.length !== 32) throw new TypeError('SHA-256 digest required');
    await this.db.prepare('INSERT INTO access_tokens (token_id, token_digest, owner_id, client_id, service_id, scopes, created_at, not_before, expires_at, revoked_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)')
      .bind(r.tokenId, Array.from(r.tokenDigest), r.ownerId, r.clientId, r.serviceId, JSON.stringify(r.scopes), r.createdAt, r.notBefore, r.expiresAt, r.revokedAt).run();
  }
  // A stale read cannot undo revocation or alter a token's owner/scope/digest.
  // This store's save contract is deliberately restricted to revocation.
  async save(r) {
    const result = await this.db.prepare('UPDATE access_tokens SET revoked_at = COALESCE(revoked_at, ?1) WHERE token_id = ?2 AND owner_id = ?3 AND client_id = ?4 AND service_id = ?5 AND hex(token_digest) = ?6 AND scopes = ?7 AND created_at = ?8 AND not_before = ?9 AND expires_at = ?10')
      .bind(r.revokedAt, r.tokenId, r.ownerId, r.clientId, r.serviceId, digestToHex(r.tokenDigest).toUpperCase(), JSON.stringify(r.scopes), r.createdAt, r.notBefore, r.expiresAt).run();
    if (result.meta.changes !== 1) throw new Error('Unknown or immutable token record');
  }
  async listForOwner(ownerId, limit = 50) {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) throw new TypeError('Limit must be 1..100');
    const result = await this.db.prepare('SELECT token_id, client_id, service_id, scopes, created_at, expires_at, revoked_at FROM access_tokens WHERE owner_id = ?1 ORDER BY created_at DESC, token_id LIMIT ?2').bind(requireId(ownerId), limit).all();
    return result.results.map(r => ({ tokenId: r.token_id, clientId: r.client_id, serviceId: r.service_id, scopes: JSON.parse(r.scopes), createdAt: r.created_at, expiresAt: r.expires_at, revokedAt: r.revoked_at }));
  }
  async revokeForOwner(ownerId, tokenId, now) {
    if (!Number.isSafeInteger(now) || now < 0) throw new TypeError('Valid instant required');
    const result = await this.db.prepare('UPDATE access_tokens SET revoked_at = COALESCE(revoked_at, ?1) WHERE owner_id = ?2 AND token_id = ?3').bind(now, requireId(ownerId), requireId(tokenId)).run();
    return result.meta.changes === 1;
  }
}

export class D1CodeStore {
  constructor(db, cipher) { this.db = db; this.cipher = cipher; }
  async put({ ownerId, recordId, serviceId, code, receivedAt, expiresAt }) {
    [ownerId, recordId, serviceId].forEach(requireId);
    if (!Number.isSafeInteger(receivedAt) || receivedAt < 0 || !Number.isSafeInteger(expiresAt) || expiresAt <= receivedAt || expiresAt - receivedAt > 86_400_000) throw new TypeError('Code lifetime must be at most 24 hours');
    if (typeof code !== 'string' || !/^[A-Za-z0-9-]{4,32}$/.test(code)) throw new TypeError('Invalid verification code');
    const context = { ownerId, recordId, serviceId, receivedAt, expiresAt };
    const envelope = await this.cipher.encrypt(code, context);
    // A provider replay cannot overwrite the first accepted record.
    const result = await this.db.prepare('INSERT INTO code_records (owner_id, record_id, service_id, envelope, received_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(owner_id, record_id) DO NOTHING')
      .bind(ownerId, recordId, serviceId, JSON.stringify(envelope), receivedAt, expiresAt).run();
    return result.meta.changes === 1;
  }
  async latest(ownerId, serviceId, now) {
    [ownerId, serviceId].forEach(requireId);
    if (!Number.isSafeInteger(now) || now < 0) throw new TypeError('Valid instant required');
    const r = await this.db.prepare('SELECT record_id, envelope, received_at, expires_at FROM code_records WHERE owner_id = ?1 AND service_id = ?2 AND received_at <= ?3 AND expires_at > ?3 ORDER BY received_at DESC, record_id DESC LIMIT 1').bind(ownerId, serviceId, now).first();
    if (!r) return undefined;
    const context = { ownerId, serviceId, recordId: r.record_id, receivedAt: r.received_at, expiresAt: r.expires_at };
    return { ...context, code: await this.cipher.decrypt(JSON.parse(r.envelope), context) };
  }
  async purgeExpired(now, limit = 100) {
    if (!Number.isSafeInteger(now) || now < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > 1000) throw new TypeError('Bounded cleanup required');
    const r = await this.db.prepare('DELETE FROM code_records WHERE rowid IN (SELECT rowid FROM code_records WHERE expires_at <= ?1 LIMIT ?2)').bind(now, limit).run();
    return r.meta.changes;
  }
  async deleteOwner(ownerId) {
    await this.db.prepare('DELETE FROM accounts WHERE owner_id = ?1').bind(requireId(ownerId)).run();
  }
}
