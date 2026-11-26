// Durable encrypted TOTP seed persistence and entry-scoped generated-code
// reads. Seeds are encrypted at rest with the seed-dedicated cipher and are
// never returned, logged or stored as delivered codes: every read decrypts in
// memory, computes the requested time step's code and discards the secret.
// Sharing an entry exposes only generated codes, exactly like delivered-code
// reads: owner always, shared recipient code-only, automation only with the
// owner's per-share allow_automation, all re-checked after decryption.
import { totp } from './totp.js';
import { base64urlEncode, base64urlDecode } from './tokens.js';

const ALGORITHMS = new Set(['SHA-1', 'SHA-256', 'SHA-512']);

function id(value) {
  if (typeof value !== 'string' || !value || value.length > 256) throw new TypeError('Bounded identifier required');
  return value;
}
function validateParameters({ secret, algorithm, digits, period }) {
  if (!(secret instanceof Uint8Array) || secret.byteLength < 10 || secret.byteLength > 128) throw new TypeError('TOTP secret must be 10..128 bytes');
  if (!ALGORITHMS.has(algorithm)) throw new RangeError('Unsupported HMAC algorithm');
  if (!Number.isInteger(digits) || (digits < 6 || digits > 8)) throw new RangeError('Digits must be 6 through 8');
  if (!Number.isSafeInteger(period) || period < 1 || period > 86400) throw new RangeError('Invalid period');
  return { secret: secret.slice(), algorithm, digits, period };
}
// Accepts explicit parameters or a parsed ProvisionedTotp (totp-uri.js),
// whose secretBytes() copy is wiped after encoding.
function readSeedInput(seed) {
  if (seed && typeof seed.secretBytes === 'function') {
    return validateParameters({ secret: seed.secretBytes(), algorithm: seed.algorithm, digits: seed.digits, period: seed.period });
  }
  return validateParameters(seed ?? {});
}

export class TotpSeedStore {
  constructor(db, cipher) { this.db = db; this.cipher = cipher; }

  // Owner-only write, one seed per entry. Replacing rotates the seed. Returns
  // whether the seed was stored; never returns or logs seed material.
  async putSeed(ownerId, entryId, seed, now) {
    id(ownerId); id(entryId);
    if (!Number.isSafeInteger(now) || now < 0) throw new TypeError('Valid clock required');
    const parameters = readSeedInput(seed);
    const payload = JSON.stringify({ secret: base64urlEncode(parameters.secret), algorithm: parameters.algorithm, digits: parameters.digits, period: parameters.period });
    parameters.secret.fill(0);
    const envelope = await this.cipher.encrypt(payload, { ownerId, entryId });
    const result = await this.db.prepare('INSERT INTO totp_seeds (owner_id, entry_id, envelope, created_at, updated_at) SELECT ?1, ?2, ?3, ?4, ?4 WHERE EXISTS (SELECT 1 FROM entries WHERE owner_id = ?1 AND entry_id = ?2) ON CONFLICT(entry_id) DO UPDATE SET envelope = excluded.envelope, updated_at = excluded.updated_at WHERE totp_seeds.owner_id = excluded.owner_id')
      .bind(ownerId, entryId, JSON.stringify(envelope), now).run();
    return result.meta.changes === 1;
  }

  // Owner-only removal. Returns whether a seed was removed.
  async removeSeed(ownerId, entryId) {
    const result = await this.db.prepare('DELETE FROM totp_seeds WHERE owner_id = ?1 AND entry_id = ?2').bind(id(ownerId), id(entryId)).run();
    return result.meta.changes === 1;
  }
}

export class EntryTotpGenerator {
  constructor(db, seeds, access) { this.db = db; this.seeds = seeds; this.access = access; }

  // Entry-scoped generated-code read for an owner, a shared recipient or an
  // automation, exactly mirroring delivered-code authorization. Returns
  // undefined when the actor is not permitted or the entry has no seed. The
  // returned record contains a generated code only, never seed material.
  async generateForActor(actorId, entryId, unixSeconds, { automation = false } = {}) {
    id(actorId); id(entryId);
    if (!Number.isSafeInteger(unixSeconds) || unixSeconds < 0) throw new RangeError('Explicit nonnegative integer Unix time required');
    if (typeof automation !== 'boolean') throw new TypeError('Explicit automation flag required');
    if (!await this.access.canRead(actorId, entryId, { automation })) return undefined;
    const row = await this.db.prepare('SELECT s.owner_id, s.envelope FROM totp_seeds s JOIN entries e ON e.owner_id = s.owner_id AND e.entry_id = s.entry_id WHERE s.entry_id = ?1').bind(entryId).first();
    if (!row) return undefined;
    const context = { ownerId: row.owner_id, entryId };
    let payload;
    try {
      payload = JSON.parse(await this.seeds.cipher.decrypt(JSON.parse(row.envelope), context));
    } catch {
      throw new Error('Invalid encrypted seed record');
    }
    if (!payload || typeof payload !== 'object' || Array.isArray(payload) || Object.keys(payload).sort().join(',') !== 'algorithm,digits,period,secret' || typeof payload.secret !== 'string' || payload.secret.length > 171) throw new Error('Invalid seed record');
    const secret = base64urlDecode(payload.secret, Math.floor(payload.secret.length * 6 / 8));
    if (!secret) throw new Error('Invalid seed record');
    let parameters;
    try {
      parameters = validateParameters({ secret, algorithm: payload.algorithm, digits: payload.digits, period: payload.period });
    } catch {
      secret.fill(0);
      throw new Error('Invalid seed record');
    }
    secret.fill(0);
    const epochStart = Math.floor(unixSeconds / parameters.period) * parameters.period;
    if (!Number.isSafeInteger(epochStart + parameters.period)) { parameters.secret.fill(0); throw new RangeError('Invalid generation horizon'); }
    let code;
    try {
      code = await totp(parameters.secret, { unixSeconds, period: parameters.period, digits: parameters.digits, algorithm: parameters.algorithm });
    } finally {
      parameters.secret.fill(0);
    }
    // Re-validate after decryption and generation: a concurrent seed rotation,
    // removal or sharing revocation during the read must not release a code.
    const current = await this.db.prepare('SELECT s.entry_id FROM totp_seeds s JOIN entries e ON e.owner_id = s.owner_id AND e.entry_id = s.entry_id WHERE s.entry_id = ?1 AND s.envelope = ?2').bind(entryId, row.envelope).first();
    if (!current) return undefined;
    if (!await this.access.canRead(actorId, entryId, { automation })) return undefined;
    return { entryId, code, period: parameters.period, validFrom: epochStart, validUntil: epochStart + parameters.period };
  }
}
