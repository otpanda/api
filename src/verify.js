// Mint, verify and revoke scoped access tokens. Verification derives a grant
// record server-side; the derived shape matches the input of permitsCodeRead
// in ./grants.js so authorization stays a separate, composable step.

import { generateAccessToken, parseAccessToken, digestSecret, timingSafeEqual } from './tokens.js';

export const REJECTION = Object.freeze({
  MALFORMED: 'malformed',
  UNKNOWN_TOKEN: 'unknown_token',
  BAD_SECRET: 'bad_secret',
  REVOKED: 'revoked',
  EXPIRED: 'expired',
  NOT_YET_VALID: 'not_yet_valid',
});

export const DEFAULT_TTL_MS = 30 * 24 * 60 * 60 * 1000;
export const MAX_TTL_MS = 366 * 24 * 60 * 60 * 1000;
export const MAX_LEEWAY_MS = 5 * 60 * 1000;

function requireName(value, field) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 256) {
    throw new TypeError(`${field} must be a non-empty string of at most 256 characters`);
  }
  return value;
}

function requireInstant(value, field) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${field} must be a non-negative epoch-milliseconds integer`);
  }
  return value;
}

function requireLeeway(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_LEEWAY_MS) {
    throw new TypeError(`leewayMs must be an integer between 0 and ${MAX_LEEWAY_MS}`);
  }
  return value;
}

// Creates a token and stores ONLY its digest. The returned token string is the
// one and only copy of the credential: hand it to the caller once, never log
// it, never persist it.
export async function mintAccessToken(store, options) {
  if (!store || typeof store.insert !== 'function') throw new TypeError('Token store required');
  if (!options || typeof options !== 'object') throw new TypeError('Options required');
  const now = options.now ?? Date.now();
  requireInstant(now, 'now');
  const notBefore = options.notBefore ?? now;
  requireInstant(notBefore, 'notBefore');
  const ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 1 || ttlMs > MAX_TTL_MS) {
    throw new TypeError(`ttlMs must be an integer between 1 and ${MAX_TTL_MS}`);
  }
  const expiresAt = requireInstant(notBefore + ttlMs, 'expiresAt');
  const { allowedScopes } = options;
  if (!Array.isArray(allowedScopes) || allowedScopes.length === 0) {
    throw new TypeError('allowedScopes must be a non-empty array');
  }
  const scopes = [...new Set(options.scopes)];
  if (scopes.length === 0 || scopes.some((s) => typeof s !== 'string' || !allowedScopes.includes(s))) {
    throw new TypeError('scopes must be a non-empty array drawn from allowedScopes');
  }
  const { token, tokenId, secret } = generateAccessToken(options.randomFill);
  const record = {
    tokenId,
    tokenDigest: await digestSecret(secret),
    ownerId: requireName(options.ownerId, 'ownerId'),
    clientId: requireName(options.clientId, 'clientId'),
    serviceId: requireName(options.serviceId, 'serviceId'),
    scopes,
    createdAt: now,
    notBefore,
    expiresAt,
    revokedAt: null,
  };
  await store.insert(record);
  return { token, record };
}

// Verify a presented token against the store. Every failure returns
// { ok: false, reason } with a reason code for server-side logging and tests;
// the HTTP layer in ./http.js collapses all of them into one identical 401 so
// callers cannot probe which check failed.
export async function verifyAccessToken(input, store, options = {}) {
  if (!store || typeof store.getByTokenId !== 'function') throw new TypeError('Token store required');
  const now = options.now ?? Date.now();
  requireInstant(now, 'now');
  const leewayMs = requireLeeway(options.leewayMs ?? 0);

  const parsed = parseAccessToken(input);
  if (!parsed) return { ok: false, reason: REJECTION.MALFORMED };

  const record = await store.getByTokenId(parsed.tokenId);
  if (!record || !(record.tokenDigest instanceof Uint8Array)) {
    return { ok: false, reason: REJECTION.UNKNOWN_TOKEN };
  }

  const presented = await digestSecret(parsed.secret);
  if (!timingSafeEqual(presented, record.tokenDigest)) {
    return { ok: false, reason: REJECTION.BAD_SECRET };
  }
  if (record.revokedAt !== null) return { ok: false, reason: REJECTION.REVOKED };
  // Expiry is inclusive: a token is dead the instant now reaches expiresAt.
  // Leeway only ever widens acceptance for clock skew, never narrows it.
  if (!Number.isSafeInteger(record.expiresAt) || record.expiresAt <= now - leewayMs) {
    return { ok: false, reason: REJECTION.EXPIRED };
  }
  if (!Number.isSafeInteger(record.notBefore) || record.notBefore > now + leewayMs) {
    return { ok: false, reason: REJECTION.NOT_YET_VALID };
  }

  // Identity and scope come from the verified record, never from
  // request-controlled input. The caller gets a frozen copy.
  return {
    ok: true,
    grant: Object.freeze({
      ownerId: record.ownerId,
      clientId: record.clientId,
      serviceId: record.serviceId,
      scopes: Object.freeze([...record.scopes]),
      notBefore: record.notBefore,
      expiresAt: record.expiresAt,
      revokedAt: record.revokedAt,
    }),
  };
}

// Idempotent: returns true when the token is revoked afterwards, false when
// the tokenId is unknown.
export async function revokeAccessToken(store, tokenId, now = Date.now()) {
  if (!store || typeof store.getByTokenId !== 'function' || typeof store.save !== 'function') {
    throw new TypeError('Token store required');
  }
  requireInstant(now, 'now');
  if (typeof tokenId !== 'string' || tokenId.length === 0) return false;
  const record = await store.getByTokenId(tokenId);
  if (!record) return false;
  if (record.revokedAt === null) {
    record.revokedAt = now;
    await store.save(record);
  }
  return true;
}

export function grantHasScope(grant, scope) {
  return Boolean(grant) && Array.isArray(grant.scopes) && grant.scopes.includes(scope);
}
