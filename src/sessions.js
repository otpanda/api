import { generateAccessToken, parseAccessToken, digestSecret, timingSafeEqual, digestToHex } from './tokens.js';

export const SESSION_COOKIE = '__Host-otpanda_session';
export const CSRF_COOKIE = '__Host-otpanda_csrf';
export const LOGIN_COOKIE = '__Host-otpanda_login';
export const SESSION_TTL = 8 * 60 * 60 * 1000;
export const LOGIN_TTL = 10 * 60 * 1000;
export const securityHeaders = {
  'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer', 'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
};
export function cookie(name, value, maxAge, httpOnly = true) {
  return `${name}=${value}; Path=/; Secure; SameSite=Lax; Max-Age=${maxAge}${httpOnly ? '; HttpOnly' : ''}`;
}
export function readCookie(request, name) {
  const matches = (request.headers.get('cookie') ?? '').split(';').map(v => v.trim()).filter(v => v.startsWith(name + '='));
  if (matches.length !== 1) return undefined;
  return matches[0].slice(name.length + 1);
}
export function json(body, status = 200, extra = {}) { return Response.json(body, { status, headers: { ...securityHeaders, ...extra } }); }
export async function opaqueDigest(token) {
  const parsed = parseAccessToken(token);
  if (!parsed) return undefined;
  return { id: parsed.tokenId, digest: await digestSecret(parsed.secret) };
}
export async function hashText(text) {
  return digestToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))));
}
export class SessionService {
  constructor(db, { origin, clock = Date.now } = {}) {
    const parsed = new URL(origin);
    if (parsed.protocol !== 'https:' || parsed.origin !== origin) throw new TypeError('Exact HTTPS application origin required');
    this.db = db; this.origin = origin; this.clock = clock;
  }
  async issue(ownerId) {
    const session = generateAccessToken();
    const csrf = generateAccessToken();
    const now = this.clock();
    await this.db.prepare('INSERT INTO sessions (session_id, session_digest, csrf_digest, owner_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)')
      .bind(session.tokenId, Array.from(await digestSecret(session.secret)), Array.from(await digestSecret(csrf.secret)), ownerId, now, now + SESSION_TTL).run();
    return { session: session.token, csrf: csrf.token, expiresAt: now + SESSION_TTL };
  }
  async authenticate(request, { mutation = false } = {}) {
    if (new URL(request.url).origin !== this.origin) return undefined;
    const credential = await opaqueDigest(readCookie(request, SESSION_COOKIE));
    if (!credential) return undefined;
    const row = await this.db.prepare('SELECT session_digest, csrf_digest, owner_id, expires_at FROM sessions WHERE session_id = ?1').bind(credential.id).first();
    if (!row || row.expires_at <= this.clock() || !timingSafeEqual(credential.digest, new Uint8Array(row.session_digest))) return undefined;
    if (mutation) {
      if (request.headers.get('origin') !== this.origin) return undefined;
      const csrf = await opaqueDigest(request.headers.get('x-otpanda-csrf'));
      if (!csrf || !timingSafeEqual(csrf.digest, new Uint8Array(row.csrf_digest))) return undefined;
    }
    return { ownerId: row.owner_id, sessionId: credential.id, expiresAt: row.expires_at };
  }
  async revoke(sessionId) { await this.db.prepare('DELETE FROM sessions WHERE session_id = ?1').bind(sessionId).run(); }
  async revokeAll(ownerId) { await this.db.prepare('DELETE FROM sessions WHERE owner_id = ?1').bind(ownerId).run(); }
  setCookies(headers, issued) {
    headers.append('Set-Cookie', cookie(SESSION_COOKIE, issued.session, SESSION_TTL / 1000));
    headers.append('Set-Cookie', cookie(CSRF_COOKIE, issued.csrf, SESSION_TTL / 1000, false));
  }
  clearCookies(headers) {
    headers.append('Set-Cookie', cookie(SESSION_COOKIE, '', 0));
    headers.append('Set-Cookie', cookie(CSRF_COOKIE, '', 0, false));
  }
}

// Exact issuer+subject identity only. Email addresses never link accounts.
export async function ownerForIdentity(db, issuer, subject, now) {
  if (typeof issuer !== 'string' || !issuer.startsWith('https://') || typeof subject !== 'string' || !subject || subject.length > 256) throw new TypeError('Validated OIDC identity required');
  const candidate = crypto.randomUUID();
  await db.batch([
    db.prepare('INSERT INTO accounts (owner_id, created_at) SELECT ?1, ?2 WHERE NOT EXISTS (SELECT 1 FROM identities WHERE issuer = ?3 AND subject = ?4)').bind(candidate, now, issuer, subject),
    db.prepare('INSERT INTO identities (issuer, subject, owner_id) SELECT ?1, ?2, ?3 WHERE EXISTS (SELECT 1 FROM accounts WHERE owner_id = ?3) ON CONFLICT(issuer, subject) DO NOTHING').bind(issuer, subject, candidate),
    db.prepare('DELETE FROM accounts WHERE owner_id = ?1 AND NOT EXISTS (SELECT 1 FROM identities WHERE owner_id = ?1)').bind(candidate),
  ]);
  const row = await db.prepare('SELECT owner_id FROM identities WHERE issuer = ?1 AND subject = ?2').bind(issuer, subject).first();
  if (!row) throw new Error('Identity provisioning failed');
  return row.owner_id;
}

// Atomic per-key fixed-window limiter. Call before expensive operations.
// bucketKey must be server-derived (never a user-selected owner/IP string).
export async function takeRateLimit(db, bucketKey, { now = Date.now(), limit = 30, windowMs = 60_000 } = {}) {
  const window = Math.floor(now / windowMs) * windowMs;
  const key = await hashText(bucketKey);
  const row = await db.prepare('INSERT INTO rate_buckets (bucket_key, count, resets_at) VALUES (?1, 1, ?2) ON CONFLICT(bucket_key) DO UPDATE SET count = CASE WHEN resets_at <= ?3 THEN 1 ELSE count + 1 END, resets_at = CASE WHEN resets_at <= ?3 THEN ?2 ELSE resets_at END RETURNING count, resets_at')
    .bind(key, window + windowMs, now).first();
  return { allowed: row.count <= limit, retryAfter: Math.max(1, Math.ceil((row.resets_at - now) / 1000)) };
    }
