// HTTP edge helpers for bearer authentication. Every authentication failure
// produces the SAME response: status, body and headers are identical whether
// the token was missing, malformed, unknown, tampered, expired or revoked, so
// the edge does not become an oracle for which check failed.

import { verifyAccessToken } from './verify.js';

const CHALLENGE_HEADERS = Object.freeze({
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'WWW-Authenticate': 'Bearer realm="otpanda", error="invalid_token"',
});

// Extracts the credential from an Authorization header. Strict shape: one
// scheme word (case-insensitive), one space, one run of visible characters.
export function bearerToken(authorization) {
  if (typeof authorization !== 'string') return null;
  const match = /^Bearer ([\x21-\x7e]+)$/i.exec(authorization);
  return match ? match[1] : null;
}

export function unauthorized() {
  return Response.json({ error: 'unauthorized' }, { status: 401, headers: CHALLENGE_HEADERS });
}

// Authenticates a Request's bearer token against the store. Returns
// { ok: true, grant } or { ok: false, response } where response is the uniform
// 401. Expiry/revocation use the caller's clock via options.now.
export async function authenticateBearer(request, store, options = {}) {
  const token = bearerToken(request?.headers?.get?.('authorization'));
  if (token === null) return { ok: false, response: unauthorized() };
  const result = await verifyAccessToken(token, store, options);
  if (!result.ok) return { ok: false, response: unauthorized() };
  return { ok: true, grant: result.grant };
}
