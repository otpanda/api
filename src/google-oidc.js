// Verifies a Google-signed OIDC JWT (RS256) against Google's published keys.
// Everything the caller must trust (audience, exact service account) is supplied
// by server configuration, never by the request. Returns claims or undefined.
const ISSUERS = new Set(['https://accounts.google.com', 'accounts.google.com']);
const dec = new TextDecoder('utf-8', { fatal: true });
function b64(part) {
  if (typeof part !== 'string' || !/^[A-Za-z0-9_-]+$/.test(part) || part.length > 4096) return;
  const pad = part.replace(/-/g, '+').replace(/_/g, '/'); let bin; try { bin = atob(pad + '='.repeat((4 - pad.length % 4) % 4)); } catch { return; }
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}
export function createGoogleOidcVerifier({ audience, serviceAccountEmail, fetchKeys, clock = Date.now, skewSeconds = 60, keyTtlSeconds = 3600, refreshCooldownSeconds = 60, maxTokenLifetimeSeconds = 3600 } = {}) {
  if (!audience || !serviceAccountEmail || typeof fetchKeys !== 'function') throw new TypeError('Audience, service account and key source required');
  let cache = new Map(), fetchedAt = -Infinity;
  // Keys are re-fetched when older than the TTL. An unknown kid may force one early
  // refresh, but never more often than the cooldown, so forged kids cannot make
  // this endpoint hammer Google.
  async function key(kid) {
    const t = clock();
    const stale = t - fetchedAt >= keyTtlSeconds * 1000;
    if (cache.has(kid) && !stale) return cache.get(kid);
    if (!stale && t - fetchedAt < refreshCooldownSeconds * 1000) return;
    const jwks = await fetchKeys(); const next = new Map();
    for (const k of jwks?.keys ?? []) if (k.kty === 'RSA' && k.kid && (!k.alg || k.alg === 'RS256')) next.set(k.kid, await crypto.subtle.importKey('jwk', { kty: 'RSA', n: k.n, e: k.e, alg: 'RS256', ext: true }, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']));
    cache = next; fetchedAt = t; return cache.get(kid);
  }
  return async function verify(token) {
    try {
      if (typeof token !== 'string' || token.length > 4096) return;
      const parts = token.split('.'); if (parts.length !== 3) return;
      const header = JSON.parse(dec.decode(b64(parts[0]))), claims = JSON.parse(dec.decode(b64(parts[1]))), sig = b64(parts[2]);
      if (header.alg !== 'RS256' || typeof header.kid !== 'string' || !sig) return;
      const k = await key(header.kid); if (!k) return;
      if (!await crypto.subtle.verify('RSASSA-PKCS1-v1_5', k, sig, new TextEncoder().encode(parts[0] + '.' + parts[1]))) return;
      const now = Math.floor(clock() / 1000);
      if (!ISSUERS.has(claims.iss) || claims.aud !== audience || claims.email !== serviceAccountEmail || claims.email_verified !== true) return;
      const num = v => typeof v === 'number' && Number.isFinite(v);
      if (!num(claims.exp) || !num(claims.iat) || claims.exp + skewSeconds < now || claims.iat - skewSeconds > now || claims.exp < claims.iat || claims.exp - claims.iat > maxTokenLifetimeSeconds + skewSeconds || claims.exp - skewSeconds > now + maxTokenLifetimeSeconds) return;
      if (claims.nbf !== undefined && (!num(claims.nbf) || claims.nbf - skewSeconds > now)) return;
      return claims;
    } catch { return; }
  };
}
