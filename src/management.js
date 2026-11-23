import { mintAccessToken, MAX_TTL_MS } from './verify.js';
import { json, takeRateLimit } from './sessions.js';

// Session-only control plane. Bearer automation grants cannot mint new grants.
export function createManagementHandler({ db, sessions, tokenStore, clock = Date.now }) {
  return {
    async fetch(request) {
      const url = new URL(request.url);
      if (!url.pathname.startsWith('/v1/manage/')) return json({ error: 'not_found' }, 404);
      const mutation = request.method !== 'GET';
      const auth = await sessions.authenticate(request, { mutation });
      if (!auth) return json({ error: 'unauthorized' }, 401);
      const rate = await takeRateLimit(db, 'management:' + auth.ownerId, { now: clock() });
      if (!rate.allowed) return json({ error: 'rate_limited' }, 429, { 'Retry-After': String(rate.retryAfter) });
      if (url.pathname === '/v1/manage/session' && request.method === 'GET') return json({ ownerId: auth.ownerId, expiresAt: auth.expiresAt });
      if (url.pathname === '/v1/manage/logout' && request.method === 'POST') {
        await sessions.revoke(auth.sessionId);
        const response = json({ ok: true }); sessions.clearCookies(response.headers); return response;
      }
      if (url.pathname === '/v1/manage/tokens' && request.method === 'GET') return json({ tokens: await tokenStore.listForOwner(auth.ownerId) });
      if (url.pathname === '/v1/manage/tokens' && request.method === 'POST') {
        if (!(request.headers.get('content-type') ?? '').startsWith('application/json')) return json({ error: 'invalid_request' }, 400);
        // Bound the streaming body even when Content-Length is missing/false.
        let bytes = 0, chunks = [];
        if (!request.body) return json({ error: 'invalid_request' }, 400);
        const reader = request.body.getReader();
        while (true) {
          const { value, done } = await reader.read(); if (done) break;
          bytes += value.byteLength;
          if (bytes > 2048) { await reader.cancel(); return json({ error: 'request_too_large' }, 413); }
          chunks.push(value);
        }
        let body;
        try {
          const buffer = new Uint8Array(bytes); let offset = 0;
          for (const chunk of chunks) { buffer.set(chunk, offset); offset += chunk.byteLength; }
          body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer));
          // Unknown fields (including owner/scopes) are rejected, not ignored.
          if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).some(k => !['clientId', 'serviceId', 'ttlMs'].includes(k)) || typeof body.clientId !== 'string' || !/^[A-Za-z0-9_.-]{1,128}$/.test(body.clientId) || typeof body.serviceId !== 'string' || !/^[a-z0-9][a-z0-9.-]{0,252}$/.test(body.serviceId) || !Number.isSafeInteger(body.ttlMs) || body.ttlMs < 1 || body.ttlMs > MAX_TTL_MS) return json({ error: 'invalid_request' }, 400);
        } catch { return json({ error: 'invalid_request' }, 400); }
          const minted = await mintAccessToken(tokenStore, { ownerId: auth.ownerId, clientId: body.clientId, serviceId: body.serviceId, ttlMs: body.ttlMs, scopes: ['codes:read'], allowedScopes: ['codes:read'], now: clock() });
          return json({ token: minted.token, tokenId: minted.record.tokenId, expiresAt: minted.record.expiresAt, scopes: minted.record.scopes, serviceId: minted.record.serviceId }, 201);
      }
      const revoke = /^\/v1\/manage\/tokens\/([A-Za-z0-9_-]{12})$/.exec(url.pathname);
      if (revoke && request.method === 'DELETE') {
        await tokenStore.revokeForOwner(auth.ownerId, revoke[1], clock());
        // Do not reveal whether another owner has this token ID.
        return json({ ok: true });
      }
      return json({ error: 'not_found' }, 404);
    },
  };
}
