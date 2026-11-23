import { MemoryTokenStore } from './token-store.js';
import { authenticateBearer } from './http.js';
import { permitsCodeRead } from './grants.js';

const headers = {
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
};

// The default token store is empty, so out of the box every authenticated
// route stays closed. A real deployment must inject a durable store whose
// records were minted through a user-authenticated management session, which
// does not exist yet.
export function createHandler({ tokenStore, codeStore, clock = Date.now } = {}) {
  const store = tokenStore ?? new MemoryTokenStore();
  return {
    async fetch(request) {
      const url = new URL(request.url);
      if (url.pathname === '/health' && request.method === 'GET') {
        return Response.json({ service: 'otpanda-api', status: 'foundation-only' }, { headers });
      }
      if (url.pathname === '/v1/auth/check' && request.method === 'GET') {
        const auth = await authenticateBearer(request, store, { now: clock() });
        if (!auth.ok) return auth.response;
        // Echoes the derived grant so a client can inspect its own scope and
        // expiry. No codes or secrets are reachable here.
        return Response.json({ grant: auth.grant }, { headers });
      }
      if (url.pathname === '/v1/codes/latest' && request.method === 'GET') {
        const auth = await authenticateBearer(request, store, { now: clock() });
        if (!auth.ok) return auth.response;
        // Authorization is the foundation's pure policy: owner/client come
        // from the verified grant, the service binding must match the query.
        const permitted = permitsCodeRead(
          auth.grant,
          { ownerId: auth.grant.ownerId, clientId: auth.grant.clientId, serviceId: url.searchParams.get('service') },
          clock(),
        );
        if (!permitted) {
          return Response.json({ error: 'forbidden' }, { status: 403, headers });
        }
        if (!codeStore) return Response.json({ error: 'not_implemented' }, { status: 501, headers });
        const record = await codeStore.latest(auth.grant.ownerId, auth.grant.serviceId, clock());
        if (!record) return Response.json({ error: 'not_found' }, { status: 404, headers });
        return Response.json({ code: record.code, serviceId: record.serviceId, receivedAt: record.receivedAt, expiresAt: record.expiresAt }, { headers });
      }
      if (url.pathname.startsWith('/v1/')) {
        return Response.json({ error: 'not_implemented' }, { status: 501, headers });
      }
      return Response.json({ error: 'not_found' }, { status: 404, headers });
    },
  };
}

export default createHandler();
