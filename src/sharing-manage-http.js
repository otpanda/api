import { json, takeRateLimit } from './sessions.js';
import { createDeviceSessionAuth } from './device-session-auth.js';
const API = 'https://otpanda-api.abrahammurciano.workers.dev', APP = 'https://otpanda.github.io', cors = { 'Access-Control-Allow-Origin': APP, Vary: 'Origin' };
const ID = /^[A-Za-z0-9_-]{1,128}$/, TOKEN = /^[A-Za-z0-9_-]{32,512}$/;
const MODES = ['all', 'allow', 'deny'];
const IDS = v => Array.isArray(v) && v.length <= 500 && v.every(x => typeof x === 'string' && ID.test(x));
const TERMS = b => MODES.includes(b.mode) && IDS(b.entryIds) && typeof b.canDelegate === 'boolean';
// Strict body schemas. Tokens only ever travel in POST bodies (never URLs, so never in access logs or Referer);
// raw machine and invite tokens are returned once, in a no-store response body.
const ROUTES = {
  '/v1/manage/sharing/invite/create': { keys: 'canDelegate,entryIds,mode,ttlSeconds', ok: b => TERMS(b) && Number.isSafeInteger(b.ttlSeconds) },
  '/v1/manage/sharing/invite/revoke': { keys: 'inviteId', ok: b => ID.test(b.inviteId ?? '') },
  '/v1/manage/sharing/invite/accept': { keys: 'token', ok: b => TOKEN.test(b.token ?? '') },
  '/v1/manage/sharing/grant/update': { keys: 'canDelegate,contactRef,entryIds,mode', ok: b => TERMS(b) && /^[0-9a-f]{32}$/.test(b.contactRef ?? '') },
  '/v1/manage/sharing/grant/create': { keys: 'canDelegate,contactRef,entryIds,mode', ok: b => TERMS(b) && /^[0-9a-f]{32}$/.test(b.contactRef ?? '') },
  '/v1/manage/sharing/contacts/list': { keys: '', ok: () => true },
  '/v1/manage/sharing/contacts/remove': { keys: 'contactRef', ok: b => /^[0-9a-f]{32}$/.test(b.contactRef ?? '') },
  '/v1/manage/sharing/grant/revoke': { keys: 'contactRef', ok: b => /^[0-9a-f]{32}$/.test(b.contactRef ?? '') },
  '/v1/manage/machine/profile/create': { keys: 'entryIds,mode,name', ok: b => MODES.includes(b.mode) && IDS(b.entryIds) && typeof b.name === 'string' && b.name.trim().length >= 1 && b.name.length <= 120 },
  '/v1/manage/machine/profiles/list': { keys: '', ok: () => true },
  '/v1/manage/machine/entries/list': { keys: '', ok: () => true },
  '/v1/manage/machine/token/revoke': { keys: 'profileId,tokenId', ok: b => ID.test(b.profileId ?? '') && ID.test(b.tokenId ?? '') },
  '/v1/manage/machine/profile/revoke': { keys: 'profileId', ok: b => ID.test(b.profileId ?? '') },
  '/v1/manage/machine/token/create': { keys: 'profileId,ttlSeconds', ok: b => ID.test(b.profileId ?? '') && (b.ttlSeconds === null || Number.isSafeInteger(b.ttlSeconds)) },
};
// Same transport rules as entry-manage-http: web bearer with Origin = app, or (native) Android bearer with no
// Origin and exact application/json. POST only, no query string, 4096-byte body, exact key sets, 30/min per owner.
export function createSharingManageHttp({ db, access, sessions, clock = Date.now, native = false } = {}) {
  const webAuth = createDeviceSessionAuth({ sessions }), androidAuth = native ? createDeviceSessionAuth({ sessions, native: true }) : undefined;
  return { async fetch(request) {
    const url = new URL(request.url), route = ROUTES[url.pathname];
    if (url.origin !== API || !route) return json({ error: 'not_found' }, 404);
    const android = request.headers.get('origin') === null;
    if (android ? !native : request.headers.get('origin') !== APP) return json({ error: 'forbidden' }, 403);
    const reply = (body, status = 200, headers = {}) => json(body, status, android ? headers : { ...cors, ...headers });
    if (url.search || url.hash) return reply({ error: 'invalid_request' }, 400);
    if (request.method === 'OPTIONS' && !android) {
      const h = (request.headers.get('access-control-request-headers') ?? '').toLowerCase().split(',').map(v => v.trim()).filter(Boolean);
      return request.headers.get('access-control-request-method') === 'POST' && h.every(v => ['authorization', 'content-type'].includes(v)) ? new Response(null, { status: 204, headers: { ...cors, 'Cache-Control': 'no-store', 'Access-Control-Allow-Methods': 'POST', 'Access-Control-Allow-Headers': 'authorization, content-type', 'Access-Control-Max-Age': '600' } }) : reply({ error: 'forbidden' }, 403);
    }
    if (request.method !== 'POST') return reply({ error: 'method_not_allowed' }, 405);
    const auth = android ? androidAuth : webAuth, kind = android ? 'android' : 'web';
    const session = await auth.authenticate(request); if (!session) return reply({ error: 'unauthorized' }, 401);
    const ct = request.headers.get('content-type') ?? '';
    if ((android ? ct !== 'application/json' : ct.split(';')[0].trim() !== 'application/json') || !request.body) return reply({ error: 'invalid_request' }, 400);
    const reader = request.body.getReader(), parts = []; let size = 0;
    try { for (;;) { const p = await reader.read(); if (p.done) break; size += p.value.byteLength; if (size > 4096) { await reader.cancel(); return reply({ error: 'invalid_request' }, 400); } parts.push(p.value); } } catch { return reply({ error: 'invalid_request' }, 400); }
    let body;
    try { const bytes = new Uint8Array(size); let i = 0; for (const p of parts) { bytes.set(p, i); i += p.byteLength; } body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { return reply({ error: 'invalid_request' }, 400); }
    if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).sort().join() !== route.keys || !route.ok(body)) return reply({ error: 'invalid_request' }, 400);
    const rate = await takeRateLimit(db, 'sharing-manage:' + session.ownerId, { now: clock(), limit: 30 });
    if (!rate.allowed) return reply({ error: 'rate_limited' }, 429, { 'Retry-After': String(rate.retryAfter) });
    const viewer = { ownerId: session.ownerId, deviceId: session.deviceId, generation: session.generation, kind }, now = clock();
    const notFound = () => reply({ error: 'not_found' }, 404);
    try {
      switch (url.pathname) {
        case '/v1/manage/sharing/invite/create': {
          const r = await access.createInvite(viewer, { mode: body.mode, entryIds: body.entryIds, canDelegate: body.canDelegate }, body.ttlSeconds * 1000, now);
          return r ? reply(r) : notFound();
        }
        case '/v1/manage/sharing/invite/revoke': return (await access.revokeInvite(viewer, body.inviteId, now)) ? reply({ ok: true }) : notFound();
        case '/v1/manage/sharing/invite/accept': { const r = await access.acceptInvite(viewer, body.token, now); return r ? reply({ ok: true, mode: r.mode, canDelegate: r.canDelegate }) : notFound(); }
        case '/v1/manage/sharing/grant/update': return (await access.updateGrantForContact(viewer, body.contactRef, { mode: body.mode, entryIds: body.entryIds, canDelegate: body.canDelegate }, now)) ? reply({ ok: true }) : notFound();
        case '/v1/manage/sharing/grant/create': return (await access.grantToContact(viewer, body.contactRef, { mode: body.mode, entryIds: body.entryIds, canDelegate: body.canDelegate }, now)) ? reply({ ok: true }) : notFound();
        case '/v1/manage/sharing/contacts/list': return reply({ contacts: await access.listContacts(viewer, now) });
        case '/v1/manage/sharing/contacts/remove': return (await access.removeContact(viewer, body.contactRef, now)) ? reply({ ok: true }) : notFound();
        case '/v1/manage/sharing/grant/revoke': return (await access.revokeGrantForContact(viewer, body.contactRef, now)) ? reply({ ok: true }) : notFound();
        case '/v1/manage/machine/profile/create': { const r = await access.createProfile(viewer, { name: body.name, mode: body.mode, entryIds: body.entryIds }, now); return r ? reply({ profileId: r }) : notFound(); }
        case '/v1/manage/machine/profiles/list': return reply({ profiles: await access.listProfiles(viewer, now) });
        case '/v1/manage/machine/entries/list': return reply({ entries: await access.listMachineEntries(viewer, now) });
        case '/v1/manage/machine/token/revoke': return (await access.revokeToken(viewer, body.profileId, body.tokenId, now)) ? reply({ ok: true }) : notFound();
        case '/v1/manage/machine/profile/revoke': return (await access.revokeProfile(viewer, body.profileId, now)) ? reply({ ok: true }) : notFound();
        case '/v1/manage/machine/token/create': { const r = await access.mintToken(viewer, body.profileId, body.ttlSeconds === null ? null : body.ttlSeconds * 1000, now); return r ? reply({ token: r.token, tokenId: r.tokenId, expiresAt: r.expiresAt }) : notFound(); }
      }
    } catch (error) {
      // Scope and bound violations (foreign entry ids, ttl out of range) are indistinguishable from unknown ids.
      if (error instanceof TypeError) return body.ttlSeconds !== undefined || url.pathname.includes('create') || url.pathname.includes('update') ? reply({ error: 'invalid_request' }, 400) : notFound();
      throw error;
    }
    return notFound();
  } };
}
