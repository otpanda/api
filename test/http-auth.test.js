import test from 'node:test';
import assert from 'node:assert/strict';
import { bearerToken, authenticateBearer, unauthorized } from '../src/http.js';
import { MemoryTokenStore } from '../src/token-store.js';
import { mintAccessToken, revokeAccessToken } from '../src/verify.js';
import { createHandler } from '../src/worker.js';

const NOW = 1_800_000_000_000;
const BASE = { ownerId: 'owner-a', clientId: 'automation-a', serviceId: 'mail.example', allowedScopes: ['codes:read'], now: NOW };

function request(path, token) {
  const headers = token === undefined ? {} : { Authorization: `Bearer ${token}` };
  return new Request('https://test.invalid' + path, { headers });
}

test('bearerToken accepts only a strict single-token Bearer header', () => {
  assert.equal(bearerToken('Bearer abc123'), 'abc123');
  assert.equal(bearerToken('bearer abc123'), 'abc123');
  for (const bad of [undefined, null, '', 'Bearer', 'Bearer ', 'Bearer  abc', 'Bearer a b', 'Basic abc', 'abc']) {
    assert.equal(bearerToken(bad), null, String(bad));
  }
});

test('every authentication failure produces the identical 401 response', async () => {
  const store = new MemoryTokenStore();
  const good = await mintAccessToken(store, { ...BASE, scopes: ['codes:read'], ttlMs: 1_000 });
  const expired = await mintAccessToken(store, { ...BASE, scopes: ['codes:read'], ttlMs: 10 });
  const revoked = await mintAccessToken(store, { ...BASE, scopes: ['codes:read'] });
  await revokeAccessToken(store, revoked.record.tokenId, NOW);

  const failures = [
    await authenticateBearer(request('/v1/auth/check'), store, { now: NOW }), // no header
    await authenticateBearer(request('/v1/auth/check', 'not-a-token'), store, { now: NOW }), // malformed
    await authenticateBearer(request('/v1/auth/check', good.token.slice(0, -2) + (good.token.at(-2) === 'A' ? 'B' : 'A') + good.token.at(-1)), store, { now: NOW }), // unknown/tampered
    await authenticateBearer(request('/v1/auth/check', expired.token), store, { now: NOW + 50 }), // expired
    await authenticateBearer(request('/v1/auth/check', revoked.token), store, { now: NOW }), // revoked
  ];
  const reference = await unauthorized().text();
  for (const failure of failures) {
    assert.equal(failure.ok, false);
    assert.equal(failure.response.status, 401);
    assert.equal(await failure.response.text(), reference);
    assert.equal(failure.response.headers.get('WWW-Authenticate'), 'Bearer realm="otpanda", error="invalid_token"');
    assert.equal(failure.response.headers.get('Cache-Control'), 'no-store');
  }
  assert.ok(!reference.includes('expired') && !reference.includes('revoked'));
});

test('a valid token authenticates and passes the derived grant through', async () => {
  const store = new MemoryTokenStore();
  const { token } = await mintAccessToken(store, { ...BASE, scopes: ['codes:read'] });
  const auth = await authenticateBearer(request('/v1/auth/check', token), store, { now: NOW });
  assert.equal(auth.ok, true);
  assert.equal(auth.grant.ownerId, 'owner-a');
});

test('worker /v1/auth/check echoes the grant for a valid token only', async () => {
  const store = new MemoryTokenStore();
  // The Worker verifies against the real clock, so mint against it too.
  const { token } = await mintAccessToken(store, { ...BASE, scopes: ['codes:read'], now: Date.now() });
  const app = createHandler({ tokenStore: store });

  assert.equal((await app.fetch(request('/v1/auth/check'))).status, 401);
  assert.equal((await app.fetch(request('/v1/auth/check', 'garbage'))).status, 401);

  const res = await app.fetch(request('/v1/auth/check', token));
  assert.equal(res.status, 200);
  const { grant } = await res.json();
  assert.equal(grant.ownerId, 'owner-a');
  assert.equal(grant.serviceId, 'mail.example');
  assert.deepEqual(grant.scopes, ['codes:read']);
});

test('worker /v1/codes/latest enforces authentication, scope and service binding', async () => {
  const store = new MemoryTokenStore();
  const reader = await mintAccessToken(store, { ...BASE, scopes: ['codes:read'], now: Date.now() });
  const otherService = await mintAccessToken(store, { ...BASE, serviceId: 'bank.example', scopes: ['codes:read'], now: Date.now() });
  const app = createHandler({ tokenStore: store });

  assert.equal((await app.fetch(request('/v1/codes/latest?service=mail.example'))).status, 401);
  assert.equal((await app.fetch(request('/v1/codes/latest?service=mail.example', 'garbage'))).status, 401);
  // Right token, but the grant is bound to a different service than requested.
  assert.equal((await app.fetch(request('/v1/codes/latest?service=bank.example', reader.token))).status, 403);
  assert.equal((await app.fetch(request('/v1/codes/latest?service=mail.example', otherService.token))).status, 403);
  // Missing service parameter fails closed.
  assert.equal((await app.fetch(request('/v1/codes/latest', reader.token))).status, 403);
  // Authenticated and authorized: storage itself is still unimplemented.
  const res = await app.fetch(request('/v1/codes/latest?service=mail.example', reader.token));
  assert.equal(res.status, 501);
  assert.deepEqual(await res.json(), { error: 'not_implemented' });
});

test('the default handler stays fail-closed with its empty store', async () => {
  const app = createHandler();
  assert.equal((await app.fetch(request('/v1/auth/check', 'otpda_' + 'A'.repeat(55)))).status, 401);
  assert.equal((await app.fetch(request('/health'))).status, 200);
  assert.equal((await app.fetch(request('/v1/anything'))).status, 501);
  assert.equal((await app.fetch(request('/nope'))).status, 404);
});
