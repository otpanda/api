import test from 'node:test';
import assert from 'node:assert/strict';
import { MemoryTokenStore } from '../src/token-store.js';
import {
  REJECTION,
  MAX_TTL_MS,
  MAX_LEEWAY_MS,
  mintAccessToken,
  verifyAccessToken,
  revokeAccessToken,
  grantHasScope,
} from '../src/verify.js';
import { permitsCodeRead } from '../src/grants.js';

const NOW = 1_800_000_000_000;
const GRANT = { ownerId: 'owner-a', clientId: 'automation-a', serviceId: 'mail.example', scopes: ['codes:read'] };
const ALLOWED = ['codes:read', 'codes:list'];

function mintInto(store, overrides = {}) {
  return mintAccessToken(store, { ...GRANT, allowedScopes: ALLOWED, now: NOW, ...overrides });
}

test('mint then verify returns a frozen grant derived from the stored record', async () => {
  const store = new MemoryTokenStore();
  const { token, record } = await mintInto(store, { ttlMs: 60_000 });
  assert.equal(record.expiresAt, NOW + 60_000);
  assert.equal(record.revokedAt, null);

  const result = await verifyAccessToken(token, store, { now: NOW });
  assert.equal(result.ok, true);
  const { grant } = result;
  assert.equal(grant.ownerId, GRANT.ownerId);
  assert.equal(grant.clientId, GRANT.clientId);
  assert.equal(grant.serviceId, GRANT.serviceId);
  assert.deepEqual([...grant.scopes], GRANT.scopes);
  assert.equal(grant.notBefore, NOW);
  assert.equal(grant.expiresAt, NOW + 60_000);
  assert.ok(Object.isFrozen(grant));
  assert.ok(Object.isFrozen(grant.scopes));
});

test('the store never holds the raw token or secret', async () => {
  const store = new MemoryTokenStore();
  const { token, record } = await mintInto(store);
  const stored = await store.getByTokenId(record.tokenId);
  assert.ok(stored.tokenDigest instanceof Uint8Array);
  assert.equal(stored.tokenDigest.length, 32);
  assert.ok(!JSON.stringify(stored).includes(token));
});

test('tampering with the secret part is rejected as a bad secret', async () => {
  const store = new MemoryTokenStore();
  const { token, record } = await mintInto(store);
  const tampered = token.slice(0, 30) + (token[30] === 'A' ? 'B' : 'A') + token.slice(31);
  assert.equal((await verifyAccessToken(tampered, store, { now: NOW })).reason, REJECTION.BAD_SECRET);
  // The original still works: tampering did not corrupt the stored record.
  assert.equal((await verifyAccessToken(token, store, { now: NOW })).ok, true);
  assert.equal(record.revokedAt, null);
});

test('tampering with the id part is rejected as an unknown token', async () => {
  const store = new MemoryTokenStore();
  const { token } = await mintInto(store);
  const i = 'otpda_'.length + 2; // inside the id segment
  const tampered = token.slice(0, i) + (token[i] === 'A' ? 'B' : 'A') + token.slice(i + 1);
  assert.equal((await verifyAccessToken(tampered, store, { now: NOW })).reason, REJECTION.UNKNOWN_TOKEN);
});

test('malformed inputs are rejected without throwing', async () => {
  const store = new MemoryTokenStore();
  for (const input of [undefined, null, 42, '', 'otpda_', 'nope', 'x'.repeat(5000)]) {
    assert.equal((await verifyAccessToken(input, store, { now: NOW })).reason, REJECTION.MALFORMED, String(input));
  }
});

test('expiry is inclusive at expiresAt and leeway only widens acceptance', async () => {
  const store = new MemoryTokenStore();
  const { token } = await mintInto(store, { ttlMs: 1_000 });
  assert.equal((await verifyAccessToken(token, store, { now: NOW + 999 })).ok, true);
  assert.equal((await verifyAccessToken(token, store, { now: NOW + 1_000 })).reason, REJECTION.EXPIRED);
  assert.equal((await verifyAccessToken(token, store, { now: NOW + 1_050, leewayMs: 100 })).ok, true);
  assert.equal((await verifyAccessToken(token, store, { now: NOW + 1_101, leewayMs: 100 })).reason, REJECTION.EXPIRED);
});

test('not-before gates use until the start instant, with leeway for skew', async () => {
  const store = new MemoryTokenStore();
  const { token } = await mintInto(store, { notBefore: NOW + 1_000, ttlMs: 60_000 });
  assert.equal((await verifyAccessToken(token, store, { now: NOW })).reason, REJECTION.NOT_YET_VALID);
  assert.equal((await verifyAccessToken(token, store, { now: NOW + 950, leewayMs: 100 })).ok, true);
  assert.equal((await verifyAccessToken(token, store, { now: NOW + 1_000 })).ok, true);
});

test('revocation denies immediately and is idempotent', async () => {
  const store = new MemoryTokenStore();
  const { token, record } = await mintInto(store);
  assert.equal((await verifyAccessToken(token, store, { now: NOW })).ok, true);
  assert.equal(await revokeAccessToken(store, record.tokenId, NOW + 1), true);
  assert.equal((await verifyAccessToken(token, store, { now: NOW + 2 })).reason, REJECTION.REVOKED);
  assert.equal(await revokeAccessToken(store, record.tokenId, NOW + 3), true);
  assert.equal(await revokeAccessToken(store, 'no-such-id', NOW), false);
  const stored = await store.getByTokenId(record.tokenId);
  assert.equal(stored.revokedAt, NOW + 1);
});

test('grants are isolated across owners and clients', async () => {
  const store = new MemoryTokenStore();
  const a = await mintInto(store);
  const b = await mintInto(store, { ownerId: 'owner-b', clientId: 'automation-b' });
  assert.equal(store.size, 2);
  assert.notEqual(a.record.tokenId, b.record.tokenId);
  const va = await verifyAccessToken(a.token, store, { now: NOW });
  const vb = await verifyAccessToken(b.token, store, { now: NOW });
  assert.equal(va.grant.ownerId, 'owner-a');
  assert.equal(vb.grant.ownerId, 'owner-b');
});

test('a verified grant plugs straight into the foundation grant policy', async () => {
  const store = new MemoryTokenStore();
  const { token, record } = await mintInto(store);
  const { grant } = await verifyAccessToken(token, store, { now: NOW });
  const own = { ownerId: grant.ownerId, clientId: grant.clientId, serviceId: grant.serviceId };
  assert.equal(permitsCodeRead(grant, own, NOW), true);
  assert.equal(permitsCodeRead(grant, { ...own, serviceId: 'other.service' }, NOW), false);
  await revokeAccessToken(store, record.tokenId, NOW + 1);
  assert.equal((await verifyAccessToken(token, store, { now: NOW + 2 })).ok, false);
});

test('mint enforces the scope allowlist and ttl bounds', async () => {
  const store = new MemoryTokenStore();
  await assert.rejects(() => mintInto(store, { scopes: ['codes:write'] }), TypeError);
  await assert.rejects(() => mintInto(store, { scopes: [] }), TypeError);
  await assert.rejects(() => mintInto(store, { allowedScopes: [] }), TypeError);
  await assert.rejects(() => mintInto(store, { ttlMs: 0 }), TypeError);
  await assert.rejects(() => mintInto(store, { ttlMs: MAX_TTL_MS + 1 }), TypeError);
  await assert.rejects(() => mintInto(store, { ttlMs: 1.5 }), TypeError);
  await assert.rejects(() => mintInto(store, { ownerId: '' }), TypeError);
  const { record } = await mintInto(store, { scopes: ['codes:read', 'codes:read'] });
  assert.deepEqual(record.scopes, ['codes:read']);
});

test('invalid clock configuration is a programming error, not a rejection', async () => {
  const store = new MemoryTokenStore();
  const { token } = await mintInto(store);
  await assert.rejects(() => verifyAccessToken(token, store, { now: NaN }), TypeError);
  await assert.rejects(() => verifyAccessToken(token, store, { leewayMs: MAX_LEEWAY_MS + 1 }), TypeError);
  await assert.rejects(() => verifyAccessToken(token, store, { leewayMs: -1 }), TypeError);
});

test('grantHasScope checks the derived scope list', async () => {
  const store = new MemoryTokenStore();
  const { token } = await mintInto(store, { scopes: ['codes:read'] });
  const { grant } = await verifyAccessToken(token, store, { now: NOW });
  assert.equal(grantHasScope(grant, 'codes:read'), true);
  assert.equal(grantHasScope(grant, 'codes:list'), false);
  assert.equal(grantHasScope(null, 'codes:read'), false);
});
