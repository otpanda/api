import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { database } from './sqlite-helper.js';
import { createHandler } from '../src/worker.js';
import { CodeCipher } from '../src/code-cipher.js';
import { D1TokenStore, D1CodeStore } from '../src/d1-store.js';
import { mintAccessToken, verifyAccessToken, revokeAccessToken } from '../src/verify.js';
const NOW = 1_800_000_000_000;
const options = { ownerId: 'a', clientId: 'extension', serviceId: 'example.com', scopes: ['codes:read'], allowedScopes: ['codes:read'], now: NOW };
async function setup(path) {
  const db = database(path);
  await db.prepare('INSERT OR IGNORE INTO accounts VALUES (?, ?)').bind('a', NOW).run();
  await db.prepare('INSERT OR IGNORE INTO accounts VALUES (?, ?)').bind('b', NOW).run();
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const cipher = new CodeCipher({ keys: new Map([['v1', key]]), activeKeyId: 'v1' });
  return { db, cipher, tokens: new D1TokenStore(db), codes: new D1CodeStore(db, cipher), key };
}
test('D1 token adapter survives reopening SQLite and stores only digests', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'otpanda-'));
  try {
    const path = join(directory, 'db.sqlite');
    const { db, tokens } = await setup(path);
    const minted = await mintAccessToken(tokens, options);
    assert.ok(!(await JSON.stringify(db.sqlite.prepare('SELECT * FROM access_tokens').all())).includes(minted.token));
    assert.equal((await verifyAccessToken(minted.token, tokens, { now: NOW })).ok, true);
    db.sqlite.close();
    const reopened = database(path);
    const durable = new D1TokenStore(reopened);
    assert.equal((await verifyAccessToken(minted.token, durable, { now: NOW })).ok, true);
    assert.equal(await durable.revokeForOwner('b', minted.record.tokenId, NOW), false);
    await revokeAccessToken(durable, minted.record.tokenId, NOW + 1);
    await durable.save(minted.record); // stale write must not undo revocation
    assert.equal((await verifyAccessToken(minted.token, durable, { now: NOW + 2 })).reason, 'revoked');
    assert.equal((await durable.listForOwner('b')).length, 0);
    assert.ok(!('tokenDigest' in (await durable.listForOwner('a'))[0]));
    await assert.rejects(durable.insert(minted.record));
    await assert.rejects(durable.save({ ...minted.record, ownerId: 'b' }));
    reopened.sqlite.close();
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
test('encrypted code storage isolates owner/service, bounds expiry and ignores replay', async () => {
  const { db, codes } = await setup();
  const record = { ownerId: 'a', recordId: 'sms-1', serviceId: 'example.com', code: '123456', receivedAt: NOW, expiresAt: NOW + 1000 };
  assert.equal(await codes.put(record), true);
  assert.equal(await codes.put({ ...record, code: '999999' }), false);
  assert.equal((await codes.latest('a', 'example.com', NOW)).code, '123456');
  assert.equal(await codes.latest('b', 'example.com', NOW), undefined);
  assert.equal(await codes.latest('a', 'wrong.com', NOW), undefined);
  assert.equal(await codes.latest('a', 'example.com', NOW - 1), undefined);
  assert.equal(await codes.latest('a', 'example.com', NOW + 1000), undefined);
  assert.ok(!JSON.stringify(db.sqlite.prepare('SELECT * FROM code_records').all()).includes('123456'));
  await assert.rejects(codes.put({ ...record, recordId: 'too-long', expiresAt: NOW + 86_400_001 }));
  await assert.rejects(codes.put({ ...record, ownerId: 'unknown' }));
  assert.equal(await codes.purgeExpired(NOW + 1000), 1);
  assert.equal(await codes.purgeExpired(NOW + 1000), 0);
  db.sqlite.close();
});
test('AES-GCM rejects ciphertext, tenant and metadata substitution; supports read-old/write-new keys', async () => {
  const { db, cipher, key } = await setup();
  const context = { ownerId: 'a', recordId: 'one', serviceId: 'example.com', receivedAt: NOW, expiresAt: NOW + 1000 };
  const envelope = await cipher.encrypt('123456', context);
  assert.notEqual((await cipher.encrypt('123456', context)).iv, envelope.iv);
  for (const field of ['ownerId', 'recordId', 'serviceId', 'receivedAt', 'expiresAt']) {
    const value = typeof context[field] === 'number' ? context[field] + 1 : 'other';
    await assert.rejects(cipher.decrypt(envelope, { ...context, [field]: value }));
  }
  await assert.rejects(cipher.decrypt({ ...envelope, ciphertext: (envelope.ciphertext[0] === 'A' ? 'B' : 'A') + envelope.ciphertext.slice(1) }, context));
  const newKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const rotated = new CodeCipher({ keys: new Map([['v1', key], ['v2', newKey]]), activeKeyId: 'v2' });
  assert.equal(await rotated.decrypt(envelope, context), '123456');
  assert.equal((await rotated.encrypt('654321', context)).keyId, 'v2');
  db.sqlite.close();
});
test('account deletion cascades tokens and code ciphertext', async () => {
  const { db, codes, tokens } = await setup();
  const minted = await mintAccessToken(tokens, options);
  await codes.put({ ownerId: 'a', recordId: 'one', serviceId: 'example.com', code: '123456', receivedAt: NOW, expiresAt: NOW + 1000 });
  await codes.deleteOwner('a');
  assert.equal(await tokens.getByTokenId(minted.record.tokenId), undefined);
  assert.equal(await codes.latest('a', 'example.com', NOW), undefined);
  db.sqlite.close();
});

test('authenticated HTTP retrieval uses only the verified owner and service', async () => {
  const { db, codes, tokens } = await setup();
  const minted = await mintAccessToken(tokens, options);
  await codes.put({ ownerId: 'a', recordId: 'one', serviceId: 'example.com', code: '123456', receivedAt: NOW, expiresAt: NOW + 1000 });
  await codes.put({ ownerId: 'b', recordId: 'two', serviceId: 'example.com', code: '999999', receivedAt: NOW + 1, expiresAt: NOW + 1000 });
  const app = createHandler({ tokenStore: tokens, codeStore: codes, clock: () => NOW + 2 });
  const fetch = path => app.fetch(new Request('https://test.invalid' + path, { headers: { authorization: 'Bearer ' + minted.token } }));
  const response = await fetch('/v1/codes/latest?service=example.com&ownerId=b');
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal((await response.json()).code, '123456');
  assert.equal((await fetch('/v1/codes/latest?service=other.com')).status, 403);
  await tokens.revokeForOwner('a', minted.record.tokenId, NOW + 2);
  assert.equal((await fetch('/v1/codes/latest?service=example.com')).status, 401);
  db.sqlite.close();
});
