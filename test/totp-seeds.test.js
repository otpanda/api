import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { SourceEntryStore } from '../src/source-entries.js';
import { EntryAccess } from '../src/entry-access.js';
import { CodeCipher } from '../src/code-cipher.js';
import { SeedCipher } from '../src/seed-cipher.js';
import { TotpSeedStore, EntryTotpGenerator } from '../src/totp-seeds.js';
import { totp, decodeBase32 } from '../src/totp.js';
import { base64urlEncode } from '../src/tokens.js';
import { parseTotpUri } from '../src/totp-uri.js';

const NOW = 1800000000000;
// RFC 6238 Appendix B secrets (ASCII).
const SHA1_SECRET = new TextEncoder().encode('12345678901234567890');
const SHA256_SECRET = new TextEncoder().encode('12345678901234567890123456789012');
const SHA512_SECRET = new TextEncoder().encode('1234567890123456789012345678901234567890123456789012345678901234');
const OTHER_SECRET = new TextEncoder().encode('abcdefghijklmnopqrst');
const seed = (over = {}) => ({ secret: SHA1_SECRET.slice(), algorithm: 'SHA-1', digits: 8, period: 30, ...over });

async function setup() {
  const db = database();
  for (const owner of ['a', 'b', 'c']) await db.prepare('INSERT INTO accounts VALUES (?,?)').bind(owner, NOW).run();
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const keys = new Map([['test', key]]);
  const codeCipher = new CodeCipher({ keys, activeKeyId: 'test' });
  const seedCipher = new SeedCipher({ keys, activeKeyId: 'test' });
  const store = new SourceEntryStore(db, codeCipher);
  const access = new EntryAccess(db, store);
  const seeds = new TotpSeedStore(db, seedCipher);
  const generator = new EntryTotpGenerator(db, seeds, access);
  const shared = await store.createEntry('a', 'google', 'Shared Google', NOW);
  const personal = await store.createEntry('a', 'google', 'Private Google', NOW);
  return { db, store, access, seeds, generator, codeCipher, seedCipher, shared, personal };
}

test('owner stores a seed and reads RFC 6238 codes for the entry', async () => {
  const { db, seeds, generator, shared } = await setup();
  assert.equal(await seeds.putSeed('a', shared, seed(), NOW), true);
  const first = await generator.generateForActor('a', shared, 59);
  assert.equal(first.code, '94287082');
  assert.deepEqual({ period: first.period, validFrom: first.validFrom, validUntil: first.validUntil }, { period: 30, validFrom: 30, validUntil: 60 });
  assert.equal(first.entryId, shared);
  assert.equal((await generator.generateForActor('a', shared, 1111111109)).code, '07081804');
  assert.equal(await seeds.putSeed('a', shared, seed({ secret: SHA256_SECRET.slice(), algorithm: 'SHA-256' }), NOW), true);
  assert.equal((await generator.generateForActor('a', shared, 59)).code, '46119246');
  assert.equal(await seeds.putSeed('a', shared, seed({ secret: SHA512_SECRET.slice(), algorithm: 'SHA-512' }), NOW), true);
  assert.equal((await generator.generateForActor('a', shared, 59)).code, '90693936');
  // Generated codes are computed on demand, never persisted as delivered codes.
  assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM incoming_codes').bind().first()).n, 0);
  assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM code_records').bind().first()).n, 0);
  db.sqlite.close();
});

test('seeds are encrypted at rest with a binding dedicated from delivered codes', async () => {
  const { db, seeds, seedCipher, codeCipher, shared, personal } = await setup();
  await seeds.putSeed('a', shared, seed(), NOW);
  const row = await db.prepare('SELECT envelope FROM totp_seeds WHERE entry_id = ?1').bind(shared).first();
  assert.ok(!row.envelope.includes(base64urlEncode(SHA1_SECRET)));
  assert.ok(!row.envelope.includes('MTIzNDU2Nzg5MDEyMzQ1Njc4OTA'));
  const envelope = JSON.parse(row.envelope);
  assert.deepEqual(Object.keys(envelope).sort(), ['bytes', 'ciphertext', 'iv', 'keyId', 'version']);
  // The same ciphertext is only readable under the seed purpose, owner and entry.
  assert.equal(JSON.parse(await seedCipher.decrypt(envelope, { ownerId: 'a', entryId: shared })).secret, base64urlEncode(SHA1_SECRET));
  await assert.rejects(seedCipher.decrypt(envelope, { ownerId: 'a', entryId: personal }));
  await assert.rejects(seedCipher.decrypt(envelope, { ownerId: 'b', entryId: shared }));
  await assert.rejects(codeCipher.decrypt(envelope, { ownerId: 'a', recordId: 'x', serviceId: shared, receivedAt: NOW, expiresAt: NOW + 1000 }));
  db.sqlite.close();
});

test('seed writes and removals are owner-only and entry-scoped', async () => {
  const { db, seeds, generator, shared, personal } = await setup();
  assert.equal(await seeds.putSeed('b', shared, seed(), NOW), false);
  assert.equal(await seeds.putSeed('a', 'missing-entry', seed(), NOW), false);
  assert.equal(await generator.generateForActor('a', shared, 59), undefined);
  await seeds.putSeed('a', shared, seed(), NOW);
  await seeds.putSeed('a', personal, seed({ secret: OTHER_SECRET.slice() }), NOW);
  assert.equal(await generator.generateForActor('a', shared, 59).then(r => r.code), '94287082');
  assert.equal(await generator.generateForActor('a', personal, 59).then(r => r.code), await totp(OTHER_SECRET, { unixSeconds: 59, period: 30, digits: 8, algorithm: 'SHA-1' }));
  assert.equal(await seeds.removeSeed('b', shared), false);
  assert.notEqual(await generator.generateForActor('a', shared, 59), undefined);
  assert.equal(await seeds.removeSeed('a', shared), true);
  assert.equal(await seeds.removeSeed('a', shared), false);
  assert.equal(await generator.generateForActor('a', shared, 59), undefined);
  db.sqlite.close();
});

test('generated codes follow sharing and automation permission and expose only codes', async () => {
  const { db, access, seeds, generator, shared } = await setup();
  await seeds.putSeed('a', shared, seed(), NOW);
  await access.share('a', shared, 'b', {}, NOW);
  const result = await generator.generateForActor('b', shared, 59);
  assert.equal(result.code, '94287082');
  assert.deepEqual(Object.keys(result).sort(), ['code', 'entryId', 'period', 'validFrom', 'validUntil']);
  assert.ok(!JSON.stringify(result).includes(base64urlEncode(SHA1_SECRET)));
  assert.equal(await generator.generateForActor('b', shared, 59, { automation: true }), undefined);
  assert.equal(await generator.generateForActor('c', shared, 59), undefined);
  await access.share('a', shared, 'b', { allowAutomation: true }, NOW);
  assert.equal((await generator.generateForActor('b', shared, 59, { automation: true })).code, '94287082');
  await access.share('a', shared, 'b', { allowAutomation: false }, NOW);
  assert.equal(await generator.generateForActor('b', shared, 59, { automation: true }), undefined);
  assert.notEqual(await generator.generateForActor('b', shared, 59), undefined);
  await access.revoke('a', shared, 'b', NOW);
  assert.equal(await generator.generateForActor('b', shared, 59), undefined);
  assert.equal(await generator.generateForActor('b', shared, 59, { automation: true }), undefined);
  assert.equal((await generator.generateForActor('a', shared, 59)).code, '94287082');
  db.sqlite.close();
});

test('permission revoked during generation is rechecked before returning a code', async () => {
  const { db, access, seeds, shared } = await setup();
  await seeds.putSeed('a', shared, seed(), NOW);
  await access.share('a', shared, 'b', {}, NOW);
  let first = true;
  const flipping = {
    canRead: async (...args) => {
      const allowed = await access.canRead(...args);
      if (first) { first = false; await access.revoke('a', shared, 'b', NOW); }
      return allowed;
    },
  };
  const generator = new EntryTotpGenerator(db, seeds, flipping);
  assert.equal(await generator.generateForActor('b', shared, 59), undefined);
  db.sqlite.close();
});

test('seed rotation during generation is rechecked before returning a code', async () => {
  const { db, access, seeds, shared } = await setup();
  await seeds.putSeed('a', shared, seed(), NOW);
  const inner = seeds.cipher;
  const rotating = {
    encrypt: inner.encrypt.bind(inner),
    decrypt: async (envelope, context) => {
      const plaintext = await inner.decrypt(envelope, context);
      await seeds.putSeed('a', shared, seed({ secret: OTHER_SECRET.slice() }), NOW + 1);
      return plaintext;
    },
  };
  const generator = new EntryTotpGenerator(db, new TotpSeedStore(db, rotating), access);
  assert.equal(await generator.generateForActor('a', shared, 59), undefined);
  db.sqlite.close();
});

test('rotating a seed replaces the single stored record', async () => {
  const { db, seeds, generator, shared } = await setup();
  await seeds.putSeed('a', shared, seed(), NOW);
  assert.equal(await seeds.putSeed('a', shared, seed({ secret: OTHER_SECRET.slice() }), NOW + 10), true);
  const row = await db.prepare('SELECT created_at, updated_at FROM totp_seeds WHERE entry_id = ?1').bind(shared).first();
  assert.equal(row.created_at, NOW);
  assert.equal(row.updated_at, NOW + 10);
  assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM totp_seeds').bind().first()).n, 1);
  assert.equal((await generator.generateForActor('a', shared, 59)).code, await totp(OTHER_SECRET, { unixSeconds: 59, period: 30, digits: 8, algorithm: 'SHA-1' }));
  db.sqlite.close();
});

test('tampered seed storage fails authenticated decryption', async () => {
  const { db, seeds, generator, shared, personal } = await setup();
  await seeds.putSeed('a', shared, seed(), NOW);
  db.sqlite.prepare('UPDATE totp_seeds SET entry_id = ? WHERE entry_id = ?').run(personal, shared);
  await assert.rejects(generator.generateForActor('a', personal, 59));
  db.sqlite.prepare('UPDATE totp_seeds SET entry_id = ? WHERE entry_id = ?').run(shared, personal);
  const row = await db.prepare('SELECT envelope FROM totp_seeds WHERE entry_id = ?1').bind(shared).first();
  const tampered = JSON.parse(row.envelope);
  tampered.ciphertext = (tampered.ciphertext[0] === 'A' ? 'B' : 'A') + tampered.ciphertext.slice(1);
  db.sqlite.prepare('UPDATE totp_seeds SET envelope = ? WHERE entry_id = ?').run(JSON.stringify(tampered), shared);
  await assert.rejects(generator.generateForActor('a', shared, 59));
  db.sqlite.close();
});

test('deleting an entry removes its seed', async () => {
  const { db, access, seeds, generator, shared } = await setup();
  await seeds.putSeed('a', shared, seed(), NOW);
  assert.equal(await access.deleteEntry('a', shared), true);
  assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM totp_seeds').bind().first()).n, 0);
  assert.equal(await generator.generateForActor('a', shared, 59), undefined);
  db.sqlite.close();
});

test('invalid seed parameters and read inputs are rejected', async () => {
  const { db, seeds, generator, shared } = await setup();
  await assert.rejects(seeds.putSeed('a', shared, seed({ secret: new Uint8Array(9) }), NOW), TypeError);
  await assert.rejects(seeds.putSeed('a', shared, seed({ secret: new Uint8Array(129) }), NOW), TypeError);
  await assert.rejects(seeds.putSeed('a', shared, seed({ algorithm: 'MD5' }), NOW), RangeError);
  await assert.rejects(seeds.putSeed('a', shared, seed({ digits: 9 }), NOW), RangeError);
  await assert.rejects(seeds.putSeed('a', shared, seed({ period: 0 }), NOW), RangeError);
  await assert.rejects(seeds.putSeed('a', shared, seed({ period: 86401 }), NOW), RangeError);
  await assert.rejects(seeds.putSeed('a', shared, seed(), -1), TypeError);
  await seeds.putSeed('a', shared, seed(), NOW);
  await assert.rejects(generator.generateForActor('a', shared, -1), RangeError);
  await assert.rejects(generator.generateForActor('a', shared, 59, { automation: 1 }), TypeError);
  assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM totp_seeds').bind().first()).n, 1);
  db.sqlite.close();
});

test('accepts a parsed provisioning URI without exposing the secret', async () => {
  const { db, seeds, generator, shared } = await setup();
  const provisioned = parseTotpUri('otpauth://totp/Issuer:alice?secret=JBSWY3DPEHPK3PXP&issuer=Issuer');
  assert.equal(await seeds.putSeed('a', shared, provisioned, NOW), true);
  const result = await generator.generateForActor('a', shared, 59);
  assert.equal(result.code, await totp(decodeBase32('JBSWY3DPEHPK3PXP'), { unixSeconds: 59, period: 30, digits: 6, algorithm: 'SHA-1' }));
  assert.ok(!JSON.stringify(result).includes('JBSWY3DPEHPK3PXP'));
  assert.ok(!JSON.stringify(result).includes(base64urlEncode(decodeBase32('JBSWY3DPEHPK3PXP'))));
  db.sqlite.close();
});

test('seed writes never mutate caller-owned raw secret bytes',async()=>{const {db,seeds,shared}=await setup();const supplied=seed(),before=supplied.secret.slice();assert.equal(await seeds.putSeed('a',shared,supplied,NOW),true);assert.deepEqual(supplied.secret,before);db.sqlite.close();});
test('decrypted malformed seed payloads have bounded generic failures',async()=>{const {db,access,seeds,shared}=await setup();await seeds.putSeed('a',shared,seed(),NOW);for(const payload of [null,[],{}, {secret:'x'.repeat(172),algorithm:'SHA-1',digits:6,period:30},{secret:base64urlEncode(SHA1_SECRET),algorithm:'SHA-1',digits:6,period:30,unexpected:'value'}]){const cipher={decrypt:async()=>JSON.stringify(payload)};const generator=new EntryTotpGenerator(db,new TotpSeedStore(db,cipher),access);await assert.rejects(generator.generateForActor('a',shared,59),{message:'Invalid seed record'});}db.sqlite.close();});
test('a generated validity window cannot exceed safe integer time',async()=>{const {db,seeds,generator,shared}=await setup();await seeds.putSeed('a',shared,seed(),NOW);await assert.rejects(generator.generateForActor('a',shared,Number.MAX_SAFE_INTEGER),RangeError);db.sqlite.close();});
test('seed removal and automation downgrade during decryption deny generated codes',async()=>{for(const action of ['remove','downgrade']){const {db,access,seeds,shared}=await setup();await seeds.putSeed('a',shared,seed(),NOW);await access.share('a',shared,'b',{allowAutomation:true},NOW);const inner=seeds.cipher,cipher={decrypt:async(e,c)=>{const plaintext=await inner.decrypt(e,c);if(action==='remove')await seeds.removeSeed('a',shared);else await access.share('a',shared,'b',{allowAutomation:false},NOW);return plaintext;}};const generator=new EntryTotpGenerator(db,new TotpSeedStore(db,cipher),access);assert.equal(await generator.generateForActor('b',shared,59,{automation:true}),undefined);db.sqlite.close();}});
