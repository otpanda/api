import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { MachineAccess, MachineReader, createMachineHandler } from '../src/machine-access.js';
import { EntryAccess } from '../src/entry-access.js';
const NOW = 1800000000000;
let V;
const cipher = { async decrypt(env) { return env.code; } };
async function setup(hook) {
  const db = database();
  V = {};
  for (const a of ['own', 'own2', 'rec', 'x']) {
    await db.prepare('INSERT INTO accounts VALUES (?,?)').bind(a, NOW).run();
    await db.prepare('INSERT INTO account_security (owner_id,generation) VALUES (?,0)').bind(a).run();
    await db.prepare("INSERT INTO passkey_credentials (credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) VALUES (?,?,x'00',0,'[]','singleDevice',0,?)").bind('cred-' + a, a, NOW).run();
    await db.prepare("INSERT INTO device_sessions (device_id,owner_id,credential_id,generation,client_kind,created_at,last_used_at,expires_at) VALUES (?,?,?,0,'web',?,?,?)").bind('dev-' + a, a, 'cred-' + a, NOW - 1000, NOW - 1000, NOW + 1e7).run();
    V[a] = { ownerId: a, deviceId: 'dev-' + a, generation: 0, kind: 'web' };
  }
  const entry = (e, o) => db.prepare('INSERT INTO entries (entry_id,owner_id,service_id,label,created_at) VALUES (?,?,?,?,?)').bind(e, o, 'g', e, NOW).run();
  for (const e of ['e1', 'e2', 'e3']) await entry(e, 'own');
  await entry('o2a', 'own2'); await entry('r1', 'rec');
  for (const [s, k, o] of [['gm1', 'gmail', 'own'], ['gm2', 'outlook', 'own'], ['sm', 'sms', 'own'], ['sm2', 'sms', 'own2']]) await db.prepare('INSERT INTO sources (source_id,owner_id,kind,label,created_at) VALUES (?,?,?,?,?)').bind(s, o, k, s, NOW).run();
  let n = 0;
  const put = (source, entryId, owner, code, at) => db.prepare("INSERT INTO incoming_codes (owner_id,event_id,source_id,entry_id,envelope,received_at,expires_at,assignment) VALUES (?,?,?,?,?,?,?,'confirmed')").bind(owner, 'ev' + (n++), source, entryId, JSON.stringify({ code }), at, NOW + 60000).run();
  await put('gm1', 'e1', 'own', 'EMAIL-OLD', NOW - 2000); await put('gm2', 'e1', 'own', 'EMAIL-NEW', NOW - 1000); await put('sm', 'e1', 'own', 'SMS1', NOW - 500);
  await put('sm', 'e2', 'own', 'SMS2', NOW - 500); await put('sm2', 'o2a', 'own2', 'SMS-O2', NOW - 500); await put('sm', 'e3', 'own', 'SMS3', NOW - 500);
  const access = new MachineAccess(db);
  const c = hook ? { async decrypt(env) { await hook(access, db); return env.code; } } : cipher;
  const reader = new MachineReader({ access, sources: { cipher: c }, seeds: { cipher: { async decrypt() { throw new Error('no seed'); } } }, clock: () => NOW });
  return { db, access, reader };
}
const read = async (a, r, p, e, k, issuedAt = NOW) => r.read(p, issuedAt, e, k, NOW);

test('own profile: all/allow/deny, one entry, newest code per kind; deny and all cover later entries', async () => {
  const { db, access, reader } = await setup();
  const all = await access.createProfile(V.own, { name: 'ci', mode: 'all' }, NOW);
  const r = await read(access, reader, all, 'e1', 'all');
  assert.equal(r.codes.email.code, 'EMAIL-NEW'); assert.equal(Object.keys(r.codes).sort().join(), 'email,sms');
  assert.equal(Object.keys((await read(access, reader, all, 'e1', 'sms')).codes).join(), 'sms');
  assert.equal(await read(access, reader, all, 'r1', 'all'), undefined);
  assert.equal(await read(access, reader, all, 'e1', 'totp'), undefined);
  const allow = await access.createProfile(V.own, { name: 'a', mode: 'allow', entryIds: ['e1'] }, NOW);
  const deny = await access.createProfile(V.own, { name: 'd', mode: 'deny', entryIds: ['e1'] }, NOW);
  assert.ok(await read(access, reader, allow, 'e1', 'sms')); assert.equal(await read(access, reader, allow, 'e2', 'sms'), undefined);
  assert.equal(await read(access, reader, deny, 'e1', 'sms'), undefined); assert.ok(await read(access, reader, deny, 'e2', 'sms'));
  await db.prepare("INSERT INTO entries (entry_id,owner_id,service_id,label,created_at) VALUES ('e9','own','g','e9',?)").bind(NOW).run();
  assert.ok(await access.canMachineRead(deny, 'e9', NOW)); assert.ok(await access.canMachineRead(all, 'e9', NOW)); assert.equal(await access.canMachineRead(allow, 'e9', NOW), undefined);
  for (const bad of [{ mode: 'allow', entryIds: [] }, { mode: 'all', entryIds: ['e1'] }, { mode: 'x' }, { mode: 'allow', entryIds: ['r1'] }, { mode: 'allow', entryIds: 'e1' }]) await assert.rejects(access.createProfile(V.own, { name: 'x', ...bad }, NOW), TypeError);
  db.sqlite.close();
});
test('multi-parent: own + two owners, overlap, per-path revoke, delegation off, narrowing', async () => {
  const { db, access, reader } = await setup();
  const legacy = new EntryAccess(db, {});
  await access.grant(V.own, 'rec', { mode: 'deny', entryIds: ['e3'], canDelegate: true }, NOW);
  await access.grant(V.own2, 'rec', { mode: 'all', canDelegate: false }, NOW);
  const p = await access.createProfile(V.rec, { name: 'm', mode: 'all' }, NOW);
  assert.ok(await read(access, reader, p, 'e1', 'sms'), 'delegated from own');
  assert.equal(await read(access, reader, p, 'e3', 'sms'), undefined, 'excluded by owner deny');
  assert.equal(await read(access, reader, p, 'o2a', 'sms'), undefined, 'own2 has not allowed delegation');
  assert.ok(await access.canHumanRead('rec', 'o2a'), 'but the human can read it');
  await access.grant(V.own2, 'rec', { mode: 'allow', entryIds: ['o2a'], canDelegate: true }, NOW + 5);
  const t2 = NOW + 5; // token minted after the restart of delegation for own2
  assert.equal(await access.canMachineRead(p, 'o2a', NOW), undefined, 'older token does not gain access');
  assert.ok(await access.canMachineRead(p, 'o2a', t2), 'new token gets it');
  // overlap on e1: grant path plus legacy per-entry share; revoking one keeps the other
  await legacy.share('own', 'e1', 'rec', { allowAutomation: true }, NOW);
  await access.revokeGrant(V.own, 'rec', NOW + 6);
  assert.ok(await access.canMachineRead(p, 'e1', NOW), 'legacy path still carries e1');
  assert.equal(await access.canMachineRead(p, 'e2', NOW + 10), undefined, 'grant-only entry gone with the grant');
  await legacy.revoke('own', 'e1', 'rec', NOW + 7);
  assert.equal(await access.canMachineRead(p, 'e1', NOW + 10), undefined);
  // own entries of the creator are always reachable through the same profile
  assert.ok(await access.canMachineRead(p, 'r1', NOW));
  db.sqlite.close();
});
test('legacy entry_shares adapt to the canonical policy', async () => {
  const { db, access } = await setup();
  const legacy = new EntryAccess(db, {});
  assert.equal(await legacy.canRead('rec', 'e1'), false);
  await access.grant(V.own, 'rec', { mode: 'deny', entryIds: ['e3'], canDelegate: false }, NOW);
  assert.equal(await legacy.canRead('rec', 'e1'), true); assert.equal(await legacy.canRead('rec', 'e3'), false);
  assert.equal(await legacy.canRead('rec', 'e1', { automation: true }), false, 'no delegation, no automation');
  await legacy.share('own', 'e1', 'rec', { allowAutomation: true }, NOW);
  assert.equal(await legacy.canRead('rec', 'e1', { automation: true }), true);
  await legacy.revoke('own', 'e1', 'rec', NOW);
  assert.equal(await legacy.canRead('rec', 'e1'), true, 'grant path survives legacy revoke');
  await access.revokeGrant(V.own, 'rec', NOW);
  assert.equal(await legacy.canRead('rec', 'e1'), false);
  // later entries follow a deny grant
  await access.grant(V.own, 'rec', { mode: 'deny', entryIds: ['e3'] }, NOW);
  await db.prepare("INSERT INTO entries (entry_id,owner_id,service_id,label,created_at) VALUES ('e9','own','g','e9',?)").bind(NOW).run();
  assert.equal(await legacy.canRead('rec', 'e9'), true);
  db.sqlite.close();
});
test('revocation never revives old tokens; narrowing is immediate; strict recipient rules', async () => {
  const { db, access, reader } = await setup();
  await access.grant(V.own, 'rec', { mode: 'all', canDelegate: true }, NOW);
  const p = await access.createProfile(V.rec, { name: 'm', mode: 'all' }, NOW);
  const t = await access.mintToken(V.rec, p, 100000, NOW);
  assert.ok(await read(access, reader, p, 'e1', 'sms'));
  await access.grant(V.own, 'rec', { mode: 'allow', entryIds: ['e2'], canDelegate: true }, NOW + 1);
  assert.equal(await read(access, reader, p, 'e1', 'sms'), undefined, 'narrowed');
  assert.ok(await read(access, reader, p, 'e2', 'sms'));
  await access.revokeGrant(V.own, 'rec', NOW + 2);
  assert.equal(await read(access, reader, p, 'e2', 'sms'), undefined);
  await access.grant(V.own, 'rec', { mode: 'all', canDelegate: true }, NOW + 3);
  assert.equal(await read(access, reader, p, 'e2', 'sms', t ? NOW : 0), undefined, 'old token stays dead after regrant');
  assert.ok(await read(access, reader, p, 'e2', 'sms', NOW + 4), 'fresh token works');
  await assert.rejects(access.grant(V.own, 'own', { mode: 'all' }, NOW), TypeError);
  await assert.rejects(access.grant(V.own, 'rec', { mode: 'allow', entryIds: ['r1'] }, NOW), TypeError);
  db.sqlite.close();
});
test('revoke/narrow/delegation-off during decryption releases nothing', async () => {
  const actions = [
    (a, d, p) => a.revokeProfile(V.own, p, NOW),
    (a, d, p) => d.prepare("UPDATE machine_profiles SET mode='allow' WHERE profile_id=?").bind(p).run(),
    (a, d) => d.prepare('UPDATE sources SET revoked_at=? WHERE source_id=?').bind(NOW, 'sm').run(),
    a => a.revokeGrant(V.own, 'rec', NOW + 1),
    a => a.grant(V.own, 'rec', { mode: 'allow', entryIds: ['e2'], canDelegate: true }, NOW + 1),
    a => a.grant(V.own, 'rec', { mode: 'all', canDelegate: false }, NOW + 1),
  ];
  for (const [i, action] of actions.entries()) {
    const { db, access } = await setup();
    let profile;
    const reader = new MachineReader({ access, sources: { cipher: { async decrypt(e) { await action(access, db, profile); return e.code; } } }, seeds: {}, clock: () => NOW });
    await access.grant(V.own, 'rec', { mode: 'all', canDelegate: true }, NOW);
    profile = await access.createProfile(i < 3 ? V.own : V.rec, { name: 'm', mode: 'all' }, NOW);
    assert.equal(await reader.read(profile, NOW, 'e1', 'sms', NOW), undefined, 'action ' + i);
    db.sqlite.close();
  }
});
test('expiry is re-checked after decryption', async () => {
  const { db, access } = await setup();
  const p = await access.createProfile(V.own, { name: 'ci', mode: 'all' }, NOW);
  let t = NOW; const reader = new MachineReader({ access, sources: { cipher: { async decrypt(e) { t = NOW + 70000; return e.code; } } }, seeds: {}, clock: () => t });
  assert.equal(await reader.read(p, NOW, 'e1', 'sms', NOW), undefined);
  db.sqlite.close();
});
test('HTTP: strict params, uniform failures, malformed tokens, no store', async () => {
  const { db, access, reader } = await setup();
  const p = await access.createProfile(V.own, { name: 'ci', mode: 'allow', entryIds: ['e1'] }, NOW);
  const t = await access.mintToken(V.own, p, 1000, NOW);
  const h = createMachineHandler({ access, reader, clock: () => NOW });
  const call = (q, token = t.token, path = '/v1/machine/code') => h.fetch(new Request('https://t.invalid' + path + '?' + q, { headers: { authorization: 'Bearer ' + token } }));
  const ok = await call('entry=e1&source=all');
  assert.equal(ok.status, 200); assert.equal(ok.headers.get('cache-control'), 'no-store');
  const body = await ok.json(); assert.equal(body.codes.email.code, 'EMAIL-NEW'); assert.equal(body.codes.sms.code, 'SMS1');
  assert.equal(JSON.stringify(body).includes('EMAIL-OLD'), false);
  for (const q of ['entry=e1', 'source=sms', 'entry=e1&entry=e2&source=sms', 'entry=e1&source=sms&source=totp', 'entry=e1&source=bulk', 'entry=e1&source=sms&x=1', 'source=sms&entry=', 'entry=e1&source=ALL', 'entry=e1&source=__proto__']) assert.equal((await call(q)).status, 400, q);
  const a = await call('entry=e2&source=sms'), b = await call('entry=nope&source=sms');
  assert.equal(a.status, 404); assert.equal(await a.text(), await b.text());
  for (const bad of ['otpda_bad', '', 'x'.repeat(5000), t.token + 'A', t.token.slice(0, -1)]) assert.equal((await call('entry=e1&source=sms', bad)).status, 401);
  assert.equal((await call('entry=e1&source=sms', t.token, '/v1/machine/codes')).status, 404);
  assert.equal((await h.fetch(new Request('https://t.invalid/v1/machine/code?entry=e1&source=sms', { method: 'POST', headers: { authorization: 'Bearer ' + t.token } }))).status, 404);
  db.sqlite.close();
});

import { CodeCipher } from '../src/code-cipher.js';
import { SeedCipher } from '../src/seed-cipher.js';
import { SourceEntryStore } from '../src/source-entries.js';
import { TotpSeedStore } from '../src/totp-seeds.js';
import { totp } from '../src/totp.js';
const count = (db, t) => db.sqlite.prepare('SELECT count(*) AS n FROM ' + t).get().n;
const SECRET = new TextEncoder().encode('12345678901234567890');

test('management writes are conditioned on a live session and owner scope in SQL', async () => {
  const { db, access } = await setup();
  const bad = [
    { ...V.own, deviceId: 'dev-rec' }, { ...V.own, generation: 1 }, { ...V.own, kind: 'android' }, { ...V.own, ownerId: 'rec' }, { ...V.own, deviceId: 'nope' },
  ];
  const before = () => [count(db, 'access_grants'), count(db, 'machine_profiles'), count(db, 'machine_tokens')].join();
  const base = before();
  for (const v of bad) {
    assert.equal(await access.grant(v, 'x', { mode: 'all', canDelegate: true }, NOW), false);
    assert.equal(await access.createProfile(v, { name: 'm', mode: 'all' }, NOW), undefined);
    assert.equal(before(), base);
  }
  db.sqlite.close();
});
test('each session-guard failure mode independently blocks every management write', async () => {
  const mutations = [
    "UPDATE device_sessions SET revoked_at=1 WHERE device_id='dev-own'",
    "UPDATE device_sessions SET expires_at=1 WHERE device_id='dev-own'",
    "UPDATE passkey_credentials SET revoked_at=1 WHERE credential_id='cred-own'",
    "UPDATE account_security SET generation=1 WHERE owner_id='own'",
  ];
  for (const m of mutations) {
    const { db, access } = await setup();
    const good = await access.createProfile(V.own, { name: 'ok', mode: 'all' }, NOW);
    db.sqlite.exec(m);
    assert.equal(await access.grant(V.own, 'rec', { mode: 'all' }, NOW), false, m);
    assert.equal(await access.createProfile(V.own, { name: 'm', mode: 'all' }, NOW), undefined, m);
    assert.equal(await access.mintToken(V.own, good, 1000, NOW), undefined, m);
    assert.equal(await access.revokeProfile(V.own, good, NOW), false, m);
    assert.equal(count(db, 'access_grants'), 0, m); assert.equal(count(db, 'machine_tokens'), 0, m);
    assert.equal(db.sqlite.prepare('SELECT revoked_at FROM machine_profiles WHERE profile_id=?').get(good).revoked_at, null, m);
    db.sqlite.close();
  }
});
test('foreign or unreachable entry ids are refused without disturbing existing grants', async () => {
  const { db, access } = await setup();
  await access.grant(V.own, 'rec', { mode: 'all', canDelegate: true }, NOW);
  await assert.rejects(access.grant(V.own, 'rec', { mode: 'deny', entryIds: ['r1'] }, NOW), TypeError);
  assert.equal(db.sqlite.prepare('SELECT mode,revoked_at FROM access_grants').get().mode, 'all');
  await assert.rejects(access.createProfile(V.rec, { name: 'm', mode: 'allow', entryIds: ['o2a'] }, NOW), TypeError);
  assert.equal(count(db, 'machine_profiles'), 0, 'rolled back entirely');
  const strangers = await access.createProfile(V.x, { name: 'm', mode: 'all' }, NOW);
  assert.equal(await access.canMachineRead(strangers, 'e1', NOW), undefined);
  assert.equal(await access.mintToken(V.x, (await access.createProfile(V.own, { name: 'o', mode: 'all' }, NOW)), 1000, NOW), undefined, 'only the creator mints');
  db.sqlite.close();
});
test('real seed: machine TOTP for own and delegated entries, gated live around decryption', async () => {
  const { db, access } = await setup();
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const keys = new Map([['t', key]]);
  const seeds = new TotpSeedStore(db, new SeedCipher({ keys, activeKeyId: 't' }));
  await seeds.putSeed('own', 'e1', { secret: SECRET.slice(), algorithm: 'SHA-1', digits: 6, period: 30 }, NOW);
  const expected = await totp(SECRET, { unixSeconds: Math.floor(NOW / 1000), period: 30, digits: 6, algorithm: 'SHA-1' });
  const reader = (hook, clock = () => NOW) => new MachineReader({ access, sources: { cipher }, seeds: { cipher: { async decrypt(...a) { await hook?.(); return seeds.cipher.decrypt(...a); } } }, clock });
  const own = await access.createProfile(V.own, { name: 'o', mode: 'all' }, NOW);
  const r = await reader().read(own, NOW, 'e1', 'totp', NOW);
  assert.equal(r.codes.totp.code, expected); assert.ok(!JSON.stringify(r).includes('secret'));
  assert.equal(await reader().read(own, NOW, 'e2', 'totp', NOW), undefined, 'no seed');
  await access.grant(V.own, 'rec', { mode: 'allow', entryIds: ['e1'], canDelegate: true }, NOW);
  const rec = await access.createProfile(V.rec, { name: 'r', mode: 'all' }, NOW);
  assert.equal((await reader().read(rec, NOW, 'e1', 'totp', NOW)).codes.totp.code, expected);
  assert.equal(await reader().read(rec, NOW, 'e1', 'all', NOW + 100) === undefined, false);
  for (const hook of [() => access.grant(V.own, 'rec', { mode: 'allow', entryIds: ['e2'], canDelegate: true }, NOW + 1), () => access.revokeGrant(V.own, 'rec', NOW + 1), () => seeds.removeSeed('own', 'e1')]) {
    await db.prepare("UPDATE access_grants SET revoked_at=NULL,mode='allow',can_delegate=1 WHERE owner_id='own'").run();
    await db.prepare('DELETE FROM access_grant_entries').run(); await db.prepare("INSERT INTO access_grant_entries SELECT grant_id,'e1' FROM access_grants").run();
    await seeds.putSeed('own', 'e1', { secret: SECRET.slice(), algorithm: 'SHA-1', digits: 6, period: 30 }, NOW);
    assert.equal(await reader(hook).read(rec, NOW, 'e1', 'totp', NOW), undefined);
  }
  // period boundary: code is not released once the clock passes its window after decryption
  await seeds.putSeed('own', 'e1', { secret: SECRET.slice(), algorithm: 'SHA-1', digits: 6, period: 30 }, NOW);
  let t = NOW; const late = reader(() => { t = NOW + 31000; }, () => t);
  assert.equal(await late.read(own, NOW, 'e1', 'totp', NOW), undefined);
  db.sqlite.close();
});
test('per-profile rate limit returns 429 with Retry-After and does not affect other profiles', async () => {
  const { db, access, reader } = await setup();
  const a = await access.createProfile(V.own, { name: 'a', mode: 'all' }, NOW), b = await access.createProfile(V.own, { name: 'b', mode: 'all' }, NOW);
  const ta = await access.mintToken(V.own, a, 100000, NOW), tb = await access.mintToken(V.own, b, 100000, NOW);
  const h = createMachineHandler({ access, reader, clock: () => NOW, limit: 2 });
  const call = t => h.fetch(new Request('https://t.invalid/v1/machine/code?entry=e1&source=sms', { headers: { authorization: 'Bearer ' + t.token } }));
  assert.equal((await call(ta)).status, 200); assert.equal((await call(ta)).status, 200);
  const limited = await call(ta); assert.equal(limited.status, 429); assert.ok(Number(limited.headers.get('retry-after')) >= 1);
  assert.equal((await call(tb)).status, 200);
  db.sqlite.close();
});
test('grant changes notify grantee and owner, bump assignment revisions, and new entries reach grantees', async () => {
  const { db, access } = await setup();
  const outbox = () => db.sqlite.prepare("SELECT account_id FROM realtime_outbox WHERE kind='account' AND claimed_at IS NULL ORDER BY account_id").all().map(r => r.account_id).join();
  const rev = () => db.sqlite.prepare("SELECT sum(mutation_revision) AS n FROM entries WHERE owner_id='own'").get().n;
  db.sqlite.exec('DELETE FROM realtime_outbox');
  const r0 = rev();
  await access.grant(V.own, 'rec', { mode: 'deny', entryIds: ['e3'], canDelegate: true }, NOW);
  assert.ok(outbox().includes('rec') && outbox().includes('own'));
  assert.ok(rev() > r0, 'assignment revision bumped on grant');
  db.sqlite.exec('DELETE FROM realtime_outbox'); const r1 = rev();
  await access.grant(V.own, 'rec', { mode: 'deny', entryIds: ['e2'], canDelegate: true }, NOW + 1);
  assert.ok(rev() > r1, 'narrowing/entry list change bumps');
  db.sqlite.exec('DELETE FROM realtime_outbox');
  await db.prepare("INSERT INTO entries (entry_id,owner_id,service_id,label,created_at) VALUES ('e8','own','g','e8',?)").bind(NOW).run();
  assert.ok(outbox().includes('rec'), 'new entry under a deny grant notifies the grantee');
  await access.grant(V.own, 'rec', { mode: 'allow', entryIds: ['e1'] }, NOW + 2);
  db.sqlite.exec('DELETE FROM realtime_outbox');
  await db.prepare("INSERT INTO entries (entry_id,owner_id,service_id,label,created_at) VALUES ('e7','own','g','e7',?)").bind(NOW).run();
  assert.ok(!outbox().includes('rec'), 'allow-list grantee is not told about unrelated entries');
  db.sqlite.exec('DELETE FROM realtime_outbox');
  await access.revokeGrant(V.own, 'rec', NOW + 3);
  assert.ok(outbox().includes('rec'), 'revocation notifies the former grantee');
  db.sqlite.close();
});

test('invitation links: single use, bounded, session-guarded, revocable, terms fixed by owner', async () => {
  const { db, access } = await setup();
  const inv = await access.createInvite(V.own, { mode: 'deny', entryIds: ['e3'], canDelegate: true }, 3600000, NOW);
  assert.ok(inv.token.startsWith('otpda_')); assert.equal(count(db, 'access_grants'), 0, 'nothing granted by creating');
  assert.ok(!JSON.stringify(db.sqlite.prepare('SELECT * FROM access_invites').all()).includes(inv.token));
  assert.equal(await access.acceptInvite(V.own, inv.token, NOW), undefined, 'owner cannot accept own invite');
  assert.equal(await access.acceptInvite({ ...V.rec, generation: 5 }, inv.token, NOW), undefined, 'dead session');
  assert.equal(await access.acceptInvite(V.rec, inv.token.slice(0, -1) + (inv.token.endsWith('A') ? 'E' : 'A'), NOW), undefined, 'tampered token');
  assert.equal(await access.acceptInvite(V.rec, inv.token, NOW + 3600000), undefined, 'expired');
  assert.equal(count(db, 'access_grants'), 0);
  const ok = await access.acceptInvite(V.rec, inv.token, NOW + 1);
  assert.deepEqual(ok, { ownerId: 'own', mode: 'deny', canDelegate: true });
  assert.ok(await access.canHumanRead('rec', 'e1')); assert.equal(await access.canHumanRead('rec', 'e3'), false);
  assert.equal(await access.acceptInvite(V.x, inv.token, NOW + 2), undefined, 'single use');
  assert.equal(await access.acceptInvite(V.rec, inv.token, NOW + 2), undefined);
  // revoked before acceptance; foreign entry; bad ttl; cap of 20 open invites
  const inv2 = await access.createInvite(V.own, { mode: 'all' }, 3600000, NOW);
  assert.equal(await access.revokeInvite(V.rec, inv2.inviteId, NOW), false, 'only owner revokes');
  assert.equal(await access.revokeInvite(V.own, inv2.inviteId, NOW), true);
  assert.equal(await access.acceptInvite(V.x, inv2.token, NOW + 1), undefined);
  await assert.rejects(access.createInvite(V.own, { mode: 'allow', entryIds: ['r1'] }, 3600000, NOW), TypeError);
  await assert.rejects(access.createInvite(V.own, { mode: 'all' }, 10 * 86400000, NOW), TypeError);
  await assert.rejects(access.createInvite(V.own, { mode: 'all' }, 1000, NOW), TypeError);
  assert.equal(await access.createInvite({ ...V.own, deviceId: 'nope' }, { mode: 'all' }, 3600000, NOW), undefined);
  // regrant via invite after revocation moves granted_at (old machine tokens stay dead)
  await access.revokeGrant(V.own, 'rec', NOW + 3);
  const inv3 = await access.createInvite(V.own, { mode: 'all', canDelegate: true }, 3600000, NOW + 4);
  assert.ok(await access.acceptInvite(V.rec, inv3.token, NOW + 5));
  assert.equal(db.sqlite.prepare("SELECT granted_at FROM access_grants WHERE grantee_id='rec'").get().granted_at, NOW + 5);
  for (let i = 0; i < 20; i++) if (!await access.createInvite(V.own, { mode: 'all' }, 3600000, NOW)) break;
  assert.equal(await access.createInvite(V.own, { mode: 'all' }, 3600000, NOW), undefined, 'cap reached');
  db.sqlite.close();
});

// Race harness: a db wrapper that runs `before` immediately before the next batch commits, i.e. after the
// method's own reads but before its transaction, which is where a concurrent writer can land.
function racing(db, before) {
  let armed = true;
  return { prepare: s => db.prepare(s), async batch(st) { if (armed) { armed = false; await before(); } return db.batch(st); } };
}
const snapshot = db => JSON.stringify(['access_grants', 'access_grant_entries', 'machine_profiles', 'machine_profile_entries', 'access_invites', 'access_invite_entries', 'realtime_outbox'].map(t => db.sqlite.prepare('SELECT * FROM ' + t + (t === 'realtime_outbox' ? " WHERE kind<>'device'" : '') + ' ORDER BY 1,2').all())) + db.sqlite.prepare("SELECT sum(mutation_revision) AS n FROM entries").get().n;

test('atomic all-or-nothing: concurrent entry removal or session loss leaves an existing grant exactly as it was', async () => {
  const { db, access } = await setup();
  await access.grant(V.own, 'rec', { mode: 'all', canDelegate: true }, NOW);
  const deletes = new MachineAccess(racing(db, async () => { await db.prepare("DELETE FROM entries WHERE entry_id='e1'").run(); }));
  await assert.rejects(deletes.grant(V.own, 'rec', { mode: 'deny', entryIds: ['e1', 'e2'] }, NOW + 1), TypeError);
  // e1 is gone (the concurrent writer's own change); everything the grant call did is rolled back
  const row = db.sqlite.prepare('SELECT mode,can_delegate,revoked_at,granted_at FROM access_grants').get();
  assert.deepEqual({ ...row }, { mode: 'all', can_delegate: 1, revoked_at: null, granted_at: NOW });
  assert.equal(count(db, 'access_grant_entries'), 0);
  // session revoked at commit time: nothing changes, caller told false
  const { db: db2, access: a2 } = await setup();
  await a2.grant(V.own, 'rec', { mode: 'allow', entryIds: ['e1'] }, NOW);
  const snap = snapshot(db2);
  const lost = new MachineAccess(racing(db2, async () => { await db2.prepare("UPDATE device_sessions SET revoked_at=1 WHERE device_id='dev-own'").run(); }));
  assert.equal(await lost.grant(V.own, 'rec', { mode: 'all' }, NOW + 1), false);
  const x = JSON.parse(snap.slice(0, -1).replace(/\d+$/, '')), y = JSON.parse(snapshot(db2).slice(0, -1).replace(/\d+$/, ''));
  assert.deepEqual(y, x);
  db.sqlite.close(); db2.sqlite.close();
});
test('atomic: profile and invite creation roll back whole on concurrent entry removal or session loss', async () => {
  const { db, access } = await setup();
  const gone = new MachineAccess(racing(db, async () => { await db.prepare("DELETE FROM entries WHERE entry_id='e2'").run(); }));
  await assert.rejects(gone.createProfile(V.own, { name: 'm', mode: 'allow', entryIds: ['e1', 'e2'] }, NOW), TypeError);
  assert.equal(count(db, 'machine_profiles'), 0); assert.equal(count(db, 'machine_profile_entries'), 0);
  const gone2 = new MachineAccess(racing(db, async () => { await db.prepare("DELETE FROM entries WHERE entry_id='e3'").run(); }));
  await assert.rejects(gone2.createInvite(V.own, { mode: 'deny', entryIds: ['e1', 'e3'] }, 3600000, NOW), TypeError);
  assert.equal(count(db, 'access_invites'), 0); assert.equal(count(db, 'access_invite_entries'), 0);
  const lost = new MachineAccess(racing(db, async () => { await db.prepare("UPDATE device_sessions SET revoked_at=1 WHERE device_id='dev-own'").run(); }));
  assert.equal(await lost.createProfile(V.own, { name: 'm', mode: 'all' }, NOW), undefined);
  assert.equal(await lost.createInvite(V.own, { mode: 'all' }, 3600000, NOW), undefined);
  assert.equal(count(db, 'machine_profiles'), 0); assert.equal(count(db, 'access_invites'), 0);
  db.sqlite.close();
});
test('atomic accept: concurrent revoke, double accept, session loss and entry removal', async () => {
  const { db, access } = await setup();
  const mk = async () => access.createInvite(V.own, { mode: 'allow', entryIds: ['e1', 'e2'], canDelegate: true }, 3600000, NOW);
  // owner revokes between the recipient's read and its commit: nothing granted, invite stays revoked
  let inv = await mk();
  const r1 = new MachineAccess(racing(db, async () => { await db.prepare('UPDATE access_invites SET revoked_at=1 WHERE invite_id=?').bind(inv.inviteId).run(); }));
  assert.equal(await r1.acceptInvite(V.rec, inv.token, NOW + 1), undefined);
  assert.equal(count(db, 'access_grants'), 0);
  // two recipients race: the one that commits first wins, the other gets nothing and no partial grant
  inv = await mk();
  const r2 = new MachineAccess(racing(db, async () => { assert.ok(await access.acceptInvite(V.x, inv.token, NOW + 1)); }));
  assert.equal(await r2.acceptInvite(V.rec, inv.token, NOW + 1), undefined);
  assert.deepEqual(db.sqlite.prepare('SELECT grantee_id FROM access_grants').all().map(r => r.grantee_id), ['x']);
  assert.equal(await access.canHumanRead('rec', 'e1'), false);
  // recipient session dies at commit: invite is not consumed, no grant
  inv = await mk();
  const r3 = new MachineAccess(racing(db, async () => { await db.prepare("UPDATE device_sessions SET revoked_at=1 WHERE device_id='dev-rec'").run(); }));
  assert.equal(await r3.acceptInvite(V.rec, inv.token, NOW + 1), undefined);
  assert.equal(db.sqlite.prepare('SELECT accepted_at FROM access_invites WHERE invite_id=?').get(inv.inviteId).accepted_at, null);
  assert.equal(db.sqlite.prepare("SELECT count(*) AS n FROM access_grants WHERE grantee_id='rec'").get().n, 0);
  db.sqlite.exec("UPDATE device_sessions SET revoked_at=NULL WHERE device_id='dev-rec'");
  // owner removes an entry before accept: grant is created with the surviving entries only (fails closed)
  await db.prepare("DELETE FROM entries WHERE entry_id='e2'").run();
  assert.ok(await access.acceptInvite(V.rec, inv.token, NOW + 2));
  assert.ok(await access.canHumanRead('rec', 'e1')); assert.equal(await access.canHumanRead('rec', 'e3'), false);
  db.sqlite.close();
});
test('concurrent entry creation under all/deny grants is covered without any list write', async () => {
  const { db, access } = await setup();
  await access.grant(V.own, 'rec', { mode: 'deny', entryIds: ['e3'] }, NOW);
  const racer = new MachineAccess(racing(db, async () => { await db.prepare("INSERT INTO entries (entry_id,owner_id,service_id,label,created_at) VALUES ('new','own','g','n',?)").bind(NOW).run(); }));
  assert.equal(await racer.grant(V.own, 'rec', { mode: 'deny', entryIds: ['e3'] }, NOW + 1), true);
  assert.ok(await access.canHumanRead('rec', 'new'));
  db.sqlite.close();
});

import { createSharingManageHttp } from '../src/sharing-manage-http.js';
const API = 'https://otpanda-api.abrahammurciano.workers.dev', APP = 'https://otpanda.github.io';
async function http(opts = {}) {
  const s = await setup();
  const sessions = { async authenticate(token) { const a = V[token]; return a ? { ownerId: a.ownerId, deviceId: a.deviceId, generation: a.generation, clientKind: 'web', expiresAt: NOW + 1e6 } : undefined; } };
  const handler = createSharingManageHttp({ db: s.db, access: s.access, sessions, clock: () => NOW + 10, ...opts });
  const post = (path, as, body, extra = {}) => handler.fetch(new Request(API + path, { method: 'POST', headers: { Origin: APP, Authorization: 'Bearer ' + as, 'Content-Type': 'application/json', ...extra }, body: typeof body === 'string' ? body : JSON.stringify(body) }));
  return { ...s, handler, post };
}
test('management routes: strict transport, schema, auth, and no token in URL', async () => {
  const { db, post, handler } = await http();
  const P = '/v1/manage/sharing/invite/create', ok = { mode: 'all', entryIds: [], canDelegate: false, ttlSeconds: 3600 };
  assert.equal((await post(P, 'nobody', ok)).status, 401);
  assert.equal((await handler.fetch(new Request(API + P, { method: 'POST', headers: { Authorization: 'Bearer own', 'Content-Type': 'application/json' }, body: '{}' }))).status, 403, 'no Origin without native');
  assert.equal((await handler.fetch(new Request(API + P + '?token=x', { method: 'POST', headers: { Origin: APP, Authorization: 'Bearer own', 'Content-Type': 'application/json' }, body: JSON.stringify(ok) }))).status, 400, 'no query');
  assert.equal((await handler.fetch(new Request(API + P, { method: 'GET', headers: { Origin: APP, Authorization: 'Bearer own' } }))).status, 405);
  assert.equal((await handler.fetch(new Request(API + '/v1/manage/sharing/nope', { method: 'POST', headers: { Origin: APP } }))).status, 404);
  for (const bad of [{ ...ok, extra: 1 }, { ...ok, mode: 'x' }, { ...ok, entryIds: 'e1' }, { ...ok, ttlSeconds: 1.5 }, { ...ok, canDelegate: 'yes' }, [], 'nope', '{"mode":', { mode: 'all', entryIds: [], canDelegate: false }]) assert.equal((await post(P, 'own', bad)).status, 400, JSON.stringify(bad));
  assert.equal((await post(P, 'own', ok, { 'Content-Type': 'text/plain' })).status, 400);
  assert.equal((await post(P, 'own', 'x'.repeat(5000))).status, 400, 'size cap');
  const r = await post(P, 'own', ok); assert.equal(r.status, 200);
  assert.equal(r.headers.get('cache-control'), 'no-store'); assert.equal(r.headers.get('referrer-policy'), 'no-referrer');
  const { token } = await r.json(); assert.ok(TOKEN_RE.test(token));
  const pre = await handler.fetch(new Request(API + P, { method: 'OPTIONS', headers: { Origin: APP, 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'authorization, content-type' } }));
  assert.equal(pre.status, 204);
  assert.equal((await handler.fetch(new Request(API + P, { method: 'OPTIONS', headers: { Origin: APP, 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'authorization, x-evil' } }))).status, 403);
  db.sqlite.close();
});
const TOKEN_RE = /^[A-Za-z0-9_-]{32,512}$/;
test('management routes: full invite -> accept -> machine profile -> token -> read flow', async () => {
  const { db, post, access, reader } = await http();
  const inv = await (await post('/v1/manage/sharing/invite/create', 'own', { mode: 'deny', entryIds: ['e3'], canDelegate: true, ttlSeconds: 3600 })).json();
  assert.equal((await post('/v1/manage/sharing/invite/accept', 'own', { token: inv.token })).status, 404, 'owner cannot accept');
  const acc = await post('/v1/manage/sharing/invite/accept', 'rec', { token: inv.token });
  assert.equal(acc.status, 200); assert.deepEqual(await acc.json(), { ok: true, mode: 'deny', canDelegate: true });
  assert.equal((await post('/v1/manage/sharing/invite/accept', 'x', { token: inv.token })).status, 404, 'single use');
  const prof = await (await post('/v1/manage/machine/profile/create', 'rec', { name: 'ci', mode: 'allow', entryIds: ['e1'] })).json();
  assert.equal((await post('/v1/manage/machine/profile/create', 'rec', { name: 'ci', mode: 'allow', entryIds: ['e3'] })).status, 400, 'unreachable entry');
  assert.equal((await post('/v1/manage/machine/token/create', 'own', { profileId: prof.profileId, ttlSeconds: 600 })).status, 404, 'only creator mints');
  assert.equal((await post('/v1/manage/machine/token/create', 'rec', { profileId: prof.profileId, ttlSeconds: 99999999999 })).status, 400);
  const tok = await (await post('/v1/manage/machine/token/create', 'rec', { profileId: prof.profileId, ttlSeconds: 600 })).json();
  const handlerM = createMachineHandler({ access, reader, clock: () => NOW + 10 });
  const get = (q) => handlerM.fetch(new Request('https://t.invalid/v1/machine/code?' + q, { headers: { authorization: 'Bearer ' + tok.token } }));
  assert.equal((await get('entry=e1&source=sms')).status, 200); assert.equal((await get('entry=e2&source=sms')).status, 404);
  const contacts = (await (await post('/v1/manage/sharing/contacts/list', 'own', {})).json()).contacts;
  assert.equal(contacts.length, 1); const ref = contacts[0].contactRef;
  assert.match(ref, /^[0-9a-f]{32}$/); assert.equal(JSON.stringify(contacts).includes('"rec"'), false, 'internal account id never sent to the owner');
  assert.deepEqual(contacts[0].grant, { mode: 'deny', canDelegate: true });
  assert.equal((await post('/v1/manage/sharing/grant/revoke', 'x', { contactRef: ref })).status, 404, 'a ref only resolves for its owner');
  assert.equal((await post('/v1/manage/machine/token/create', 'rec', { profileId: prof.profileId, ttlSeconds: null })).status, 200, 'never expires is allowed');
  // owner updates, then revokes the grant: machine access follows immediately
  assert.equal((await post('/v1/manage/sharing/grant/update', 'own', { contactRef: ref, mode: 'allow', entryIds: ['e2'], canDelegate: true })).status, 200);
  assert.equal((await get('entry=e1&source=sms')).status, 404);
  assert.equal((await post('/v1/manage/sharing/grant/update', 'own', { contactRef: '0'.repeat(32), mode: 'all', entryIds: [], canDelegate: false })).status, 404, 'update never creates');
  assert.equal((await post('/v1/manage/sharing/grant/revoke', 'own', { contactRef: ref })).status, 200);
  assert.equal((await get('entry=e2&source=sms')).status, 404);
  assert.equal((await post('/v1/manage/sharing/grant/update', 'own', { contactRef: ref, mode: 'all', entryIds: [], canDelegate: true })).status, 404, 'update never revives');
  assert.equal((await post('/v1/manage/machine/profile/revoke', 'rec', { profileId: prof.profileId })).status, 200);
  db.sqlite.close();
});
test('management routes: per-owner rate limit and dead session', async () => {
  const { db, post } = await http();
  const ok = { mode: 'all', entryIds: [], canDelegate: false, ttlSeconds: 3600 };
  db.sqlite.exec("UPDATE device_sessions SET revoked_at=1 WHERE device_id='dev-x'");
  assert.equal((await post('/v1/manage/sharing/invite/create', 'x', ok)).status, 404, 'authenticated by the fake but dead in SQL: write refused');
  assert.equal(count(db, 'access_invites'), 0);
  for (let i = 0; i < 30; i++) await post('/v1/manage/sharing/invite/revoke', 'rec', { inviteId: 'zz' });
  const r = await post('/v1/manage/sharing/invite/revoke', 'rec', { inviteId: 'zz' });
  assert.equal(r.status, 429); assert.ok(Number(r.headers.get('retry-after')) >= 1);
  db.sqlite.close();
});
test('remembered recipients: only an accepted invite creates a contact, owner-private opaque ref, regrant without a link', async () => {
  const { db, access } = await setup();
  assert.equal(await access.grantToContact(V.own, 'f'.repeat(32), { mode: 'all', canDelegate: false }, NOW), false, 'unknown ref is not reachable');
  assert.equal(await access.grantToContact(V.own, 'rec', { mode: 'all', canDelegate: false }, NOW), false, 'an account id is not a ref');
  assert.deepEqual(await access.listContacts(V.own, NOW), []);
  const inv = await access.createInvite(V.own, { mode: 'allow', entryIds: ['e1'], canDelegate: false }, 3600000, NOW);
  assert.deepEqual(await access.listContacts(V.own, NOW), [], 'creating an invite remembers nobody');
  assert.ok(await access.acceptInvite(V.rec, inv.token, NOW + 1));
  await db.prepare("INSERT INTO account_emails (owner_id,email,verified_at,updated_at) VALUES ('rec','rec@example.test',?1,?1)").bind(NOW).run();
  await db.prepare("INSERT INTO provider_identities (identity_id,owner_id,provider,issuer,subject,email,created_at,picture,display_name) VALUES ('pi','rec','google','https://accounts.google.com','s1','rec@example.test',?,'https://lh3.googleusercontent.com/a/x','Rec Ipient')").bind(NOW).run();
  const listed = await access.listContacts(V.own, NOW + 2);
  assert.deepEqual(listed.map(c => [c.name, c.email, c.picture, c.hidden, c.grant]), [['Rec Ipient', 'rec@example.test', 'https://lh3.googleusercontent.com/a/x', false, { mode: 'allow', canDelegate: false }]]);
  const ref = listed[0].contactRef; assert.match(ref, /^[0-9a-f]{32}$/); assert.equal(JSON.stringify(listed).includes('"rec"'), false);
  assert.deepEqual(await access.listContacts(V.rec, NOW + 2), [], 'recipient does not learn or keep the owner as a contact');
  assert.deepEqual(await access.listContacts(V.x, NOW + 2), []);
  assert.equal(await access.grantToContact(V.x, ref, { mode: 'all', canDelegate: false }, NOW + 2), false, 'another owner cannot use the ref');
  assert.equal(await access.revokeGrantForContact(V.own, ref, NOW + 3), true);
  assert.equal(await access.canHumanRead('rec', 'e1'), false);
  assert.equal((await access.listContacts(V.own, NOW + 3))[0].grant, null);
  assert.equal(await access.grantToContact(V.own, ref, { mode: 'allow', entryIds: ['e2'], canDelegate: false }, NOW + 4), true);
  assert.equal(await access.canHumanRead('rec', 'e2'), true); assert.equal(await access.canHumanRead('rec', 'e1'), false);
  await assert.rejects(access.grantToContact(V.own, ref, { mode: 'allow', entryIds: ['r1'], canDelegate: false }, NOW + 5), TypeError);
  assert.equal(await access.grantToContact({ ...V.own, generation: 9 }, ref, { mode: 'all', canDelegate: false }, NOW + 6), false);
  assert.equal(await access.removeContact(V.own, ref, NOW + 7), true);
  assert.equal(await access.canHumanRead('rec', 'e2'), true, 'hiding a contact leaves the grant alone');
  const still = await access.listContacts(V.own, NOW + 7);
  assert.equal(still.length, 1); assert.equal(still[0].hidden, true, 'hidden contact with a live grant stays manageable');
  assert.equal(await access.grantToContact(V.own, ref, { mode: 'all', canDelegate: false }, NOW + 8), false, 'hidden contact gets no new shares');
  assert.equal(await access.updateGrantForContact(V.own, ref, { mode: 'all', canDelegate: false }, NOW + 8), true, 'but the live grant can be edited');
  assert.equal(await access.revokeGrantForContact(V.own, ref, NOW + 9), true);
  assert.deepEqual(await access.listContacts(V.own, NOW + 9), [], 'hidden and no grant: gone from the list');
  assert.equal(await access.removeContact(V.x, ref, NOW + 9), false);
  const inv2 = await access.createInvite(V.own, { mode: 'all', canDelegate: false }, 3600000, NOW + 10);
  assert.ok(await access.acceptInvite(V.rec, inv2.token, NOW + 11));
  const back = await access.listContacts(V.own, NOW + 12);
  assert.equal(back.length, 1); assert.equal(back[0].contactRef, ref, 'same ref, reinstated'); assert.equal(back[0].hidden, false);
  db.sqlite.close();
});
test('refused upsert at the SAME fixed clock cannot wipe an existing grant (causal nonce, not timestamp)', async () => {
  const { db, access } = await setup();
  // Same instant, upsert refused (grantee not a contact, mode 2): the old list must survive untouched.
  assert.equal(await access.grantToContact(V.own, 'a'.repeat(32), { mode: 'allow', entryIds: ['e3'], canDelegate: false }, NOW), false);
  // Removed-contact refusal INSIDE the batch (ref resolved, then contact hidden before the write): use #grant mode 2 directly via a hook.
  const inv = await access.createInvite(V.own, { mode: 'all', canDelegate: false }, 3600000, NOW);
  await access.acceptInvite(V.rec, inv.token, NOW);
  await access.grant(V.own, 'rec', { mode: 'allow', entryIds: ['e1', 'e2'], canDelegate: false }, NOW);
  const ref = (await access.listContacts(V.own, NOW))[0].contactRef;
  const real = access.db.prepare.bind(access.db);
  let hidden = false;
  access.db.prepare = (sql) => { if (!hidden && /^INSERT INTO access_grants/.test(sql)) { hidden = true; db.sqlite.prepare("UPDATE sharing_contacts SET removed_at=1").run(); } return real(sql); };
  assert.equal(await access.grantToContact(V.own, ref, { mode: 'allow', entryIds: ['e3'], canDelegate: false }, NOW), false, 'contact hidden mid-flight: refused in SQL');
  access.db.prepare = real;
  assert.equal((await db.prepare("SELECT count(*) n FROM access_grant_entries").first()).n, 2);
  assert.equal(await access.canHumanRead('rec', 'e1'), true);
  assert.equal(await access.canHumanRead('rec', 'e3'), false);
  // Same for updateGrant on a revoked grant at the same clock.
  await access.revokeGrant(V.own, 'rec', NOW);
  assert.equal(await access.updateGrantForContact(V.own, ref, { mode: 'all', canDelegate: false }, NOW), false);
  assert.equal(await access.canHumanRead('rec', 'e1'), false);
  db.sqlite.close();
});
test('google display name: bounded plain text, stored on link and refreshed on sign-in', async () => {
  const { googleDisplayName } = await import('../src/account-identity.js');
  assert.equal(googleDisplayName('  Abe M  '), 'Abe M');
  for (const bad of ['', '   ', 'a'.repeat(101), 'x\u202ey', 'a\nb', 5, null, undefined]) assert.equal(googleDisplayName(bad), undefined);
});
test('replaying a consumed invite at the same clock cannot restore older, wider terms', async () => {
  const { db, access } = await setup();
  const inv = await access.createInvite(V.own, { mode: 'all' }, 3600000, NOW);
  assert.ok(await access.acceptInvite(V.rec, inv.token, NOW + 1));
  assert.equal(await access.grant(V.own, 'rec', { mode: 'allow', entryIds: ['e2'], canDelegate: false }, NOW + 1), true);
  const snap = () => JSON.stringify([db.sqlite.prepare('SELECT mode,can_delegate,write_nonce,revoked_at FROM access_grants').all(), db.sqlite.prepare('SELECT * FROM access_grant_entries').all()]);
  const before = snap();
  assert.equal(await access.acceptInvite(V.rec, inv.token, NOW + 1), undefined, 'replay at the same clock is refused');
  assert.equal(snap(), before, 'narrower grant preserved byte for byte');
  assert.equal(await access.canHumanRead('rec', 'e1'), false);
  assert.ok(await access.canHumanRead('rec', 'e2'));
  db.sqlite.close();
});
test('owner metadata lists: profiles and tokens without secrets, delegated entries offered, token revoke is separate', async () => {
  const { db, access } = await setup();
  await access.grant(V.own, 'rec', { mode: 'allow', entryIds: ['e1'], canDelegate: true }, NOW);
  const p = await access.createProfile(V.rec, { name: 'box', mode: 'all' }, NOW);
  const t1 = await access.mintToken(V.rec, p, null, NOW), t2 = await access.mintToken(V.rec, p, 1000, NOW);
  const list = await access.listProfiles(V.rec, NOW);
  assert.equal(list.length, 1); assert.equal(list[0].tokens.length, 2);
  const text = JSON.stringify(list); assert.ok(!text.includes(t1.token) && !text.includes('digest'));
  assert.deepEqual(await access.listProfiles(V.x, NOW), [], 'foreign owner sees nothing');
  assert.deepEqual(await access.listProfiles({ ...V.rec, generation: 9 }, NOW), [], 'dead session sees nothing');
  const ents = await access.listMachineEntries(V.rec, NOW);
  assert.deepEqual(ents.map(e => [e.entryId, e.owned]).sort(), [['e1', false], ['r1', true]]);
  assert.equal(await access.revokeToken(V.x, p, t1.tokenId, NOW), false, 'foreign owner cannot revoke');
  assert.equal(await access.revokeToken(V.rec, p, t1.tokenId, NOW + 1), true);
  assert.equal(await access.verifyToken(t1.token, NOW + 2), undefined);
  assert.ok(await access.verifyToken(t2.token, NOW + 2), 'other token and profile unaffected');
  assert.equal(db.sqlite.prepare('SELECT revoked_at FROM machine_profiles').get().revoked_at, null);
  db.sqlite.close();
});

test('lost create reply recovered as metadata only, cap released by owner revoke, foreign refusal',async()=>{
 const {db,access}=await setup();try{
  for(let i=0;i<20;i++)await access.createInvite(V.own,{mode:'all',entryIds:[],canDelegate:false},86400000,NOW);
  const pending=await access.listInvites(V.own,NOW);assert.equal(pending.length,20);
  assert.deepEqual(Object.keys(pending[0]).sort(),['canDelegate','createdAt','expiresAt','inviteId','mode']);
  assert.equal(await access.createInvite(V.own,{mode:'all',entryIds:[],canDelegate:false},86400000,NOW),undefined);
  assert.deepEqual(await access.listInvites(V.own2,NOW),[]);
  assert.equal(await access.revokeInvite(V.own2,pending[0].inviteId,NOW),false);
  assert.equal(await access.revokeInvite(V.own,pending[0].inviteId,NOW),true);
  assert.equal((await access.listInvites(V.own,NOW)).length,19);
  assert.ok(await access.createInvite(V.own,{mode:'all',entryIds:[],canDelegate:false},86400000,NOW));
  await db.prepare('UPDATE device_sessions SET revoked_at=? WHERE device_id=?').bind(NOW,V.own.deviceId).run();
  assert.deepEqual(await access.listInvites(V.own,NOW),[]);
 }finally{db.sqlite.close();}
});
