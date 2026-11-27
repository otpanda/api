// Synthetic sharing / machine-access qualification checks against whatever D1 binding they are given.
// Imported by the isolated Worker (remote D1) and by tool/d1-qualify-sharing.mjs (local simulation).
// All data is synthetic and created here. Nothing here is imported by production code.
import { MachineAccess, MachineReader, createMachineHandler } from '../../src/machine-access.js';

const NOW = 1800000000000;
const fail = (m) => { throw new Error(m); };
const eq = (a, b, m) => { if (JSON.stringify(a) !== JSON.stringify(b)) fail(`${m}: expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`); };
const ok = (v, m) => { if (!v) fail(m); };

export async function runChecks(db) {
  const results = [];
  const check = async (name, fn) => {
    const t = Date.now();
    try { await fn(); results.push({ name, pass: true, ms: Date.now() - t }); }
    catch (e) { results.push({ name, pass: false, error: String(e?.message ?? e).slice(0, 400), ms: Date.now() - t }); }
  };
  const V = {};
  for (const a of ['own', 'rec', 'x']) {
    await db.prepare('INSERT INTO accounts VALUES (?,?)').bind(a, NOW).run();
    await db.prepare('INSERT INTO account_security (owner_id,generation) VALUES (?,0)').bind(a).run();
    await db.prepare("INSERT INTO passkey_credentials (credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) VALUES (?,?,x'00',0,'[]','singleDevice',0,?)").bind('c-' + a, a, NOW).run();
    await db.prepare("INSERT INTO device_sessions (device_id,owner_id,credential_id,generation,client_kind,created_at,last_used_at,expires_at) VALUES (?,?,?,0,'web',?,?,?)").bind('d-' + a, a, 'c-' + a, NOW - 1000, NOW - 1000, NOW + 1e7).run();
    V[a] = { ownerId: a, deviceId: 'd-' + a, generation: 0, kind: 'web' };
  }
  for (const e of ['e1', 'e2', 'e3']) await db.prepare('INSERT INTO entries (entry_id,owner_id,service_id,label,created_at) VALUES (?,?,?,?,?)').bind(e, 'own', 'g', e, NOW).run();
  await db.prepare('INSERT INTO entries (entry_id,owner_id,service_id,label,created_at) VALUES (?,?,?,?,?)').bind('r1', 'rec', 'g', 'r1', NOW).run();
  await db.prepare('INSERT INTO sources (source_id,owner_id,kind,label,created_at) VALUES (?,?,?,?,?)').bind('sm', 'own', 'sms', 'sm', NOW).run();
  await db.prepare("INSERT INTO incoming_codes (owner_id,event_id,source_id,entry_id,envelope,received_at,expires_at,assignment) VALUES ('own','ev1','sm','e1',?,?,?,'confirmed')").bind(JSON.stringify({ code: 'SMS1' }), NOW - 500, NOW + 60000).run();
  const access = new MachineAccess(db);
  // Synthetic decrypt stand-in: the envelope is the plain code. Real cipher paths are not part of this harness.
  const reader = new MachineReader({ access, sources: { cipher: { async decrypt(e) { return e.code; } } }, seeds: {}, clock: () => NOW });
  const count = async t => (await db.prepare('SELECT count(*) AS n FROM ' + t).first()).n;
  const grants = async () => JSON.stringify([(await db.prepare('SELECT owner_id,grantee_id,mode,can_delegate,write_nonce,revoked_at FROM access_grants ORDER BY grantee_id').all()).results, (await db.prepare('SELECT * FROM access_grant_entries ORDER BY grant_id,entry_id').all()).results]);

  await check('grant upsert and list rewrite in one batch', async () => {
    ok(await access.grant(V.own, 'rec', { mode: 'deny', entryIds: ['e3'], canDelegate: true }, NOW), 'grant');
    ok(await access.canHumanRead('rec', 'e1'), 'deny covers e1'); eq(await access.canHumanRead('rec', 'e3'), false, 'deny excludes e3');
    ok(await access.grant(V.own, 'rec', { mode: 'allow', entryIds: ['e1', 'e2'], canDelegate: true }, NOW + 1), 'regrant');
    eq([await count('access_grants'), await count('access_grant_entries')], [1, 2], 'row counts');
  });
  await check('foreign entry id rolls the whole batch back (D1 error text matched)', async () => {
    const before = await grants();
    let threw = false;
    try { await access.grant(V.own, 'rec', { mode: 'deny', entryIds: ['e1', 'nope'] }, NOW + 2); } catch (e) { threw = e instanceof TypeError; }
    ok(threw, 'expected TypeError');
    eq(await grants(), before, 'state unchanged'); eq(await count('tx_assert'), 0, 'tx_assert empty');
  });
  await check('dead session is refused in SQL and changes nothing', async () => {
    const before = await grants();
    eq(await access.grant({ ...V.own, generation: 9 }, 'x', { mode: 'all' }, NOW), false, 'dead generation');
    eq(await access.grant({ ...V.x, ownerId: 'own' }, 'x', { mode: 'all' }, NOW), false, 'device of another owner');
    eq(await grants(), before, 'state unchanged');
  });
  await check('same-clock narrowing then consumed-invite replay cannot restore wider terms', async () => {
    const inv = await access.createInvite(V.own, { mode: 'all' }, 3600000, NOW + 20);
    ok(await access.acceptInvite(V.x, inv.token, NOW + 21), 'accept');
    ok(await access.grant(V.own, 'x', { mode: 'allow', entryIds: ['e2'], canDelegate: false }, NOW + 21), 'narrow');
    const before = await grants();
    eq(await access.acceptInvite(V.x, inv.token, NOW + 21), undefined, 'replay refused');
    eq(await grants(), before, 'narrower grant preserved');
    eq(await access.canHumanRead('x', 'e1'), false, 'e1 unreadable'); ok(await access.canHumanRead('x', 'e2'), 'e2 readable');
    eq(await count('tx_assert'), 0, 'tx_assert empty');
  });
  await check('single-use invite: second account and a replay by the same account are refused', async () => {
    const inv = await access.createInvite(V.own, { mode: 'allow', entryIds: ['e1'], canDelegate: false }, 3600000, NOW + 30);
    ok(await access.acceptInvite(V.rec, inv.token, NOW + 31), 'first accept');
    eq(await access.acceptInvite(V.x, inv.token, NOW + 32), undefined, 'other account');
    eq(await access.acceptInvite(V.rec, inv.token, NOW + 32), undefined, 'same account again');
    const own = await access.acceptInvite(V.own, (await access.createInvite(V.own, { mode: 'all' }, 3600000, NOW + 33)).token, NOW + 34);
    eq(own, undefined, 'owner cannot accept own invite');
  });
  let profile, token;
  await check('machine profile, token, one-code read; revoke and narrowing stay effective', async () => {
    await access.grant(V.own, 'rec', { mode: 'allow', entryIds: ['e1'], canDelegate: true }, NOW + 40);
    profile = await access.createProfile(V.rec, { name: 'ci', mode: 'all' }, NOW + 41);
    token = await access.mintToken(V.rec, profile, null, NOW + 41);
    ok(profile && token, 'profile and never-expiring token');
    const h = createMachineHandler({ access, reader, clock: () => NOW + 45 });
    const call = (q) => h.fetch(new Request('https://t.invalid/v1/machine/code?' + q, { headers: { authorization: 'Bearer ' + token.token } }));
    const res = await call('entry=e1&source=sms');
    eq(res.status, 200, 'e1 sms'); eq((await res.json()).codes.sms.code, 'SMS1', 'code');
    eq((await call('entry=e2&source=sms')).status, 404, 'e2 not delegated');
    eq((await call('entry=e1&source=sms&entry=e2')).status, 400, 'no multi-entry');
    await access.grant(V.own, 'rec', { mode: 'allow', entryIds: ['e2'], canDelegate: true }, NOW + 46);
    eq((await call('entry=e1&source=sms')).status, 404, 'narrowing is immediate');
    await access.grant(V.own, 'rec', { mode: 'all', canDelegate: true }, NOW + 47);
    await access.revokeGrant(V.own, 'rec', NOW + 48);
    eq((await call('entry=e1&source=sms')).status, 404, 'revoke is immediate');
  });
  await check('owner metadata lists carry no secrets; token revoke is separate from profile revoke', async () => {
    const t2 = await access.mintToken(V.rec, profile, 1000, NOW + 50);
    const list = await access.listProfiles(V.rec, NOW + 50), text = JSON.stringify(list);
    ok(list.length === 1 && list[0].tokens.length === 2, 'one profile, two tokens');
    ok(!text.includes(token.token) && !text.includes(t2.token) && !/digest|secret/i.test(text), 'no secret material');
    eq(await access.listProfiles(V.x, NOW + 50), [], 'foreign owner sees nothing');
    eq(await access.listProfiles({ ...V.rec, generation: 9 }, NOW + 50), [], 'dead session sees nothing');
    eq((await access.listMachineEntries(V.rec, NOW + 50)).map(e => e.entryId), ['r1'], 'delegation was revoked, own entries only');
    eq(await access.revokeToken(V.x, profile, token.tokenId, NOW + 51), false, 'foreign owner cannot revoke');
    ok(await access.revokeToken(V.rec, profile, token.tokenId, NOW + 51), 'owner revokes one token');
    eq(await access.verifyToken(token.token, NOW + 52), undefined, 'revoked token dead');
    ok(await access.verifyToken(t2.token, NOW + 52), 'sibling token alive');
    eq((await db.prepare('SELECT revoked_at FROM machine_profiles').first()).revoked_at, null, 'profile not revoked');
  });
  await check('triggers fire on grant writes (outbox and revision)', async () => {
    ok(await count('realtime_outbox') > 0, 'outbox rows');
    ok((await db.prepare("SELECT sum(mutation_revision) AS n FROM entries WHERE owner_id='own'").first()).n > 0, 'revision bumped');
  });
  return { synthetic: true, checks: results, pass: results.every(r => r.pass) };
}
