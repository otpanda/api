import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { SessionService, ownerForIdentity, SESSION_COOKIE, takeRateLimit } from '../src/sessions.js';
import { D1TokenStore } from '../src/d1-store.js';
import { createManagementHandler } from '../src/management.js';
import { verifyAccessToken } from '../src/verify.js';
const NOW = 1_800_000_000_000;
async function setup() {
  const db = database();
  const a = await ownerForIdentity(db, 'https://id.test', 'a', NOW);
  const b = await ownerForIdentity(db, 'https://id.test', 'b', NOW);
  const sessions = new SessionService(db, { origin: 'https://app.test', clock: () => NOW });
  const issued = await sessions.issue(a);
  const tokens = new D1TokenStore(db);
  const management = createManagementHandler({ db, sessions, tokenStore: tokens, clock: () => NOW });
  function request(path, method = 'GET', body, extra = {}) {
    return new Request('https://app.test' + path, { method, headers: { cookie: SESSION_COOKIE + '=' + issued.session, origin: 'https://app.test', 'x-otpanda-csrf': issued.csrf, 'content-type': 'application/json', ...extra }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  }
  return { db, a, b, sessions, issued, tokens, management, request };
}
test('identity is issuer+subject, never email or request owner; repeat sign-in is stable', async () => {
  const { db, a, b } = await setup();
  assert.notEqual(a, b);
  assert.equal(await ownerForIdentity(db, 'https://id.test', 'a', NOW), a);
  assert.notEqual(await ownerForIdentity(db, 'https://other.test', 'a', NOW), a);
  assert.equal(db.sqlite.prepare('SELECT count(*) AS n FROM accounts').get().n, 3);
  db.sqlite.close();
});
test('session authenticates digest, rejects duplicate cookies, bad origin/CSRF and expiry', async () => {
  const { db, sessions, issued, a, request } = await setup();
  assert.equal((await sessions.authenticate(request('/'))).ownerId, a);
  assert.equal(await sessions.authenticate(request('/', 'POST', {}, { origin: 'https://evil.test' }), { mutation: true }), undefined);
  assert.equal(await sessions.authenticate(request('/', 'POST', {}, { 'x-otpanda-csrf': 'bad' }), { mutation: true }), undefined);
  assert.equal(await sessions.authenticate(request('/', 'GET', undefined, { cookie: `${SESSION_COOKIE}=${issued.session}; ${SESSION_COOKIE}=${issued.session}` })), undefined);
  assert.ok(!JSON.stringify(db.sqlite.prepare('SELECT * FROM sessions').all()).includes(issued.session));
  db.sqlite.prepare('UPDATE sessions SET created_at = ?, expires_at = ?').run(NOW - 1, NOW);
  assert.equal(await sessions.authenticate(request('/')), undefined);
  db.sqlite.close();
});
test('management creates narrow grants once, lists safely, denies owner spoof and revokes only own tokens', async () => {
  const { db, a, b, tokens, management, request } = await setup();
  const body = { clientId: 'extension', serviceId: 'example.com', ttlMs: 60000 };
  assert.equal((await management.fetch(request('/v1/manage/tokens', 'POST', { ...body, ownerId: b }))).status, 400);
  const response = await management.fetch(request('/v1/manage/tokens', 'POST', body));
  assert.equal(response.status, 201);
  const minted = await response.json();
  assert.equal((await verifyAccessToken(minted.token, tokens, { now: NOW })).grant.ownerId, a);
  const listed = await (await management.fetch(request('/v1/manage/tokens'))).json();
  assert.ok(!JSON.stringify(listed).includes(minted.token));
  assert.equal(listed.tokens.length, 1);
  assert.equal(await tokens.revokeForOwner(b, minted.tokenId, NOW), false);
  assert.equal((await management.fetch(request('/v1/manage/tokens/' + minted.tokenId, 'DELETE'))).status, 200);
  assert.equal((await verifyAccessToken(minted.token, tokens, { now: NOW })).reason, 'revoked');
  assert.equal((await management.fetch(request('/v1/manage/tokens', 'POST', body, { origin: 'https://evil.test' }))).status, 401);
  assert.equal((await management.fetch(request('/v1/manage/logout', 'POST'))).status, 200);
  assert.equal((await management.fetch(request('/v1/manage/session'))).status, 401);
  db.sqlite.close();
});
test('management rejects oversized body without Content-Length and bearer-only clients', async () => {
  const { db, management, request } = await setup();
  assert.equal((await management.fetch(request('/v1/manage/tokens', 'POST', { huge: 'x'.repeat(3000) }))).status, 413);
  const response = await management.fetch(new Request('https://app.test/v1/manage/tokens', { headers: { authorization: 'Bearer synthetic' } }));
  assert.equal(response.status, 401);
  db.sqlite.close();
});
test('atomic rate buckets reset and isolate keys', async () => {
  const { db } = await setup();
  assert.equal((await takeRateLimit(db, 'a', { now: NOW, limit: 1 })).allowed, true);
  assert.equal((await takeRateLimit(db, 'a', { now: NOW, limit: 1 })).allowed, false);
  assert.equal((await takeRateLimit(db, 'b', { now: NOW, limit: 1 })).allowed, true);
  assert.equal((await takeRateLimit(db, 'a', { now: NOW + 60000, limit: 1 })).allowed, true);
  db.sqlite.close();
});

test('denied rate requests saturate without mutation and preserve stored reset under clock rollback', async () => {
 const {db}=await setup();try{
 const now=120000;
 assert.equal((await takeRateLimit(db,'saturate',{now,limit:2})).allowed,true);
 assert.equal((await takeRateLimit(db,'saturate',{now,limit:2})).allowed,true);
 const before=db.sqlite.prepare('SELECT * FROM rate_buckets').all();
 for(let i=0;i<10;i++)assert.deepEqual(await takeRateLimit(db,'saturate',{now,limit:2}),{allowed:false,retryAfter:60});
 assert.deepEqual(db.sqlite.prepare('SELECT * FROM rate_buckets').all(),before);
 assert.deepEqual(await takeRateLimit(db,'saturate',{now:60000,limit:2}),{allowed:false,retryAfter:120});
 assert.equal((await takeRateLimit(db,'saturate',{now:180000,limit:2})).allowed,true);
 assert.equal(db.sqlite.prepare('SELECT count FROM rate_buckets').get().count,1);
 }finally{db.sqlite.close();}
});

test('rate limiter rejects invalid configuration before D1 and permits explicit limit changes safely',async()=>{
 const {db}=await setup();try{
 for(const limit of [0,-1,1.5,NaN,Infinity,'3',null])await assert.rejects(takeRateLimit(db,'invalid',{now:120000,limit}),TypeError);
 for(const windowMs of [0,-1,1.5,Infinity])await assert.rejects(takeRateLimit(db,'invalid',{now:120000,windowMs}),TypeError);
 for(const now of [-1,NaN,Infinity,Number.MAX_SAFE_INTEGER])await assert.rejects(takeRateLimit(db,'invalid',{now}),TypeError);
 assert.equal(db.sqlite.prepare('SELECT count(*) AS n FROM rate_buckets').get().n,0);
 assert.equal((await takeRateLimit(db,'change',{now:120000,limit:1})).allowed,true);
 assert.equal((await takeRateLimit(db,'change',{now:120000,limit:1})).allowed,false);
 assert.equal((await takeRateLimit(db,'change',{now:120000,limit:2})).allowed,true);
 assert.equal((await takeRateLimit(db,'change',{now:120000,limit:1})).allowed,false);
 assert.equal(db.sqlite.prepare('SELECT count FROM rate_buckets').get().count,2);
 }finally{db.sqlite.close();}
});
