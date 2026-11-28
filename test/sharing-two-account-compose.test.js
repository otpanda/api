import {createIdentityRuntime} from '../src/identity-runtime.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { AccountIdentityService } from '../src/account-identity.js';
import { PasskeySignupService } from '../src/passkey-signup.js';
import { DeviceSessionService } from '../src/device-sessions.js';
import { CodeCipher } from '../src/code-cipher.js';
import { SourceEntryStore } from '../src/source-entries.js';
import { authenticator } from './passkey-fixture.js';

// Joined two-account execution on one stack: real accounts, real sessions,
// real cipher, the staged sharing/machine handlers and the already-mounted
// device-read handler behind one fetch. No fake transports: every step is an
// actual HTTP request through the composed routes. Local SQLite only; this
// proves nothing about the deployed worker or remote D1.
const API = 'https://otpanda-api.abrahammurciano.workers.dev', APP = 'https://otpanda.github.io', NOW = 1_800_000_000_000;

async function fixture() {
  const db = database();
  let now = NOW;
  const clock = () => now;
  const sessions = new DeviceSessionService(db, { clock });
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const cipher = new CodeCipher({ keys: new Map([['test', key]]), activeKeyId: 'test' });
  const sources = new SourceEntryStore(db, cipher);
  // Actual identity runtime route composition, explicit local-only opt-in.
  const app=createIdentityRuntime({db,keys:new Map([['test',key]]),activeKeyId:'test',trustedRequestKey:()=> '192.0.2.3',clock,sharing:{enabled:true}});
  async function signup(email, binding) {
    const identity = new AccountIdentityService(db, { clock });
    const signup = new PasskeySignupService(db, { clock });
    const e = await identity.issueEmailChallenge({ purpose: 'signup-email', email });
    const c = await signup.begin({ email, emailToken: e.token, binding });
    const a = authenticator();
    const account = await signup.finish({ token: c.token, binding, response: a.registration({ expected: c.options.challenge }) });
    const issued = await sessions.issue({ proof: { ...account, purpose: 'authenticate', verifiedAt: NOW }, clientKind: 'web' });
    return { account, issued };
  }
  function call(path, { bearer, body, machine } = {}) {
    const headers = {};
    if (!machine) headers.Origin = APP;
    if (bearer) headers.Authorization = 'Bearer ' + bearer;
    if (body) headers['content-type'] = 'application/json';
    return app.fetch(new Request(API + path, { method: body ? 'POST' : 'GET', headers, body: body ? JSON.stringify(body) : undefined }), { clientAddress: 'test' });
  }
  return { db, sources, signup, call, setNow: (v) => (now = v) };
}

test('owner invite -> recipient accept -> read-only entries -> revoke -> refusal, one composed stack', async () => {
  const f = await fixture();
  try {
    const owner = await f.signup('owner@example.test', 'owner');
    const recipient = await f.signup('recipient@example.test', 'recipient');
    const gmail = await f.sources.createSource(owner.account.ownerId, 'gmail', 'Owner mail', NOW);
    const sms = await f.sources.createSource(owner.account.ownerId, 'sms', 'Owner phone', NOW);
    const e1 = await f.sources.createEntry(owner.account.ownerId, 'test', 'Shared entry', NOW);
    const e2 = await f.sources.createEntry(owner.account.ownerId, 'test', 'Private entry', NOW);
    await f.sources.receive(owner.account.ownerId, { sourceId: gmail, eventId: 'm1', code: '111111', receivedAt: NOW - 1000, expiresAt: NOW + 60000 });
    await f.sources.confirm(owner.account.ownerId, gmail, 'm1', e1, NOW);
    await f.sources.receive(owner.account.ownerId, { sourceId: sms, eventId: 's1', code: '222222', receivedAt: NOW - 500, expiresAt: NOW + 60000 });
    await f.sources.confirm(owner.account.ownerId, sms, 's1', e1, NOW);
    await f.sources.receive(owner.account.ownerId, { sourceId: sms, eventId: 's2', code: '333333', receivedAt: NOW - 500, expiresAt: NOW + 60000 });
    await f.sources.confirm(owner.account.ownerId, sms, 's2', e2, NOW);

    // Actual route grammar refusals: no trimmed/query/overlong invite token accepted.
    for(const token of ['short','A'.repeat(513),'A'.repeat(32)+'?x=1']){
      assert.equal((await f.call('/v1/manage/sharing/invite/accept',{bearer:recipient.issued.access,body:{token}})).status,400);
    }
    // 1. Owner mints an invite over HTTP; the token travels in a body only.
    const invite = await f.call('/v1/manage/sharing/invite/create', {
      bearer: owner.issued.access,
      body: { mode: 'allow', entryIds: [e1], canDelegate: true, ttlSeconds: 86400 },
    });
    assert.equal(invite.status, 200);
    const inviteBody = await invite.json();
    assert.ok(inviteBody.token && inviteBody.inviteId);

    // 2. Recipient accepts over HTTP with their own session.
    const pendingResponse=await f.call('/v1/manage/sharing/invite/list',{bearer:owner.issued.access,body:{}});
    assert.equal(pendingResponse.status,200);const pending=await pendingResponse.json();
    assert.equal(pending.invites.length,1);assert.equal(pending.invites[0].inviteId,inviteBody.inviteId);
    assert.deepEqual(Object.keys(pending.invites[0]).sort(),['canDelegate','createdAt','expiresAt','inviteId','mode']);
    assert.deepEqual(await (await f.call('/v1/manage/sharing/invite/list',{bearer:recipient.issued.access,body:{}})).json(),{invites:[]});
    assert.equal((await f.call('/v1/manage/sharing/invite/revoke',{bearer:recipient.issued.access,body:{inviteId:inviteBody.inviteId}})).status,404);
    const accept = await f.call('/v1/manage/sharing/invite/accept', { bearer: recipient.issued.access, body: { token: inviteBody.token } });
    assert.equal(accept.status, 200);
    assert.deepEqual(await accept.json(), { ok: true, mode: 'allow', canDelegate: true });

    // 3. Recipient entries read: exactly the shared entry, read-only.
    const entries = await (await f.call('/v1/manage/entries', { bearer: recipient.issued.access })).json();
    assert.deepEqual(entries.entries.map((e) => [e.entry_id, e.capabilities.manage]), [[e1, false]]);
    // Active codes: the latest code per entry, only for the shared entry.
    const active = await (await f.call('/v1/manage/active-codes', { bearer: recipient.issued.access })).json();
    assert.deepEqual(active.records.map((r) => [r.entryId, r.code]), [[e1, '222222']]);

    // 4. A replayed accept of the consumed invite is refused.
    assert.equal((await f.call('/v1/manage/sharing/invite/accept', { bearer: recipient.issued.access, body: { token: inviteBody.token } })).status, 404);

    // 5. Owner revokes through the remembered contact handle.
    const contacts = await (await f.call('/v1/manage/sharing/contacts/list', { bearer: owner.issued.access, body: {} })).json();
    assert.equal(contacts.contacts.length, 1);
    assert.match(contacts.contacts[0].contactRef, /^[0-9a-f]{32}$/);
    assert.ok(!('contactId' in contacts.contacts[0]) && !('ownerId' in contacts.contacts[0]), 'no internal account id to the owner');
    const revoke = await f.call('/v1/manage/sharing/grant/revoke', { bearer: owner.issued.access, body: { contactRef: contacts.contacts[0].contactRef } });
    assert.equal(revoke.status, 200);

    // 6. After revoke the recipient read refuses immediately.
    assert.deepEqual((await (await f.call('/v1/manage/entries', { bearer: recipient.issued.access })).json()).entries, []);
    assert.deepEqual((await (await f.call('/v1/manage/active-codes', { bearer: recipient.issued.access })).json()).records, []);
  } finally {
    f.db.sqlite.close();
  }
});

test('machine tokens stay scoped: one account and one code per source, delegation ceiling, narrowing voids', async () => {
  const f = await fixture();
  try {
    const owner = await f.signup('owner@example.test', 'owner');
    const recipient = await f.signup('recipient@example.test', 'recipient');
    const gmail = await f.sources.createSource(owner.account.ownerId, 'gmail', 'Owner mail', NOW);
    const sms = await f.sources.createSource(owner.account.ownerId, 'sms', 'Owner phone', NOW);
    const e1 = await f.sources.createEntry(owner.account.ownerId, 'test', 'Shared entry', NOW);
    const e2 = await f.sources.createEntry(owner.account.ownerId, 'test', 'Private entry', NOW);
    await f.sources.receive(owner.account.ownerId, { sourceId: gmail, eventId: 'm1', code: '111111', receivedAt: NOW - 1000, expiresAt: NOW + 60000 });
    await f.sources.confirm(owner.account.ownerId, gmail, 'm1', e1, NOW);
    await f.sources.receive(owner.account.ownerId, { sourceId: sms, eventId: 's1', code: '222222', receivedAt: NOW - 500, expiresAt: NOW + 60000 });
    await f.sources.confirm(owner.account.ownerId, sms, 's1', e1, NOW);

    // Share e1 to the recipient WITHOUT machine delegation.
    const invite = await (await f.call('/v1/manage/sharing/invite/create', {
      bearer: owner.issued.access,
      body: { mode: 'allow', entryIds: [e1], canDelegate: false, ttlSeconds: 86400 },
    })).json();
    assert.equal((await f.call('/v1/manage/sharing/invite/accept', { bearer: recipient.issued.access, body: { token: invite.token } })).status, 200);

    // Owner machine profile over e1, one token shown once.
    const profile = await (await f.call('/v1/manage/machine/profile/create', { bearer: owner.issued.access, body: { name: 'ci', mode: 'allow', entryIds: [e1] } })).json();
    const minted = await (await f.call('/v1/manage/machine/token/create', { bearer: owner.issued.access, body: { profileId: profile.profileId, ttlSeconds: 3600 } })).json();
    assert.ok(minted.token && minted.tokenId);

    // One account, one code per source: "all" returns one email and one sms.
    const all = await f.call('/v1/machine/code?entry=' + e1 + '&source=all', { bearer: minted.token, machine: true });
    assert.equal(all.status, 200);
    assert.equal(all.headers.get('cache-control'), 'no-store');
    const allBody = await all.json();
    assert.deepEqual(Object.keys(allBody.codes).sort(), ['email', 'sms']);
    assert.equal(allBody.codes.email.code, '111111');
    assert.equal(allBody.codes.sms.code, '222222');
    // A single kind returns only that kind.
    const smsOnly = await (await f.call('/v1/machine/code?entry=' + e1 + '&source=sms', { bearer: minted.token, machine: true })).json();
    assert.deepEqual(Object.keys(smsOnly.codes), ['sms']);
    // Outside the profile: same 404 as an unknown entry. Bad shapes: 400. No token: 401.
    assert.equal((await f.call('/v1/machine/code?entry=' + e2 + '&source=all', { bearer: minted.token, machine: true })).status, 404);
    assert.equal((await f.call('/v1/machine/code?entry=' + e1 + '&source=bogus', { bearer: minted.token, machine: true })).status, 400);
    assert.equal((await f.call('/v1/machine/code?entry=' + e1 + '&source=all&x=1', { bearer: minted.token, machine: true })).status, 400);
    assert.equal((await f.call('/v1/machine/code?entry=' + e1 + '&source=all', { machine: true })).status, 401);

    // Recipient machines cannot exceed the parent grant: no delegation yet.
    const blocked = await f.call('/v1/manage/machine/profile/create', { bearer: recipient.issued.access, body: { name: 'm', mode: 'allow', entryIds: [e1] } });
    assert.equal(blocked.status, 400, 'no delegation, no machine profile over the shared entry');
    assert.deepEqual((await (await f.call('/v1/manage/machine/profiles/list', { bearer: recipient.issued.access, body: {} })).json()).profiles, []);

    // Owner turns delegation on; recipient machine now reads within the grant.
    const ref = (await (await f.call('/v1/manage/sharing/contacts/list', { bearer: owner.issued.access, body: {} })).json()).contacts[0].contactRef;
    assert.equal((await f.call('/v1/manage/sharing/grant/update', { bearer: owner.issued.access, body: { contactRef: ref, mode: 'allow', entryIds: [e1], canDelegate: true } })).status, 200);
    const rProfile = await (await f.call('/v1/manage/machine/profile/create', { bearer: recipient.issued.access, body: { name: 'm', mode: 'allow', entryIds: [e1] } })).json();
    const rMinted = await (await f.call('/v1/manage/machine/token/create', { bearer: recipient.issued.access, body: { profileId: rProfile.profileId, ttlSeconds: 3600 } })).json();
    assert.equal((await f.call('/v1/machine/code?entry=' + e1 + '&source=sms', { bearer: rMinted.token, machine: true })).status, 200);
    // The delegated machine still cannot reach the owner's private entry.
    assert.equal((await f.call('/v1/machine/code?entry=' + e2 + '&source=all', { bearer: rMinted.token, machine: true })).status, 404);

    // Narrowing the grant to nothing (deny covering every owned entry) voids
    // the recipient's existing machine token at once.
    assert.equal((await f.call('/v1/manage/sharing/grant/update', { bearer: owner.issued.access, body: { contactRef: ref, mode: 'deny', entryIds: [e1, e2], canDelegate: true } })).status, 200);
    assert.equal((await f.call('/v1/machine/code?entry=' + e1 + '&source=sms', { bearer: rMinted.token, machine: true })).status, 404);
    // The recipient human read narrows the same way.
    const entries = await (await f.call('/v1/manage/entries', { bearer: recipient.issued.access })).json();
    assert.deepEqual(entries.entries, []);
  } finally {
    f.db.sqlite.close();
  }
});

test('public auth-only adapter gates sharing and distinct machine token boundary',async()=>{
 const {createAuthOnlyWorker}=await import('../src/auth-only-worker.js');
 const f=await fixture();try{
  const owner=await f.signup('adapter-owner@example.test','adapter-owner');
  const yes={limit:async()=>({success:true})};
  const env={DEPLOYMENT_STAGE:'auth-only',AUTH_ONLY_SIGNUP_MODE:'public',SHARING_ENABLED:'1',DB:f.db,ACTIVE_KEY_ID:'adapter',ENCRYPTION_KEYRING:JSON.stringify([{id:'adapter',key:Buffer.alloc(32,7).toString('base64url')}]),IDENTITY_ADDRESS_LIMIT:yes,IDENTITY_AUTH_GLOBAL_LIMIT:yes,IDENTITY_READ_GLOBAL_LIMIT:yes};
  const worker=createAuthOnlyWorker({clock:()=>NOW});
  const req=(path,{method='POST',origin=APP,bearer=owner.issued.access,body={}}={})=>Object.assign(new Request(API+path,{method,headers:{'CF-Connecting-IP':'192.0.2.19',...(origin===null?{}:{Origin:origin}),...(bearer?{Authorization:'Bearer '+bearer}:{}),...(method==='POST'?{'Content-Type':'application/json'}:{})},...(method==='POST'?{body:JSON.stringify(body)}:{})}),{cf:{colo:'TLV',httpProtocol:'HTTP/2',tlsVersion:'TLSv1.3'}});
  for(const flag of [undefined,'0','true']){const off=createAuthOnlyWorker({clock:()=>NOW});assert.equal((await off.fetch(req('/v1/manage/sharing/invite/list'),{...env,SHARING_ENABLED:flag})).status,404);assert.equal((await off.fetch(req('/v1/machine/code?entry=x&source=email',{method:'GET',origin:null}),{...env,SHARING_ENABLED:flag})).status,404);}
  const pre=new Request(API+'/v1/manage/sharing/invite/list',{method:'OPTIONS',headers:{Origin:APP,'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'Authorization, Content-Type'}});
  assert.equal((await worker.fetch(pre,env)).status,204);
  assert.equal((await worker.fetch(req('/v1/manage/sharing/invite/list'),env)).status,200);
  const entry=await f.sources.createEntry(owner.account.ownerId,'test','Adapter empty entry',NOW);
  const {importBrowserKeyring}=await import('../src/browser-keyring.js');const localSources=new SourceEntryStore(f.db,new CodeCipher(await importBrowserKeyring(env)));const source=await localSources.createSource(owner.account.ownerId,'gmail','Adapter source',NOW);await localSources.receive(owner.account.ownerId,{sourceId:source,eventId:'adapter-event',code:'765432',receivedAt:NOW,expiresAt:NOW+60000,entryIds:[entry]});
  await localSources.confirm(owner.account.ownerId,source,'adapter-event',entry,NOW);
  const profile=await (await worker.fetch(req('/v1/manage/machine/profile/create',{body:{mode:'all',entryIds:[],name:'Adapter'}}),env)).json();
  assert.ok(profile.profileId);
  const token=await(await worker.fetch(req('/v1/manage/machine/token/create',{body:{profileId:profile.profileId,ttlSeconds:3600}}),env)).json();assert.ok(token.token);
  const path='/v1/machine/code?entry='+entry+'&source=email';
  assert.equal((await worker.fetch(req(path,{method:'GET',origin:APP,bearer:token.token}),env)).status,403);
  assert.equal((await worker.fetch(req(path,{method:'GET',origin:'https://wrong.test',bearer:token.token}),env)).status,403);
  assert.equal((await worker.fetch(req(path,{method:'GET',origin:null}),env)).status,401); // session bearer is never a machine fallback
  const read=await worker.fetch(req(path,{method:'GET',origin:null,bearer:token.token}),env);assert.equal(read.status,200);assert.equal(read.headers.get('Access-Control-Allow-Origin'),null);
  assert.equal((await worker.fetch(req(path+'&entry=other',{method:'GET',origin:null,bearer:token.token}),env)).status,400);
  assert.equal((await worker.fetch(req('/v1/manage/machine/token/revoke',{body:{profileId:profile.profileId,tokenId:token.tokenId}}),env)).status,200);
  assert.equal((await worker.fetch(req(path,{method:'GET',origin:null,bearer:token.token}),env)).status,401);
 }finally{f.db.sqlite.close();}
});
