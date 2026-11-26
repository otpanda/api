import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
// Pins the callback path the live app bridge (app tool/session-bootstrap.js) requires.
// The app rejects any authorization URL whose redirect_uri differs, so both server sides must match it.
const APP_CALLBACK = '/sources/gmail/oauth/callback';
const read = f => readFileSync(new URL('../src/' + f, import.meta.url), 'utf8');
test('server callback path matches the live app bridge redirect_uri', () => {
  assert.ok(read('gmail-source-http.js').includes("CALLBACK='" + APP_CALLBACK + "'"));
  assert.ok(read('gmail-source-runtime.js').includes("redirectUri:API+'" + APP_CALLBACK + "'"));
  assert.ok(!/sources\/gmail\/callback/.test(read('gmail-source-http.js') + read('gmail-source-runtime.js')));
});
test('label-mode scopes equal the three scopes the app bridge accepts', async () => {
  const {GMAIL_SCOPES_LABEL_FILTER: s} = await import('../src/gmail-label-filter.js');
  assert.deepEqual([...s].sort(), ['https://www.googleapis.com/auth/gmail.labels', 'https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.settings.basic']);
});
import {createGmailSourceServices, createGmailCollectionHost} from '../src/gmail-source-runtime.js';
import {GMAIL_CODE_FILTER} from '../src/gmail-label-filter.js';
import {database} from './sqlite-helper.js';
const API = 'https://otpanda-api.abrahammurciano.workers.dev';
test('composition without GMAIL_DEV_MAILBOX is not built and routes answer 503 with no DB access', async () => {
  let calls = 0; const fail = () => { calls++; throw Error('no'); };
  const env = {DB: {prepare: fail}};
  await assert.rejects(createGmailSourceServices(env));
  const h = createGmailCollectionHost({fetchImpl: fail});
  for (const path of ['/v1/manage/gmail-source/status', '/sources/gmail/oauth/callback?state=a&code=b', '/sources/gmail/push'])
    assert.equal((await h.fetch(new Request(API + path, {method: path.endsWith('push') ? 'POST' : 'GET', headers: {origin: 'https://otpanda.github.io'}}), env)).status, 503);
  assert.deepEqual(await h.scheduled({}, env), {ready: false});
  assert.equal(calls, 0);
});
test('composition is label mode bound to one canonical dev mailbox, never INBOX mode', async () => {
  const k = new Uint8Array(32).fill(7);
  const env = {DB: database(), ACTIVE_KEY_ID: 'k1', ENCRYPTION_KEYRING: JSON.stringify([{id: 'k1', key: Buffer.from(k).toString('base64url')}]), GMAIL_SOURCE_CLIENT_ID: 'cid', GMAIL_SOURCE_CLIENT_SECRET: 'sec', GMAIL_DEV_MAILBOX: ' Dev.Box@Example.TEST '};
  let svc; try { svc = await createGmailSourceServices(env); } catch (e) { assert.fail('keyring env shape: ' + e.message); }
  assert.equal(svc.sync.labelFilter, GMAIL_CODE_FILTER);
  assert.equal(svc.devMailbox, 'dev.box@example.test');
  assert.equal(svc.oauth.devMailbox, 'dev.box@example.test');
  assert.equal(svc.oauth.scopes().length, 3);
  env.DB.sqlite?.close?.();
});
