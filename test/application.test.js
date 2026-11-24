import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { createApplication } from '../src/application.js';
import { SessionService, ownerForIdentity } from '../src/sessions.js';
import { D1TokenStore, D1CodeStore } from '../src/d1-store.js';
import { CodeCipher } from '../src/code-cipher.js';

test('composed application limits ingress, fails closed on database failure and cleans bounded records', async () => {
  const db = database();
  const now = Date.now();
  const sessions = new SessionService(db, { origin: 'https://app.test', clock: () => now });
  const key = await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);
  const codes = new D1CodeStore(db, new CodeCipher({keys:new Map([['test',key]]),activeKeyId:'test'}));
  const app = createApplication({ db, tokenStore: new D1TokenStore(db), codeStore: codes, sessions, trustedRequestKey: () => 'trusted-platform-source', clock: () => now });
  assert.equal((await app.fetch(new Request('https://app.test/auth/start'))).status,404);
  for(let i=0;i<59;i++) assert.equal((await app.fetch(new Request('https://app.test/health'))).status,200);
  assert.equal((await app.fetch(new Request('https://app.test/health'))).status,429);
  assert.equal((await app.fetch(new Request('https://wrong.test/health'))).status,404);
  const owner = await ownerForIdentity(db,'https://id.test','one',now-1000);
  await codes.put({ownerId:owner,recordId:'one',serviceId:'example.com',code:'123456',receivedAt:now-1000,expiresAt:now});
  await app.cleanup();
  assert.equal(db.sqlite.prepare('SELECT count(*) AS n FROM code_records').get().n,0);
  db.sqlite.close();
  assert.equal((await app.fetch(new Request('https://app.test/health'))).status,503);
});
