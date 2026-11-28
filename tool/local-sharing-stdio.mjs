import {createIdentityRuntime} from '../src/identity-runtime.js';
import { database } from '../test/sqlite-helper.js';
import { AccountIdentityService } from '../src/account-identity.js';
import { PasskeySignupService } from '../src/passkey-signup.js';
import { DeviceSessionService } from '../src/device-sessions.js';
import { CodeCipher } from '../src/code-cipher.js';
import { SourceEntryStore } from '../src/source-entries.js';
import { authenticator } from '../test/passkey-fixture.js';
import {createInterface} from 'node:readline';

const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',NOW=1800000000000;
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

const f=await fixture();const owner=await f.signup('owner@example.test','owner'),recipient=await f.signup('recipient@example.test','recipient');
for await(const line of createInterface({input:process.stdin})){
 try{const x=JSON.parse(line),r=await f.call(x.path,{bearer:(x.actor==='recipient'?recipient:owner).issued.access,body:x.body});console.log(JSON.stringify({status:r.status,body:await r.text()}));}
 catch{console.log(JSON.stringify({status:503,body:'{}'}));}
}
f.db.sqlite.close();
