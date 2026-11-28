import {createIdentityRuntime} from '../src/identity-runtime.js';
import { database as sqliteDatabase } from '../test/sqlite-helper.js';
const database=process.env.IMPORT_LOCAL_D1==='1'?(await import('./local-d1-fixture.mjs')).localDatabase:sqliteDatabase;
import { AccountIdentityService } from '../src/account-identity.js';
import { PasskeySignupService } from '../src/passkey-signup.js';
import { DeviceSessionService } from '../src/device-sessions.js';
import { CodeCipher } from '../src/code-cipher.js';
import { SourceEntryStore } from '../src/source-entries.js';
import { authenticator } from '../test/passkey-fixture.js';
import {createInterface} from 'node:readline';

let syntheticAuthenticator;let counter=0;let fenceNext=false,lastFinish;const trace=[];
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',NOW=Date.now();
async function fixture() {
  const db = await database();
  let now = NOW;
  const clock = () => now;
  const sessions = new DeviceSessionService(db, { clock });
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const cipher = new CodeCipher({ keys: new Map([['test', key]]), activeKeyId: 'test' });
  const sources = new SourceEntryStore(db, cipher);
  // Actual identity runtime route composition, explicit local-only opt-in.
  const app=createIdentityRuntime({db,keys:new Map([['test',key]]),activeKeyId:'test',trustedRequestKey:()=> '192.0.2.3',clock,transfer:{batchImport:true}});
  async function signup(email, binding) {
    const identity = new AccountIdentityService(db, { clock });
    const signup = new PasskeySignupService(db, { clock });
    const e = await identity.issueEmailChallenge({ purpose: 'signup-email', email });
    const c = await signup.begin({ email, emailToken: e.token, binding });
    const a = authenticator();syntheticAuthenticator=a;
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

const f=await fixture();const owner=await f.signup('owner@example.test','owner');
const input=createInterface({input:process.stdin});
let closing;const close=()=>closing??=Promise.resolve(f.db.sqlite.close());
for(const sig of ['SIGTERM','SIGINT'])process.once(sig,()=>{input.close();process.stdin.destroy();void close();});
try{
console.log(JSON.stringify({access:owner.issued.access,deviceId:owner.issued.deviceId??owner.issued.device_id,expiresAt:owner.issued.accessExpiresAt,now:NOW}));
for await(const line of input){
 try{
 const x=JSON.parse(line);
 if(x.op==='shutdown'){console.log('{}');break;}
 if(x.op==='fenceNext'){fenceNext=true;console.log('{}');continue;}
 if(x.op==='lateFinish'){const r=await f.call('/v1/manage/totp/batch-finish',{bearer:owner.issued.access,body:lastFinish});console.log(JSON.stringify({status:r.status,body:await r.text()}));continue;}
 if(x.op==='assert'){console.log(JSON.stringify(syntheticAuthenticator.assertion({expected:x.options.challenge,counter:++counter})));continue;}
 if(x.op==='counts'){let out={};for(const t of ['entries','totp_seeds','totp_batch_imports','totp_import_admissions'])out[t]=(await f.db.prepare('SELECT count(*) n FROM '+t).first()).n;out.trace=trace;console.log(JSON.stringify(out));continue;}
 if(x.path?.endsWith('batch-finish')){lastFinish=x.body;if(fenceNext){fenceNext=false;await f.call('/v1/manage/totp/batch-outcome',{bearer:owner.issued.access,body:{protocol:2,admissionId:x.body.admissionId,batchNonce:x.body.batchNonce,fence:true}});}}
 const r=await f.call(x.path,{bearer:owner.issued.access,body:x.body});trace.push({path:x.path,status:r.status});console.log(JSON.stringify({status:r.status,body:await r.text()}));
 }catch(e){console.error(e);console.log(JSON.stringify({fixtureError:true}));process.exitCode=1;}
}
}finally{input.close();process.stdin.destroy();await close();}
