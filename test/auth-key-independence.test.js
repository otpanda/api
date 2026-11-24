import test from 'node:test';
import assert from 'node:assert/strict';
import {database} from './sqlite-helper.js';
import {createIdentityRuntime} from '../src/identity-runtime.js';
import {createBrowserWorkerAdapter} from '../src/browser-worker-adapter.js';
import {base64urlEncode} from '../src/tokens.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io';
const opaque=()=>base64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
const start=()=>new Request(API+'/auth/login/start?'+new URLSearchParams({challenge:opaque(),state:opaque(),redirect_uri:APP+'/app/'}));
test('login start and unauthorized session work without encryption keys, no key callback',async()=>{
 const db=database();let calls=0;
 try{
  const app=createIdentityRuntime({db,trustedRequestKey:()=> '192.0.2.1',loadCodeKeys(){calls++;throw Error('private key unavailable');}});
  const r=await app.fetch(start());assert.equal(r.status,303);assert.ok(r.headers.get('location').startsWith(APP+'/app/#login='));
  for(const path of ['session','entries','active-codes','unassigned','sources']){
   const denied=await app.fetch(new Request(API+'/v1/manage/'+path,{headers:{Origin:APP}}));assert.equal(denied.status,401);
  }
  assert.equal(calls,0);
  assert.equal(db.sqlite.prepare('SELECT count(*) AS n FROM accounts').get().n,0);
 }finally{db.sqlite.close();}
});
test('worker login initializes without touching absent code key bindings',async()=>{
 const db=database(),yes={limit:async()=>({success:true})};
 try{
  const adapter=createBrowserWorkerAdapter({resolveTrustedIngress:()=> '192.0.2.1'});
  const env={DB:db,IDENTITY_ADDRESS_LIMIT:yes,IDENTITY_AUTH_GLOBAL_LIMIT:yes,IDENTITY_READ_GLOBAL_LIMIT:yes};
  const r=await adapter.fetch(start(),env);assert.equal(r.status,303);
  const denied=await adapter.fetch(new Request(API+'/v1/manage/session',{headers:{Origin:APP}}),env);assert.equal(denied.status,401);
 }finally{db.sqlite.close();}
});
import {AccountIdentityService} from '../src/account-identity.js';
import {PasskeySignupService} from '../src/passkey-signup.js';
import {authenticator} from './passkey-fixture.js';
import {pkceChallenge} from '../src/browser-exchanges.js';
test('cryptographic login completion and session work keyless; encrypted reads stay503 and key failure is cached',async()=>{
 const db=database(),a=authenticator();let calls=0;
 try{
  const identity=new AccountIdentityService(db),signup=new PasskeySignupService(db),email='keyless@example.test';
  const e=await identity.issueEmailChallenge({purpose:'signup-email',email}),c=await signup.begin({email,emailToken:e.token,binding:'synthetic-setup'});
  const account=await signup.finish({token:c.token,binding:'synthetic-setup',response:a.registration({expected:c.options.challenge})});
  const app=createIdentityRuntime({db,trustedRequestKey:()=> '192.0.2.1',loadCodeKeys(){calls++;throw Error('private configuration');}});
  const verifier=opaque(),q=new URLSearchParams({challenge:await pkceChallenge(verifier),state:opaque(),redirect_uri:APP+'/app/'});
  const begin=await app.fetch(new Request(API+'/auth/login/start?'+q));assert.equal(begin.status,303);
  const binding=begin.headers.get('set-cookie').split(';')[0];
  const challenge=JSON.parse(Buffer.from(new URLSearchParams(new URL(begin.headers.get('location')).hash.slice(1)).get('login'),'base64url'));
  const response=a.assertion({expected:challenge.options.challenge});response.response.userHandle=Buffer.from(account.ownerId).toString('base64url');
  const verified=await app.fetch(new Request(API+'/auth/login/verify',{method:'POST',headers:{Origin:APP,'Content-Type':'application/json'},body:JSON.stringify({token:challenge.token,response})}));assert.equal(verified.status,200);
  const h=await verified.json(),page=await app.fetch(new Request(API+'/auth/login/complete'));
  const csrf=page.headers.get('set-cookie').split(';')[0];
  const complete=await app.fetch(new Request(API+'/auth/login/complete',{method:'POST',headers:{Origin:API,'Content-Type':'application/x-www-form-urlencoded',Cookie:binding+'; '+csrf},body:new URLSearchParams({csrf:csrf.slice(csrf.indexOf('=')+1),handoff:h.handoff})}));assert.equal(complete.status,303);
  const grant=new URLSearchParams(new URL(complete.headers.get('location')).hash.slice(1));
  const exchanged=await app.fetch(new Request(API+'/auth/exchange',{method:'POST',headers:{Origin:APP,'Content-Type':'application/json'},body:JSON.stringify({code:grant.get('code'),verifier,redirect_uri:APP+'/app/'})}));
  assert.equal(exchanged.status,200);const result=await exchanged.json();
  const read=path=>app.fetch(new Request(API+'/v1/manage/'+path,{headers:{Origin:APP,Authorization:'Bearer '+result.access}}));
  assert.equal((await read('session')).status,200);assert.equal((await read('entries')).status,200);assert.equal(calls,0);
  for(const path of ['active-codes','unassigned','sources']){const denied=await read(path);assert.equal(denied.status,503);assert.equal(denied.headers.get('access-control-allow-origin'),APP);assert.equal(denied.headers.get('vary'),'Origin');assert.equal(denied.headers.get('cache-control'),'no-store');assert.equal(denied.headers.get('access-control-allow-credentials'),null);assert.deepEqual(await denied.json(),{error:'unavailable'});}
  assert.equal(calls,1);assert.equal((await read('session')).status,200);
 }finally{db.sqlite.close();}
});

import {DeviceSessionService} from '../src/device-sessions.js';
async function authorizedFixture(loadCodeKeys){
 const db=database(),identity=new AccountIdentityService(db),signup=new PasskeySignupService(db),email='lazy@example.test',a=authenticator();
 const e=await identity.issueEmailChallenge({purpose:'signup-email',email}),c=await signup.begin({email,emailToken:e.token,binding:'lazy-fixture'});
 const account=await signup.finish({token:c.token,binding:'lazy-fixture',response:a.registration({expected:c.options.challenge})});
 const sessions=new DeviceSessionService(db),issued=await sessions.issue({proof:{...account,purpose:'authenticate',verifiedAt:Date.now()},clientKind:'web'});
 const app=createIdentityRuntime({db,trustedRequestKey:()=> '192.0.2.1',loadCodeKeys});
 const read=(path,origin=APP)=>app.fetch(new Request(API+'/v1/manage/'+path,{headers:{Origin:origin,Authorization:'Bearer '+issued.access}}));
 return{db,read,sessions,issued,account};
}
test('successful lazy import is shared by concurrent reads and skips wrong-origin requests',async()=>{
 let calls=0,release,enter;const gate=new Promise(r=>release=r),entered=new Promise(r=>enter=r);
 const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);
 const f=await authorizedFixture(async()=>{calls++;enter();await gate;return{keys:new Map([['test',key]]),activeKeyId:'test'};});
 try{
  assert.equal((await f.read('sources','https://evil.test')).status,403);assert.equal(calls,0);
  const requests=['active-codes','sources','unassigned'].map(path=>f.read(path));
  await entered;assert.equal(calls,1);release();
  for(const response of await Promise.all(requests)){assert.equal(response.status,200);assert.equal(response.headers.get('access-control-allow-origin'),APP);}
  assert.equal((await f.read('sources')).status,200);assert.equal(calls,1);
 }finally{release();f.db.sqlite.close();}
});
test('revocation during successful lazy import wins before response',async()=>{
 let release,enter;const gate=new Promise(r=>release=r),entered=new Promise(r=>enter=r),key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);
 const f=await authorizedFixture(async()=>{enter();await gate;return{keys:new Map([['test',key]]),activeKeyId:'test'};});
 try{const pending=f.read('sources');await entered;await f.sessions.revoke({ownerId:f.account.ownerId,deviceId:f.issued.deviceId});release();const response=await pending;assert.equal(response.status,401);assert.equal(response.headers.get('access-control-allow-origin'),APP);}finally{release();f.db.sqlite.close();}
});
