import {APPROVAL_PATHS} from '../src/approvals-http.js';
import {lazyHttp} from '../src/lazy-http.js';
import test from 'node:test';import assert from 'node:assert/strict';
import {database} from './sqlite-helper.js';import {createIdentityRuntime} from '../src/identity-runtime.js';
import {SessionService,SESSION_COOKIE} from '../src/sessions.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',NOW=1800000000000;
async function config(){const db=database(),key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);return {db,keys:new Map([['test',key]]),activeKeyId:'test',trustedRequestKey:()=> '192.0.2.1',clock:()=>NOW};}
test('new composition rejects every legacy mutation, OIDC and unknown route without minting accounts',async()=>{const c=await config();try {const app=createIdentityRuntime(c);for(const path of ['/auth/start','/auth/callback','/v1/manage/logout','/v1/manage/tokens','/v1/codes/latest','/auth/login/other','/auth/signup','/v1/manage/entries/delete'])for(const method of ['GET','POST'])assert.equal((await app.fetch(new Request(API+path,{method}))).status,404,path);assert.equal(c.db.sqlite.prepare('SELECT count(*) AS n FROM accounts').get().n,0);assert.equal(c.db.sqlite.prepare('SELECT count(*) AS n FROM oauth_transactions').get().n,0);assert.equal((await app.fetch(new Request('https://wrong.test/auth/restore'))).status,404);await app.cleanup();}finally{c.db.sqlite.close();}});
test('legacy session cookie and arbitrary bearer never authorize new reads; host errors stay generic',async()=>{const c=await config();try {await c.db.prepare('INSERT INTO accounts VALUES (?,?)').bind('owner',NOW).run();const old=await new SessionService(c.db,{origin:API,clock:()=>NOW}).issue('owner'),app=createIdentityRuntime(c);for(const headers of [{cookie:SESSION_COOKIE+'='+old.session},{Authorization:'Bearer synthetic-token'}]) {const r=await app.fetch(new Request(API+'/v1/manage/session',{headers:{Origin:APP,...headers}}));assert.equal(r.status,401);assert.equal(r.headers.get('access-control-allow-credentials'),null);}assert.equal((await app.fetch(new Request(API+'/v1/manage/entries',{method:'POST',headers:{Origin:APP}}))).status,405);const bad=createIdentityRuntime({...c,trustedRequestKey(){throw Error('private failure');}}),r=await bad.fetch(new Request(API+'/v1/manage/session',{headers:{Origin:APP}}));assert.equal(r.status,503);assert.deepEqual(await r.json(),{error:'unavailable'});}finally{c.db.sqlite.close();}});

test('optional batch ignores injected dependencies and isolates invalid policy from existing routes',async()=>{const c=await config();try{
 const request=p=>new Request(API+p,{headers:{Origin:APP,Authorization:'Bearer untrusted'}});
 assert.equal((await createIdentityRuntime(c).fetch(request('/v1/manage/totp-codes?entry=a'))).status,404);
 const invalid=createIdentityRuntime({...c,batch:{horizonPolicy:{entryCap:999}}});
 assert.deepEqual(invalid.health,{batch:'invalid_configuration'});assert.equal(Object.isFrozen(invalid.health),true);
 assert.equal((await invalid.fetch(request('/v1/manage/totp-codes?entry=a'))).status,503);
 for(const p of ['/v1/manage/totp-code?entry=a','/v1/manage/session'])assert.equal((await invalid.fetch(request(p))).status,401);
 assert.deepEqual(createIdentityRuntime(c).health,{batch:'disabled'});
 let hostile=0;const app=createIdentityRuntime({...c,batch:{horizonPolicy:{entryCap:2,budget:10,minPeriod:20,maxPeriod:86400,maxWindow:600,minUsefulWindow:40},ratePerMinute:24,minRemainingMs:1000,sessions:{authenticate(){hostile++;return{ownerId:'a'}}},generator:{generateWindowForActor(){hostile++;return{}}},db:{},clock:()=>NaN}});
 assert.deepEqual(app.health,{batch:'ready'});
 assert.equal((await app.fetch(request('/v1/manage/totp-codes?entry=a'))).status,401);assert.equal(hostile,0);
 }finally{c.db.sqlite.close();}});

test('all lazy HTTP routes construct on first use and fail generically without a session',async()=>{const c=await config();try{
 const app=createIdentityRuntime(c);
 const paths=['/auth/login/start','/auth/restore','/auth/device/logout','/v1/manage/session','/v1/manage/totp-code?entry=a','/v1/manage/totp','/v1/manage/security/status','/v1/manage/first-passkey/begin','/v1/manage/passkey/add/verify-begin','/v1/manage/recovery/status','/v1/manage/session/describe','/v1/manage/passkey/rename','/v1/manage/account','/v1/manage/google/link/ticket','/v1/manage/organization','/v1/manage/assignment/begin','/v1/manage/entry/domains','/v1/manage/entry/rename'];
 for(const path of paths){const r=await app.fetch(new Request(API+path,{headers:{Origin:APP}}));assert.ok([200,400,401,403,405].includes(r.status),path+' '+r.status);assert.equal((await r.text()).includes('TypeError'),false);}
 const broken=createIdentityRuntime({...c,db:new Proxy(c.db,{get(target,key){if(key==='prepare')return()=>{throw Error('private constructor or DB detail');};return target[key];}})});
 const r=await broken.fetch(new Request(API+'/v1/manage/session',{headers:{Origin:APP,Authorization:'Bearer a.b'}}));assert.ok([401,503].includes(r.status));assert.equal((await r.text()).includes('private'),false);
 assert.equal((await broken.fetch(new Request(API+'/unknown'))).status,404);
 const nativeApp=createIdentityRuntime({...c,native:{enabled:true}});for(const path of ['/v1/manage/device-key/enroll-begin','/v1/manage/device-key/adopt-begin',...APPROVAL_PATHS]){const r=await nativeApp.fetch(new Request(API+path,{headers:{Origin:APP}}));assert.ok([400,401,403,405].includes(r.status),path+' '+r.status);}

}finally{c.db.sqlite.close();}});

test('throwing lazy factory returns generic 503 with no partial/detail leak and other handlers work',async()=>{let attempts=0;const handler=lazyHttp(()=>{attempts++;throw Error('private constructor detail')});const okay=lazyHttp(()=>({fetch:()=>Response.json({ok:true})}));for(let n=0;n<2;n++){const response=await handler.fetch(new Request(API,{headers:{Origin:APP}}));assert.equal(response.status,503);assert.equal(response.headers.get('access-control-allow-origin'),APP);assert.equal(response.headers.get('cache-control'),'no-store');assert.equal(response.headers.get('x-content-type-options'),'nosniff');assert.deepEqual(await response.json(),{error:'unavailable'});assert.equal((await okay.fetch(new Request(API))).status,200);}assert.equal(attempts,2);});

test('deployment batch config absent stays disabled and malformed/falsy present fails isolated',async()=>{const {batchConfiguration}=await import('../src/browser-worker-adapter.js');assert.equal(batchConfiguration({}),undefined);for(const value of ['null','false','0','{}','broken']){const c=await config();try{const app=createIdentityRuntime({...c,batch:batchConfiguration({TOTP_BATCH_CONFIGURATION:value})});assert.equal(app.health.batch,'invalid_configuration');assert.equal((await app.fetch(new Request(API+'/v1/manage/totp-codes?entry=a',{headers:{Origin:APP}}))).status,503);assert.equal((await app.fetch(new Request(API+'/v1/manage/session',{headers:{Origin:APP}}))).status,401);}finally{c.db.sqlite.close();}}});
