import test from 'node:test';
import assert from 'node:assert/strict';
import {database} from './sqlite-helper.js';
import {createAuthOnlyWorker} from '../src/auth-only-worker.js';
const API='https://otpanda-api.abrahammurciano.workers.dev';
const yes={limit:async()=>({success:true})};
function env(db){return {DEPLOYMENT_STAGE:'auth-only',AUTH_ONLY_SIGNUP_MODE:'public',DB:db,BREVO_API_KEY:'synthetic',BREVO_SENDER_EMAIL:'otpanda.app@gmail.com',BREVO_REPLY_TO_EMAIL:'otpanda.app@gmail.com',SIGNUP_ADDRESS_LIMIT:yes,SIGNUP_GLOBAL_LIMIT:yes,SIGNUP_VERIFY_ADDRESS_LIMIT:yes,SIGNUP_VERIFY_GLOBAL_LIMIT:yes,IDENTITY_ADDRESS_LIMIT:yes,IDENTITY_AUTH_GLOBAL_LIMIT:yes,IDENTITY_READ_GLOBAL_LIMIT:yes};}
function req(path,options={}){const r=new Request(API+path,{...options,headers:{'CF-Connecting-IP':'192.0.2.1',...options.headers}});Object.defineProperty(r,'cf',{value:{colo:'LHR',httpProtocol:'HTTP/2',tlsVersion:'TLSv1.3'}});return r;}
const start='/auth/signup/app?'+new URLSearchParams({challenge:'a'.repeat(43),state:'b'.repeat(43),redirect_uri:'https://otpanda.github.io/app/'});
test('explicit public readiness accepts no owner binding, rejects ambiguous policy, and latches changes',async()=>{
 const db=database();try{
 const e=env(db),w=createAuthOnlyWorker();assert.equal((await w.fetch(req('/ready'),e)).status,200);
 assert.equal((await w.fetch(req('/ready'),{...e,AUTH_ONLY_SIGNUP_MODE:'owner',AUTH_ONLY_SIGNUP_EMAIL:'owner@example.test'})).status,503);
 assert.equal((await w.fetch(req('/ready'),e)).status,503);
 for(const mode of ['', '*','PUBLIC','public,owner',undefined]){const bad={...e,AUTH_ONLY_SIGNUP_MODE:mode};assert.equal((await createAuthOnlyWorker().fetch(req('/ready'),bad)).status,503);}
 for(const email of ['', '*','owner@example.test'])assert.equal((await createAuthOnlyWorker().fetch(req('/ready'),{...e,AUTH_ONLY_SIGNUP_EMAIL:email})).status,503);
 const owner={...e,AUTH_ONLY_SIGNUP_MODE:'owner',AUTH_ONLY_SIGNUP_EMAIL:'owner@example.test'},o=createAuthOnlyWorker();assert.equal((await o.fetch(req('/ready'),owner)).status,200);assert.equal((await o.fetch(req('/ready'),e)).status,503);assert.equal((await o.fetch(req('/ready'),owner)).status,503);
 }finally{db.sqlite.close();}
});
test('public HTTP issues two distinct verified-mail challenges without owner allowlist and preserves recipient quota',async()=>{
 const db=database(),e=env(db),sent=[],pending=[],w=createAuthOnlyWorker({fetchImpl:async(url,options)=>{sent.push(JSON.parse(options.body));return new Response(JSON.stringify({messageId:'synthetic'}),{status:201});}}),ctx={waitUntil:p=>pending.push(p)};
 try{
 for(const email of ['first@example.test','friend@example.test','friend@example.test','friend@example.test','friend@example.test']){
 const r=await w.fetch(req(start),e,ctx);assert.equal(r.status,200);const cookies=r.headers.getSetCookie().map(x=>x.split(';')[0]),csrf=cookies.find(x=>x.startsWith('__Host-otpanda_signup_csrf=')).split('=')[1];
 const response=await w.fetch(req(start,{method:'POST',headers:{Origin:API,'Content-Type':'application/x-www-form-urlencoded',Cookie:cookies.join('; ')},body:new URLSearchParams({action:'email',email,csrf})}),e,ctx);assert.equal(response.status,303);await Promise.all(pending);
 }
 assert.equal(sent.length,4);assert.deepEqual(sent.map(x=>x.to[0].email),['first@example.test','friend@example.test','friend@example.test','friend@example.test']);assert.equal(db.sqlite.prepare('SELECT count(*) n FROM auth_challenges').get().n,4);assert.equal(db.sqlite.prepare('SELECT count(*) n FROM accounts').get().n,0);
 for(const path of ['/v1/manage/entries','/auth/recovery','/v1/manage/sources'])assert.equal((await w.fetch(req(path),e,ctx)).status,404);
 // Scope changes poison only signup. Existing-account unauthenticated login/session still respond normally.
 assert.equal((await w.fetch(req(start),{...e,AUTH_ONLY_SIGNUP_MODE:'invalid'},ctx)).status,503);
 assert.equal((await w.fetch(req('/v1/manage/session',{headers:{Origin:'https://otpanda.github.io'}}),e,ctx)).status,401);
 }finally{db.sqlite.close();}
});
