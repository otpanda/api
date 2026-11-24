import test from 'node:test';
import assert from 'node:assert/strict';
import {createAuthOnlyWorker} from '../src/auth-only-worker.js';
import {database} from './sqlite-helper.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io';
const yes={limit:async()=>({success:true})};
function request(path,{method='GET',headers={},body}={}) {
 const r=new Request(API+path,{method,headers:{'CF-Connecting-IP':'192.0.2.1',...headers},...(body?{body}:{})});
 Object.defineProperty(r,'cf',{value:{colo:'LHR',httpProtocol:'HTTP/2',tlsVersion:'TLSv1.3'}});return r;
}
function config(db) {return {DEPLOYMENT_STAGE:'auth-only',AUTH_ONLY_SIGNUP_EMAIL:'owner@example.test',DB:db,BREVO_API_KEY:'synthetic',BREVO_SENDER_EMAIL:'project@example.test',BREVO_REPLY_TO_EMAIL:'project@example.test',SIGNUP_ADDRESS_LIMIT:yes,SIGNUP_GLOBAL_LIMIT:yes,SIGNUP_VERIFY_ADDRESS_LIMIT:yes,SIGNUP_VERIFY_GLOBAL_LIMIT:yes,IDENTITY_ADDRESS_LIMIT:yes,IDENTITY_AUTH_GLOBAL_LIMIT:yes,IDENTITY_READ_GLOBAL_LIMIT:yes};}
test('deployment explicitly selects bounded public auth-only stage; other stages refused',async()=>{
 const fs=await import('node:fs/promises');const deployment=JSON.parse(await fs.readFile('wrangler.jsonc','utf8'));assert.equal(deployment.main,'src/auth-only-worker.js');assert.equal(deployment.vars.DEPLOYMENT_STAGE,'auth-only');assert.equal(deployment.vars.AUTH_ONLY_SIGNUP_MODE,'public');assert.equal(deployment.vars.AUTH_ONLY_SIGNUP_EMAIL,undefined);
 for(const env of [undefined,{}, {DEPLOYMENT_STAGE:'bootstrap'},{DEPLOYMENT_STAGE:'active'}])assert.equal((await createAuthOnlyWorker().fetch(request('/auth/signup/start'),env)).status,503);
});
test('auth-only stage cannot mount code source mutation recovery legacy or unknown paths',async()=>{
 const worker=createAuthOnlyWorker();let calls=0;const env=config({prepare(){calls++;throw Error('must not touch database');}});
 for(const path of ['/v1/manage/entries','/v1/manage/active-codes','/v1/manage/unassigned','/v1/manage/sources','/v1/manage/organization','/v1/manage/organization-copy','/v1/manage/assignment/begin','/auth/recovery','/auth/start','/v1/manage/session/'])for(const method of ['GET','POST','OPTIONS'])assert.equal((await worker.fetch(request(path,{method}),env)).status,404,path);
 assert.equal(calls,0);assert.equal((await worker.fetch(new Request('https://wrong.test/health'),env)).status,404);
 const health=await worker.fetch(request('/health'),env);assert.equal(health.status,200);assert.deepEqual(await health.json(),{service:'otpanda-api',status:'auth-only',authentication:'staged',codes:'unavailable',sources:'unavailable',recovery:'unavailable'});
});
test('production-shaped signup and protected session route work without cipher or invented ingress',async()=>{
 const db=database(),worker=createAuthOnlyWorker(),env=config(db),ctx={waitUntil(){}};
 try {
 const start=await worker.fetch(request('/auth/signup/app?'+new URLSearchParams({challenge:'a'.repeat(43),state:'b'.repeat(43),redirect_uri:APP+'/app/'})),env,ctx);assert.equal(start.status,200);assert.doesNotMatch(await start.text(),/<h1>|<button|<input/i);
 const session=await worker.fetch(request('/v1/manage/session',{headers:{Origin:APP}}),{...env},ctx);assert.equal(session.status,401);
 assert.equal((await worker.fetch(request('/v1/manage/session',{headers:{Origin:'https://wrong.test'}}),env,ctx)).status,403);
 assert.equal((await worker.fetch(request('/v1/manage/session',{headers:{Origin:APP,'CF-Worker':'untrusted.test'}}),env,ctx)).status,503);
 assert.equal((await worker.fetch(new Request(API+'/v1/manage/session',{headers:{Origin:APP,'CF-Connecting-IP':'192.0.2.1'}}),env,ctx)).status,503);
 for(const table of ['accounts','identities','sources','entries'])assert.equal(db.sqlite.prepare(`SELECT count(*) n FROM ${table}`).get().n,0);
 }finally{db.sqlite.close();}
});
test('permitted CORS preflight needs no bindings; denied methods remain denied',async()=>{
 const worker=createAuthOnlyWorker(),env={DEPLOYMENT_STAGE:'auth-only'};
 for(const [path,method,headers] of [['/auth/signup/verify','POST','Content-Type'],['/auth/login/verify','POST','Content-Type'],['/auth/exchange','POST','Content-Type'],['/v1/manage/session','GET','Authorization']])assert.equal((await worker.fetch(request(path,{method:'OPTIONS',headers:{Origin:APP,'Access-Control-Request-Method':method,'Access-Control-Request-Headers':headers}}),env)).status,204);
 assert.equal((await worker.fetch(request('/v1/manage/session',{method:'OPTIONS',headers:{Origin:APP,'Access-Control-Request-Method':'PUT'}}),env)).status,403);
});
test('auth-only scheduled cleanup is capped and wrong stage performs no writes',async()=>{
 const db=database(),worker=createAuthOnlyWorker(),env=config(db);try{
 for(let i=0;i<105;i++)await db.prepare('INSERT INTO browser_logout_bindings VALUES (?,?)').bind('test-'+i,Date.now()-1).run();let work;
 await worker.scheduled({},env,{waitUntil(p){work=p;}});assert.ok(work);await work;assert.equal(db.sqlite.prepare('SELECT count(*) n FROM browser_logout_bindings').get().n,5);
 await worker.scheduled({},{...env,DEPLOYMENT_STAGE:'bootstrap'});assert.equal(db.sqlite.prepare('SELECT count(*) n FROM browser_logout_bindings').get().n,5);
 }finally{db.sqlite.close();}
});

test('auth-only readiness checks schema and configured budgets without consuming quotas or loading cipher',async()=>{
 const db=database(),worker=createAuthOnlyWorker(),env={...config(db),BREVO_SENDER_EMAIL:'otpanda.app@gmail.com',BREVO_REPLY_TO_EMAIL:'otpanda.app@gmail.com'};
 try {const r=await worker.fetch(request('/ready'),env);assert.equal(r.status,200);assert.equal((await r.json()).mail,'configured-not-delivery-proof');
 for(const change of [{IDENTITY_READ_GLOBAL_LIMIT:undefined},{BREVO_API_KEY:''},{BREVO_SENDER_EMAIL:'wrong@example.test'},{DB:{prepare(){throw Error('secret detail');}}}]){const failed=await worker.fetch(request('/ready'),{...env,...change});assert.equal(failed.status,503);assert.deepEqual(await failed.json(),{error:'unavailable'});}
 }finally{db.sqlite.close();}
});

test('legacy interactive signup routes immediately return to app, without HTML or side effects',async()=>{const db=database(),worker=createAuthOnlyWorker(),e={...config(db),AUTH_ONLY_SIGNUP_MODE:'public'};delete e.AUTH_ONLY_SIGNUP_EMAIL;for(const path of ['/auth/signup/start','/auth/signup/email','/auth/signup/begin'])for(const method of ['GET','POST']){const r=await worker.fetch(request(path,{method}),e,{waitUntil(){throw Error('must not send');}});assert.equal(r.status,303);assert.equal(r.headers.get('location'),'https://otpanda.github.io/app/');assert.equal(await r.text(),'');}assert.equal(db.sqlite.prepare('SELECT count(*) n FROM auth_challenges').get().n,0);});
test('additional-passkey routes mount behind session auth and bounded preflight',async()=>{const db=database(),worker=createAuthOnlyWorker(),env=config(db);try{for(const step of ['verify-begin','verify-finish','register-begin','register-finish']){const path='/v1/manage/passkey/add/'+step;assert.equal((await worker.fetch(request(path,{method:'OPTIONS',headers:{Origin:APP,'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'Authorization,Content-Type,X-OTPanda-Enrollment'}}),{DEPLOYMENT_STAGE:'auth-only'})).status,204);assert.equal((await worker.fetch(request(path,{method:'POST',headers:{Origin:APP,'Content-Type':'application/json'},body:'{}'}),env)).status,401);assert.equal((await worker.fetch(request(path,{method:'POST',headers:{Origin:'https://wrong.test','Content-Type':'application/json'},body:'{}'}),env)).status,403);}assert.equal(db.sqlite.prepare('SELECT count(*) n FROM passkey_add_authorizations').get().n,0);}finally{db.sqlite.close();}});
