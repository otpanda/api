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
 for(const path of ['/auth/recovery','/auth/start','/v1/manage/session/'])for(const method of ['GET','POST','OPTIONS'])assert.equal((await worker.fetch(request(path,{method}),env)).status,404,path);
 assert.equal(calls,0);assert.equal((await worker.fetch(new Request('https://wrong.test/health'),env)).status,404);
 const health=await worker.fetch(request('/health'),env);assert.equal(health.status,200);assert.deepEqual(await health.json(),{service:'otpanda-api',status:'auth-only',authentication:'staged',codes:'authenticated-received-and-totp',totp:'passkey-enrollment-code-only-read',sources:'authenticated-read-only',recovery:'email-escape-opt-in',enrolledClientApproval:'unavailable'});
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
 try {const r=await worker.fetch(request('/ready'),env);assert.equal(r.status,200);{const j=await r.json();assert.equal(j.mail,'configured-not-delivery-proof');assert.equal(j.recoveryDelivery,'ok');}
 for(const change of [{IDENTITY_READ_GLOBAL_LIMIT:undefined},{BREVO_API_KEY:''},{BREVO_SENDER_EMAIL:'wrong@example.test'},{DB:{prepare(){throw Error('secret detail');}}}]){const failed=await worker.fetch(request('/ready'),{...env,...change});assert.equal(failed.status,503);assert.deepEqual(await failed.json(),{error:'unavailable'});}
 }finally{db.sqlite.close();}
});

test('legacy interactive signup routes immediately return to app, without HTML or side effects',async()=>{const db=database(),worker=createAuthOnlyWorker(),e={...config(db),AUTH_ONLY_SIGNUP_MODE:'public'};delete e.AUTH_ONLY_SIGNUP_EMAIL;for(const path of ['/auth/signup/start','/auth/signup/email','/auth/signup/begin'])for(const method of ['GET','POST']){const r=await worker.fetch(request(path,{method}),e,{waitUntil(){throw Error('must not send');}});assert.equal(r.status,303);assert.equal(r.headers.get('location'),'https://otpanda.github.io/app/');assert.equal(await r.text(),'');}assert.equal(db.sqlite.prepare('SELECT count(*) n FROM auth_challenges').get().n,0);});
test('additional-passkey routes mount behind session auth and bounded preflight',async()=>{const db=database(),worker=createAuthOnlyWorker(),env=config(db);try{for(const step of ['verify-begin','verify-finish','register-begin','register-finish']){const path='/v1/manage/passkey/add/'+step;assert.equal((await worker.fetch(request(path,{method:'OPTIONS',headers:{Origin:APP,'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'Authorization,Content-Type,X-OTPanda-Enrollment'}}),{DEPLOYMENT_STAGE:'auth-only'})).status,204);assert.equal((await worker.fetch(request(path,{method:'POST',headers:{Origin:APP,'Content-Type':'application/json'},body:'{}'}),env)).status,401);assert.equal((await worker.fetch(request(path,{method:'POST',headers:{Origin:'https://wrong.test','Content-Type':'application/json'},body:'{}'}),env)).status,403);}assert.equal(db.sqlite.prepare('SELECT count(*) n FROM passkey_add_authorizations').get().n,0);}finally{db.sqlite.close();}});
test('all mounted auth GET surfaces are redirects or noninteractive blank bridges',async()=>{const db=database(),worker=createAuthOnlyWorker(),env=config(db),query='?'+new URLSearchParams({challenge:'a'.repeat(43),state:'b'.repeat(43),redirect_uri:APP+'/app/'});try{const routes=['/auth/signup/app'+query,'/auth/signup/start','/auth/signup/email','/auth/signup/begin','/auth/signup/verify','/auth/login/start'+query,'/auth/login/verify','/auth/login/complete','/auth/restore'+query,'/auth/exchange','/auth/device/logout','/auth/google/start'+query,'/auth/callback',...['email','begin','verify','complete'].map(p=>'/auth/google/continue/'+p),...['status','begin','verify','complete'].map(p=>'/auth/google/protection/'+p)];for(const path of routes){const r=await worker.fetch(request(path),env,{waitUntil(){}});const body=await r.text();assert.doesNotMatch(body,/<(?:button|h[1-6]|a|select|textarea)\b/i,path);assert.doesNotMatch(body,/<input\b(?![^>]*type=["']hidden["'])/i,path);if(r.headers.get('content-type')?.includes('text/html')){const visible=body.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi,'').replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi,'').replace(/<head\b[^>]*>[\s\S]*?<\/head>/gi,'').replace(/<title\b[^>]*>[\s\S]*?<\/title>/gi,'').replace(/<[^>]*>/g,'').trim();assert.equal(visible,'',path);}}}finally{db.sqlite.close();}});
test('invalid top-level links return to app without weakening POST or fetch denials',async()=>{const db=database(),worker=createAuthOnlyWorker(),env=config(db);try{for(const path of ['/auth/restore?invalid=yes','/auth/device/logout?invalid=yes','/auth/login/start?invalid=yes','/auth/login/complete?invalid=yes']){const r=await worker.fetch(request(path),env);assert.equal(r.status,303);assert.ok(r.headers.get('location').startsWith(APP+'/app/#auth='+(path.startsWith('/auth/device/logout')?'logout-incomplete':'restart')));assert.equal(await r.text(),'');}assert.equal((await worker.fetch(request('/auth/device/logout',{method:'POST',headers:{Origin:API,'Content-Type':'application/x-www-form-urlencoded'},body:'csrf=wrong'}),env)).status,403);}finally{db.sqlite.close();}});

test('read-only data routes require device access and never mount legacy mutations',async()=>{const db=database(),worker=createAuthOnlyWorker(),env=config(db);try{for(const path of ['/v1/manage/entries','/v1/manage/active-codes','/v1/manage/unassigned','/v1/manage/sources']){assert.equal((await worker.fetch(request(path,{headers:{Origin:APP}}),env)).status,401);assert.equal((await worker.fetch(request(path,{headers:{Origin:'https://wrong.test'}}),env)).status,403);assert.equal((await worker.fetch(request(path,{method:'OPTIONS',headers:{Origin:APP,'Access-Control-Request-Method':'GET','Access-Control-Request-Headers':'Authorization'}}),{DEPLOYMENT_STAGE:'auth-only'})).status,204);for(const method of ['POST','PATCH','DELETE'])assert.equal((await worker.fetch(request(path,{method,headers:{Origin:APP,'Content-Type':'application/json'},body:'{}'}),env)).status,405);}for(const path of ['/v1/manage/entries/delete','/v1/manage/revoke-source','/v1/manage/tokens'])assert.equal((await worker.fetch(request(path,{method:'POST',headers:{Origin:APP,'Content-Type':'application/json'},body:'{}'}),env)).status,404);}finally{db.sqlite.close();}});

test('signed-in Google link routes are mounted in the actual auth-only deployment entry, not 404',async()=>{
 const db=database(),worker=createAuthOnlyWorker(),env=config(db),ctx={waitUntil(){}};
 try{
  const pre=await worker.fetch(request('/v1/manage/google/link/ticket',{method:'OPTIONS',headers:{Origin:APP,'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'authorization, content-type'}}),env,ctx);assert.equal(pre.status,204);
  const t=await worker.fetch(request('/v1/manage/google/link/ticket',{method:'POST',headers:{Origin:APP,'Content-Type':'application/json'},body:JSON.stringify({state:'s'.repeat(43)})}),env,ctx);assert.equal(t.status,401,'mounted and authenticating, not 404');
  assert.equal((await worker.fetch(request('/v1/manage/google/link/ticket',{method:'GET',headers:{Origin:APP}}),env,ctx)).status,405);
  const s=await worker.fetch(request('/auth/google/link/start?ticket='+'x'.repeat(43)),env,ctx);assert.notEqual(s.status,404,'link start is mounted');
  const post=await worker.fetch(request('/auth/google/link/start',{method:'POST',headers:{Origin:API}}),env,ctx);assert.notEqual(post.status,200);assert.notEqual(post.status,404);assert.equal(post.headers.getSetCookie().length,0);
 }finally{db.sqlite.close?.();}
});
test('native Android routes are mounted in the auth-only entry: JSON, no CORS, no Origin, fail closed without config',async()=>{
 const db=database(),worker=createAuthOnlyWorker(),env={...config(db),NATIVE_AUTH_ENABLED:'1'},ctx={waitUntil(){}},go=(p,o={})=>worker.fetch(request(p,o),env,ctx);
 try{
  const post={method:'POST',headers:{'Content-Type':'application/json'},body:'{}'};
  for(const p of ['exchange','challenge','renew','logout'])assert.equal((await go('/auth/native/'+p,post)).status,400,p+' mounted: strict body check, not 404');
  assert.equal((await go('/auth/native/exchange',{...post,headers:{...post.headers,Origin:APP}})).status,403,'browser origins refused');
  assert.equal((await go('/auth/native/exchange',{method:'GET'})).status,405);
  assert.equal((await go('/auth/native/exchange?x=1',post)).status,403,'no query');
  for(const p of ['begin','complete'])assert.equal((await go('/auth/native/google/'+p,post)).status,503,'google fails closed without audience/JWKS');
  assert.equal((await go('/auth/native/nope',post)).status,404);
  const approve=await go('/auth/native/approve');assert.equal(approve.status,400);assert.equal(approve.headers.get('access-control-allow-origin'),null);
  const landing=await go('/app-return');assert.equal(landing.status,200);assert.match(landing.headers.get('content-type'),/text\/html/);assert.equal(landing.headers.get('access-control-allow-origin'),null);
  assert.equal((await go('/.well-known/assetlinks.json')).status,404,'no fingerprints, fail closed');
  assert.equal((await go('/app-return',{method:'POST'})).status,405);
 }finally{db.sqlite.close?.();}
});
test('native assetlinks serves only configured SHA-256 signer fingerprints; approve POST needs the API origin',async()=>{
 const db=database(),worker=createAuthOnlyWorker(),fp=Array.from({length:32},(_,i)=>(i*7%256).toString(16).padStart(2,'0').toUpperCase()).join(':'),env={...config(db),NATIVE_AUTH_ENABLED:'1',NATIVE_ASSET_FINGERPRINTS:fp},ctx={waitUntil(){}};
 try{
  const r=await worker.fetch(request('/.well-known/assetlinks.json'),env,ctx);assert.equal(r.status,200);
  assert.deepEqual(await r.json(),[{relation:['delegate_permission/common.handle_all_urls'],target:{namespace:'android_app',package_name:'app.otpanda',sha256_cert_fingerprints:[fp]}}]);
  const post={method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'x=1'};
  assert.equal((await worker.fetch(request('/auth/native/approve',post),env,ctx)).status,403);
  assert.equal((await worker.fetch(request('/auth/native/approve',{...post,headers:{...post.headers,Origin:APP}}),env,ctx)).status,403);
 }finally{db.sqlite.close?.();}
});

test('native Android routes are OFF by default: every native path is 404 before any database or limiter access, flag must be exactly 1',async()=>{
 const touched=[],db=new Proxy(database(),{get(t,k){touched.push(String(k));return t[k];}});
 const base=config(db),limiter={limit:async()=>{touched.push('limiter');return {success:true};}};
 const paths=['/auth/native/exchange','/auth/native/challenge','/auth/native/renew','/auth/native/logout','/auth/native/google/begin','/auth/native/google/complete','/auth/native/approve','/app-return','/.well-known/assetlinks.json'];
 try{
  for(const flag of [undefined,'','0','true','TRUE','yes',' 1','1 '])for(const p of paths)for(const method of ['GET','POST','OPTIONS']){
   const worker=createAuthOnlyWorker(),env={...base,IDENTITY_ADDRESS_LIMIT:limiter,IDENTITY_AUTH_GLOBAL_LIMIT:limiter,IDENTITY_READ_GLOBAL_LIMIT:limiter,NATIVE_ASSET_FINGERPRINTS:Array(32).fill('AB').join(':'),...(flag===undefined?{}:{NATIVE_AUTH_ENABLED:flag})};
   const before=touched.length,r=await worker.fetch(request(p,{method,headers:{'Content-Type':'application/json'},...(method==='POST'?{body:'{}'}:{})}),env,ctx0);
   assert.equal(r.status,404,String(flag)+' '+method+' '+p);assert.equal(touched.length,before,'no database or limiter use: '+p);
  }
 }finally{db.sqlite?.close?.();}
});
const ctx0={waitUntil(){}};
test('NATIVE_AUTH_ENABLED is part of the latched configuration: flipping it on a live isolate fails closed (503), never half-enables native',async()=>{
 const db=database(),worker=createAuthOnlyWorker(),env=config(db),ctx1={waitUntil(){}};
 const first=await worker.fetch(request('/v1/manage/session',{headers:{Origin:'https://otpanda.github.io',Authorization:'Bearer '+'a'.repeat(43)}}),env,ctx1);assert.notEqual(first.status,503);
 const flipped=await worker.fetch(request('/v1/manage/session',{headers:{Origin:'https://otpanda.github.io',Authorization:'Bearer '+'a'.repeat(43)}}),{...env,NATIVE_AUTH_ENABLED:'1'},ctx1);assert.equal(flipped.status,503);
 db.sqlite?.close?.();
});

test('actual auth-only ready reports cached read-only context health for off, valid, overdue and failed probes',async()=>{
 const secret=Array.from({length:32},(_,i)=>(i*7+13).toString(16).padStart(2,'0')).join(''),now=1800000000000;
 for(const c of [{name:'off empty',on:false,row:null,want:'ok'},{name:'off residual',on:false,row:{x:1},want:'attention'},{name:'valid empty',on:true,row:null,want:'ok'},{name:'valid overdue',on:true,row:{x:1},want:'attention'},{name:'probe failure',on:true,fail:true,want:'attention'}]){
  const raw=database();let probes=0,writes=0;const queries=[];
  const db={prepare(sql){queries.push(sql);if(sql.includes('unassigned_context')&&!/^\s*SELECT\b/i.test(sql))writes++;if(sql.includes('FROM unassigned_context')){probes++;assert.match(sql,/LIMIT 1/);assert.doesNotMatch(sql,/count\s*\(/i);const q={bind(){return q;},async first(){if(c.fail)throw Error('private-owner-source-secret');return c.row;}};return q;}return raw.prepare(sql);}};
  const worker=createAuthOnlyWorker({clock:()=>now}),env={...config(db),BREVO_SENDER_EMAIL:'otpanda.app@gmail.com',BREVO_REPLY_TO_EMAIL:'otpanda.app@gmail.com',...(c.on?{CONTEXT_DIGEST_SECRET:secret,CONTEXT_RETENTION_DAYS:'30'}:{})};
  try{
   const before=raw.sqlite.prepare('SELECT total_changes() n').get().n;
   const responses=await Promise.all(Array.from({length:4},()=>worker.fetch(request('/ready'),env)));
   for(const r of responses){assert.equal(r.status,200,c.name);const j=await r.json();assert.equal(j.context,c.want,c.name);assert.deepEqual(Object.keys(j).sort(),['application','context','database','edgeBindings','mail','recoveryDelivery','service','stage'].sort());assert.doesNotMatch(JSON.stringify(j),/private-owner|retain_until|context_id|fingerprint|sender|count/i);}
   assert.equal(probes,1,c.name+': concurrent cache');assert.equal(writes,0,queries.filter(q=>!/^\s*SELECT\b/i.test(q)).join(";"));assert.equal(raw.sqlite.prepare('SELECT total_changes() n').get().n,before);
   const cached=await worker.fetch(request('/ready'),env);assert.equal((await cached.json()).context,c.want);assert.equal(probes,1,c.name+': repeated cache');
   assert.ok(queries.filter(q=>q.includes('FROM unassigned_context')).every(q=>/^SELECT /i.test(q)));
  }finally{raw.sqlite.close();}
 }
});
