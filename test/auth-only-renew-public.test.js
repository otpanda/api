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
const body=JSON.stringify({lineage_id:'L'.repeat(20),expires_at:Date.now()+30000,signature:'A'.repeat(86)});
test('PUBLIC worker: /auth/renew preflight allows exactly authorization+content-type from the app origin only',async()=>{
 const db=database(),worker=createAuthOnlyWorker(),env=config(db),ctx={waitUntil(){}};
 try{
  const pre=(h,o=APP,m='POST')=>worker.fetch(request('/auth/renew',{method:'OPTIONS',headers:{Origin:o,'Access-Control-Request-Method':m,'Access-Control-Request-Headers':h}}),env,ctx);
  const ok=await pre('authorization, content-type');assert.equal(ok.status,204);
  const allow=ok.headers.get('access-control-allow-headers').toLowerCase().split(',').map(v=>v.trim()).sort();assert.deepEqual(allow,['authorization','content-type']);
  assert.equal(ok.headers.get('access-control-allow-origin'),APP);assert.notEqual(ok.headers.get('access-control-allow-credentials'),'true');
  assert.equal((await pre('content-type')).status,204);
  assert.equal((await pre('authorization, content-type, x-otpanda-enrollment')).status,403,'no extra header');
  assert.equal((await pre('authorization, content-type, x-evil')).status,403);
  assert.equal((await pre('authorization, content-type','https://wrong.test')).status,403);
  assert.equal((await pre('authorization, content-type',APP,'GET')).status,403);
  assert.equal((await pre('authorization, content-type',APP,'PUT')).status,403);
 }finally{db.sqlite.close();}});
test('PUBLIC worker: POST /auth/renew reaches the inner handler (401 for a bad bearer, never 403/503 from the outer layer); /auth/exchange preflight stays content-type only',async()=>{
 const db=database(),worker=createAuthOnlyWorker(),env=config(db),ctx={waitUntil(){}};
 try{
  const post=await worker.fetch(request('/auth/renew',{method:'POST',headers:{Origin:APP,'Content-Type':'application/json',Authorization:'Bearer otpda_'+'A'.repeat(55)},body}),env,ctx);assert.equal(post.status,401);assert.equal((await post.json()).error,'invalid_grant');
  assert.equal((await worker.fetch(request('/auth/renew',{method:'POST',headers:{Origin:'https://wrong.test','Content-Type':'application/json',Authorization:'Bearer otpda_'+'A'.repeat(55)},body}),env,ctx)).status,403);
  assert.equal((await worker.fetch(request('/auth/renew',{method:'GET',headers:{Origin:APP}}),env,ctx)).status,405);
  const ex=await worker.fetch(request('/auth/exchange',{method:'OPTIONS',headers:{Origin:APP,'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'authorization, content-type'}}),env,ctx);assert.equal(ex.status,403,'exchange must not allow authorization');
 }finally{db.sqlite.close();}});
