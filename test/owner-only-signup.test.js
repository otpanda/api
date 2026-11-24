import test from 'node:test';
import assert from 'node:assert/strict';
import {database} from './sqlite-helper.js';
import {createAuthOnlyWorker} from '../src/auth-only-worker.js';
import {SignupEmailService} from '../src/signup-email.js';
import {AccountIdentityService} from '../src/account-identity.js';
import {PasskeySignupService} from '../src/passkey-signup.js';
import {authenticator} from './passkey-fixture.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',NOW=1800000000000;
const request=()=>new Request(API+'/auth/signup/start');
test('auth-only signup fails closed with absent malformed removed or changed owner configuration',async()=>{
 for(const value of [undefined,'','*','a@example.test,b@example.test',' owner@example.test']) {
  const worker=createAuthOnlyWorker();assert.equal((await worker.fetch(request(),{DEPLOYMENT_STAGE:'auth-only',AUTH_ONLY_SIGNUP_EMAIL:value})).status,503);
 }
 const worker=createAuthOnlyWorker(),env={DEPLOYMENT_STAGE:'auth-only',AUTH_ONLY_SIGNUP_EMAIL:'owner@example.test'};
 // No binding means downstream503, but still latches policy before service use.
 assert.equal((await worker.fetch(request(),env)).status,503);
 assert.equal((await worker.fetch(request(),{...env,AUTH_ONLY_SIGNUP_EMAIL:'other@example.test'})).status,503);
 assert.equal((await worker.fetch(request(),env)).status,503);
});
test('denied mailbox produces no mail proof quota or account rows',async()=>{
 const db=database();let sent=0;try{
 const service=new SignupEmailService(db,{clock:()=>NOW,deliver:async()=>{sent++;},signupAllowed:e=>e==='owner@example.test'});
 assert.deepEqual(await service.request({email:'other@example.test',clientAddress:'trusted',cookieBinding:'a'.repeat(48)}),{status:'accepted'});
 assert.equal(sent,0);
 for(const table of ['auth_challenges','signup_mail_bindings','accounts','rate_buckets'])assert.equal(db.sqlite.prepare(`SELECT count(*) n FROM ${table}`).get().n,0);
 }finally{db.sqlite.close();}
});
async function setup(){const db=database();let allowed=true;const signupAllowed=e=>allowed&&e==='owner@example.test',identity=new AccountIdentityService(db,{clock:()=>NOW}),signup=new PasskeySignupService(db,{clock:()=>NOW,signupAllowed});const proof=await identity.issueEmailChallenge({purpose:'signup-email',email:'owner@example.test'});return{db,signup,proof,deny(){allowed=false;}};}
test('policy is enforced before beginning and again before persistent account creation',async()=>{
 const a=await setup();try{a.deny();assert.equal(await a.signup.begin({email:'owner@example.test',emailToken:a.proof.token,binding:'fixture'}),undefined);assert.equal(a.db.sqlite.prepare('SELECT count(*) n FROM passkey_signups').get().n,0);}finally{a.db.sqlite.close();}
 const b=await setup();try{const pending=await b.signup.begin({email:'owner@example.test',emailToken:b.proof.token,binding:'fixture'});assert.ok(pending);b.deny();assert.equal(await b.signup.finish({token:pending.token,binding:'fixture',response:authenticator().registration({expected:pending.options.challenge})}),undefined);assert.equal(b.db.sqlite.prepare('SELECT count(*) n FROM accounts').get().n,0);}finally{b.db.sqlite.close();}
});
test('policy change during authenticator verification is checked before account transaction',async()=>{
 const s=await setup();try{const c=await s.signup.begin({email:'owner@example.test',emailToken:s.proof.token,binding:'fixture'}),real=s.signup.verifier; s.signup.verifier={...real,async verifyRegistration(...args){const r=await real.verifyRegistration(...args);s.deny();return r;}};
 assert.equal(await s.signup.finish({token:c.token,binding:'fixture',response:authenticator().registration({expected:c.options.challenge})}),undefined);assert.equal(s.db.sqlite.prepare('SELECT count(*) n FROM accounts').get().n,0);
 }finally{s.db.sqlite.close();}
});

test('actual auth-only HTTP accepts denied email generically without sending or issuing proof',async()=>{
 const db=database(),yes={limit:async()=>({success:true})},env={DEPLOYMENT_STAGE:'auth-only',AUTH_ONLY_SIGNUP_EMAIL:'owner@example.test',DB:db,BREVO_API_KEY:'synthetic',BREVO_SENDER_EMAIL:'project@example.test',BREVO_REPLY_TO_EMAIL:'project@example.test',SIGNUP_ADDRESS_LIMIT:yes,SIGNUP_GLOBAL_LIMIT:yes,SIGNUP_VERIFY_ADDRESS_LIMIT:yes,SIGNUP_VERIFY_GLOBAL_LIMIT:yes};let sent=0;const worker=createAuthOnlyWorker({fetchImpl:async()=>{sent++;throw Error('must not send');}}),pending=[];
 function req(path,options={}){const r=new Request(API+path,{...options,headers:{'CF-Connecting-IP':'192.0.2.1',...options.headers}});Object.defineProperty(r,'cf',{value:{colo:'LHR',httpProtocol:'HTTP/2',tlsVersion:'TLSv1.3'}});return r;}
 try{const path='/auth/signup/start?'+new URLSearchParams({challenge:'a'.repeat(43),state:'b'.repeat(43),redirect_uri:'https://otpanda.github.io/app/'}),ctx={waitUntil:p=>pending.push(p)},start=await worker.fetch(req(path),env,ctx);assert.equal(start.status,200);
 const cookies=start.headers.getSetCookie().map(v=>v.split(';')[0]),csrf=cookies.find(v=>v.startsWith('__Host-otpanda_signup_csrf=')).split('=')[1],cookie=cookies.join('; ');
 const response=await worker.fetch(req('/auth/signup/email',{method:'POST',headers:{Origin:API,'Content-Type':'application/x-www-form-urlencoded',Cookie:cookie},body:new URLSearchParams({csrf,email:'denied@example.test'})}),env,ctx);assert.equal(response.status,202);await Promise.all(pending);assert.equal(sent,0);assert.equal(db.sqlite.prepare('SELECT count(*) n FROM auth_challenges').get().n,0);
 assert.equal((await worker.fetch(req(path),{...env,AUTH_ONLY_SIGNUP_EMAIL:'other@example.test'},ctx)).status,503);assert.equal((await worker.fetch(req(path),env,ctx)).status,503);
 }finally{db.sqlite.close();}
});
