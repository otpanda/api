import test from 'node:test';import assert from 'node:assert/strict';
import {database} from './sqlite-helper.js';
import {createLocalLockRecoveryHttp} from '../src/local-lock-recovery-http.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',NOW=1800000000000,G='a'.repeat(43);
function setup(){const db=database(),user={ownerId:'owner',deviceId:'device',generation:3,clientKind:'android'},calls=[];let current=user;const sessions={authenticate:async()=>current};const passkeys={begin:async v=>{calls.push(v);return{token:'synthetic',options:{},expiresAt:NOW+120000};},finishAuthentication:async v=>{calls.push(v);return{ownerId:'owner',generation:3};}};const app=createLocalLockRecoveryHttp({db,sessions,passkeys,clock:()=>NOW});const request=(step,v,headers={})=>app.fetch(new Request(API+'/v1/manage/local-lock/'+step,{method:'POST',headers:{Authorization:'Bearer synthetic','Content-Type':'application/json',...headers},body:JSON.stringify(v)}),{clientAddress:'192.0.2.1'});return{db,calls,request,setUser:u=>current=u,revoke:()=>current=null};}
test('separate exact intents are owner/device/security-generation/local-generation bound',async()=>{const x=setup();try{for(const intent of ['local-unlock-once','local-lock-disable']){assert.equal((await x.request('begin',{intent,lockGeneration:G})).status,200);const call=x.calls.at(-1);assert.equal(call.action,intent);assert.deepEqual(JSON.parse(call.binding),['local-lock-v1','owner','device',3,G]);const r=await x.request('finish',{intent,lockGeneration:G,token:'otpda_'+'a'.repeat(55),response:{}});assert.equal(r.status,200);assert.deepEqual(await r.json(),{intent,lockGeneration:G,deviceId:'device',generation:3});}}finally{x.db.sqlite.close();}});
test('invalid intent, generation, extra fields and browser origins cannot authorize local recovery',async()=>{const x=setup();try{for(const v of [{intent:'security.disable',lockGeneration:G},{intent:'local-unlock-once',lockGeneration:'short'},{intent:'local-unlock-once',lockGeneration:G,extra:true}])assert.equal((await x.request('begin',v)).status,400);assert.equal((await x.request('begin',{intent:'local-unlock-once',lockGeneration:G},{Origin:'https://otpanda.github.io'})).status,403);assert.equal(x.calls.length,0);}finally{x.db.sqlite.close();}});
test('missing session fails before ceremony work',async()=>{const x=setup();try{x.revoke();assert.equal((await x.request('begin',{intent:'local-unlock-once',lockGeneration:G})).status,401);assert.equal(x.calls.length,0);}finally{x.db.sqlite.close();}});

test('real one-use ceremonies reject cross-intent, cross-local-generation and replay',async()=>{
 const {PasskeySignupService}=await import('../src/passkey-signup.js');const {AccountIdentityService}=await import('../src/account-identity.js');const {authenticator}=await import('./passkey-fixture.js');
 const db=database();try{const clock=()=>NOW,identity=new AccountIdentityService(db,{clock}),signup=new PasskeySignupService(db,{clock}),email='local@example.invalid';const {token}=await identity.issueEmailChallenge({purpose:'signup-email',email});const begin=await signup.begin({email,emailToken:token,binding:'signup'}),a=authenticator(),owner=await signup.finish({token:begin.token,binding:'signup',response:a.registration({expected:begin.options.challenge})});
 const user={ownerId:owner.ownerId,deviceId:'device',generation:owner.generation,clientKind:'android'},app=createLocalLockRecoveryHttp({db,sessions:{authenticate:async()=>user},clock});
 const req=async(step,value)=>app.fetch(new Request(API+'/v1/manage/local-lock/'+step,{method:'POST',headers:{Authorization:'Bearer fixture','Content-Type':'application/json'},body:JSON.stringify(value)}),{clientAddress:'192.0.2.2'});
 const intent='local-unlock-once',c=await(await req('begin',{intent,lockGeneration:G})).json(),response=a.assertion({expected:c.options.challenge,userHandle:owner.ownerId});
 assert.equal((await req('finish',{intent:'local-lock-disable',lockGeneration:G,token:c.token,response})).status,403);
 assert.equal((await req('finish',{intent,lockGeneration:'b'.repeat(43),token:c.token,response})).status,403);
 assert.equal((await req('finish',{intent,lockGeneration:G,token:c.token,response})).status,200);
 assert.equal((await req('finish',{intent,lockGeneration:G,token:c.token,response})).status,403);
 assert.equal(db.sqlite.prepare('SELECT count(*) n FROM new_device_verification').get().n,0);
 }finally{db.sqlite.close();}
});

test('web and extension bearer sessions fail before local ceremony work',async()=>{
 for(const clientKind of ['web','extension']){const x=setup();try{x.setUser({ownerId:'owner',deviceId:'device',generation:3,clientKind});assert.equal((await x.request('begin',{intent:'local-unlock-once',lockGeneration:G})).status,401);assert.equal(x.calls.length,0);}finally{x.db.sqlite.close();}}
});

test('21st local recovery request is rate limited before consuming a ceremony',async()=>{
 const x=setup();try{for(let n=0;n<20;n++)assert.equal((await x.request('begin',{intent:'local-unlock-once',lockGeneration:G})).status,200);const count=x.calls.length;assert.equal((await x.request('finish',{intent:'local-unlock-once',lockGeneration:G,token:'otpda_'+'a'.repeat(55),response:{}})).status,429);assert.equal(x.calls.length,count);}finally{x.db.sqlite.close();}
});

test('real verifier rejects absent UV and account step-up ceremony on local recovery',async()=>{
 const {PasskeySignupService}=await import('../src/passkey-signup.js');const {AccountIdentityService}=await import('../src/account-identity.js');const {PasskeyService}=await import('../src/passkey-service.js');const {authenticator}=await import('./passkey-fixture.js');
 const db=database();try{
  const clock=()=>NOW,identity=new AccountIdentityService(db,{clock}),signup=new PasskeySignupService(db,{clock}),email='negative-local@example.invalid';const {token}=await identity.issueEmailChallenge({purpose:'signup-email',email});const begun=await signup.begin({email,emailToken:token,binding:'signup'}),a=authenticator(),owner=await signup.finish({token:begun.token,binding:'signup',response:a.registration({expected:begun.options.challenge})});
  const passkeys=new PasskeyService(db,{clock}),user={ownerId:owner.ownerId,deviceId:'device',generation:owner.generation,clientKind:'android'},app=createLocalLockRecoveryHttp({db,sessions:{authenticate:async()=>user},passkeys,clock});
  const req=async(step,value)=>app.fetch(new Request(API+'/v1/manage/local-lock/'+step,{method:'POST',headers:{Authorization:'Bearer fixture','Content-Type':'application/json'},body:JSON.stringify(value)}),{clientAddress:'192.0.2.3'});
  const intent='local-unlock-once',c=await(await req('begin',{intent,lockGeneration:G})).json();
  assert.equal((await req('finish',{intent,lockGeneration:G,token:c.token,response:a.assertion({expected:c.options.challenge,flags:1})})).status,403);
  const binding=JSON.stringify(['local-lock-v1',owner.ownerId,'device',owner.generation,G]);
  const account=await passkeys.begin({purpose:'step-up',ownerId:owner.ownerId,binding,action:'security.disable'}),response=a.assertion({expected:account.options.challenge});
  assert.equal((await req('finish',{intent,lockGeneration:G,token:account.token,response})).status,403);
  assert.ok(await passkeys.finishAuthentication({token:account.token,binding,action:'security.disable',ownerId:owner.ownerId,response}));
 }finally{db.sqlite.close();}
});

test('rate limit preserves the actual one-use ceremony for a later permitted finish',async()=>{
 const {PasskeySignupService}=await import('../src/passkey-signup.js');const {AccountIdentityService}=await import('../src/account-identity.js');const {PasskeyService}=await import('../src/passkey-service.js');const {authenticator}=await import('./passkey-fixture.js');
 const db=database();try{
  let now=NOW;const clock=()=>now,identity=new AccountIdentityService(db,{clock}),signup=new PasskeySignupService(db,{clock}),email='rate-local@example.invalid';const {token}=await identity.issueEmailChallenge({purpose:'signup-email',email});const begun=await signup.begin({email,emailToken:token,binding:'signup'}),a=authenticator(),owner=await signup.finish({token:begun.token,binding:'signup',response:a.registration({expected:begun.options.challenge})});
  const passkeys=new PasskeyService(db,{clock}),user={ownerId:owner.ownerId,deviceId:'device',generation:owner.generation,clientKind:'android'},app=createLocalLockRecoveryHttp({db,sessions:{authenticate:async()=>user},passkeys,clock});
  const req=async(step,value)=>app.fetch(new Request(API+'/v1/manage/local-lock/'+step,{method:'POST',headers:{Authorization:'Bearer fixture','Content-Type':'application/json'},body:JSON.stringify(value)}),{clientAddress:'192.0.2.4'});
  const intent='local-unlock-once',c=await(await req('begin',{intent,lockGeneration:G})).json();
  for(let n=1;n<20;n++)assert.equal((await req('begin',{intent,lockGeneration:G})).status,200);
  const value={intent,lockGeneration:G,token:c.token,response:a.assertion({expected:c.options.challenge})};
  assert.equal((await req('finish',value)).status,429);
  assert.equal(db.sqlite.prepare('SELECT count(*) n FROM passkey_ceremonies').get().n,20);
  now+=60001;
  assert.equal((await req('finish',value)).status,200);
 }finally{db.sqlite.close();}
});
