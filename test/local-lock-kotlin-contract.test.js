// Cross-language contract: the REAL Kotlin LocalLockRecovery core (JVM) against the REAL local-lock HTTP handler, passkey service and a WebAuthn authenticator fixture.
// Skipped unless KOTLIN_CONTRACT_CLASSES (compiled classes dir) and KOTLIN_LIB (dir with kotlin-stdlib-2.0.20.jar) are set. Proves wire compatibility only: not Android, not Credential Manager.
import test from 'node:test';import assert from 'node:assert/strict';import {spawn} from 'node:child_process';import readline from 'node:readline';
import {database} from './sqlite-helper.js';import {createLocalLockRecoveryHttp} from '../src/local-lock-recovery-http.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',NOW=1800000000000,CLASSES=process.env.KOTLIN_CONTRACT_CLASSES,LIB=process.env.KOTLIN_LIB;
const skip=!CLASSES||!LIB?'KOTLIN_CONTRACT_CLASSES and KOTLIN_LIB not set':false;
async function world(){
 const {PasskeySignupService}=await import('../src/passkey-signup.js'),{AccountIdentityService}=await import('../src/account-identity.js'),{authenticator}=await import('./passkey-fixture.js');
 const db=database(),clock=()=>NOW,identity=new AccountIdentityService(db,{clock}),signup=new PasskeySignupService(db,{clock}),email='kt@example.invalid';
 const {token}=await identity.issueEmailChallenge({purpose:'signup-email',email});const begin=await signup.begin({email,emailToken:token,binding:'signup'}),a=authenticator();
 const owner=await signup.finish({token:begin.token,binding:'signup',response:a.registration({expected:begin.options.challenge})});
 const user={ownerId:owner.ownerId,deviceId:'dev-kt',generation:owner.generation,clientKind:'android'};
 return {db,a,owner,user,app:createLocalLockRecoveryHttp({db,sessions:{authenticate:async()=>user},clock})};
}
// mode: 'ok' | 'userHandle' (adds a userHandle like Credential Manager) | 'cancel' | 'badchallenge'
async function run(intent,mode){
 const w=await world(),log=[];
 const child=spawn('java',['-cp',`${CLASSES}:${LIB}/kotlin-stdlib-2.0.20.jar`,'org.otpanda.recovery.LocalLockContractRunnerKt',intent,'bearer-token-0123456789',w.user.deviceId],{stdio:['pipe','pipe','inherit']});
 const rl=readline.createInterface({input:child.stdout});let outcome;
 const reply=o=>child.stdin.write(JSON.stringify(o)+'\n');
 const done=new Promise((res,rej)=>{child.on('error',rej);rl.on('line',async line=>{try{
  const m=JSON.parse(line);log.push(m);
  if(m.t==='http'){const step=m.path.split('/').pop(),r=await w.app.fetch(new Request(API+m.path,{method:'POST',headers:{Authorization:'Bearer '+m.bearer,'Content-Type':'application/json'},body:m.body}),{clientAddress:'192.0.2.9'});reply({status:r.status,body:await r.text()});log.push({step,status:r.status});}
  else if(m.t==='passkey'){if(mode==='cancel')return reply({assertion:null});const req=JSON.parse(m.request);
   const x=w.a.assertion({expected:mode==='badchallenge'?'z'.repeat(43):req.challenge});
   if(mode==='userHandle')x.response.userHandle=Buffer.from(w.owner.ownerId).toString('base64url');
   x.authenticatorAttachment='platform';reply({assertion:JSON.stringify(x)});}
  else if(m.t==='outcome'){outcome=m;child.stdin.end();}
 }catch(e){rej(e);}});child.on('close',()=>res());});
 try{await done;}finally{w.db.sqlite.close();}
 return {outcome,log};
}
for(const mode of ['ok','userHandle']){
 test(`Kotlin core disable and unlock complete against the real server (${mode})`,{skip},async()=>{
  const d=await run('local-lock-disable',mode);assert.equal(d.outcome.outcome,'DISABLED',JSON.stringify(d.log));assert.equal(d.outcome.disables,1);
  const u=await run('local-unlock-once',mode);assert.equal(u.outcome.outcome,'UNLOCK_GRANTED');assert.equal(u.outcome.unlock,true);assert.equal(u.outcome.disables,0);
  assert.deepEqual(d.log.filter(x=>x.step).map(x=>x.step+':'+x.status),['begin:200','finish:200']);
 });
}
test('Kotlin core: wrong assertion challenge is refused by the real server and nothing is applied',{skip},async()=>{
 const r=await run('local-lock-disable','badchallenge');assert.equal(r.outcome.outcome,'RESTART');assert.equal(r.outcome.disables,0);assert.equal(r.outcome.unlock,false);
});
test('Kotlin core: user cancel sends no finish and applies nothing',{skip},async()=>{
 const r=await run('local-lock-disable','cancel');assert.equal(r.outcome.outcome,'USER_CANCELLED');assert.equal(r.outcome.disables,0);assert.deepEqual(r.log.filter(x=>x.step).map(x=>x.step),['begin']);
});
