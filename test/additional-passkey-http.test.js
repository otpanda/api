import test from 'node:test';import assert from 'node:assert/strict';
import {database} from './sqlite-helper.js';import {PasskeySignupService} from '../src/passkey-signup.js';import {AccountIdentityService} from '../src/account-identity.js';import {DeviceSessionService} from '../src/device-sessions.js';import {PasskeyService} from '../src/passkey-service.js';import {authenticator} from './passkey-fixture.js';
import {createAddPasskeyHttp} from '../src/additional-passkey-http.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',NOW=1_800_000_000_000;
async function fixture(){const db=database(),clock=()=>NOW,identity=new AccountIdentityService(db,{clock}),signup=new PasskeySignupService(db,{clock}),e=await identity.issueEmailChallenge({purpose:'signup-email',email:'a@example.com'}),c=await signup.begin({email:'a@example.com',emailToken:e.token,binding:'binding'}),a=authenticator(),account=await signup.finish({token:c.token,binding:'binding',response:a.registration({expected:c.options.challenge})}),sessions=new DeviceSessionService(db,{clock}),passkeys=new PasskeyService(db,{clock}),d=await sessions.issue({proof:{ownerId:account.ownerId,credentialId:a.credential.id,generation:account.generation??0,purpose:'authenticate',verifiedAt:NOW},clientKind:'web'});
 const http=createAddPasskeyHttp({db,sessions,clock,passkeys});
 const call=(step,value={},{grant,headers={},method='POST',origin=APP,auth=d.access}={})=>http.fetch(new Request(API+'/v1/manage/passkey/add/'+step,{method,headers:{Origin:origin,'Content-Type':'application/json',...(auth?{Authorization:'Bearer '+auth}:{}),...(grant?{'X-OTPanda-Enrollment':grant}:{}),...headers},...(method==='POST'?{body:JSON.stringify(value)}:{})}),{clientAddress:'t'});
 return{db,a,d,call,sessions};}
const pk=r=>({id:r.id,rawId:r.rawId,type:r.type,response:r.response,clientExtensionResults:r.clientExtensionResults});
async function verify(f,a=f.a){const b=await (await f.call('verify-begin')).json();assert.ok(b.token);const r=await f.call('verify-finish',{token:b.token,response:a.assertion({expected:b.options.challenge})});return r;}
test('full HTTP flow adds a second passkey; replay and unauthenticated calls fail',async()=>{const f=await fixture();try{
 assert.equal((await f.call('verify-begin',{},{auth:null})).status,401);
 assert.equal((await f.call('verify-begin',{},{origin:'https://evil.test'})).status,403);
 assert.equal((await f.call('register-begin',{},{grant:'otpda_'+'A'.repeat(55)})).status,403);
 const v=await verify(f);assert.equal(v.status,200);const g=(await v.json()).token;
 const rb=await f.call('register-begin',{},{grant:g});assert.equal(rb.status,200);const c=await rb.json();assert.ok(c.options.excludeCredentials.some(e=>e.id===f.a.credential.id));
 const n=authenticator(),resp=n.registration({expected:c.options.challenge});
 assert.equal((await f.call('register-finish',{token:c.token,response:resp},{grant:g})).status,200);
 assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM passkey_credentials WHERE revoked_at IS NULL').get().n,2);
 assert.equal((await f.call('register-finish',{token:c.token,response:resp},{grant:g})).status,403);
 assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM passkey_credentials').get().n,2);
}finally{f.db.sqlite.close();}});
test('step-up assertion for another action cannot authorize adding a passkey',async()=>{const f=await fixture();try{
 const ps=new PasskeyService(f.db,{clock:()=>NOW}),owner=f.db.sqlite.prepare('SELECT owner_id,generation FROM device_sessions LIMIT 1').get();
 const b=await ps.begin({purpose:'step-up',ownerId:owner.owner_id,binding:JSON.stringify(['add-passkey',f.d.deviceId,owner.generation]),action:'extra-verification:disable'});
 const r=await f.call('verify-finish',{token:b.token,response:f.a.assertion({expected:b.options.challenge})});assert.equal(r.status,403);
 assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM passkey_add_authorizations').get().n,0);
}finally{f.db.sqlite.close();}});
test('authorization is bound to its device and rejects extra fields or wrong grant shape',async()=>{const f=await fixture();try{
 const row=f.db.sqlite.prepare('SELECT owner_id,credential_id,generation FROM device_sessions WHERE device_id=?').get(f.d.deviceId),other=await f.sessions.issue({proof:{ownerId:row.owner_id,credentialId:row.credential_id,generation:row.generation,purpose:'authenticate',verifiedAt:NOW},clientKind:'web'});
 const g=(await (await verify(f)).json()).token;
 assert.equal((await f.call('register-begin',{},{grant:g,auth:other.access})).status,403);
 assert.equal((await f.call('register-begin',{extra:1},{grant:g})).status,400);
 assert.equal((await f.call('register-begin',{},{})).status,403);
 assert.equal((await f.call('verify-begin',{},{method:'GET'})).status,400);
}finally{f.db.sqlite.close();}});
import {createIdentityRuntime} from '../src/identity-runtime.js';
test('runtime mounts the four routes and unknown add paths stay 404',async()=>{const db=database(),rt=createIdentityRuntime({db,keys:{},activeKeyId:'k',trustedRequestKey:async()=>'203.0.113.9',clock:()=>NOW});
 for(const s of ['verify-begin','verify-finish','register-begin','register-finish'])assert.equal((await rt.fetch(new Request(API+'/v1/manage/passkey/add/'+s,{method:'POST',headers:{Origin:APP,'Content-Type':'application/json'},body:'{}'}))).status,401);
 assert.equal((await rt.fetch(new Request(API+'/v1/manage/passkey/add/other',{method:'POST',headers:{Origin:APP,'Content-Type':'application/json'},body:'{}'}))).status,404);db.sqlite.close();});
