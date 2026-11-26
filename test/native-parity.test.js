import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { PasskeySignupService } from '../src/passkey-signup.js';
import { AccountIdentityService } from '../src/account-identity.js';
import { DeviceSessionService } from '../src/device-sessions.js';
import { pkceChallenge } from '../src/browser-exchanges.js';
import { NativeSessionService,NATIVE_REDIRECT } from '../src/native-sessions.js';
import { createDeviceSessionAuth } from '../src/device-session-auth.js';
import { createAccountOverviewHttp } from '../src/account-overview-http.js';
import { createTotpManagementHttp } from '../src/totp-management-http.js';
import { cleanupIdentity } from '../src/identity-cleanup.js';
import { base64urlEncode } from '../src/tokens.js';
import { authenticator } from './passkey-fixture.js';
const NOW=1_800_000_000_000,API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',verifier='q'.repeat(43);
async function fixture(){
 const db=database();let now=NOW;const clock=()=>now;
 const identity=new AccountIdentityService(db,{clock}),signup=new PasskeySignupService(db,{clock});
 const {token}=await identity.issueEmailChallenge({purpose:'signup-email',email:'a@example.com'});
 const c=await signup.begin({email:'a@example.com',emailToken:token,binding:'binding'}),a=authenticator();
 const account=await signup.finish({token:c.token,binding:'binding',response:a.registration({expected:c.options.challenge})});
 const sessions=new DeviceSessionService(db,{clock}),web=await sessions.issue({proof:{...account,verifiedAt:NOW,purpose:'authenticate'},clientKind:'web'}),native=new NativeSessionService(db,{clock});
 const k=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign']),pub=base64urlEncode(new Uint8Array(await crypto.subtle.exportKey('raw',k.publicKey)));
 const m=await native.mint({sourceDeviceId:web.deviceId,challenge:await pkceChallenge(verifier),redirectUri:NATIVE_REDIRECT}),and=await native.exchange({code:m.code,verifier,redirectUri:NATIVE_REDIRECT,renewalKey:pub});
 return{db,sessions,web,and,clock,setNow:v=>now=v};
}
const req=(url,token,origin)=>new Request(API+url,{headers:{...(origin?{Origin:origin}:{}),Authorization:'Bearer '+token}});
test('adapter: web default unchanged; native opt-in needs NO Origin and an android token; kinds never cross',async()=>{
 const f=await fixture(),webAuth=createDeviceSessionAuth({sessions:f.sessions}),nat=createDeviceSessionAuth({sessions:f.sessions,native:true});
 const webAccess=(await f.sessions.rotate(f.web.refresh,{clientKind:'web'})).access;
 assert.ok(await webAuth.authenticate(req('/x',webAccess,APP)));assert.ok(await nat.authenticate(req('/x',webAccess,APP)),'web still works on an opted-in route');
 assert.equal(await webAuth.authenticate(req('/x',f.and.access)),undefined,'default route refuses native');
 assert.equal(await webAuth.authenticate(req('/x',f.and.access,APP)),undefined);
 assert.ok(await nat.authenticate(req('/x',f.and.access)));
 assert.equal(await nat.authenticate(req('/x',f.and.access,APP)),undefined,'android token with a browser Origin');
 assert.equal(await nat.authenticate(req('/x',webAccess)),undefined,'web token without Origin');
 assert.equal(await nat.authenticate(req('/x',f.and.access,'https://evil.example')),undefined);
 assert.equal(nat.originAllowed(req('/x','t','https://evil.example')),false);assert.equal(webAuth.originAllowed(req('/x','t')),false);
 f.setNow(NOW+900001);assert.equal(await nat.authenticate(req('/x',f.and.access)),undefined,'expired');f.db.sqlite.close();});
test('route: account overview serves native only when opted in, same data as web, revocation ends it',async()=>{
 const f=await fixture(),opts={clientAddress:'9.9.9.9'},off=createAccountOverviewHttp({db:f.db,sessions:f.sessions,clock:f.clock}),on=createAccountOverviewHttp({db:f.db,sessions:f.sessions,clock:f.clock,native:true});
 assert.equal((await off.fetch(req('/v1/manage/account',f.and.access),opts)).status,403);
 const r=await on.fetch(req('/v1/manage/account',f.and.access),opts),b=await r.json();assert.equal(r.status,200);assert.equal(b.email,'a@example.com');
 const w=(await f.sessions.rotate(f.web.refresh,{clientKind:'web'})).access,rw=await off.fetch(req('/v1/manage/account',w,APP),opts);assert.deepEqual(await rw.json(),b);
 f.db.sqlite.prepare("UPDATE device_sessions SET revoked_at=? WHERE client_kind='android'").run(NOW);
 assert.equal((await on.fetch(req('/v1/manage/account',f.and.access),opts)).status,401);f.db.sqlite.close();});
test('totp-create now accepts a native session at the boundary (passkey+origin proof in native-totp-stepup.test.js); the body is still validated',async()=>{
 const f=await fixture(),h=createTotpManagementHttp({native:true,db:f.db,sessions:f.sessions,getSeedCipher:async()=>{throw Error('unused');},clock:f.clock});
 const r=await h.fetch(new Request(API+'/v1/manage/totp',{method:'POST',headers:{Authorization:'Bearer '+f.and.access,'Content-Type':'application/json'},body:'{}'}),{clientAddress:'1.1.1.1'});assert.equal(r.status,400);f.db.sqlite.close();});
test('scheduled identity cleanup removes expired native exchanges and challenges, and cascades native keys with expired devices',async()=>{
 const f=await fixture();const n=new NativeSessionService(f.db,{clock:f.clock});
 await n.mint({sourceDeviceId:f.web.deviceId,challenge:await pkceChallenge(verifier),redirectUri:NATIVE_REDIRECT});await n.challenge({deviceId:f.and.deviceId,purpose:'renew'});
 const cnt=t=>f.db.sqlite.prepare(`SELECT count(*) n FROM ${t}`).get().n;assert.equal(cnt('native_exchanges'),1);assert.equal(cnt('native_challenges'),1);
 f.setNow(NOW+120000);const r=await cleanupIdentity({db:f.db,clock:f.clock,limit:100});assert.equal(r.native_exchanges,1);assert.equal(r.native_challenges,1);
 f.setNow(NOW+31*86400000);await cleanupIdentity({db:f.db,clock:f.clock,limit:100});assert.equal(cnt('native_keys'),0);f.db.sqlite.close();});
