import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { PasskeySignupService } from '../src/passkey-signup.js';
import { AccountIdentityService } from '../src/account-identity.js';
import { DeviceSessionService } from '../src/device-sessions.js';
import { pkceChallenge } from '../src/browser-exchanges.js';
import { NativeSessionService,NATIVE_REDIRECT } from '../src/native-sessions.js';
import { createIdentityRuntime } from '../src/identity-runtime.js';
import { createIdentityEdgeHost } from '../src/identity-edge-host.js';
import { base64urlEncode } from '../src/tokens.js';
import { authenticator } from './passkey-fixture.js';
const NOW=1_800_000_000_000,API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',verifier='q'.repeat(43),yes={limit:async()=>({success:true})};
const req=(p,{token,origin,method='GET',body}={})=>new Request(API+p,{method,headers:{...(origin?{Origin:origin}:{}),...(token?{Authorization:'Bearer '+token}:{}),...(body?{'Content-Type':'application/json'}:{})},body});
async function fixture(){
 const db=database(),clock=()=>NOW,identity=new AccountIdentityService(db,{clock}),signup=new PasskeySignupService(db,{clock}),a=authenticator();
 const {token}=await identity.issueEmailChallenge({purpose:'signup-email',email:'a@example.com'});const c=await signup.begin({email:'a@example.com',emailToken:token,binding:'b'});
 const account=await signup.finish({token:c.token,binding:'b',response:a.registration({expected:c.options.challenge})});
 const sessions=new DeviceSessionService(db,{clock}),web=await sessions.issue({proof:{...account,verifiedAt:NOW,purpose:'authenticate'},clientKind:'web'}),webAccess=(await sessions.rotate(web.refresh,{clientKind:'web'})).access;
 const k=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign']),pub=base64urlEncode(new Uint8Array(await crypto.subtle.exportKey('raw',k.publicKey)));
 const native=new NativeSessionService(db,{clock}),m=await native.mint({sourceDeviceId:web.deviceId,challenge:await pkceChallenge(verifier),redirectUri:NATIVE_REDIRECT}),and=await native.exchange({code:m.code,verifier,redirectUri:NATIVE_REDIRECT,renewalKey:pub});
 const host=on=>createIdentityEdgeHost({nativeApi:on,resolveTrustedIngress:()=>'192.0.2.1',edgeAddress:yes,edgeAuthGlobal:yes,edgeReadGlobal:yes,initialize:async()=>createIdentityRuntime({db,keys:new Map(),activeKeyId:'x',trustedRequestKey:()=>'192.0.2.1',clock,native:{enabled:on}})});
 return{db,webAccess,android:and.access,host};
}
const GETS=['/v1/manage/account','/v1/manage/session','/v1/manage/entries','/v1/manage/active-codes','/v1/manage/sources','/v1/manage/unassigned','/v1/manage/unassigned-context','/v1/manage/organization','/v1/manage/totp-code?entry=x'];
test('activation ON: each Android client route accepts the android token with NO Origin; web token and browser Origin stay segregated',async()=>{
 const f=await fixture(),h=f.host(true);
 for(const p of GETS){
  const a=await h.fetch(req(p,{token:f.android}));assert.ok([200,400,404,503].includes(a.status)&&a.status!==401&&a.status!==403,'android '+p+' '+a.status);
  assert.equal((await h.fetch(req(p,{token:f.webAccess}))).status,401,'web token without Origin '+p);
  assert.equal((await h.fetch(req(p,{token:f.android,origin:APP}))).status,401,'android token with web Origin '+p);
  assert.equal((await h.fetch(req(p,{token:f.android,origin:'https://evil.example'}))).status,403,'foreign Origin '+p);
  assert.equal((await h.fetch(req(p,{token:f.webAccess,origin:APP}))).status===401,false,'web unchanged '+p);
 }
 for(const p of ['/v1/manage/organization','/v1/manage/organization-copy','/v1/manage/totp','/v1/manage/totp/begin']){
  const r=await h.fetch(req(p,{token:f.android,method:p==='/v1/manage/organization'?'PUT':'POST',body:'{}'}));assert.ok(![401,403,404,415].includes(r.status),p+' '+r.status);
  assert.equal((await h.fetch(req(p,{token:f.webAccess,method:p==='/v1/manage/organization'?'PUT':'POST',body:'{}'}))).status,401,'web token without Origin '+p);
 }
 // never native: batch codes, realtime
 for(const [p,m] of [['/v1/manage/totp-codes','GET'],['/auth/realtime/ticket','POST']]){
  const r=await h.fetch(req(p,{token:f.android,method:m}));assert.ok([403,404].includes(r.status),p+' must stay refused for no-Origin native: '+r.status);
 }
 // Settings parity: security, recovery and google link ticket accept the android token with NO Origin, and stay segregated from web tokens and browser Origins.
 for(const [p,m] of [['/v1/manage/security/status','GET'],['/v1/manage/recovery/status','GET'],['/v1/manage/passkey/rename','POST'],['/v1/manage/google/link/ticket','POST']]){
  const r=await h.fetch(req(p,{token:f.android,method:m,...(m==='POST'?{body:'{}'}:{})}));assert.ok(![401,403,404,405].includes(r.status),'android '+p+' '+r.status);
  assert.equal((await h.fetch(req(p,{token:f.webAccess,method:m,...(m==='POST'?{body:'{}'}:{})}))).status,401,'web token without Origin '+p);
  assert.equal((await h.fetch(req(p,{token:f.android,method:m,origin:APP,...(m==='POST'?{body:'{}'}:{})}))).status,401,'android token with web Origin '+p);
 }
 for(const p of ['/v1/manage/assignment/begin','/v1/manage/assignment/finish','/v1/manage/assignment/status','/v1/manage/device-key/enroll-begin','/v1/manage/device-key/enroll-finish','/v1/manage/device-key/enroll-status','/v1/manage/device-key/adopt-begin','/v1/manage/device-key/adopt-finish','/v1/manage/device-key/add-request','/v1/manage/device-key/add-begin','/v1/manage/device-key/add-finish','/v1/manage/approval/status','/v1/manage/approval/approve-begin','/v1/manage/approval/approve-finish']){
  const r=await h.fetch(req(p,{token:f.android,method:'POST',body:'{}'}));assert.ok(![401,403,404,405,415].includes(r.status),'android '+p+' '+r.status);assert.equal(req(p,{token:f.android,method:'POST',body:'{}'}).headers.get('content-type'),'application/json','native client sends exactly application/json, no charset');
  assert.equal((await h.fetch(req(p,{token:f.webAccess,method:'POST',body:'{}'}))).status,401,'web token without Origin '+p);
  assert.equal((await h.fetch(req(p,{token:f.android,method:'POST',body:'{}',origin:'https://evil.example'}))).status,403,'foreign Origin '+p);
 }
 f.db.sqlite.close();});
test('activation OFF (default): no-Origin android token is refused on every /v1 route, native paths 404, web unchanged, preflight never opens native',async()=>{
 const f=await fixture(),h=f.host(false);
 for(const p of GETS)assert.equal((await h.fetch(req(p,{token:f.android}))).status,403,p);
 assert.equal((await h.fetch(req('/v1/manage/totp',{token:f.android,method:'POST',body:'{}'}))).status,403);
 for(const p of ['/auth/native/exchange','/auth/native/approve','/app-return','/.well-known/assetlinks.json'])assert.equal((await h.fetch(req(p))).status,404,p);
 assert.equal((await h.fetch(req('/v1/manage/session',{token:f.webAccess,origin:APP}))).status,200);
 const pre=await f.host(true).fetch(new Request(API+'/v1/manage/session',{method:'OPTIONS'}));assert.equal(pre.status,403,'preflight without Origin is never granted');
 f.db.sqlite.close();});
test('activation OFF at the runtime itself (no edge help): android token is refused on totp/begin and totp; ON accepts it past auth',async()=>{
 const f=await fixture(),mk=on=>createIdentityRuntime({db:f.db,keys:new Map(),activeKeyId:'x',trustedRequestKey:()=>'192.0.2.1',clock:()=>NOW,native:{enabled:on}});
 for(const p of ['/v1/manage/totp/begin','/v1/manage/totp']){
  const off=await mk(false).fetch(req(p,{token:f.android,method:'POST',body:'{}'}),{waitUntil(){}});assert.ok([401,403].includes(off.status),'off '+p+off.status);
  const on=await mk(true).fetch(req(p,{token:f.android,method:'POST',body:'{}'}),{waitUntil(){}});assert.ok(![401,403].includes(on.status),'on '+p+on.status);
 }
 f.db.sqlite.close();});

test('batch route is edge-recognized but stays absent from runtime without explicit config',async()=>{
 const f=await fixture();try{for(const origin of [undefined,APP]){
  const runtime=createIdentityRuntime({db:f.db,keys:new Map(),activeKeyId:'x',trustedRequestKey:()=>{throw Error('disabled batch must not touch ingress');},native:{enabled:true}});
  const r=await runtime.fetch(req('/v1/manage/totp-codes',{origin}));assert.equal(r.status,404);
 }
 let initialized=0;const host=createIdentityEdgeHost({nativeApi:true,edgeAddress:yes,edgeAuthGlobal:yes,edgeReadGlobal:yes,resolveTrustedIngress:()=>'192.0.2.1',initialize(){initialized++;return{fetch:async()=>new Response(null,{status:401})};}});
 assert.equal((await host.fetch(req('/v1/manage/totp-codes?entry=x',{origin:APP}))).status,401);assert.equal(initialized,1);
 }finally{f.db.sqlite.close();}
});
