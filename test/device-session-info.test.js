import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { PasskeySignupService } from '../src/passkey-signup.js';
import { AccountIdentityService } from '../src/account-identity.js';
import { DeviceSessionService } from '../src/device-sessions.js';
import { RecoveryControls } from '../src/recovery-controls.js';
import { pkceChallenge } from '../src/browser-exchanges.js';
import { NativeSessionService,NATIVE_REDIRECT } from '../src/native-sessions.js';
import { createIdentityRuntime } from '../src/identity-runtime.js';
import { createIdentityEdgeHost } from '../src/identity-edge-host.js';
import { base64urlEncode } from '../src/tokens.js';
import { authenticator } from './passkey-fixture.js';
const NOW=1_800_000_000_000,API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',verifier='q'.repeat(43),yes={limit:async()=>({success:true})};
async function fixture(){
 const db=database(),clock=()=>NOW,identity=new AccountIdentityService(db,{clock}),signup=new PasskeySignupService(db,{clock}),a=authenticator(),{token}=await identity.issueEmailChallenge({purpose:'signup-email',email:'a@example.com'});
 const c=await signup.begin({email:'a@example.com',emailToken:token,binding:'b'}),account=await signup.finish({token:c.token,binding:'b',response:a.registration({expected:c.options.challenge})});
 const sessions=new DeviceSessionService(db,{clock}),d=await sessions.issue({proof:{...account,verifiedAt:NOW,purpose:'authenticate'},clientKind:'web'}),web=(await sessions.rotate(d.refresh,{clientKind:'web'})).access;
 const k=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign']),pub=base64urlEncode(new Uint8Array(await crypto.subtle.exportKey('raw',k.publicKey)));
 const native=new NativeSessionService(db,{clock}),m=await native.mint({sourceDeviceId:d.deviceId,challenge:await pkceChallenge(verifier),redirectUri:NATIVE_REDIRECT}),and=await native.exchange({code:m.code,verifier,redirectUri:NATIVE_REDIRECT,renewalKey:pub});
 const host=on=>createIdentityEdgeHost({nativeApi:on,resolveTrustedIngress:()=>'192.0.2.1',edgeAddress:yes,edgeAuthGlobal:yes,edgeReadGlobal:yes,initialize:async()=>createIdentityRuntime({db,keys:new Map(),activeKeyId:'x',trustedRequestKey:()=>'192.0.2.1',clock,native:{enabled:on}})});
 const rc=new RecoveryControls(db,{clock}),list=async(deviceId)=>(await rc.status({ownerId:account.ownerId,deviceId,generation:0})).sessions;
 const call=(h,token,body,{origin,method='POST',ct='application/json'}={})=>h.fetch(new Request(API+'/v1/manage/session/describe',{method,headers:{...(origin?{Origin:origin}:{}),...(token?{Authorization:'Bearer '+token}:{}),'Content-Type':ct},...(method==='GET'?{}:{body:typeof body==='string'?body:JSON.stringify(body)})}));
 return{db,web,android:and.access,webId:d.deviceId,androidId:and.deviceId,host,list,call};
}
test('web describes itself: closed enums, name must be null, shown in status, replaced on repeat, other sessions untouched',async()=>{
 const f=await fixture(),h=f.host(false);
 {const r=await f.call(h,f.web,{browser:'firefox',os:'linux',name:null},{origin:APP});assert.equal(r.status,200,await r.text());}
 let s=await f.list(f.webId),w=s.find(x=>x.id===f.webId);assert.deepEqual([w.browser,w.os,w.name],['firefox','linux',null]);
 assert.deepEqual(Object.keys(w).sort(),['browser','clientKind','createdAt','current','id','lastUsedAt','name','os']);
 const other=s.find(x=>x.id!==f.webId);assert.deepEqual([other.browser,other.os,other.name],[null,null,null],'undescribed sessions show nulls');
 assert.equal((await f.call(h,f.web,{browser:'chrome',os:'windows',name:null},{origin:APP})).status,200);w=(await f.list(f.webId)).find(x=>x.id===f.webId);assert.deepEqual([w.browser,w.os],['chrome','windows']);
 assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM device_session_info').get().n,1);
 for(const b of [{browser:'firefox',os:'linux',name:'Abraham PC'},{browser:'netscape',os:'linux',name:null},{browser:'firefox',os:'beos',name:null},{browser:'firefox',os:'linux'},{browser:'firefox',os:'linux',name:null,x:1},{browser:5,os:'linux',name:null},'{bad',[]])assert.equal((await f.call(h,f.web,b,{origin:APP})).status,400,JSON.stringify(b));
 assert.equal((await f.call(h,f.web,{browser:null,os:null,name:null},{origin:APP})).status,200,'all-null is allowed');
 assert.equal((await f.call(h,f.web,{browser:'firefox',os:'linux',name:null},{origin:APP,ct:'text/plain'})).status,400);
 assert.equal((await f.call(h,f.web,{},{origin:APP,method:'GET'})).status,405);assert.equal((await f.call(h,null,{browser:null,os:null,name:null},{origin:APP})).status,401);
 assert.equal((await f.call(h,f.web,{browser:null,os:null,name:null},{origin:'https://evil.example'})).status,403);
 f.db.sqlite.close();});
test('native describes with the device name: only with the flag on, no Origin, android token, no browser; web token cannot, android cannot use web Origin',async()=>{
 const f=await fixture(),on=f.host(true),off=f.host(false),ok={browser:null,os:'android',name:"Abraham's Pixel 8a"};
 assert.equal((await f.call(off,f.android,ok)).status,403,'flag off: no-Origin refused');assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM device_session_info').get().n,0);
 assert.equal((await f.call(on,f.android,ok)).status,200);const a=(await f.list(f.androidId)).find(x=>x.id===f.androidId);assert.deepEqual([a.clientKind,a.browser,a.os,a.name],['android',null,'android',"Abraham's Pixel 8a"]);
 assert.equal((await f.call(on,f.android,{...ok,browser:'chrome'})).status,400,'native session carries no browser');
 assert.equal((await f.call(on,f.android,{...ok,name:'a'.repeat(61)})).status,400);assert.equal((await f.call(on,f.android,{...ok,name:'x\u0000y'})).status,400);
 assert.equal((await f.call(on,f.android,{...ok,name:'  '})).status,400);assert.equal((await f.call(on,f.android,{...ok,name:null})).status,200);
 assert.equal((await f.call(on,f.web,ok)).status,401,'web token without Origin');assert.equal((await f.call(on,f.android,ok,{origin:APP})).status,401,'android token with web Origin');
 assert.equal((await f.call(on,f.web,{browser:'safari',os:'mac',name:null},{origin:APP})).status,200,'web path unchanged with the flag on');
 f.db.sqlite.prepare('UPDATE device_sessions SET revoked_at=? WHERE device_id=?').run(NOW,f.androidId);assert.equal((await f.call(on,f.android,ok)).status,401,'revoked session cannot write');
 f.db.sqlite.close();});
