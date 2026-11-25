import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { PasskeySignupService } from '../src/passkey-signup.js';
import { AccountIdentityService } from '../src/account-identity.js';
import { DeviceSessionService } from '../src/device-sessions.js';
import { RecoveryControls } from '../src/recovery-controls.js';
import { pkceChallenge } from '../src/browser-exchanges.js';

import { createIdentityRuntime } from '../src/identity-runtime.js';
import { createIdentityEdgeHost } from '../src/identity-edge-host.js';
import { base64urlEncode } from '../src/tokens.js';
import { authenticator } from './passkey-fixture.js';
const NOW=1_800_000_000_000,API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',verifier='q'.repeat(43),yes={limit:async()=>({success:true})};
async function fixture(){
 const db=database(),clock=()=>NOW,identity=new AccountIdentityService(db,{clock}),signup=new PasskeySignupService(db,{clock}),a=authenticator(),{token}=await identity.issueEmailChallenge({purpose:'signup-email',email:'a@example.com'});
 const c=await signup.begin({email:'a@example.com',emailToken:token,binding:'b'}),account=await signup.finish({token:c.token,binding:'b',response:a.registration({expected:c.options.challenge})});
 const sessions=new DeviceSessionService(db,{clock}),d=await sessions.issue({proof:{...account,verifiedAt:NOW,purpose:'authenticate'},clientKind:'web'}),web=(await sessions.rotate(d.refresh,{clientKind:'web'})).access;
 const other=await sessions.issue({proof:{...account,verifiedAt:NOW,purpose:'authenticate'},clientKind:'web'});
 const host=on=>createIdentityEdgeHost({nativeApi:on,resolveTrustedIngress:()=>'192.0.2.1',edgeAddress:yes,edgeAuthGlobal:yes,edgeReadGlobal:yes,initialize:async()=>createIdentityRuntime({db,keys:new Map(),activeKeyId:'x',trustedRequestKey:()=>'192.0.2.1',clock,native:{enabled:on}})});
 const rc=new RecoveryControls(db,{clock}),list=async(deviceId)=>(await rc.status({ownerId:account.ownerId,deviceId,generation:0})).sessions;
 const call=(h,token,body,{origin,method='POST',ct='application/json'}={})=>h.fetch(new Request(API+'/v1/manage/session/describe',{method,headers:{...(origin?{Origin:origin}:{}),...(token?{Authorization:'Bearer '+token}:{}),'Content-Type':ct},...(method==='GET'?{}:{body:typeof body==='string'?body:JSON.stringify(body)})}));
 return{db,web,webId:d.deviceId,host,list,call};
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
