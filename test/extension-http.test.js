import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { PasskeySignupService } from '../src/passkey-signup.js';
import { AccountIdentityService } from '../src/account-identity.js';
import { DeviceSessionService } from '../src/device-sessions.js';
import { pkceChallenge } from '../src/browser-exchanges.js';
import { NativeSessionService,extensionProfile,nativeMessage } from '../src/native-sessions.js';
import { createExtensionHttp } from '../src/extension-http.js';
import { base64urlEncode } from '../src/tokens.js';
import { authenticator } from './passkey-fixture.js';
const NOW=1_800_000_000_000,API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',verifier='h'.repeat(43),state='s'.repeat(43);
const R1='https://abcdefghijklmnopabcdefghijklmnop.chromiumapp.org/',R2='https://ffff.example-fx.test/',EXTO='chrome-extension://abcdefghijklmnopabcdefghijklmnop',enc=u=>base64urlEncode(new Uint8Array(u));
const prof=extensionProfile([R1,R2]);
async function setup(){
 const db=database();let now=NOW;const clock=()=>now;
 const identity=new AccountIdentityService(db,{clock}),signup=new PasskeySignupService(db,{clock});
 const {token}=await identity.issueEmailChallenge({purpose:'signup-email',email:'a@example.com'});
 const c=await signup.begin({email:'a@example.com',emailToken:token,binding:'binding'}),a=authenticator();
 const account=await signup.finish({token:c.token,binding:'binding',response:a.registration({expected:c.options.challenge})});
 const proof={...account,verifiedAt:NOW,purpose:'authenticate'},sessions=new DeviceSessionService(db,{clock}),web=await sessions.issue({proof,clientKind:'web'});
 const extension=new NativeSessionService(db,{clock,profile:prof}),http=createExtensionHttp({sessions,extension,db,redirects:{chrome:R1,firefox:R2},extensionOrigins:[EXTO],clock});
 const k=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign']),pub=enc(await crypto.subtle.exportKey('raw',k.publicKey));
 const call=(path,{method='POST',origin,auth,data,raw,type='application/json'}={})=>http.fetch(new Request(API+path,{method,headers:{...(type?{'content-type':type}:{}),...(origin?{origin}:{}),...(auth?{authorization:'Bearer '+auth}:{})},body:method==='GET'?undefined:raw??JSON.stringify(data??{})}),{clientAddress:'1.2.3.4'});
 return{db,sessions,web,extension,call,k,pub,proof,setNow:v=>now=v};
}
const beginBody=async(o={})=>({challenge:await pkceChallenge(verifier),confirm:true,redirect:'chrome',state,...o});
const frag=r=>new URLSearchParams(new URL(r).hash.slice(1));
test('begin: explicit confirm, web bearer + APP origin only; code in the fragment, never the query; redirect chosen by key',async()=>{
 const f=await setup(),ok=await f.call('/auth/extension/begin',{origin:APP,auth:f.web.access,data:await beginBody()});assert.equal(ok.status,200);
 const j=await ok.json(),u=new URL(j.redirect);assert.equal(u.origin+'/',R1);assert.equal(u.search,'');assert.ok(frag(j.redirect).get('code'));assert.equal(frag(j.redirect).get('state'),state);
 assert.equal(ok.headers.get('access-control-allow-origin'),APP);
 for(const [name,over,opt] of [['no confirm',{confirm:undefined},{}],['confirm string',{confirm:'true'},{}],['confirm false',{confirm:false},{}],['url as redirect',{redirect:R1},{}],['unknown key',{redirect:'evil'},{}],['bad challenge',{challenge:'x'},{}],['bad state',{state:'x'},{}]]){
  const b=await beginBody(over);if(over.confirm===undefined)delete b.confirm;
  assert.equal((await f.call('/auth/extension/begin',{origin:APP,auth:f.web.access,data:b,...opt})).status,400,name);}
 assert.equal((await f.call('/auth/extension/begin',{auth:f.web.access,data:await beginBody()})).status,403,'no origin');
 assert.equal((await f.call('/auth/extension/begin',{origin:EXTO,auth:f.web.access,data:await beginBody()})).status,403,'extension origin');
 assert.equal((await f.call('/auth/extension/begin',{origin:APP,data:await beginBody()})).status,401,'no bearer');
 assert.equal((await f.call('/auth/extension/begin?x=1',{origin:APP,auth:f.web.access,data:await beginBody()})).status,400);
 assert.equal((await f.call('/auth/extension/begin',{method:'GET',origin:APP,auth:f.web.access})).status,405,'a page load (GET) mints nothing');
 assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM native_exchanges').get().n,1);f.db.sqlite.close();
});
test('full flow: begin -> exchange (fragment code, redirect key) -> challenge -> signed renew -> access logout; token routes never emit CORS headers',async()=>{
 const f=await setup(),j=await (await f.call('/auth/extension/begin',{origin:APP,auth:f.web.access,data:await beginBody()})).json(),code=frag(j.redirect).get('code');
 const ex=await f.call('/auth/extension/exchange',{data:{code,redirect:'chrome',renewal_key:f.pub,verifier}});assert.equal(ex.status,200);assert.equal(ex.headers.get('access-control-allow-origin'),null);
 const e=await ex.json(),a=await f.sessions.authenticate(e.access);assert.equal(a.clientKind,'extension');
 const ch=await (await f.call('/auth/extension/challenge',{origin:EXTO,data:{device_id:e.device_id,purpose:'renew'}})).json();
 const sig=enc(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},f.k.privateKey,nativeMessage({purpose:'renew',deviceId:e.device_id,nonce:ch.nonce,expiresAt:ch.expires_at,profile:prof})));
 const rn=await f.call('/auth/extension/renew',{origin:EXTO,data:{device_id:e.device_id,nonce:ch.nonce,expires_at:ch.expires_at,signature:sig}});assert.equal(rn.status,200);
 assert.equal((await f.call('/auth/extension/renew',{data:{device_id:e.device_id,nonce:ch.nonce,expires_at:ch.expires_at,signature:sig}})).status,401,'replay');
 assert.equal((await f.call('/auth/extension/logout',{auth:(await rn.json()).access,raw:''})).status,204);assert.equal(await f.sessions.authenticate(e.access),undefined);f.db.sqlite.close();
});
test('token routes refuse foreign, web and null Origins; replayed or wrong-redirect codes fail; web token cannot log out an extension',async()=>{
 const f=await setup(),mk=async()=>frag((await (await f.call('/auth/extension/begin',{origin:APP,auth:f.web.access,data:await beginBody()})).json()).redirect).get('code');
 const code=await mk(),d={code,redirect:'chrome',renewal_key:f.pub,verifier};
 for(const o of [APP,'null','https://evil.example','chrome-extension://zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz','moz-extension://anything'])assert.equal((await f.call('/auth/extension/exchange',{origin:o,data:d})).status,403,o);
 assert.equal((await f.call('/auth/extension/exchange',{data:{...d,redirect:'firefox'}})).status,401,'minted for chrome, presented for firefox');
 assert.equal((await f.call('/auth/extension/exchange',{data:{...d,redirect:R1}})).status,400,'URL instead of key');
 assert.equal((await f.call('/auth/extension/exchange',{data:{...d,extra:1}})).status,400);
 assert.equal((await f.call('/auth/extension/exchange',{data:d})).status,200);assert.equal((await f.call('/auth/extension/exchange',{data:d})).status,401,'replay');
 assert.equal((await f.call('/auth/extension/exchange',{method:'GET'})).status,405);assert.equal((await f.call('/auth/extension/exchange?code=1',{data:d})).status,400);
 assert.equal((await f.call('/auth/extension/logout',{auth:f.web.access,raw:''})).status,401);assert.equal((await f.call('/auth/native/exchange',{data:d})).status,404);f.db.sqlite.close();
});
test('source web device is re-checked in the exchange write: revoked, or a generation change, after mint spends the code and creates nothing',async()=>{
 const f=await setup(),code=frag((await (await f.call('/auth/extension/begin',{origin:APP,auth:f.web.access,data:await beginBody()})).json()).redirect).get('code');
 await f.sessions.revoke({ownerId:f.proof.ownerId,deviceId:f.web.deviceId});
 assert.equal((await f.call('/auth/extension/exchange',{data:{code,redirect:'chrome',renewal_key:f.pub,verifier}})).status,401);
 assert.equal(f.db.sqlite.prepare("SELECT count(*) n FROM device_sessions WHERE client_kind='extension'").get().n,0);f.db.sqlite.close();
});
test('a generation bump after mint (sign out everywhere) also blocks the exchange and creates nothing',async()=>{
 const f=await setup(),code=frag((await (await f.call('/auth/extension/begin',{origin:APP,auth:f.web.access,data:await beginBody()})).json()).redirect).get('code');
 const before=f.db.sqlite.prepare('SELECT generation g FROM account_security WHERE owner_id=?').get(f.proof.ownerId).g;
 f.db.sqlite.prepare('UPDATE account_security SET generation=generation+1 WHERE owner_id=?').run(f.proof.ownerId);
 assert.equal(f.db.sqlite.prepare('SELECT generation g FROM account_security WHERE owner_id=?').get(f.proof.ownerId).g,before+1);
 assert.equal((await f.call('/auth/extension/exchange',{data:{code,redirect:'chrome',renewal_key:f.pub,verifier}})).status,401);
 assert.equal(f.db.sqlite.prepare("SELECT count(*) n FROM device_sessions WHERE client_kind='extension'").get().n,0);f.db.sqlite.close();
});
test('config: redirect keys must map to allowlisted exact URIs',async()=>{
 const f=await setup();assert.throws(()=>createExtensionHttp({sessions:f.sessions,extension:f.extension,db:f.db,redirects:{chrome:'https://evil.chromiumapp.org/'}}),TypeError);
 assert.throws(()=>createExtensionHttp({sessions:f.sessions,extension:new NativeSessionService(f.db),db:f.db,redirects:{chrome:R1}}),TypeError);f.db.sqlite.close();
});
