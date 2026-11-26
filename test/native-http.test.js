import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { PasskeySignupService } from '../src/passkey-signup.js';
import { AccountIdentityService } from '../src/account-identity.js';
import { DeviceSessionService } from '../src/device-sessions.js';
import { pkceChallenge } from '../src/browser-exchanges.js';
import { NativeSessionService,nativeMessage,NATIVE_REDIRECT } from '../src/native-sessions.js';
import { createNativeHttp } from '../src/native-http.js';
import { base64urlEncode } from '../src/tokens.js';
import { authenticator } from './passkey-fixture.js';
const NOW=1_800_000_000_000,API='https://otpanda-api.abrahammurciano.workers.dev',verifier='h'.repeat(43),enc=u=>base64urlEncode(new Uint8Array(u)),FPR=Array(32).fill('AB').join(':');
async function newKey(){const k=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign']);return{priv:k.privateKey,pub:enc(await crypto.subtle.exportKey('raw',k.publicKey))};}
async function fixture(fps=[]){
 const db=database();let now=NOW;const clock=()=>now;
 const identity=new AccountIdentityService(db,{clock}),signup=new PasskeySignupService(db,{clock});
 const {token}=await identity.issueEmailChallenge({purpose:'signup-email',email:'a@example.com'});
 const c=await signup.begin({email:'a@example.com',emailToken:token,binding:'binding'}),a=authenticator();
 const account=await signup.finish({token:c.token,binding:'binding',response:a.registration({expected:c.options.challenge})});
 const sessions=new DeviceSessionService(db,{clock}),web=await sessions.issue({proof:{...account,verifiedAt:NOW,purpose:'authenticate'},clientKind:'web'}),native=new NativeSessionService(db,{clock});
 const http=createNativeHttp({sessions,native,db,clock,assetFingerprints:fps}),opts={clientAddress:'1.2.3.4'};
 const post=(path,body,h={})=>http.fetch(new Request(API+path,{method:'POST',headers:{'Content-Type':'application/json',...h},body:typeof body==='string'?body:JSON.stringify(body)}),opts);
 return{db,sessions,web,native,http,post,opts,setNow:v=>now=v,clock};
}
const intent=async()=>({challenge:await pkceChallenge(verifier),state:'s'.repeat(43)});
async function approvePage(f,i,cookie){const r=await f.http.fetch(new Request(API+'/auth/native/approve?'+new URLSearchParams({...i,redirect_uri:NATIVE_REDIRECT})),f.opts);return r;}
async function approve(f,webRefresh){
 const i=await intent(),g=await approvePage(f,i),html=await g.text(),csrf=html.match(/name="csrf" value="([^"]+)"/)[1],setc=g.headers.get('set-cookie').split(';')[0];
 const form=new URLSearchParams({...i,redirect_uri:NATIVE_REDIRECT,csrf});
 return {i,g,html,csrf,setc,post:(over={})=>f.http.fetch(new Request(API+'/auth/native/approve',{method:'POST',headers:{Origin:API,'Content-Type':'application/x-www-form-urlencoded',Cookie:`${setc}; __Host-otpanda_device=${webRefresh}`,...over.headers},body:(over.form??form).toString()}),f.opts)};
}
test('assetlinks fails closed with no fingerprints, then lists exactly the configured verified signer for app.otpanda',async()=>{
 let f=await fixture();assert.equal((await f.http.fetch(new Request(API+'/.well-known/assetlinks.json'),f.opts)).status,404);
 assert.throws(()=>createNativeHttp({sessions:f.sessions,native:f.native,db:f.db,assetFingerprints:['05c6']}),TypeError);
 f=await fixture([FPR]);const r=await f.http.fetch(new Request(API+'/.well-known/assetlinks.json'),f.opts),b=await r.json();
 assert.equal(r.status,200);assert.deepEqual(b[0].target,{namespace:'android_app',package_name:'app.otpanda',sha256_cert_fingerprints:[FPR]});});
test('approve: explicit Continue page, intent-bound CSRF, then 303 to the exact App Link with code+state in the FRAGMENT',async()=>{
 const f=await fixture(),ap=await approve(f,f.web.refresh);
 assert.equal(ap.g.status,200);assert.match(ap.html,/class="brand"/);assert.match(ap.html,/Figtree/);assert.match(ap.html,/<svg/);assert.doesNotMatch(ap.html,/<script|onload=|requestSubmit|autofocus=/i);assert.match(ap.g.headers.get('content-security-policy'),/default-src 'none'/);assert.match(ap.g.headers.get('content-security-policy'),/font-src data:/);assert.equal(ap.g.headers.get('referrer-policy'),'same-origin','form POST must retain a same-origin Origin header in Chromium');assert.match(ap.html,/Continue/);assert.match(ap.g.headers.get('content-security-policy'),/form-action 'self'/);assert.match(ap.g.headers.get('set-cookie'),/__Host-otpanda_native=.*Secure.*HttpOnly/);
 const r=await ap.post();assert.equal(r.status,303);const loc=new URL(r.headers.get('location'));
 assert.equal(loc.origin+loc.pathname,NATIVE_REDIRECT);assert.equal(loc.search,'');const h=new URLSearchParams(loc.hash.slice(1));assert.equal(h.get('state'),ap.i.state);assert.ok(h.get('code'));
 // rotated web cookie is reissued; a native exchange completes with PKCE and the bound key
 assert.match(r.headers.getSetCookie().join('\n'),/__Host-otpanda_device=/);
 // approve rotation is identical to /auth/restore: only the refresh cookie is reissued and the native CSRF cookie cleared. No recognition/remember cookie is read, set or cleared.
 {const names=r.headers.getSetCookie().map(c=>c.split('=')[0]).sort();assert.deepEqual(names,['__Host-otpanda_device','__Host-otpanda_native']);assert.match(r.headers.getSetCookie().find(c=>c.startsWith('__Host-otpanda_native=')),/Max-Age=0/);}
 const k=await newKey(),x=await f.post('/auth/native/exchange',{code:h.get('code'),verifier,redirect_uri:NATIVE_REDIRECT,renewal_key:k.pub}),xb=await x.json();
 assert.equal(x.status,200);assert.deepEqual(Object.keys(xb).sort(),['access','access_expires_at','device_id']);assert.equal((await f.sessions.authenticate(xb.access)).clientKind,'android');
 assert.equal((await f.post('/auth/native/exchange',{code:h.get('code'),verifier,redirect_uri:NATIVE_REDIRECT,renewal_key:k.pub})).status,401,'one use');f.db.sqlite.close();});
test('approve POST refuses: no CSRF cookie, wrong/other-intent csrf, foreign Origin, no or revoked web cookie, replayed cookie; GET refuses extra or bad params',async()=>{
 const f=await fixture(),ap=await approve(f,f.web.refresh);
 const count=()=>f.db.sqlite.prepare('SELECT count(*) n FROM native_exchanges').get().n;
 assert.equal((await ap.post({headers:{Cookie:`__Host-otpanda_device=${f.web.refresh}`}})).status,403,'no csrf cookie');
 const other=await intent();assert.equal((await ap.post({form:new URLSearchParams({...other,state:'t'.repeat(43),redirect_uri:NATIVE_REDIRECT,csrf:ap.csrf})})).status,403,'csrf bound to the exact intent');
 assert.equal((await ap.post({form:new URLSearchParams({challenge:ap.i.challenge,state:ap.i.state,redirect_uri:'https://evil.example/',csrf:ap.csrf})})).status,403,'redirect fixed');
 assert.equal((await ap.post({headers:{Origin:'https://evil.example'}})).status,403,'foreign origin');
 assert.equal((await ap.post({headers:{Cookie:ap.setc}})).status,401,'no web cookie');
 assert.equal(count(),0);
 await f.sessions.revoke({ownerId:f.web.ownerId??f.db.sqlite.prepare('select owner_id o from device_sessions').get().o,deviceId:f.web.deviceId});
 assert.equal((await ap.post()).status,401,'revoked web device');assert.equal(count(),0);
 const bad=await f.http.fetch(new Request(API+'/auth/native/approve?challenge=x&state=y&redirect_uri='+encodeURIComponent(NATIVE_REDIRECT)),f.opts);assert.equal(bad.status,400);
 const extra=await f.http.fetch(new Request(API+'/auth/native/approve?'+new URLSearchParams({...ap.i,redirect_uri:NATIVE_REDIRECT,x:'1'})),f.opts);assert.equal(extra.status,400);f.db.sqlite.close();});
test('an android session cannot be the approval authority (web cookie rotation only for web devices)',async()=>{
 const f=await fixture(),k=await newKey(),ap0=await approve(f,f.web.refresh),loc=new URLSearchParams(new URL((await ap0.post()).headers.get('location')).hash.slice(1));
 const x=await (await f.post('/auth/native/exchange',{code:loc.get('code'),verifier,redirect_uri:NATIVE_REDIRECT,renewal_key:k.pub})).json();
 const ap=await approve(f,x.access);assert.equal((await ap.post()).status,401);f.db.sqlite.close();});
test('token routes: browser Origin refused, strict bodies, query refused, renew/logout over HTTP with the signed nonce, no cookies set',async()=>{
 const f=await fixture(),k=await newKey(),ap=await approve(f,f.web.refresh),loc=new URLSearchParams(new URL((await ap.post()).headers.get('location')).hash.slice(1));
 const ex=await f.post('/auth/native/exchange',{code:loc.get('code'),verifier,redirect_uri:NATIVE_REDIRECT,renewal_key:k.pub}),e=await ex.json();assert.equal(ex.headers.get('set-cookie'),null);
 assert.equal((await f.post('/auth/native/challenge',{device_id:e.device_id,purpose:'renew'},{Origin:'https://otpanda.github.io'})).status,403);
 assert.equal((await f.post('/auth/native/challenge',{device_id:e.device_id,purpose:'renew',extra:1})).status,400);
 assert.equal((await f.post('/auth/native/challenge','{bad')).status,400);
 assert.equal((await f.http.fetch(new Request(API+'/auth/native/challenge?x=1',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}),f.opts)).status,403);
 assert.equal((await f.http.fetch(new Request(API+'/auth/native/renew',{method:'GET'}),f.opts)).status,405);
 const sig=async(purpose,c)=>enc(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},k.priv,nativeMessage({purpose,deviceId:e.device_id,nonce:c.nonce,expiresAt:c.expires_at})));
 const c=await (await f.post('/auth/native/challenge',{device_id:e.device_id,purpose:'renew'})).json();
 assert.equal((await f.post('/auth/native/renew',{device_id:e.device_id,nonce:c.nonce,expires_at:c.expires_at,signature:'A'.repeat(86)})).status,401);
 f.setNow(NOW+4000000);const c2=await (await f.post('/auth/native/challenge',{device_id:e.device_id,purpose:'renew'})).json();
 const rr=await f.post('/auth/native/renew',{device_id:e.device_id,nonce:c2.nonce,expires_at:c2.expires_at,signature:await sig('renew',c2)}),rb=await rr.json();
 assert.equal(rr.status,200);assert.equal((await f.sessions.authenticate(rb.access)).clientKind,'android');
 assert.equal((await f.post('/auth/native/renew',{device_id:e.device_id,nonce:c2.nonce,expires_at:c2.expires_at,signature:await sig('renew',c2)})).status,401,'replay');
 const l=await (await f.post('/auth/native/challenge',{device_id:e.device_id,purpose:'logout'})).json();
 assert.equal((await f.post('/auth/native/logout',{device_id:e.device_id,nonce:l.nonce,expires_at:l.expires_at,signature:await sig('renew',l)})).status,401,'wrong purpose signature');
 assert.equal((await f.post('/auth/native/logout',{device_id:e.device_id,nonce:l.nonce,expires_at:l.expires_at,signature:await sig('logout',l)})).status,204);
 assert.equal(await f.sessions.authenticate(rb.access),undefined);f.db.sqlite.close();});
test('bearer logout: android access only, body must be empty; web access is refused',async()=>{
 const f=await fixture(),k=await newKey(),ap=await approve(f,f.web.refresh),loc=new URLSearchParams(new URL((await ap.post()).headers.get('location')).hash.slice(1));
 const e=await (await f.post('/auth/native/exchange',{code:loc.get('code'),verifier,redirect_uri:NATIVE_REDIRECT,renewal_key:k.pub})).json();
 const webAccess=await f.sessions.rotate(f.web.refresh,{clientKind:'web'});
 assert.equal((await f.post('/auth/native/logout','',{Authorization:'Bearer '+webAccess.access})).status,401);
 assert.equal((await f.post('/auth/native/logout','',{Authorization:'Bearer '+e.access})).status,204);assert.equal(await f.sessions.authenticate(e.access),undefined);f.db.sqlite.close();});
