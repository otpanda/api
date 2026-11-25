import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { PasskeySignupService } from '../src/passkey-signup.js';
import { AccountIdentityService } from '../src/account-identity.js';
import { DeviceSessionService } from '../src/device-sessions.js';
import { PasskeyService } from '../src/passkey-service.js';
import { PasskeyVerifier } from '../src/passkey-verifier.js';
import { NativeSessionService } from '../src/native-sessions.js';
import { NativeGoogle } from '../src/native-google.js';
import { GoogleContinuation } from '../src/google-continuation.js';
import { CodeCipher } from '../src/code-cipher.js';
import { createNativeHttp, androidOriginsFromFingerprints } from '../src/native-http.js';
import { base64urlEncode } from '../src/tokens.js';
import { authenticator } from './passkey-fixture.js';
const NOW=1_800_000_000_000,API='https://otpanda-api.abrahammurciano.workers.dev',AUD='123-abc.apps.googleusercontent.com',FPR=Array(32).fill('AB').join(':'),enc=u=>base64urlEncode(new Uint8Array(u)),te=s=>new TextEncoder().encode(s);
const ORIGIN=androidOriginsFromFingerprints([FPR])[0];
const rsa=await crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['sign','verify']);
const jwk=await crypto.subtle.exportKey('jwk',rsa.publicKey),getKey=async kid=>kid==='k1'?jwk:undefined;
async function idToken(over){const h=enc(te(JSON.stringify({alg:'RS256',kid:'k1'}))),c=enc(te(JSON.stringify({iss:'https://accounts.google.com',aud:AUD,sub:'g-sub-new',email:'a@example.com',email_verified:true,iat:Math.floor(NOW/1000),exp:Math.floor(NOW/1000)+600,...over})));return h+'.'+c+'.'+enc(await crypto.subtle.sign('RSASSA-PKCS1-v1_5',rsa.privateKey,te(h+'.'+c)));}
async function newKey(){const k=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign']);return enc(await crypto.subtle.exportKey('raw',k.publicKey));}
async function fixture({wired=true,broken=false}={}){
 const db=database();let now=NOW;const clock=()=>now;
 const identity=new AccountIdentityService(db,{clock}),signup=new PasskeySignupService(db,{clock});
 const {token}=await identity.issueEmailChallenge({purpose:'signup-email',email:'a@example.com'});
 const c=await signup.begin({email:'a@example.com',emailToken:token,binding:'binding'}),a=authenticator();
 const account=await signup.finish({token:c.token,binding:'binding',response:a.registration({expected:c.options.challenge})});
 const sessions=new DeviceSessionService(db,{clock}),native=new NativeSessionService(db,{clock});
 const managed=new PasskeyService(db,{clock,verifier:new PasskeyVerifier({androidOrigins:[ORIGIN]})});
 const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']),cipher=new CodeCipher({keys:new Map([['t',key]]),activeKeyId:'t'});
 const google=new NativeGoogle(db,{native,audiences:[AUD],getKey,clock,...(broken?{continuations:async()=>{throw new Error('keyring unavailable');}}:wired?{continuations:async()=>new GoogleContinuation(db,{cipher,clock,passkeys:managed})}:{})});
 const http=createNativeHttp({sessions,native,db,google,clock});let n=0;
 const post=(path,body,h={})=>http.fetch(new Request(API+path,{method:'POST',headers:{'Content-Type':'application/json',...h},body:typeof body==='string'?body:JSON.stringify(body)}),{clientAddress:'10.0.1.'+(n++)});
 const assertion=(challenge,o={})=>{const r=a.assertion({origin:ORIGIN,expected:challenge,...o});r.response.userHandle=o.handle??base64urlEncode(new TextEncoder().encode(account.ownerId));return r;};
 const start=async(key,over={})=>{const b=await (await post('/auth/native/google/begin','')).json();return post('/auth/native/google/complete',{id_token:await idToken({nonce:b.nonce,...over}),renewal_key:key,remember:true});};
 return{db,sessions,post,account,assertion,start,setNow:v=>now=v,q:(s,...p)=>db.sqlite.prepare(s).get(...p)};
}
const cont=async(f,key)=>{const r=await f.start(key);assert.equal(r.status,200);return r.json();};
test('existing account with a new Google subject returns a link continuation, creates nothing, and a passkey step-up links and signs in',async()=>{
 const f=await fixture(),key=await newKey(),c=await cont(f,key);
 assert.deepEqual(Object.keys(c).sort(),['continuation','email','expires_at','kind','status']);assert.equal(c.status,'continue_required');assert.equal(c.kind,'link');assert.equal(c.email,'a@example.com');
 assert.equal(f.q('SELECT count(*) n FROM accounts').n,1);assert.equal(f.q('SELECT count(*) n FROM device_sessions').n,0);assert.equal(f.q('SELECT count(*) n FROM provider_identities').n,0);
 const b=await (await f.post('/auth/native/google/continue/begin',{continuation:c.continuation,renewal_key:key})).json();assert.equal(b.options.rpId,'otpanda.github.io');
 const r=await f.post('/auth/native/google/continue/finish',{continuation:c.continuation,renewal_key:key,token:b.token,response:f.assertion(b.options.challenge)});
 assert.equal(r.status,200);const d=await r.json();assert.equal(r.headers.get('cache-control'),'no-store');assert.ok(d.recognition,'native remembers');assert.equal(d.enroll_grant,undefined);
 assert.equal((await f.sessions.authenticate(d.access)).clientKind,'android');assert.equal(f.q('SELECT count(*) n FROM provider_identities WHERE revoked_at IS NULL').n,1);assert.equal(f.q('SELECT count(*) n FROM accounts').n,1);
 assert.equal(f.q('SELECT public_key p FROM native_keys').p,key);
 // single use: replay of finish, and the continuation row is gone
 assert.equal((await f.post('/auth/native/google/continue/finish',{continuation:c.continuation,renewal_key:key,token:b.token,response:f.assertion(b.options.challenge,{counter:5})})).status,401);
 // next Google sign-in is the ordinary linked path
 assert.equal((await f.start(await newKey())).status,200);
});
test('a different install key, a bad or missing assertion, a wrong-origin assertion and an expired continuation are opaque 401 and link nothing',async()=>{
 const f=await fixture(),key=await newKey(),c=await cont(f,key),other=await newKey();
 assert.equal((await f.post('/auth/native/google/continue/begin',{continuation:c.continuation,renewal_key:other})).status,401);
 const b=await (await f.post('/auth/native/google/continue/begin',{continuation:c.continuation,renewal_key:key})).json();
 assert.equal((await f.post('/auth/native/google/continue/finish',{continuation:c.continuation,renewal_key:other,token:b.token,response:f.assertion(b.options.challenge)})).status,401);
 for(const [i,o] of [{invalidSignature:true},{origin:'android:apk-key-hash:'+'A'.repeat(43)},{rp:'evil.example'}].entries()){
  const r=await f.post('/auth/native/google/continue/finish',{continuation:c.continuation,renewal_key:key,token:b.token,response:f.assertion(b.options.challenge,{counter:i+2,...o})});assert.equal(r.status,401);assert.deepEqual(await r.json(),{error:'invalid_grant'});}
 assert.equal(f.q('SELECT count(*) n FROM provider_identities').n,0);assert.equal(f.q('SELECT count(*) n FROM device_sessions').n,0);
 f.setNow(NOW+11*60_000);
 assert.equal((await f.post('/auth/native/google/continue/begin',{continuation:c.continuation,renewal_key:key})).status,401);
 assert.equal((await f.post('/auth/native/google/continue/finish',{continuation:'otpda_'+'A'.repeat(55),renewal_key:key,token:b.token,response:f.assertion(b.options.challenge)})).status,401);
});
test('extra verification on new devices does not block the link: the fresh passkey proof is the strong method',async()=>{
 const f=await fixture(),key=await newKey(),c=await cont(f,key);
 f.db.sqlite.exec(`INSERT INTO new_device_verification(owner_id,enabled_at,generation) VALUES('${f.account.ownerId}',0,0)`);
 const b=await (await f.post('/auth/native/google/continue/begin',{continuation:c.continuation,renewal_key:key})).json();
 assert.equal((await f.post('/auth/native/google/continue/finish',{continuation:c.continuation,renewal_key:key,token:b.token,response:f.assertion(b.options.challenge)})).status,200);
 // but a plain Google sign-in on another new install with protection on is still refused (browser_required), unchanged
 assert.equal((await f.start(await newKey())).status,409);
});
test('web and native stay separate: no Origin allowed, strict bodies, unwired continuations fall back to browser_required',async()=>{
 const f=await fixture(),key=await newKey(),c=await cont(f,key);
 assert.equal((await f.post('/auth/native/google/continue/begin',{continuation:c.continuation,renewal_key:key},{Origin:'https://otpanda.github.io'})).status,403);
 assert.equal((await f.post('/auth/native/google/continue/begin',{continuation:c.continuation,renewal_key:key,extra:1})).status,400);
 assert.equal((await f.post('/auth/native/google/continue/begin',{continuation:c.continuation,renewal_key:'x'})).status,400);
 assert.equal((await f.post('/auth/native/google/continue/finish',{continuation:c.continuation,renewal_key:key,token:'t',response:[]})).status,400);
 const g=await fixture({wired:false}),r=await g.start(await newKey());assert.equal(r.status,409);assert.equal((await g.post('/auth/native/google/continue/begin',{continuation:'x',renewal_key:await newKey()})).status,401);
 assert.equal((await f.post('/auth/native/google/continue/begin',{continuation:c.continuation,renewal_key:key})).status,200);
});
test('a failing continuation factory disables only the continue step: 409 browser_required at complete, opaque 401 at begin and finish, never a 500',async()=>{
 const f=await fixture({broken:true}),key=await newKey(),r=await f.start(key);assert.equal(r.status,409);
 assert.equal((await f.post('/auth/native/google/continue/begin',{continuation:'otpda_'+'A'.repeat(55),renewal_key:key})).status,401);
 assert.equal((await f.post('/auth/native/google/continue/finish',{continuation:'otpda_'+'A'.repeat(55),renewal_key:key,token:'t',response:{}})).status,401);
 assert.equal(f.q('SELECT count(*) n FROM device_sessions').n,0);
});
