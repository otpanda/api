import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { PasskeySignupService } from '../src/passkey-signup.js';
import { AccountIdentityService } from '../src/account-identity.js';
import { DeviceSessionService } from '../src/device-sessions.js';
import { PasskeyService } from '../src/passkey-service.js';
import { PasskeyVerifier } from '../src/passkey-verifier.js';
import { NativeSessionService } from '../src/native-sessions.js';
import { createNativeHttp, androidOriginsFromFingerprints } from '../src/native-http.js';
import { base64urlEncode } from '../src/tokens.js';
import { authenticator } from './passkey-fixture.js';
const NOW=1_800_000_000_000,API='https://otpanda-api.abrahammurciano.workers.dev',FPR=Array(32).fill('AB').join(':'),enc=u=>base64urlEncode(new Uint8Array(u));
const ORIGIN=androidOriginsFromFingerprints([FPR])[0];
async function newKey(){const k=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign']);return enc(await crypto.subtle.exportKey('raw',k.publicKey));}
async function fixture({origins=[ORIGIN],wired=true}={}){
 if(!origins.length)origins=['android:apk-key-hash:'+'B'.repeat(43)];// nativeOnly needs at least one signer; none matches the assertion
 const db=database();let now=NOW;const clock=()=>now;
 const identity=new AccountIdentityService(db,{clock}),signup=new PasskeySignupService(db,{clock});
 const {token}=await identity.issueEmailChallenge({purpose:'signup-email',email:'a@example.com'});
 const c=await signup.begin({email:'a@example.com',emailToken:token,binding:'binding'}),a=authenticator();
 const account=await signup.finish({token:c.token,binding:'binding',response:a.registration({expected:c.options.challenge})});
 const sessions=new DeviceSessionService(db,{clock}),native=new NativeSessionService(db,{clock});
 const passkeys=new PasskeyService(db,{clock,verifier:new PasskeyVerifier({androidOrigins:origins,nativeOnly:true})});
 const http=createNativeHttp({sessions,native,db,clock,passkeys:wired?passkeys:undefined});
 let n=0;const post=(path,body,h={})=>http.fetch(new Request(API+path,{method:'POST',headers:{'Content-Type':'application/json',...h},body:typeof body==='string'?body:JSON.stringify(body)}),{clientAddress:'10.0.0.'+(n++)});
 const assertion=(challenge,o={})=>{const r=a.assertion({origin:ORIGIN,expected:challenge,...o});r.response.userHandle=o.handle??base64urlEncode(new TextEncoder().encode(account.ownerId));return r;};
 return{db,sessions,native,post,a,account,assertion,setNow:v=>now=v,passkeys};
}
const begin=async(f,key)=>(await f.post('/auth/native/passkey/begin',{renewal_key:key})).json();
test('begin then complete issues an android device via the OS passkey; the session is android, passkey-method and renewable key bound',async()=>{
 const f=await fixture(),key=await newKey(),b=await begin(f,key);
 assert.equal(b.options.rpId,'otpanda.github.io');assert.equal(b.options.userVerification,'required');assert.equal(b.options.allowCredentials,undefined);
 const r=await f.post('/auth/native/passkey/complete',{renewal_key:key,token:b.token,response:f.assertion(b.options.challenge)});
 assert.equal(r.status,200);assert.equal(r.headers.get('cache-control'),'no-store');const d=await r.json();
 assert.deepEqual(Object.keys(d).sort(),['access','access_expires_at','device_id']);
 const s=await f.db.prepare('SELECT client_kind,credential_id,provider_identity_id FROM device_sessions WHERE device_id=?1').bind(d.device_id).first();
 assert.equal(s.client_kind,'android');assert.equal(s.credential_id,f.a.credential.id);assert.equal(s.provider_identity_id,null);
 assert.equal((await f.db.prepare('SELECT public_key FROM native_keys WHERE device_id=?1').bind(d.device_id).first()).public_key,key);
 const au=await f.sessions.authenticate(d.access);assert.equal(au.clientKind,'android');
});
test('replay, wrong renewal key binding, wrong origin, wrong rp, other web origin and missing user handle are all opaque 401',async()=>{
 const f=await fixture(),key=await newKey();
 const attempt=async(mk,k=key)=>{const b=await begin(f,key);const r=await f.post('/auth/native/passkey/complete',{renewal_key:k,token:b.token,response:mk(b.options.challenge)});return {r,b};};
 let counter=1;
 for(const mk of [c=>f.assertion(c,{origin:'android:apk-key-hash:'+'A'.repeat(43),counter:counter++}),c=>f.assertion(c,{rp:'evil.example',counter:counter++}),c=>f.assertion(c,{handle:'AAAA',counter:counter++}),c=>f.assertion(c,{expected:Buffer.alloc(32,9).toString('base64url'),counter:counter++}),c=>f.assertion(c,{invalidSignature:true,counter:counter++})]){
  const {r}=await attempt(mk);assert.equal(r.status,401);assert.deepEqual(await r.json(),{error:'invalid_grant'});}
 const other=await newKey(),{r}=await attempt(c=>f.assertion(c,{counter:counter++}),other);assert.equal(r.status,401);
 const b=await begin(f,key),resp=f.assertion(b.options.challenge,{counter:counter++});
 assert.equal((await f.post('/auth/native/passkey/complete',{renewal_key:key,token:b.token,response:resp})).status,200);
 assert.equal((await f.post('/auth/native/passkey/complete',{renewal_key:key,token:b.token,response:resp})).status,401);
 assert.equal((await f.db.prepare('SELECT count(*) n FROM device_sessions').first()).n,1);
});
test('android origin is accepted only when configured; the web service never accepts it; expired ceremony refused',async()=>{
 const f=await fixture({origins:[]}),key=await newKey(),b=await begin(f,key);
 assert.equal((await f.post('/auth/native/passkey/complete',{renewal_key:key,token:b.token,response:f.assertion(b.options.challenge)})).status,401);
 const g=await fixture(),k2=await newKey(),b2=await begin(g,k2);g.setNow(NOW+10*60_000);
 assert.equal((await g.post('/auth/native/passkey/complete',{renewal_key:k2,token:b2.token,response:g.assertion(b2.options.challenge)})).status,401);
 assert.throws(()=>androidOriginsFromFingerprints(['05c6']),TypeError);assert.match(ORIGIN,/^android:apk-key-hash:[A-Za-z0-9_-]{43}$/);
});
test('boundary: no Origin, exact content type, exact fields, POST only, fails closed when unwired, per-route 400s',async()=>{
 const f=await fixture(),key=await newKey();
 assert.equal((await f.post('/auth/native/passkey/begin',{renewal_key:key},{Origin:'https://otpanda.github.io'})).status,403);
 assert.equal((await f.post('/auth/native/passkey/begin',{renewal_key:key},{'Content-Type':'application/json; charset=utf-8'})).status,400);
 assert.equal((await f.post('/auth/native/passkey/begin',{renewal_key:key,extra:1})).status,400);
 assert.equal((await f.post('/auth/native/passkey/begin',{renewal_key:123})).status,400);
 assert.equal((await f.post('/auth/native/passkey/complete',{renewal_key:key,token:'x',response:[]})).status,400);
 assert.equal((await f.post('/auth/native/passkey/complete',{renewal_key:key})).status,400);
 const http=createNativeHttp({sessions:f.sessions,native:f.native,db:f.db});
 const r=await http.fetch(new Request(API+'/auth/native/passkey/begin',{method:'GET'}),{clientAddress:'1.2.3.4'});assert.equal(r.status,405);
 const u=await fixture({wired:false});assert.equal((await u.post('/auth/native/passkey/begin',{renewal_key:key})).status,503);
});
test('a web-bound ceremony cannot be completed natively and a native ceremony cannot be completed by web binding; revoked credential refused',async()=>{
 const f=await fixture(),key=await newKey();
 const w=await f.passkeys.begin({purpose:'authenticate',binding:'cookie-binding'});
 assert.equal((await f.post('/auth/native/passkey/complete',{renewal_key:key,token:w.token,response:f.assertion(w.options.challenge)})).status,401);
 const b=await begin(f,key);
 assert.equal(await f.passkeys.finishAuthentication({token:b.token,binding:'cookie-binding',response:f.assertion(b.options.challenge,{counter:2})}),undefined);
 const b2=await begin(f,key);await f.db.prepare('UPDATE passkey_credentials SET revoked_at=?1').bind(NOW).run();
 assert.equal((await f.post('/auth/native/passkey/complete',{renewal_key:key,token:b2.token,response:f.assertion(b2.options.challenge,{counter:3})})).status,401);
});
test('device cap: no new android device past the cap',async()=>{
 const f=await fixture();let last;
 for(let i=0;i<60;i++){const key=await newKey(),b=await f.passkeys.begin({purpose:'authenticate',binding:'native-passkey-v1:'+key});last=await f.post('/auth/native/passkey/complete',{renewal_key:key,token:b.token,response:f.assertion(b.options.challenge,{counter:i+1})});if(last.status!==200)break;}
 assert.equal(last.status,401);assert.ok((await f.db.prepare('SELECT count(*) n FROM device_sessions').first()).n<=50);
});

test('native verifier is native-only: the exact web origin is refused natively; the web verifier is unchanged; empty native origins rejected',async()=>{
 const f=await fixture(),key=await newKey(),b=await begin(f,key);
 assert.equal((await f.post('/auth/native/passkey/complete',{renewal_key:key,token:b.token,response:f.assertion(b.options.challenge,{origin:'https://otpanda.github.io'})})).status,401);
 assert.throws(()=>new PasskeyVerifier({androidOrigins:[],nativeOnly:true}),TypeError);
 assert.deepEqual(new PasskeyVerifier({androidOrigins:[ORIGIN]}).origins,['https://otpanda.github.io',ORIGIN]);
 assert.deepEqual(new PasskeyVerifier({androidOrigins:[ORIGIN],nativeOnly:true}).origins,[ORIGIN]);
 assert.deepEqual(new PasskeyVerifier().origins,['https://otpanda.github.io']);
});
test('begin refuses a malformed renewal key with 400 before any ceremony row exists',async()=>{
 const f=await fixture();
 for(const k of ['x','a'.repeat(43),'!'.repeat(87)])assert.equal((await f.post('/auth/native/passkey/begin',{renewal_key:k})).status,400);
 assert.equal((await f.db.prepare('SELECT count(*) n FROM passkey_ceremonies').first()).n,0);
});
test('protected owner (extra verification on new devices) can still sign in natively with a passkey',async()=>{
 const f=await fixture(),key=await newKey();
 await f.db.prepare('INSERT INTO new_device_verification(owner_id,enabled_at,generation) VALUES (?1,?2,?3)').bind(f.account.ownerId,NOW,0).run();
 const b=await begin(f,key),r=await f.post('/auth/native/passkey/complete',{renewal_key:key,token:b.token,response:f.assertion(b.options.challenge)});
 assert.equal(r.status,200);
});
test('credential revoked after verification: issuePasskey writes no device, key or handle row',async()=>{
 const f=await fixture(),key=await newKey(),proof={ownerId:f.account.ownerId,credentialId:f.a.credential.id,generation:f.account.generation??1,verifiedAt:NOW,purpose:'authenticate'};
 const control=await f.native.issuePasskey({proof,renewalKey:await newKey()});assert.ok(control,'positive control: the same proof is valid before revoke (generation matches)');
 const before=Object.fromEntries(await Promise.all(['device_sessions','native_keys','device_access_handles'].map(async t=>[t,(await f.db.prepare(`SELECT count(*) n FROM ${t}`).first()).n])));
 await f.db.prepare('UPDATE passkey_credentials SET revoked_at=?1').bind(NOW).run();
 assert.equal(await f.native.issuePasskey({proof,renewalKey:key}),undefined);
 for(const t of Object.keys(before))assert.equal((await f.db.prepare(`SELECT count(*) n FROM ${t}`).first()).n,before[t],t+' unchanged after refused issue');
 assert.equal(await f.native.issuePasskey({proof:{...proof,purpose:'step-up'},renewalKey:key}),undefined);
});
