import test from 'node:test';import assert from 'node:assert/strict';
import{database}from'./sqlite-helper.js';import{createBrowserWorkerAdapter,nativeGoogleAudiences}from'../src/browser-worker-adapter.js';import{createGoogleJwks}from'../src/google-jwks.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',AUD='367143149550-560r90pmkqr71qp1tid3amck2a053rdg.apps.googleusercontent.com',yes={limit:async()=>({success:true})};
const env=(over={})=>({DB:database(),IDENTITY_ADDRESS_LIMIT:yes,IDENTITY_AUTH_GLOBAL_LIMIT:yes,IDENTITY_READ_GLOBAL_LIMIT:yes,NATIVE_AUTH_ENABLED:'1',...over});
const begin=(adapter,e)=>adapter.fetch(new Request(API+'/auth/native/google/begin',{method:'POST',headers:{'Content-Type':'application/json'},body:''}),e);
test('worker adapter wires native Google: configured audience gives a nonce, none stays 503, flag off stays 404',async()=>{
 const mk=()=>createBrowserWorkerAdapter({resolveTrustedIngress:async()=>'192.0.2.1',fetchImpl:async()=>{throw Error('no network')}});
 const on=env({GOOGLE_CLIENT_ID:AUD}),r=await begin(mk(),on);assert.equal(r.status,200);const b=await r.json();assert.match(b.nonce,/^otpda_/);assert.ok(b.expires_at>0);
 assert.equal((await begin(mk(),env({}))).status,503);// no audience: fail closed
 assert.equal((await begin(mk(),env({GOOGLE_CLIENT_ID:AUD,NATIVE_AUTH_ENABLED:'0'}))).status,404);
 assert.equal((await begin(mk(),env({NATIVE_GOOGLE_AUDIENCES:'not-a-google-client'}))).status,503);// non-Google audience syntax is dropped
 const ex=await begin(mk(),env({GOOGLE_CLIENT_ID:'other.apps.googleusercontent.com',NATIVE_GOOGLE_AUDIENCES:AUD}));assert.equal(ex.status,200);// explicit audiences win
});
test('nativeGoogleAudiences: explicit list wins over the web client id; blanks dropped',()=>{assert.deepEqual(nativeGoogleAudiences({GOOGLE_CLIENT_ID:'a'}),['a']);assert.deepEqual(nativeGoogleAudiences({NATIVE_GOOGLE_AUDIENCES:' x , ,y',GOOGLE_CLIENT_ID:'a'}),['x','y']);assert.deepEqual(nativeGoogleAudiences({}),[]);});
test('google jwks: caches, refetches once per minute for an unknown kid, filters non-RSA, fails closed on errors',async()=>{
 let t=1e12,calls=0,mode='ok';const clock=()=>t,fetchImpl=async()=>{calls++;if(mode==='bad')return new Response('x',{status:500});return new Response(JSON.stringify({keys:[{kty:'RSA',kid:'k1',n:'AQAB',e:'AQAB',alg:'RS256',use:'sig'},{kty:'EC',kid:'e1',crv:'P-256',x:'a',y:'b'},{kty:'RSA',kid:'k2',n:'AQAB',e:'AQAB',alg:'RS384'}]}),{headers:{'cache-control':'public, max-age=300'}});};
 const get=createGoogleJwks({fetchImpl,clock});assert.equal((await get('k1')).kty,'RSA');assert.equal(calls,1);assert.ok(await get('k1'));assert.equal(calls,1);
 assert.equal(await get('e1'),undefined);assert.equal(await get('k2'),undefined);assert.equal(calls,1);// unknown within the minute: no refetch
 t+=61000;assert.equal(await get('nope'),undefined);assert.equal(calls,2);
 t+=3600000+1;mode='bad';assert.equal(await get('k1'),undefined,'expired keys are never served when the refresh fails');
 const bad=createGoogleJwks({fetchImpl:async()=>{throw Error('x')},clock});assert.equal(await bad('k1'),undefined);assert.equal(await get(''),undefined);assert.equal(await get('k'.repeat(200)),undefined);
});

const NOW=1_800_000_000_000,enc=u=>Buffer.from(u).toString('base64url'),te=s=>new TextEncoder().encode(s);
const mkKey=()=>crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['sign','verify']);
async function rig(over={},{keys}={}){
 const good=await mkKey(),evil=await mkKey(),jwk=await crypto.subtle.exportKey('jwk',good.publicKey);
 const state={calls:0,keys:keys??[{...jwk,kid:'k1',alg:'RS256',use:'sig'}],age:'max-age=3600'};
 const fetchImpl=async url=>{assert.equal(String(url),'https://www.googleapis.com/oauth2/v3/certs');state.calls++;return new Response(JSON.stringify({keys:state.keys}),{headers:{'cache-control':state.age}});};
 let now=NOW;const adapter=createBrowserWorkerAdapter({resolveTrustedIngress:async()=>'192.0.2.1',fetchImpl,clock:()=>now}),e=env({GOOGLE_CLIENT_ID:AUD,...over});
 const kp=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']),rk=enc(await crypto.subtle.exportKey('raw',kp.publicKey));
 const token=async(key,claims={},kid='k1')=>{const nonce=(await(await begin(adapter,e)).json()).nonce,h=enc(te(JSON.stringify({alg:'RS256',kid,typ:'JWT'}))),c=enc(te(JSON.stringify({iss:'https://accounts.google.com',aud:AUD,sub:'sub-1',email:'g@gmail.com',email_verified:true,nonce,iat:Math.floor(now/1000),exp:Math.floor(now/1000)+600,...claims})));return h+'.'+c+'.'+enc(await crypto.subtle.sign('RSASSA-PKCS1-v1_5',key,te(h+'.'+c)));};
 const complete=async(key,claims,kid)=>adapter.fetch(new Request(API+'/auth/native/google/complete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id_token:await token(key,claims,kid),renewal_key:rk})}),e);
 const effects=()=>({sessions:e.DB.sqlite.prepare('SELECT count(*) n FROM device_sessions').get().n,accounts:e.DB.sqlite.prepare('SELECT count(*) n FROM accounts').get().n});
 return{good,evil,state,e,complete,effects,tick:ms=>{now+=ms;}};
}
const NONE={sessions:0,accounts:0};
test('adapter e2e: Google-signed token gives exact 200 (android device, access, enroll grant) and one android session',async()=>{
 const r=await rig();const res=await r.complete(r.good.privateKey);assert.equal(res.status,200);const b=await res.json();
 assert.deepEqual(Object.keys(b).sort(),['access','access_expires_at','device_id','enroll_grant']);assert.match(b.access,/^otpda_/);assert.match(b.enroll_grant,/^otpda_/);assert.equal(b.access_expires_at,NOW+300000);
 assert.equal(r.effects().sessions,1);assert.equal(r.e.DB.sqlite.prepare('SELECT client_kind FROM device_sessions').get().client_kind,'android');assert.ok(r.state.calls>=1);
});
test('adapter e2e: wrong signer, wrong audience, expired, unknown kid, removed (rotated) kid: 401 invalid_grant and no account/device effects',async()=>{
 const r=await rig();
 for(const [name,call] of [['wrong signer',()=>r.complete(r.evil.privateKey)],['wrong aud',()=>r.complete(r.good.privateKey,{aud:'other.apps.googleusercontent.com'})],['expired',()=>r.complete(r.good.privateKey,{exp:Math.floor(NOW/1000)-10})],['unknown kid',()=>r.complete(r.good.privateKey,{},'zz')],['non-google iss',()=>r.complete(r.good.privateKey,{iss:'https://evil.test'})]]){
  const res=await call();assert.equal(res.status,401,name);assert.deepEqual(await res.json(),{error:'invalid_grant'},name);assert.deepEqual(r.effects(),NONE,name);
 }
 // rotation: Google drops k1 and publishes k2; after the cache lapses the old key is refused and no effects occur
 const k2=await mkKey();r.state.keys=[{...await crypto.subtle.exportKey('jwk',k2.publicKey),kid:'k2',alg:'RS256',use:'sig'}];r.tick(3600001);
 const old=await r.complete(r.good.privateKey);assert.equal(old.status,401);assert.deepEqual(r.effects(),NONE);
 assert.equal((await r.complete(k2.privateKey,{},'k2')).status,200);
});
test('adapter e2e: optional authorized-party pin fails closed when configured',async()=>{
 const A='android-1.apps.googleusercontent.com',r=await rig({NATIVE_GOOGLE_AUTHORIZED_PARTIES:A});
 assert.equal((await r.complete(r.good.privateKey)).status,401);// azp absent
 assert.equal((await r.complete(r.good.privateKey,{azp:'other.apps.googleusercontent.com'})).status,401);assert.deepEqual(r.effects(),NONE);
 assert.equal((await r.complete(r.good.privateKey,{azp:A})).status,200);
 const open=await rig();assert.equal((await open.complete(open.good.privateKey,{azp:'anything.apps.googleusercontent.com'})).status,200);// unset: no pin
});
test('google jwks: max-age=0 is floored to 60 s, concurrent misses share one fetch, hung fetch aborts and fails closed',async()=>{
 let t=1e12,calls=0,age='max-age=0';const clock=()=>t,ok=()=>new Response(JSON.stringify({keys:[{kty:'RSA',kid:'k1',n:'AQAB',e:'AQAB'}]}),{headers:{'cache-control':age}});
 const get=createGoogleJwks({fetchImpl:async()=>{calls++;await new Promise(r=>setTimeout(r,20));return ok();},clock});
 const rs=await Promise.all([get('k1'),get('k1'),get('k1')]);assert.ok(rs.every(Boolean));assert.equal(calls,1);
 t+=59000;await get('k1');assert.equal(calls,1);t+=2000;await get('k1');assert.equal(calls,2);// floor 60 s, then refresh
 const hung=createGoogleJwks({fetchImpl:(u,{signal})=>new Promise((_,rej)=>signal.addEventListener('abort',()=>rej(new Error('abort')))),clock});
 const t0=Date.now();assert.equal(await hung('k1'),undefined);assert.ok(Date.now()-t0<5500,'aborted by the 4 s timeout');
 const slowBody=createGoogleJwks({fetchImpl:async(u,{signal})=>({ok:true,headers:new Headers(),json:()=>new Promise(()=>{})}),clock});assert.equal(await slowBody('k1'),undefined);
});
