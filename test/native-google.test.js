import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { NativeSessionService } from '../src/native-sessions.js';
import { NativeGoogle,verifyGoogleIdToken } from '../src/native-google.js';
import { createNativeHttp } from '../src/native-http.js';
import { DeviceSessionService } from '../src/device-sessions.js';
import { base64urlEncode } from '../src/tokens.js';
const NOW=1_800_000_000_000,API='https://otpanda-api.abrahammurciano.workers.dev',AUD='123-abc.apps.googleusercontent.com',enc=u=>base64urlEncode(new Uint8Array(u)),te=s=>new TextEncoder().encode(s);
const rsa=await crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['sign','verify']);
const jwk=await crypto.subtle.exportKey('jwk',rsa.publicKey),getKey=async kid=>kid==='k1'?jwk:undefined;
async function idToken(over={},{kid='k1',alg='RS256',key=rsa.privateKey}={}){
 const h=enc(te(JSON.stringify({alg,kid,typ:'JWT'}))),c=enc(te(JSON.stringify({iss:'https://accounts.google.com',aud:AUD,sub:'g-sub-1',email:'g@gmail.com',email_verified:true,iat:Math.floor(NOW/1000),exp:Math.floor(NOW/1000)+600,...over})));
 const sig=enc(await crypto.subtle.sign('RSASSA-PKCS1-v1_5',key,te(h+'.'+c)));return h+'.'+c+'.'+sig;
}
async function newKey(){const k=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign']);return enc(await crypto.subtle.exportKey('raw',k.publicKey));}
async function fixture(audiences=[AUD]){
 const db=database();let now=NOW;const clock=()=>now,native=new NativeSessionService(db,{clock}),google=new NativeGoogle(db,{native,audiences,getKey,clock}),sessions=new DeviceSessionService(db,{clock});
 const http=createNativeHttp({sessions,native,db,google,clock}),post=(p,b)=>http.fetch(new Request(API+p,{method:'POST',headers:{'Content-Type':'application/json'},body:typeof b==='string'?b:JSON.stringify(b)}),{clientAddress:'1.1.1.1'});
 return{db,native,google,sessions,http,post,setNow:v=>now=v,q:(s,...p)=>db.sqlite.prepare(s).get(...p)};
}
test('verifier: signature, alg, issuer (both forms), audience, azp, expiry, iat, nonce/email claims; no key means no trust',async()=>{
 const ok=async(t,opts={})=>verifyGoogleIdToken({token:t,audiences:[AUD],getKey,now:NOW,...opts});
 assert.ok(await ok(await idToken({nonce:'n'})));assert.equal((await ok(await idToken({nonce:'n',iss:'accounts.google.com'}))).iss,'https://accounts.google.com');
 const bad=[await idToken({nonce:'n',aud:'other.apps.googleusercontent.com'}),await idToken({nonce:'n',iss:'https://evil.example'}),await idToken({nonce:'n',exp:Math.floor(NOW/1000)}),await idToken({nonce:'n',iat:Math.floor(NOW/1000)+3600}),await idToken({nonce:'n',email_verified:false}),await idToken({}),await idToken({nonce:'n',aud:[AUD,'x.apps.googleusercontent.com']}),await idToken({nonce:'n'},{kid:'unknown'}),await idToken({nonce:'n'},{alg:'none'})];
 for(const [i,t] of bad.entries())assert.equal(await ok(t),undefined,'case '+i);
 const other=await crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['sign']);
 assert.equal(await ok(await idToken({nonce:'n'},{key:other.privateKey})),undefined,'wrong signing key');
 const t=await idToken({nonce:'n'}),[h,c,s]=t.split('.');assert.equal(await ok(h+'.'+enc(te(JSON.stringify({...JSON.parse(atob(c.replace(/-/g,'+').replace(/_/g,'/'))),sub:'other'})))+'.'+s),undefined,'tampered payload');
 assert.equal(await ok(t,{audiences:[]}),undefined);assert.equal(await ok(t,{getKey:undefined}),undefined);assert.equal(await ok('a.b'),undefined);assert.equal(await ok('x'.repeat(9000)),undefined);});
test('unconfigured: begin/complete fail closed with 503 and store nothing',async()=>{
 const f=await fixture([]);assert.equal(f.google.configured,false);
 assert.equal((await f.post('/auth/native/google/begin','')).status,503);assert.equal((await f.post('/auth/native/google/complete',{id_token:'x',renewal_key:await newKey()})).status,503);assert.equal(f.q('SELECT count(*) n FROM native_google_nonces').n,0);
 const none=createNativeHttp({sessions:f.sessions,native:f.native,db:f.db});assert.equal((await none.fetch(new Request(API+'/auth/native/google/begin',{method:'POST',headers:{'Content-Type':'application/json'}}),{clientAddress:'1.1.1.1'})).status,503);
 f.db.sqlite.close();});
test('new Google account: nonce one use, native device created, access works, signature-bound key stored',async()=>{
 const f=await fixture(),b=await (await f.post('/auth/native/google/begin','')).json(),k=await newKey();
 assert.ok(b.nonce);const r=await f.post('/auth/native/google/complete',{id_token:await idToken({nonce:b.nonce}),renewal_key:k}),body=await r.json();
 assert.equal(r.status,200);assert.equal((await f.sessions.authenticate(body.access)).clientKind,'android');assert.equal(f.q('SELECT public_key p FROM native_keys').p,k);
 assert.equal(f.q('SELECT count(*) n FROM accounts').n,1);assert.equal(f.q('SELECT provider_identity_id p FROM device_sessions').p!==null,true);
 assert.equal((await f.post('/auth/native/google/complete',{id_token:await idToken({nonce:b.nonce}),renewal_key:k})).status,401,'nonce is one use');
 // second sign-in with the same Google identity reuses the account (linked)
 const b2=await (await f.post('/auth/native/google/begin','')).json();assert.equal((await f.post('/auth/native/google/complete',{id_token:await idToken({nonce:b2.nonce}),renewal_key:await newKey()})).status,200);assert.equal(f.q('SELECT count(*) n FROM accounts').n,1);f.db.sqlite.close();});
test('denied without effect: bad key, unknown/expired nonce, nonce from a token for another audience, forged signature',async()=>{
 const f=await fixture(),k=await newKey(),b=await (await f.post('/auth/native/google/begin','')).json();
 const snap=()=>JSON.stringify([f.q('SELECT count(*) n FROM accounts'),f.q('SELECT count(*) n FROM device_sessions')]);const s0=snap();
 assert.equal((await f.post('/auth/native/google/complete',{id_token:await idToken({nonce:b.nonce}),renewal_key:'bad'})).status,401);
 assert.equal((await f.post('/auth/native/google/complete',{id_token:await idToken({nonce:'otpda_'+'Z'.repeat(55)}),renewal_key:k})).status,401);
 assert.equal((await f.post('/auth/native/google/complete',{id_token:await idToken({nonce:b.nonce,aud:'x.apps.googleusercontent.com'}),renewal_key:k})).status,401);
 assert.equal(snap(),s0);assert.equal(f.q('SELECT count(*) n FROM native_google_nonces').n,1,'nonce survives rejected tokens');
 f.setNow(NOW+301000);const late=await idToken({nonce:b.nonce},{});assert.equal((await f.post('/auth/native/google/complete',{id_token:late,renewal_key:k})).status,401,'expired nonce');f.db.sqlite.close();});
test('browser_required, nothing created: existing mailbox owner without a link, and owners with extra verification',async()=>{
 const f=await fixture();
 // existing account owning the mailbox via a different method: linking needs passkey step-up in the browser
 f.db.sqlite.exec("INSERT INTO accounts(owner_id,created_at) VALUES('o1',0);INSERT INTO account_emails(owner_id,email,verified_at,updated_at) VALUES('o1','g@gmail.com',0,0);INSERT INTO account_security(owner_id) VALUES('o1')");
 let b=await (await f.post('/auth/native/google/begin','')).json(),k=await newKey();
 let r=await f.post('/auth/native/google/complete',{id_token:await idToken({nonce:b.nonce}),renewal_key:k});assert.equal(r.status,409);assert.equal((await r.json()).error,'browser_required');assert.equal(f.q('SELECT count(*) n FROM device_sessions').n,0);assert.equal(f.q('SELECT count(*) n FROM provider_identities').n,0);
 // linked owner with new-device verification enabled
 f.db.sqlite.exec("INSERT INTO provider_identities(identity_id,owner_id,provider,issuer,subject,email,created_at) VALUES('i1','o1','google','https://accounts.google.com','g-sub-1','g@gmail.com',0)");
 const ok=await f.native.issueProvider({ownerId:'o1',generation:0,issuer:'https://accounts.google.com',subject:'g-sub-1',renewalKey:k});assert.ok(ok,'linked owner without protection');
 f.db.sqlite.exec("DELETE FROM device_sessions");const cols=f.db.sqlite.prepare("PRAGMA table_info(new_device_verification)").all().map(c=>c.name);
 const vals={owner_id:"'o1'"};for(const c of cols)if(!(c in vals))vals[c]=c.includes('at')?'0':(c==='enabled'?'1':"'x'");
 f.db.sqlite.exec(`INSERT INTO new_device_verification(${cols.join(',')}) VALUES(${cols.map(c=>vals[c]).join(',')})`);
 b=await (await f.post('/auth/native/google/begin','')).json();r=await f.post('/auth/native/google/complete',{id_token:await idToken({nonce:b.nonce}),renewal_key:k});assert.equal(r.status,409);assert.equal(f.q('SELECT count(*) n FROM device_sessions').n,0);f.db.sqlite.close();});
test('revoked identity link or generation drift at write time refuses the device',async()=>{
 const f=await fixture(),k=await newKey();
 f.db.sqlite.exec("INSERT INTO accounts(owner_id,created_at) VALUES('o1',0);INSERT INTO account_emails(owner_id,email,verified_at,updated_at) VALUES('o1','g@gmail.com',0,0);INSERT INTO account_security(owner_id) VALUES('o1');INSERT INTO provider_identities(identity_id,owner_id,provider,issuer,subject,email,created_at) VALUES('i1','o1','google','https://accounts.google.com','g-sub-1','g@gmail.com',0)");
 assert.equal(await f.native.issueProvider({ownerId:'o1',generation:5,issuer:'https://accounts.google.com',subject:'g-sub-1',renewalKey:k}),undefined);
 f.db.sqlite.exec("UPDATE provider_identities SET revoked_at=1");assert.equal(await f.native.issueProvider({ownerId:'o1',generation:0,issuer:'https://accounts.google.com',subject:'g-sub-1',renewalKey:k}),undefined);
 assert.equal(f.q('SELECT count(*) n FROM native_keys').n,0);f.db.sqlite.close();});
