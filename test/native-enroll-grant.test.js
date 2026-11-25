import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { NativeSessionService } from '../src/native-sessions.js';
import { NativeGoogle,verifyGoogleIdToken } from '../src/native-google.js';
import { createNativeHttp } from '../src/native-http.js';
import { createDeviceKeyHttp } from '../src/device-key-http.js';
import { GoogleDeviceEnrollment } from '../src/google-device-enrollment.js';
import { DurableDeviceKeys } from '../src/durable-device-keys.js';
import { FirstPasskeyEnrollment } from '../src/first-passkey-enrollment.js';
import { NATIVE_REDIRECT } from '../src/native-sessions.js';
import { pkceChallenge } from '../src/browser-exchanges.js';
import { deviceProofMessage } from '../src/device-key-proof.js';
import { hashText } from '../src/sessions.js';
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
 const bad=[await idToken({nonce:'n',aud:'other.apps.googleusercontent.com'}),await idToken({nonce:'n',iss:'https://evil.example'}),await idToken({nonce:'n',exp:Math.floor(NOW/1000)}),await idToken({nonce:'n',iat:Math.floor(NOW/1000)+3600}),await idToken({nonce:'n',email_verified:false}),await idToken({}),await idToken({nonce:'n',aud:[AUD,'x.apps.googleusercontent.com']}),await idToken({nonce:'n'},{kid:'unknown'}),await idToken({nonce:'n'},{alg:'none'})];

async function ecKey(){const k=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']),j=await crypto.subtle.exportKey('jwk',k.publicKey);return{k,jwk:{kty:j.kty,crv:j.crv,x:j.x,y:j.y}};}
const sign=async(k,c)=>enc(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},k.k.privateKey,deviceProofMessage(c)));
async function signedIn(){
 const f=await fixture(),dk=createDeviceKeyHttp({db:f.db,sessions:f.sessions,enrollment:new GoogleDeviceEnrollment(f.db,{clock:()=>NOW}),keys:new DurableDeviceKeys(f.db,{clock:()=>NOW}),clock:()=>NOW});
 const nonce=(await (await f.post('/auth/native/google/begin','')).json()).nonce;
 const r=await f.post('/auth/native/google/complete',{id_token:await idToken({nonce}),renewal_key:await newKey()}),body=await r.json();
 const call=(op,b,headers={})=>dk.fetch(new Request(API+'/v1/manage/device-key/'+op,{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+body.access,...headers},body:JSON.stringify(b)}),{clientAddress:'2.2.2.2'});
 return{...f,r,body,call,dk};
}
test('google/complete adds only the optional enroll_grant; no strong-method accounts get one, others never',async()=>{const f=await signedIn();assert.equal(f.r.status,200);assert.deepEqual(Object.keys(f.body).sort(),['access','access_expires_at','device_id','enroll_grant']);assert.match(f.body.enroll_grant,/^otpda_[A-Za-z0-9_-]{55}$/);
 f.db.sqlite.prepare("INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) SELECT 'c',owner_id,x'00',0,'[]','singleDevice',0,1 FROM accounts LIMIT 1").run();
 const nonce=(await (await f.post('/auth/native/google/begin','')).json()).nonce,r2=await f.post('/auth/native/google/complete',{id_token:await idToken({nonce}),renewal_key:await newKey()});assert.deepEqual(Object.keys(await r2.json()).sort(),['access','access_expires_at','device_id']);});
test('device-key HTTP end to end: begin, finish, replay, status, method_exists, exact key sets, origin and web-token refusal',async()=>{
 const f=await signedIn(),k=await ecKey(),digest=await hashText(JSON.stringify(k.jwk));
 assert.equal((await f.call('enroll-begin',{publicJwk:k.jwk,grant:f.body.enroll_grant},{Origin:'https://otpanda.github.io'})).status,403);
 assert.equal((await f.call('enroll-begin',{publicJwk:k.jwk})).status,400);assert.equal((await f.call('enroll-begin',{publicJwk:k.jwk,grant:f.body.enroll_grant,extra:1})).status,400);
 const b=await f.call('enroll-begin',{publicJwk:k.jwk,grant:f.body.enroll_grant}),bj=await b.json();assert.equal(b.status,200);assert.equal(b.headers.get('cache-control'),'no-store');assert.deepEqual(Object.keys(bj).sort(),['challenge','token']);assert.deepEqual(Object.keys(bj.challenge).sort(),['actionDigest','challenge','expiresAt','generation','keyId','ownerId','purpose']);
 const sig=await sign(k,bj.challenge),fin=await f.call('enroll-finish',{grant:f.body.enroll_grant,token:bj.token,signature:sig}),fj=await fin.json();assert.equal(fin.status,200);assert.deepEqual(fj,{status:'enrolled',keyId:bj.challenge.keyId});
 assert.deepEqual(await (await f.call('enroll-finish',{grant:f.body.enroll_grant,token:bj.token,signature:sig})).json(),fj);
 assert.deepEqual(await (await f.call('enroll-status',{digest})).json(),{status:'enrolled',keyId:fj.keyId});assert.deepEqual(await (await f.call('enroll-status',{digest:'0'.repeat(64)})).json(),{status:'absent'});
 const k2=await ecKey(),g2=await new FirstPasskeyEnrollment(f.db,{clock:()=>NOW}).issue({ownerId:bj.challenge.ownerId,deviceId:f.body.device_id,generation:0,issuer:'https://accounts.google.com',subject:'g-sub-1',verifiedAt:NOW});assert.equal(g2,undefined);
 const bad=await f.call('enroll-finish',{grant:f.body.enroll_grant,token:bj.token,signature:'A'.repeat(86)});assert.equal(bad.status,200);// receipt replay needs no new proof
 const nb=await f.call('enroll-finish',{grant:'otpda_'+'B'.repeat(55),token:bj.token,signature:sig});assert.equal(nb.status,409);assert.deepEqual(await nb.json(),{error:'unavailable'});
 const web=await f.sessions.issue({proof:{authMethod:'google',issuer:'https://accounts.google.com',subject:'g-sub-1',ownerId:bj.challenge.ownerId,generation:0,purpose:'authenticate',verifiedAt:NOW},clientKind:'web'});
 const wr=await f.dk.fetch(new Request(API+'/v1/manage/device-key/enroll-status',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+web.access},body:JSON.stringify({digest})}),{clientAddress:'3.3.3.3'});assert.equal(wr.status,401);});
test('method_exists is begin-only on the wire',async()=>{const f=await signedIn(),k=await ecKey();f.db.sqlite.prepare("INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) SELECT 'c',owner_id,x'00',0,'[]','singleDevice',0,1 FROM accounts LIMIT 1").run();
 const r=await f.call('enroll-begin',{publicJwk:k.jwk,grant:f.body.enroll_grant});assert.equal(r.status,409);assert.deepEqual(await r.json(),{error:'method_exists'});
 const fin=await f.call('enroll-finish',{grant:f.body.enroll_grant,token:'otpda_'+'C'.repeat(55),signature:'A'.repeat(86)});assert.deepEqual(await fin.json(),{error:'unavailable'});});
test('browser handoff carries the live web grant into one exchange, capped, once; none without a web grant',async()=>{
 const f=await fixture(),proof={authMethod:'google',issuer:'https://accounts.google.com',subject:'one',ownerId:'owner',generation:0,purpose:'authenticate',verifiedAt:NOW};
 f.db.sqlite.prepare('INSERT INTO accounts(owner_id,created_at) VALUES(?,?)').run('owner',NOW);f.db.sqlite.prepare('INSERT INTO account_emails VALUES(?,?,?,?)').run('owner','a@gmail.com',NOW,NOW);f.db.sqlite.prepare('INSERT INTO account_security(owner_id) VALUES(?)').run('owner');
 f.db.sqlite.prepare("INSERT INTO provider_identities(identity_id,owner_id,provider,issuer,subject,email,created_at) VALUES('one','owner','google','https://accounts.google.com','one','a@gmail.com',?)").run(NOW);
 const web=await f.sessions.issue({proof,clientKind:'web'}),wg=await new FirstPasskeyEnrollment(f.db,{clock:()=>NOW}).issue({...proof,ownerId:'owner',deviceId:web.deviceId});assert.ok(wg);
 const v='v'.repeat(43),pub=await newKey(),m=await f.native.mint({sourceDeviceId:web.deviceId,challenge:await pkceChallenge(v),redirectUri:NATIVE_REDIRECT}),r=await f.native.exchange({code:m.code,verifier:v,redirectUri:NATIVE_REDIRECT,renewalKey:pub});
 assert.match(r.enrollGrant,/^otpda_/);const rows=f.db.sqlite.prepare('SELECT device_id,consumed_at,expires_at FROM google_enrollment_grants ORDER BY created_at').all();assert.equal(rows.length,2);assert.ok(rows[0].consumed_at!==null);assert.equal(rows[1].device_id,r.deviceId);assert.ok(rows[1].expires_at<=rows[0].expires_at);assert.equal(rows[1].consumed_at,null);
 const m2=await f.native.mint({sourceDeviceId:web.deviceId,challenge:await pkceChallenge(v),redirectUri:NATIVE_REDIRECT}),r2=await f.native.exchange({code:m2.code,verifier:v,redirectUri:NATIVE_REDIRECT,renewalKey:await newKey()});assert.equal(r2.enrollGrant,undefined);assert.ok(r2.access);});
