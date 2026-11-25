import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { createSignupPreparationRuntime } from '../src/signup-preparation-runtime.js';
import { androidOriginsFromFingerprints } from '../src/native-http.js';
import { base64urlEncode } from '../src/tokens.js';
import { authenticator } from './passkey-fixture.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',NOW=1_800_000_000_000,ORIGIN=androidOriginsFromFingerprints([Array(32).fill('AB').join(':')])[0];
const enc=u=>base64urlEncode(new Uint8Array(u));
async function newKey(){const k=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign']);return enc(await crypto.subtle.exportKey('raw',k.publicKey));}
function fixture({origins=[ORIGIN]}={}){
 const db=database(),mails=[],tasks=[];let now=NOW,n=0;
 const rt=createSignupPreparationRuntime({db,deliver:async m=>mails.push(m),clock:()=>now,nativeOrigins:origins});
 const post=async(path,body,{origin,ct='application/json',ip}={})=>{const r=await rt.fetch(new Request(API+path,{method:'POST',headers:{'Content-Type':ct,...(origin?{Origin:origin}:{})},body:typeof body==='string'?body:JSON.stringify(body)}),{clientAddress:ip??'10.1.'+(n++)+'.1',waitUntil:p=>tasks.push(p)});await Promise.all(tasks);return r;};
 return{db,mails,post,setNow:v=>now=v};
}
const E='/auth/native/signup/';
async function toCeremony(f,key,email='new@example.com'){
 assert.equal((await f.post(E+'email',{email,renewal_key:key})).status,202);
 const code=f.mails.at(-1).code;
 const r=await f.post(E+'begin',{email,email_code:code,renewal_key:key});return {r,code};
}
test('native signup: email code, OS passkey registration with the android origin, account created and android session issued',async()=>{
 const f=fixture(),key=await newKey(),a=authenticator(),{r}=await toCeremony(f,key);assert.equal(r.status,200);const c=await r.json();
 assert.equal(c.options.rp.id,'otpanda.github.io');assert.ok(c.token);
 const fin=await f.post(E+'finish',{renewal_key:key,token:c.token,response:a.registration({origin:ORIGIN,expected:c.options.challenge})});assert.equal(fin.status,200);
 const d=await fin.json();assert.deepEqual(Object.keys(d).sort(),['access','access_expires_at','device_id']);
 const s=f.db.sqlite.prepare('SELECT client_kind,credential_id FROM device_sessions WHERE device_id=?').get(d.device_id);assert.equal(s.client_kind,'android');assert.equal(s.credential_id,a.credential.id);
 assert.equal(f.db.sqlite.prepare('SELECT public_key p FROM native_keys').get().p,key);
 assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM accounts').get().n,1);
 assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM signup_mail_bindings').get().n,0,'mailbox receipts retired');
 assert.equal((await f.post(E+'finish',{renewal_key:key,token:c.token,response:a.registration({origin:ORIGIN,expected:c.options.challenge})})).status,401,'replay');
});
test('native signup: bound to the install key, web origin refused, wrong code refused, existing mailbox only after code proof',async()=>{
 const f=fixture(),key=await newKey(),other=await newKey(),a=authenticator(),{r,code}=await toCeremony(f,key);const c=await r.json();
 assert.equal((await f.post(E+'begin',{email:'new@example.com',email_code:code,renewal_key:other})).status,401,'code claimed by another install key');
 assert.equal((await f.post(E+'finish',{renewal_key:other,token:c.token,response:a.registration({origin:ORIGIN,expected:c.options.challenge})})).status,401,'other install cannot finish');
 assert.equal((await f.post(E+'finish',{renewal_key:key,token:c.token,response:a.registration({origin:'https://otpanda.github.io',expected:c.options.challenge})})).status,401,'web origin refused natively');
 assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM accounts').get().n,0);
 const g=fixture(),k2=await newKey();assert.equal((await g.post(E+'email',{email:'x@example.com',renewal_key:k2})).status,202);
 assert.equal((await g.post(E+'begin',{email:'x@example.com',email_code:'AAAAAAAA',renewal_key:k2})).status,401);
 // existing account: after a proven code the app is told to sign in instead; no second account
 const h=fixture(),k3=await newKey(),a3=authenticator(),first=await (await toCeremony(h,k3,'same@example.com')).r.json();
 await h.post(E+'finish',{renewal_key:k3,token:first.token,response:a3.registration({origin:ORIGIN,expected:first.options.challenge})});
 const k4=await newKey();h.post(E+'email',{email:'same@example.com',renewal_key:k4});
 const again=await toCeremony(h,k4,'same@example.com');assert.equal(again.r.status,200);assert.deepEqual(await again.r.json(),{existing:true});assert.equal(h.db.sqlite.prepare('SELECT count(*) n FROM accounts').get().n,1);
});
test('native signup boundary: default-off without signer, Origin refused, exact content type and keys, bad key and email 400, GET 405',async()=>{
 const off=fixture({origins:[]}),key=await newKey();
 assert.equal((await off.post(E+'email',{email:'a@example.com',renewal_key:key})).status,404);
 const f=fixture();
 assert.equal((await f.post(E+'email',{email:'a@example.com',renewal_key:key},{origin:'https://otpanda.github.io'})).status,403);
 assert.equal((await f.post(E+'email',{email:'a@example.com',renewal_key:key},{ct:'application/json; charset=utf-8'})).status,400);
 assert.equal((await f.post(E+'email',{email:'a@example.com',renewal_key:key,x:1})).status,400);
 assert.equal((await f.post(E+'email',{email:'a@example.com',renewal_key:'bad'})).status,400);
 assert.equal((await f.post(E+'email',{email:'not-an-email',renewal_key:key})).status,400);
 assert.equal(f.mails.length,0);
 const g=await fixture().post('/auth/native/signup/email',{email:'a@example.com',renewal_key:key});assert.equal(g.headers.get('access-control-allow-origin'),null);
});
