import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { SeedCipher } from '../src/seed-cipher.js';
import { createTotpManagementHttp } from '../src/totp-management-http.js';
import { PasskeyService } from '../src/passkey-service.js';
import { PasskeyVerifier } from '../src/passkey-verifier.js';
import { authenticator } from './passkey-fixture.js';
const cipher=new SeedCipher({keys:new Map([['test',await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt'])]]),activeKeyId:'test'});
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',HASH='android:apk-key-hash:'+'A'.repeat(43),OTHER='android:apk-key-hash:'+'B'.repeat(43);
async function fixture(androidOrigins,kind='android',deviceId='ndev'){
 const db=database(),now=59000,a=authenticator(),c=a.credential;
 await db.prepare('INSERT INTO accounts VALUES (?,?)').bind('owner',0).run();await db.prepare('INSERT INTO account_security(owner_id) VALUES (?)').bind('owner').run();
 await db.prepare("INSERT INTO account_emails(owner_id,email,verified_at,updated_at) VALUES ('owner','synthetic@example.test',0,0)").run();
 await db.prepare("INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) VALUES (?,'owner',?,0,'[]','singleDevice',0,0)").bind(c.id,Array.from(c.publicKey)).run();
 await db.prepare("INSERT INTO device_sessions(device_id,owner_id,credential_id,provider_identity_id,generation,client_kind,created_at,last_used_at,expires_at) VALUES (?,'owner',?,NULL,0,?,0,0,999999)").bind(deviceId,c.id,kind).run();
 const sessions={authenticate:async()=>({ownerId:'owner',deviceId,generation:0,clientKind:kind,expiresAt:999999})};
 const http=createTotpManagementHttp({native:true,db,sessions,getSeedCipher:async()=>cipher,clock:()=>now,passkeys:new PasskeyService(db,{clock:()=>now,verifier:new PasskeyVerifier({androidOrigins})})});
 const input={label:'L',account:'a@x.test',secret:'JBSWY3DPEHPK3PXP'};
 const send=(path,v,headers={})=>http.fetch(new Request(API+path,{method:'POST',headers:{Authorization:'Bearer access','Content-Type':'application/json',...headers},body:JSON.stringify(v)}),{clientAddress:'n'+Math.random()});
 return {db,a,input,send,count:()=>db.prepare('SELECT count(*) n FROM totp_seeds').first().then(r=>r.n)};
}
test('native step-up: android device, no Origin, passkey with configured android origin creates the entry; replay and changed action fail',async()=>{
 const f=await fixture([HASH]);try{
  const b=await(await f.send('/v1/manage/totp/begin',f.input)).json();assert.ok(b.token);
  assert.equal((await f.send('/v1/manage/totp',{...f.input,label:'Changed',token:b.token,response:f.a.assertion({expected:b.options.challenge,origin:HASH})})).status,403);
  const n=await(await f.send('/v1/manage/totp/begin',f.input)).json(),r=f.a.assertion({expected:n.options.challenge,origin:HASH,counter:2});
  assert.equal((await f.send('/v1/manage/totp',{...f.input,token:n.token,response:r})).status,201);assert.equal(await f.count(),1);
  assert.equal((await f.send('/v1/manage/totp',{...f.input,token:n.token,response:r})).status,403);assert.equal(await f.count(),1);
 }finally{f.db.sqlite.close();}});
test('fail closed: no configured android origin, or a different signer hash, cannot step up',async()=>{
 for(const cfg of [[],[OTHER]]){const f=await fixture(cfg);try{
  const b=await(await f.send('/v1/manage/totp/begin',f.input)).json();
  assert.equal((await f.send('/v1/manage/totp',{...f.input,token:b.token,response:f.a.assertion({expected:b.options.challenge,origin:HASH})})).status,403);assert.equal(await f.count(),0);
 }finally{f.db.sqlite.close();}}});
test('user verification is required even for the android origin',async()=>{
 const f=await fixture([HASH]);try{const b=await(await f.send('/v1/manage/totp/begin',f.input)).json();
  assert.equal((await f.send('/v1/manage/totp',{...f.input,token:b.token,response:f.a.assertion({expected:b.options.challenge,origin:HASH,flags:1})})).status,403);assert.equal(await f.count(),0);
 }finally{f.db.sqlite.close();}});
test('ceremony is bound to the device: a token begun on one native device cannot finish on another',async()=>{
 const f=await fixture([HASH]);try{const b=await(await f.send('/v1/manage/totp/begin',f.input)).json();
  const {PasskeyService:P}=await import('../src/passkey-service.js');
  const other=createTotpManagementHttp({native:true,db:f.db,sessions:{authenticate:async()=>({ownerId:'owner',deviceId:'other',generation:0,clientKind:'android',expiresAt:999999})},getSeedCipher:async()=>cipher,clock:()=>59000,passkeys:new P(f.db,{clock:()=>59000,verifier:new PasskeyVerifier({androidOrigins:[HASH]})})});
  const res=await other.fetch(new Request(API+'/v1/manage/totp',{method:'POST',headers:{Authorization:'Bearer x','Content-Type':'application/json'},body:JSON.stringify({...f.input,token:b.token,response:f.a.assertion({expected:b.options.challenge,origin:HASH,counter:2})})}),{clientAddress:'o1'});
  assert.equal(res.status,403);assert.equal(await f.count(),0);
 }finally{f.db.sqlite.close();}});
test('origin/kind boundary: Origin header with an android token, or no Origin with a web token, is refused; web path unchanged',async()=>{
 const n=await fixture([HASH]);try{
  assert.equal((await n.send('/v1/manage/totp/begin',n.input,{Origin:APP})).status,401,'android token with web Origin');
  assert.equal((await n.send('/v1/manage/totp/begin',n.input,{Origin:'https://evil.example'})).status,403);
 }finally{n.db.sqlite.close();}
 const w=await fixture([HASH],'web','wdev');try{
  assert.equal((await w.send('/v1/manage/totp/begin',w.input)).status,401,'web token without Origin');
  const b=await(await w.send('/v1/manage/totp/begin',w.input,{Origin:APP})).json();assert.ok(b.token);
  assert.equal((await w.send('/v1/manage/totp',{...w.input,token:b.token,response:w.a.assertion({expected:b.options.challenge,counter:2})},{Origin:APP})).status,201);
 }finally{w.db.sqlite.close();}});
