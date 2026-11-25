import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { database } from './sqlite-helper.js';
import { SeedCipher } from '../src/seed-cipher.js';
import { createTotpManagementHttp } from '../src/totp-management-http.js';
import { createDeviceReadHttp } from '../src/device-read-http.js';
import { PasskeyService } from '../src/passkey-service.js';
import { authenticator } from './passkey-fixture.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',EXTO='chrome-extension://abcdefghijklmnopabcdefghijklmnop';
let n=0;
async function fx(){
 const db=database(),now=59000;
 await db.prepare('INSERT INTO accounts VALUES (?,?)').bind('owner',0).run();await db.prepare('INSERT INTO accounts VALUES (?,?)').bind('rcpt',0).run();
 for(const o of ['owner','rcpt'])await db.prepare('INSERT INTO account_security(owner_id) VALUES (?)').bind(o).run();
 await db.prepare("INSERT INTO provider_identities(identity_id,owner_id,provider,issuer,subject,email,created_at) VALUES ('provider','owner','google','https://accounts.google.com','subject','synthetic@example.test',0)").run();
 await db.prepare("INSERT INTO device_sessions(device_id,owner_id,provider_identity_id,generation,client_kind,created_at,last_used_at,expires_at) VALUES ('device','owner','provider',0,'web',0,0,999999)").run();
 const a=authenticator(),c=a.credential;
 await db.prepare("INSERT INTO account_emails(owner_id,email,verified_at,updated_at) VALUES ('owner','synthetic@example.test',0,0)").run();
 await db.prepare("INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) VALUES (?,'owner',?,0,'[]','singleDevice',0,0)").bind(c.id,Array.from(c.publicKey)).run();
 const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']),cipher=new SeedCipher({keys:new Map([['test',key]]),activeKeyId:'test'});
 const sessions={authenticate:async()=>({ownerId:'owner',deviceId:'device',generation:0,clientKind:'web',expiresAt:999999})};
 const http=createTotpManagementHttp({db,sessions,getSeedCipher:async()=>cipher,clock:()=>now,passkeys:new PasskeyService(db,{clock:()=>now})});
 const send=(path,v)=>http.fetch(new Request(API+path,{method:'POST',headers:{Origin:APP,Authorization:'Bearer access','Content-Type':'application/json'},body:JSON.stringify(v)}),{clientAddress:'cat'+(n++)});
 const base={label:'Test',account:'a@example.test',secret:'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'};
 const enroll=async(begin,finish,n=2)=>{const b=await(await send('/v1/manage/totp/begin',begin)).json();return send('/v1/manage/totp',{...finish,token:b.token,response:a.assertion({expected:b.options.challenge,counter:n})});};
 return{db,a,send,base,enroll};
}
const services=db=>db.prepare('SELECT count(*) n FROM services').first();
test('absent catalogId: behavior and stored row unchanged (NULL), only custom-totp service written',async()=>{
 const f=await fx();try{const r=await f.enroll(f.base,f.base);assert.equal(r.status,201);const {entryId}=await r.json();
  const e=await f.db.prepare('SELECT service_id,catalog_id FROM entries WHERE entry_id=?').bind(entryId).first();assert.equal(e.service_id,'custom-totp');assert.equal(e.catalog_id,null);
  assert.equal((await services(f.db)).n,1);}finally{f.db.sqlite.close();}});
test('present catalogId is stored, bound by the passkey action; add, drop or change at finish is denied; services/routes untouched',async()=>{
 const f=await fx();try{
  const withId={...f.base,catalogId:'github.com'};
  assert.equal((await f.enroll(withId,f.base,2)).status,403,'dropped at finish');
  assert.equal((await f.enroll(f.base,withId,3)).status,403,'added at finish');
  assert.equal((await f.enroll(withId,{...f.base,catalogId:'gitlab.com'},4)).status,403,'changed at finish');
  assert.equal((await f.db.prepare('SELECT count(*) n FROM entries').first()).n,0);
  for(const t of ['totp_seeds','service_routes','entry_domain_associations'])assert.equal((await f.db.prepare('SELECT count(*) n FROM '+t).first()).n,0,t+' untouched by denied finishes');
  assert.equal((await services(f.db)).n,0,'no services row written by denied finishes');
  const r=await f.enroll(withId,withId,5);assert.equal(r.status,201);const {entryId}=await r.json();
  const e=await f.db.prepare('SELECT service_id,catalog_id,label FROM entries WHERE entry_id=?').bind(entryId).first();assert.deepEqual({...e},{service_id:'custom-totp',catalog_id:'github.com',label:'Test'});
  assert.equal((await services(f.db)).n,1);assert.equal((await f.db.prepare('SELECT count(*) n FROM service_routes').first()).n,0);
  assert.equal((await f.db.prepare("SELECT count(*) n FROM services WHERE service_id='github.com'").first()).n,0,'no global services row for the claim');
  await f.db.prepare("UPDATE entries SET label='Renamed' WHERE entry_id=?").bind(entryId).run();assert.equal((await f.db.prepare('SELECT catalog_id c FROM entries WHERE entry_id=?').bind(entryId).first()).c,'github.com','rename keeps identity');
 }finally{f.db.sqlite.close();}});
test('invalid catalogId shapes are 400 on begin and finish and write nothing',async()=>{
 const f=await fx();try{
  for(const bad of ['','GitHub.com','-a.com','a b','a/b','https://a.com','a@b','x'.repeat(129),'é.com',5,null,[],{}]){
   assert.equal((await f.send('/v1/manage/totp/begin',{...f.base,catalogId:bad})).status,400,JSON.stringify(bad));
   assert.equal((await f.send('/v1/manage/totp',{...f.base,catalogId:bad,token:'t',response:{}})).status,400,'finish '+JSON.stringify(bad));}
  assert.equal((await f.send('/v1/manage/totp/begin',{...f.base,catalogId:'a.com',extra:1})).status,400);
  assert.equal((await f.db.prepare('SELECT count(*) n FROM entries').first()).n,0);
 }finally{f.db.sqlite.close();}});
test('migration check constraint rejects malformed ids at the database too',async()=>{
 const f=await fx();try{
  await f.db.prepare("INSERT INTO services(service_id,name) VALUES ('custom-totp','Authenticator')").run().catch(()=>{});
  const ins=id=>f.db.sqlite.prepare("INSERT INTO entries(entry_id,owner_id,service_id,label,created_at,catalog_id) VALUES (?, 'owner','custom-totp','L',1,?)").run('e'+Math.random(),id);
  ins('ok.com');ins(null);for(const bad of ['Bad','','a b','a/b'])assert.throws(()=>ins(bad),/CHECK|constraint/i,bad);
  assert.match(readFileSync(new URL('../migrations/0049_totp_catalog_identity.sql',import.meta.url),'utf8'),/ADD COLUMN catalog_id/);
 }finally{f.db.sqlite.close();}});
test('reads on web, native and extension sessions show catalogId to owner and recipient, omit it when absent, and expose nothing else new',async()=>{
 const f=await fx();try{
  await f.db.prepare("INSERT INTO services(service_id,name) VALUES ('custom-totp','Authenticator') ON CONFLICT DO NOTHING").run();
  const ins=(id,cat)=>f.db.prepare("INSERT INTO entries(entry_id,owner_id,service_id,label,created_at,catalog_id) VALUES (?,'owner','custom-totp','Label',1,?)").bind(id,cat).run();
  await ins('e1','github.com');await ins('e2',null);await f.db.prepare("INSERT INTO entry_shares(entry_id,recipient_id,created_at) VALUES ('e1','rcpt',1)").run();
  const kinds={web:['owner','web'],and:['owner','android'],ext:['owner','extension'],rcpt:['rcpt','web']};
  const sessions={authenticate:async t=>kinds[t]?{ownerId:kinds[t][0],deviceId:'d',generation:0,clientKind:kinds[t][1],expiresAt:999999}:undefined};
  const http=createDeviceReadHttp({db:f.db,sessions,sources:{},access:{},clock:()=>59000,native:true,extensionOrigins:[EXTO]});
  const get=(t,origin)=>http.fetch(new Request(API+'/v1/manage/entries',{headers:{...(origin?{origin}:{}),authorization:'Bearer '+t}}),{clientAddress:'1.1.1.1'});
  for(const [t,o] of [['web',APP],['and',undefined],['ext',undefined],['ext',EXTO],['rcpt',APP]]){
   const r=await get(t,o);assert.equal(r.status,200,t);const {entries}=await r.json();const e1=entries.find(e=>e.entry_id==='e1');
   if(t==='rcpt'){assert.equal(entries.length,1);}
   assert.equal(e1.catalogId,'github.com',t);assert.equal('catalog_id' in e1,false);
   if(t!=='rcpt'){const e2=entries.find(e=>e.entry_id==='e2');assert.equal('catalogId' in e2,false,'omitted when absent');}}
 }finally{f.db.sqlite.close();}});
const uri=(issuer,prefix=true)=>('otpauth://totp/'+(issuer&&prefix?encodeURIComponent(issuer)+':':'')+'a%40example.test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'+(issuer?'&issuer='+encodeURIComponent(issuer):''));
test('scanned issuer comes only from a validated otpauth URI, is bound by the passkey action, survives rename, manual and legacy rows stay NULL',async()=>{
 const f=await fx();try{
  const moz={...f.base,secret:uri('Mozilla')},other={...f.base,secret:uri('Mozilla Firefox')},none={...f.base,secret:uri(null)};
  assert.equal((await f.enroll(moz,other,2)).status,403,'issuer changed between begin and finish');
  assert.equal((await f.enroll(moz,none,3)).status,403,'issuer dropped at finish');
  assert.equal((await f.enroll(none,moz,4)).status,403,'issuer added at finish');
  for(const t of ['entries','totp_seeds','service_routes'])assert.equal((await f.db.prepare('SELECT count(*) n FROM '+t).first()).n,0,t);
  const r=await f.enroll(moz,moz,5);assert.equal(r.status,201);const {entryId}=await r.json();
  const row=()=>f.db.prepare('SELECT service_id,catalog_id,issuer,label FROM entries WHERE entry_id=?').bind(entryId).first();
  assert.deepEqual({...await row()},{service_id:'custom-totp',catalog_id:null,issuer:'Mozilla',label:'Test'});
  await f.db.prepare("UPDATE entries SET label='Mozilla Firefox' WHERE entry_id=?").bind(entryId).run();
  assert.deepEqual({...await row()},{service_id:'custom-totp',catalog_id:null,issuer:'Mozilla',label:'Mozilla Firefox'},'rename touches only label');
  assert.equal((await f.db.prepare("SELECT count(*) n FROM services WHERE name LIKE 'Mozilla%'").first()).n,0,'issuer never reaches services');
  const manual=await f.enroll(f.base,f.base,6);assert.equal(manual.status,201);assert.equal((await f.db.prepare('SELECT issuer FROM entries WHERE entry_id=?').bind((await manual.json()).entryId).first()).issuer,null,'manual key: NULL');
  const noIssuerUri=await f.enroll(none,none,7);assert.equal(noIssuerUri.status,201);assert.equal((await f.db.prepare('SELECT issuer FROM entries WHERE entry_id=?').bind((await noIssuerUri.json()).entryId).first()).issuer,null,'URI without issuer: NULL');
  // a request member named issuer is not accepted (the issuer is never client-asserted)
  assert.equal((await f.send('/v1/manage/totp/begin',{...f.base,issuer:'Mozilla'})).status,400);
  assert.throws(()=>f.db.sqlite.prepare("INSERT INTO entries(entry_id,owner_id,service_id,label,created_at,issuer) VALUES ('x','owner','custom-totp','L',1,' pad ')").run());
 }finally{f.db.sqlite.close();}});
test('reads show issuer on web, native, extension and recipient only when set; legacy and absent omit it',async()=>{
 const f=await fx();try{
  await f.db.prepare("INSERT INTO services(service_id,name) VALUES ('custom-totp','Authenticator') ON CONFLICT DO NOTHING").run();
  const ins=(id,iss)=>f.db.prepare("INSERT INTO entries(entry_id,owner_id,service_id,label,created_at,issuer) VALUES (?,'owner','custom-totp','Renamed',1,?)").bind(id,iss).run();
  await ins('e1','Mozilla');await ins('e2',null);await f.db.prepare("INSERT INTO entry_shares(entry_id,recipient_id,created_at) VALUES ('e1','rcpt',1)").run();
  const kinds={web:['owner','web'],and:['owner','android'],ext:['owner','extension'],rcpt:['rcpt','web']};
  const sessions={authenticate:async t=>kinds[t]?{ownerId:kinds[t][0],deviceId:'d',generation:0,clientKind:kinds[t][1],expiresAt:999999}:undefined};
  const http=createDeviceReadHttp({db:f.db,sessions,sources:{},access:{},clock:()=>59000,native:true,extensionOrigins:[EXTO]});
  const get=(t,origin)=>http.fetch(new Request(API+'/v1/manage/entries',{headers:{...(origin?{origin}:{}),authorization:'Bearer '+t}}),{clientAddress:'1.1.1.1'});
  for(const [t,o] of [['web',APP],['and',undefined],['ext',undefined],['ext',EXTO],['rcpt',APP]]){
   const {entries}=await (await get(t,o)).json(),e1=entries.find(e=>e.entry_id==='e1');
   assert.equal(e1.issuer,'Mozilla',t);assert.equal(e1.label,'Renamed');assert.equal('catalogId' in e1,false);
   if(t!=='rcpt')assert.equal('issuer' in entries.find(e=>e.entry_id==='e2'),false,'NULL omitted');}
 }finally{f.db.sqlite.close();}});
