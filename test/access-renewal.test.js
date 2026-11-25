import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { PasskeySignupService } from '../src/passkey-signup.js';
import { AccountIdentityService } from '../src/account-identity.js';
import { BrowserExchangeService,pkceChallenge } from '../src/browser-exchanges.js';
import { DeviceSessionService } from '../src/device-sessions.js';
import { authenticator } from './passkey-fixture.js';
const NOW=1_800_000_000_000,DAY=86400000;
async function setup(){const db=database();let now=NOW;const identity=new AccountIdentityService(db,{clock:()=>now}),signup=new PasskeySignupService(db,{clock:()=>now});const {token}=await identity.issueEmailChallenge({purpose:'signup-email',email:'a@example.com'});const c=await signup.begin({email:'a@example.com',emailToken:token,binding:'binding'}),a=authenticator();const account=await signup.finish({token:c.token,binding:'binding',response:a.registration({expected:c.options.challenge})});const proof={...account,verifiedAt:NOW,purpose:'authenticate'};const service=new DeviceSessionService(db,{clock:()=>now});return {db,service,proof,setNow:v=>now=v};}
import { AccessRenewal,renewalMessage,resumeMessage,MAX_LINEAGES } from '../src/access-renewal.js';
import { base64urlEncode } from '../src/tokens.js';
import { createBrowserSessionHttp } from '../src/browser-session-http.js';
const redirectUri='https://otpanda.github.io/app/',verifier='a'.repeat(43),API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io';
const enc=u=>base64urlEncode(new Uint8Array(u));
async function newKey(){const k=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign']);return{priv:k.privateKey,pub:enc(await crypto.subtle.exportKey('raw',k.publicKey))};}
async function sign(k,{lineageId,handleId,expiresAt}){return enc(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},k.priv,renewalMessage({lineageId,handleId,expiresAt})));}
async function fixture(){const f=await setup();let now=NOW;const clock=()=>now;const service=new DeviceSessionService(f.db,{clock}),d=await service.issue({proof:f.proof,clientKind:'web'}),exchange=new BrowserExchangeService(f.db,{redirectUri,clock}),renewals=new AccessRenewal(f.db,{clock});
 const bind=async(key,v=verifier)=>{const x=await exchange.mint({deviceId:d.deviceId,challenge:await pkceChallenge(v),redirectUri});return exchange.exchange({code:x.code,verifier:v,redirectUri,...(key?{renewalKey:key.pub}:{})});};
 return{...f,service,d,exchange,renewals,clock,bind,setTime:v=>{now=v;f.setNow(v);}};}
const renewReq=async(f,k,e,over={})=>({token:e.access,lineageId:e.renewal.lineageId,expiresAt:f.clock()+30000,...over});
async function renew(f,k,e,over={}){const r=await renewReq(f,k,e,over);r.signature=over.signature??await sign(k,{lineageId:r.lineageId,handleId:over.handleId??e.renewal.handleId,expiresAt:r.expiresAt});return f.renewals.renew(r);}
test('only the one-use exchange binds a key; no key means no renewal capability and the old response shape',async()=>{
 const f=await fixture(),k=await newKey();const plain=await f.bind();assert.deepEqual(Object.keys(plain).sort(),['access','accessExpiresAt']);assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM access_lineages').get().n,0);
 const e=await f.bind(k);assert.ok(e.renewal.lineageId&&e.renewal.handleId);const row=f.db.sqlite.prepare('SELECT lineage_id,public_key FROM access_lineages').get();assert.equal(row.public_key,k.pub);
 assert.equal(f.db.sqlite.prepare('SELECT lineage_id l FROM device_access_handles WHERE handle_id=?').get(e.renewal.handleId).l,e.renewal.lineageId);
 // a plain (key-less) handle cannot renew, with any signature
 const other=await newKey();assert.equal((await f.renewals.renew({token:plain.access,lineageId:e.renewal.lineageId,expiresAt:f.clock()+1000,signature:await sign(k,{lineageId:e.renewal.lineageId,handleId:'x',expiresAt:f.clock()+1000})})).status,'denied');f.db.sqlite.close();});
test('malformed, compressed, off-curve and wrong-length keys are refused BEFORE the code is spent',async()=>{
 const f=await fixture(),ok=await newKey();const x=await f.exchange.mint({deviceId:f.d.deviceId,challenge:await pkceChallenge(verifier),redirectUri});
 const raw=Uint8Array.from(atob(ok.pub.replace(/-/g,'+').replace(/_/g,'/')+'='),c=>c.charCodeAt(0));const bad=[ok.pub.slice(1),'x'.repeat(87),enc(Uint8Array.from([2,...raw.slice(1,33)])),enc(Uint8Array.from([4,...new Uint8Array(64).fill(1)])),enc(Uint8Array.from([5,...raw.slice(1)])),42];
 for(const b of bad)assert.equal(await f.exchange.exchange({code:x.code,verifier,redirectUri,renewalKey:b}),undefined,String(b));
 assert.ok(await f.exchange.exchange({code:x.code,verifier,redirectUri,renewalKey:ok.pub}),'code was not burned by bad keys');f.db.sqlite.close();});
test('valid signed renewal: one successor in the same lineage, old handle spent once, device idle extended, nothing else minted',async()=>{
 const f=await fixture(),k=await newKey(),e=await f.bind(k);const before={ref:f.db.sqlite.prepare('SELECT count(*) n FROM device_refresh_handles').get().n,ex:f.db.sqlite.prepare('SELECT count(*) n FROM browser_exchanges').get().n,dev:f.db.sqlite.prepare('SELECT count(*) n FROM device_sessions').get().n,rec:f.db.sqlite.prepare('SELECT count(*) n FROM recognized_browsers').get().n};
 f.setTime(NOW+240000);const r=await renew(f,k,e);assert.equal(r.status,'renewed');assert.equal(r.renewal.lineageId,e.renewal.lineageId);assert.notEqual(r.renewal.handleId,e.renewal.handleId);assert.equal(r.accessExpiresAt,NOW+240000+300000);
 assert.equal(f.db.sqlite.prepare('SELECT lineage_id l FROM device_access_handles WHERE handle_id=?').get(r.renewal.handleId).l,e.renewal.lineageId);
 assert.equal((await f.service.authenticate(r.access)).deviceId,f.d.deviceId);
 assert.deepEqual({ref:f.db.sqlite.prepare('SELECT count(*) n FROM device_refresh_handles').get().n,ex:f.db.sqlite.prepare('SELECT count(*) n FROM browser_exchanges').get().n,dev:f.db.sqlite.prepare('SELECT count(*) n FROM device_sessions').get().n,rec:f.db.sqlite.prepare('SELECT count(*) n FROM recognized_browsers').get().n},before);
 assert.equal(f.db.sqlite.prepare('SELECT expires_at e FROM device_sessions').get().e,NOW+240000+30*86400000);
 // the spent handle stays valid for reads until its own expiry but can never renew again
 assert.ok(await f.service.authenticate(e.access));assert.equal((await renew(f,k,e)).status,'renewed-elsewhere');f.db.sqlite.close();});
test('bad signature, wrong key, wrong handle, wrong lineage, wrong endpoint domain and out-of-window expiry spend and revoke nothing',async()=>{
 const f=await fixture(),k=await newKey(),wrong=await newKey(),e=await f.bind(k),e2=await f.bind(await newKey(),'b'.repeat(43));
 const snap=()=>JSON.stringify([f.db.sqlite.prepare('SELECT handle_id,renewed_at,renew_receipt FROM device_access_handles ORDER BY handle_id').all(),f.db.sqlite.prepare('SELECT revoked_at FROM device_sessions').all()]);const s0=snap();
 const exp=f.clock()+20000,lid=e.renewal.lineageId,hid=e.renewal.handleId;
 const cases={wrongKey:await sign(wrong,{lineageId:lid,handleId:hid,expiresAt:exp}),otherHandle:await sign(k,{lineageId:lid,handleId:e2.renewal.handleId,expiresAt:exp}),otherLineage:await sign(k,{lineageId:e2.renewal.lineageId,handleId:hid,expiresAt:exp}),otherExpiry:await sign(k,{lineageId:lid,handleId:hid,expiresAt:exp+1}),garbage:'A'.repeat(86),short:'A'.repeat(10)};
 for(const [n,sig] of Object.entries(cases))assert.equal((await f.renewals.renew({token:e.access,lineageId:lid,expiresAt:exp,signature:sig})).status,'denied',n);
 // domain/endpoint separation: a signature over another message shape is rejected
 const alt=enc(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},k.priv,new TextEncoder().encode(['otpanda-other','POST /auth/renew',lid,hid,String(exp)].join('\n'))));assert.equal((await f.renewals.renew({token:e.access,lineageId:lid,expiresAt:exp,signature:alt})).status,'denied');
 for(const bad of [f.clock()-1,f.clock()+60001,1.5,'x'])assert.equal((await f.renewals.renew({token:e.access,lineageId:lid,expiresAt:bad,signature:await sign(k,{lineageId:lid,handleId:hid,expiresAt:typeof bad==='number'?bad:0})})).status,'denied');
 // the other lineage's token cannot renew under this lineage id even with its own valid signature
 assert.equal((await f.renewals.renew({token:e2.access,lineageId:lid,expiresAt:exp,signature:await sign(k,{lineageId:lid,handleId:e2.renewal.handleId,expiresAt:exp})})).status,'denied');
 assert.equal(snap(),s0,'no state changed by any denial');assert.equal((await renew(f,k,e)).status,'renewed','legitimate renewal still works afterwards');f.db.sqlite.close();});
test('a bearer alone, or a bearer with a new public key, can neither renew nor rebind; only the exchange binds',async()=>{
 const f=await fixture(),k=await newKey(),e=await f.bind(k);
 assert.equal((await f.renewals.renew({token:e.access,lineageId:e.renewal.lineageId,expiresAt:f.clock()+1000,signature:'A'.repeat(86)})).status,'denied');
 const http=createBrowserSessionHttp({sessions:f.service,exchanges:f.exchange,renewals:f.renewals,db:f.db,clock:f.clock});
 const call=(path,body,headers={})=>http.fetch(new Request(API+path,{method:'POST',headers:{Origin:APP,'Content-Type':'application/json',...headers},body:JSON.stringify(body)}),{clientAddress:'t'});
 let r=await call('/auth/renew',{lineage_id:e.renewal.lineageId,expires_at:f.clock()+1000,signature:'A'.repeat(86),renewal_key:(await newKey()).pub},{Authorization:'Bearer '+e.access});assert.equal(r.status,400);
 assert.equal(f.db.sqlite.prepare('SELECT public_key p FROM access_lineages WHERE lineage_id=?').get(e.renewal.lineageId).p,k.pub);
 assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM access_lineages').get().n,1);f.db.sqlite.close();});
test('replay of the signed request, concurrent renewals and a lost response: exactly one winner, losers refused without revoking the device',async()=>{
 const f=await fixture(),k=await newKey(),e=await f.bind(k);const exp=f.clock()+30000,sig=await sign(k,{lineageId:e.renewal.lineageId,handleId:e.renewal.handleId,expiresAt:exp});
 const rs=await Promise.all(Array.from({length:8},()=>f.renewals.renew({token:e.access,lineageId:e.renewal.lineageId,expiresAt:exp,signature:sig})));
 assert.equal(rs.filter(r=>r.status==='renewed').length,1);assert.equal(rs.filter(r=>r.status==='renewed-elsewhere').length,7);assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM device_access_handles WHERE lineage_id=?').get(e.renewal.lineageId).n,2);
 assert.equal(f.db.sqlite.prepare('SELECT revoked_at r FROM device_sessions').get().r,null);
 assert.equal((await f.renewals.renew({token:e.access,lineageId:e.renewal.lineageId,expiresAt:exp,signature:sig})).status,'renewed-elsewhere','replay refused');assert.equal(f.db.sqlite.prepare('SELECT revoked_at r FROM device_sessions').get().r,null);
 // the winner's successor keeps renewing
 const win=rs.find(r=>r.status==='renewed');assert.equal((await renew(f,k,win)).status,'renewed');f.db.sqlite.close();});
test('guards repeat at the final write: revoke, generation, credential revocation, expiry and lineage removal end renewal',async()=>{
 for(const kind of ['device','generation','credential','access-expiry','device-expiry','lineage-gone']){
  const f=await fixture(),k=await newKey(),e=await f.bind(k);const base=f.db.sqlite.prepare('SELECT count(*) n FROM device_access_handles').get().n;
  if(kind==='device')await f.service.revoke({ownerId:f.proof.ownerId,deviceId:f.d.deviceId});
  if(kind==='generation')f.db.sqlite.prepare('UPDATE account_security SET generation=generation+1').run();
  if(kind==='credential')f.db.sqlite.prepare('UPDATE passkey_credentials SET revoked_at=?').run(NOW);
  if(kind==='access-expiry')f.setTime(NOW+300001);
  if(kind==='device-expiry'){f.db.sqlite.prepare('UPDATE device_sessions SET expires_at=?').run(NOW+1);f.setTime(NOW+1000);}
  if(kind==='lineage-gone')f.db.sqlite.prepare('DELETE FROM access_lineages').run();
  const r=await renew(f,k,e,kind==='access-expiry'?{expiresAt:f.clock()+1000}:{});assert.notEqual(r.status,'renewed',kind);assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM device_access_handles').get().n,kind==='lineage-gone'?base-1:base,kind);f.db.sqlite.close();}});
test('race: device revoked between verification and the write cannot get a successor',async()=>{
 const f=await fixture(),k=await newKey(),e=await f.bind(k);const real=f.db.batch.bind(f.db);f.db.batch=async s=>{await f.service.revoke({ownerId:f.proof.ownerId,deviceId:f.d.deviceId});return real(s);};
 const r=await renew(f,k,e);assert.notEqual(r.status,'renewed');assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM device_access_handles').get().n,2);f.db.sqlite.close();});
test('independent tabs get independent lineages; one tab renewing or exchanging never disturbs another; lineage cap evicts the oldest',async()=>{
 const f=await fixture(),ks=[],es=[];for(let i=0;i<2;i++){ks.push(await newKey());es.push(await f.bind(ks[i],String.fromCharCode(97+i).repeat(43)));}
 assert.notEqual(es[0].renewal.lineageId,es[1].renewal.lineageId);assert.equal((await renew(f,ks[0],es[0])).status,'renewed');assert.equal((await renew(f,ks[1],es[1])).status,'renewed');
 assert.equal((await f.renewals.renew({token:es[0].access,lineageId:es[1].renewal.lineageId,expiresAt:f.clock()+1000,signature:await sign(ks[0],{lineageId:es[1].renewal.lineageId,handleId:es[0].renewal.handleId,expiresAt:f.clock()+1000})})).status,'denied');
 const first=es[0].renewal.lineageId;for(let i=2;i<MAX_LINEAGES+3;i++)await f.bind(await newKey(),String.fromCharCode(97+(i%20)).repeat(42)+String(i%10));
 assert.ok(f.db.sqlite.prepare('SELECT count(*) n FROM access_lineages').get().n<=MAX_LINEAGES);assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM access_lineages WHERE lineage_id=?').get(first).n,0,'oldest evicted');f.db.sqlite.close();});
test('mounted HTTP: strict CORS/Origin/JSON, per-lineage rate limit, statuses, and exchange accepts the optional key field only',async()=>{
 const f=await fixture(),k=await newKey(),http=createBrowserSessionHttp({sessions:f.service,exchanges:f.exchange,renewals:f.renewals,db:f.db,clock:f.clock});
 const run=(path,init,addr='t')=>http.fetch(new Request(API+path,init),{clientAddress:addr});
 const x=await f.exchange.mint({deviceId:f.d.deviceId,challenge:await pkceChallenge(verifier),redirectUri});
 let r=await run('/auth/exchange',{method:'POST',headers:{Origin:APP,'Content-Type':'application/json'},body:JSON.stringify({code:x.code,verifier,redirect_uri:redirectUri,renewal_key:k.pub})});assert.equal(r.status,200);const e=await r.json();assert.ok(e.renewal.lineageId);
 r=await run('/auth/exchange',{method:'POST',headers:{Origin:APP,'Content-Type':'application/json'},body:JSON.stringify({code:x.code,verifier,redirect_uri:redirectUri,extra:1})});assert.equal(r.status,400);
 r=await run('/auth/renew',{method:'OPTIONS',headers:{Origin:APP,'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'authorization, content-type'}});assert.equal(r.status,204);assert.equal(r.headers.get('access-control-allow-origin'),APP);assert.equal(r.headers.get('access-control-allow-credentials'),null);
 r=await run('/auth/renew',{method:'OPTIONS',headers:{Origin:APP,'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'x-evil'}});assert.equal(r.status,403);
 const body=async o=>JSON.stringify({lineage_id:e.renewal.lineageId,expires_at:f.clock()+20000,...o});const exp=f.clock()+20000,sig=await sign(k,{lineageId:e.renewal.lineageId,handleId:e.renewal.handleId,expiresAt:exp});
 const post=(b,headers)=>run('/auth/renew',{method:'POST',headers:{Origin:APP,'Content-Type':'application/json',...headers},body:b});
 assert.equal((await post(JSON.stringify({lineage_id:e.renewal.lineageId,expires_at:exp,signature:sig}),{Origin:'https://evil.test',Authorization:'Bearer '+e.access})).status,403);
 assert.equal((await post(JSON.stringify({lineage_id:e.renewal.lineageId,expires_at:exp,signature:sig}),{})).status,401);
 assert.equal((await post(JSON.stringify({lineage_id:e.renewal.lineageId,expires_at:exp}),{Authorization:'Bearer '+e.access})).status,400);
 assert.equal((await post(JSON.stringify({lineage_id:e.renewal.lineageId,expires_at:exp,signature:'A'.repeat(86)}),{Authorization:'Bearer '+e.access})).status,401);
 const ok=await post(JSON.stringify({lineage_id:e.renewal.lineageId,expires_at:exp,signature:sig}),{Authorization:'Bearer '+e.access});assert.equal(ok.status,200);const nx=await ok.json();assert.ok(nx.access&&nx.renewal.handleId);assert.equal(ok.headers.get('set-cookie'),null);
 assert.equal((await post(JSON.stringify({lineage_id:e.renewal.lineageId,expires_at:exp,signature:sig}),{Authorization:'Bearer '+e.access})).status,409);
 let limited=0;for(let i=0;i<30;i++){const s=await post(JSON.stringify({lineage_id:e.renewal.lineageId,expires_at:exp,signature:'A'.repeat(86)}),{Authorization:'Bearer '+nx.access});if(s.status===429)limited++;}assert.ok(limited>0,'per-lineage rate limit');f.db.sqlite.close();});
test('firstPartyExpiresAt is the actual refresh-cookie deadline: unchanged by signed renewals, advanced only by a real rotation in any tab',async()=>{
 const f=await fixture(),k=await newKey(),e=await f.bind(k);assert.equal(e.renewal.firstPartyExpiresAt,f.d.refreshExpiresAt);assert.equal(e.renewal.firstPartyExpiresAt,NOW+30*DAY);
 f.setTime(NOW+240000);const r=await renew(f,k,e);assert.equal(r.status,'renewed');assert.equal(r.renewal.firstPartyExpiresAt,f.d.refreshExpiresAt,'renewal extends device idle but not the cookie');
 assert.ok(f.db.sqlite.prepare('SELECT expires_at e FROM device_sessions').get().e>f.d.refreshExpiresAt);
 f.setTime(NOW+DAY);const rot=await f.service.rotate(f.d.refresh,{clientKind:'web'});assert.equal(rot.status,'rotated');
 const k2=await newKey(),e2=await f.bind(k2,'b'.repeat(43));assert.equal(e2.renewal.firstPartyExpiresAt,rot.refreshExpiresAt);assert.equal(rot.refreshExpiresAt,NOW+DAY+30*DAY);
 f.setTime(NOW+DAY+1000);const r2=await renew(f,k2,e2);assert.equal(r2.status,'renewed');assert.equal(r2.renewal.firstPartyExpiresAt,rot.refreshExpiresAt,'renewal reports the current cookie deadline');
 f.db.sqlite.close();});
test('malformed lineage_id is refused with 400 before any rate-limit bucket is allocated',async()=>{
 const f=await fixture(),k=await newKey(),e=await f.bind(k),http=createBrowserSessionHttp({sessions:f.service,exchanges:f.exchange,renewals:f.renewals,db:f.db,clock:f.clock});
 const n=()=>f.db.sqlite.prepare('SELECT count(*) n FROM rate_buckets').get().n,before=n();
 for(const bad of ['short','x'.repeat(65),'has space!!','a/b/c/d/e/f','é'.repeat(10)]){const r=await http.fetch(new Request(API+'/auth/renew',{method:'POST',headers:{Origin:APP,'Content-Type':'application/json',Authorization:'Bearer '+e.access},body:JSON.stringify({lineage_id:bad,expires_at:f.clock()+1000,signature:'A'.repeat(86)})}),{clientAddress:'t'});assert.equal(r.status,400);}
 assert.ok(n()<=before+1,'only the per-address bucket may be touched');
 const b2=n();await http.fetch(new Request(API+'/auth/renew',{method:'POST',headers:{Origin:APP,'Content-Type':'application/json',Authorization:'Bearer '+e.access},body:JSON.stringify({lineage_id:'q'.repeat(30),expires_at:f.clock()+1000,signature:'A'.repeat(86)})}),{clientAddress:'t'});assert.equal(n(),b2+1,'well-formed id allocates one lineage bucket');
 f.db.sqlite.close();});
test('serverTime is the server clock reading the access expiry is derived from, on exchange and renew, whatever the client clock says',async()=>{
 const f=await fixture(),k=await newKey(),e=await f.bind(k);assert.equal(e.renewal.serverTime,NOW);assert.equal(e.accessExpiresAt-e.renewal.serverTime,300000);
 f.setTime(NOW+200000);const r=await renew(f,k,e);assert.equal(r.renewal.serverTime,NOW+200000);assert.equal(r.accessExpiresAt-r.renewal.serverTime,300000);assert.ok(Number.isSafeInteger(r.renewal.serverTime));
 const plain=await f.bind(undefined,'c'.repeat(43));assert.deepEqual(Object.keys(plain).sort(),['access','accessExpiresAt']);f.db.sqlite.close();});

async function resume(f,k,lineageId,handleId,over={}){const expiresAt=over.expiresAt??f.clock()+30000;const signature=over.signature??enc(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},k.priv,resumeMessage({lineageId,handleId,expiresAt})));return f.renewals.resume({lineageId,handleId,signature,expiresAt});}
test('resume: after the access life (and after cleanup) the key alone renews; expired access stays dead; head moves once',async()=>{
 const f=await fixture(),k=await newKey(),e=await f.bind(k),L=e.renewal.lineageId;
 f.setTime(NOW+20*DAY);await f.service.cleanup({limit:500});
 assert.equal(await f.service.authenticate(e.access),undefined);
 assert.equal((await resume(f,await newKey(),L,e.renewal.handleId)).status,'denied','other key');
 assert.equal((await resume(f,k,L,'x'.repeat(16))).status,'denied','not the head');
 const exp=f.clock()+30000,sig=enc(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},k.priv,resumeMessage({lineageId:L,handleId:e.renewal.handleId,expiresAt:exp})));
 const rs=await Promise.all(Array.from({length:6},()=>resume(f,k,L,e.renewal.handleId,{signature:sig,expiresAt:exp})));
 assert.equal(rs.filter(r=>r.status==='renewed').length,1);assert.equal(rs.filter(r=>r.status!=='renewed'&&r.status!=='denied'&&r.status!=='renewed-elsewhere').length,0);
 const r=rs.find(r=>r.status==='renewed');assert.equal(r.accessExpiresAt,f.clock()+300000);assert.equal((await f.service.authenticate(r.access)).deviceId,f.d.deviceId);
 assert.equal(f.db.sqlite.prepare('SELECT head_handle_id h FROM access_lineages WHERE lineage_id=?').get(L).h,r.renewal.handleId);
 assert.equal((await resume(f,k,L,e.renewal.handleId)).status,'denied','replaying the old head never works');
 f.setTime(NOW+20*DAY+400000);const again=await resume(f,k,L,r.renewal.handleId);assert.equal(again.status,'renewed','chain continues');
 assert.equal(f.db.sqlite.prepare('SELECT expires_at e FROM device_sessions').get().e,NOW+20*DAY+400000+30*DAY);f.db.sqlite.close();});
test('resume refused: revoked device, generation bump, device idle expired (30d), wrong domain signature, bad skew; bearer and resume cannot both win',async()=>{
 for(const kind of ['device','generation','idle','domain','skew','race']){
  const f=await fixture(),k=await newKey(),e=await f.bind(k),L=e.renewal.lineageId,H=e.renewal.handleId;
  if(kind==='device')await f.service.revoke({ownerId:f.proof.ownerId,deviceId:f.d.deviceId});
  if(kind==='generation')f.db.sqlite.prepare('UPDATE account_security SET generation=generation+1').run();
  if(kind==='idle')f.setTime(NOW+31*DAY);
  const over=kind==='domain'?{signature:await sign(k,{lineageId:L,handleId:H,expiresAt:f.clock()+30000})}:kind==='skew'?{expiresAt:f.clock()+61000}:{};
  if(kind==='race'){const b=await renew(f,k,e);assert.equal(b.status,'renewed');assert.equal((await resume(f,k,L,H)).status,'denied','old head after bearer renewal');
   const f2=await fixture(),k2=await newKey(),e2=await f2.bind(k2);const r2=await resume(f2,k2,e2.renewal.lineageId,e2.renewal.handleId);assert.equal(r2.status,'renewed');assert.equal((await renew(f2,k2,e2)).status,'renewed-elsewhere','bearer after resume');f2.db.sqlite.close();}
  else assert.notEqual((await resume(f,k,L,H,over)).status,'renewed',kind);
  f.db.sqlite.close();}});
test('resume over HTTP: no bearer allowed or read, same CORS/Origin/rate limits, expired access still 401 elsewhere',async()=>{
 const f=await fixture(),k=await newKey(),e=await f.bind(k),http=createBrowserSessionHttp({sessions:f.service,exchanges:f.exchange,renewals:f.renewals,db:f.db,clock:f.clock});
 f.setTime(NOW+3600000);const L=e.renewal.lineageId,H=e.renewal.handleId,exp=f.clock()+30000,signature=enc(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},k.priv,resumeMessage({lineageId:L,handleId:H,expiresAt:exp})));
 const post=(body,headers={},o=APP)=>http.fetch(new Request(API+'/auth/renew',{method:'POST',headers:{Origin:o,'Content-Type':'application/json',...headers},body:JSON.stringify(body)}),{clientAddress:'t'});
 const good={lineage_id:L,handle_id:H,expires_at:exp,signature};
 assert.equal((await post(good,{Authorization:'Bearer '+e.access})).status,400,'a bearer on resume is refused, never read');
 assert.equal((await post(good,{},'https://evil.example')).status,403);
 assert.equal((await post({...good,extra:1})).status,400);assert.equal((await post({lineage_id:L,expires_at:exp,signature})).status,401,'bearer mode still requires its bearer');
 const r=await post(good);assert.equal(r.status,200);const j=await r.json();assert.equal(j.renewal.lineageId,L);assert.notEqual(j.renewal.handleId,H);
 assert.equal((await post(good)).status,401,'replay');f.db.sqlite.close();});
import { cleanupIdentity } from '../src/identity-cleanup.js';
test('identity cleanup keeps a lineage renewable for 30 days after its last renewal and then drops it',async()=>{
 const f=await fixture(),k=await newKey(),e=await f.bind(k),L=e.renewal.lineageId,n=()=>f.db.sqlite.prepare('SELECT count(*) n FROM access_lineages WHERE lineage_id=?').get(L).n;
 f.setTime(NOW+10*DAY);await cleanupIdentity({db:f.db,clock:f.clock,limit:500});assert.equal(n(),1);assert.equal((await resume(f,k,L,e.renewal.handleId)).status,'renewed');
 f.setTime(NOW+10*DAY+29*DAY);await cleanupIdentity({db:f.db,clock:f.clock,limit:500});assert.equal(n(),1);
 f.db.sqlite.prepare('UPDATE device_sessions SET expires_at=?').run(NOW+100*DAY);f.setTime(NOW+10*DAY+31*DAY);await cleanupIdentity({db:f.db,clock:f.clock,limit:500});assert.equal(n(),0);f.db.sqlite.close();});
