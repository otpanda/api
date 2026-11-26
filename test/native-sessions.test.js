import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { PasskeySignupService } from '../src/passkey-signup.js';
import { AccountIdentityService } from '../src/account-identity.js';
import { DeviceSessionService } from '../src/device-sessions.js';
import { pkceChallenge } from '../src/browser-exchanges.js';
import { NativeSessionService,nativeMessage,NATIVE_REDIRECT } from '../src/native-sessions.js';
import { base64urlEncode } from '../src/tokens.js';
import { authenticator } from './passkey-fixture.js';
const NOW=1_800_000_000_000,verifier='n'.repeat(43),enc=u=>base64urlEncode(new Uint8Array(u));
async function newKey(){const k=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign']);return{priv:k.privateKey,pub:enc(await crypto.subtle.exportKey('raw',k.publicKey))};}
async function sign(k,{purpose,deviceId,nonce,expiresAt}){return enc(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},k.priv,nativeMessage({purpose,deviceId,nonce,expiresAt})));}
async function fixture(){
 const db=database();let now=NOW;const clock=()=>now;
 const identity=new AccountIdentityService(db,{clock}),signup=new PasskeySignupService(db,{clock});
 const {token}=await identity.issueEmailChallenge({purpose:'signup-email',email:'a@example.com'});
 const c=await signup.begin({email:'a@example.com',emailToken:token,binding:'binding'}),a=authenticator();
 const account=await signup.finish({token:c.token,binding:'binding',response:a.registration({expected:c.options.challenge})});
 const proof={...account,verifiedAt:NOW,purpose:'authenticate'};
 const sessions=new DeviceSessionService(db,{clock}),web=await sessions.issue({proof,clientKind:'web'}),native=new NativeSessionService(db,{clock});
 const q=(sql,...p)=>db.sqlite.prepare(sql).get(...p);
 const bind=async(key,v=verifier)=>{const m=await native.mint({sourceDeviceId:web.deviceId,challenge:await pkceChallenge(v),redirectUri:NATIVE_REDIRECT});return native.exchange({code:m?.code,verifier:v,redirectUri:NATIVE_REDIRECT,renewalKey:key.pub});};
 const renew=async(k,e,over={})=>{const ch=over.ch??await native.challenge({deviceId:e.deviceId,purpose:'renew'});const body={deviceId:e.deviceId,nonce:ch.nonce,expiresAt:ch.expiresAt,...over};body.signature=over.signature??await sign(over.key??k,{purpose:'renew',deviceId:body.deviceId,nonce:body.nonce,expiresAt:body.expiresAt});return native.renew(body);};
 return{db,q,sessions,web,native,clock,bind,renew,proof,setNow:v=>now=v};
}
test('exchange creates one android device with its key and a short access handle; web authority is separate',async()=>{
 const f=await fixture(),k=await newKey(),e=await f.bind(k);
 assert.deepEqual(Object.keys(e).sort(),['access','accessExpiresAt','deviceId','idleExpiresAt']);
 const a=await f.sessions.authenticate(e.access);assert.equal(a.clientKind,'android');assert.equal(a.deviceId,e.deviceId);assert.equal(a.generation,f.web.generation??a.generation);
 assert.equal(f.q('SELECT public_key p FROM native_keys WHERE device_id=?',e.deviceId).p,k.pub);
 assert.equal(f.q("SELECT count(*) n FROM device_refresh_handles WHERE device_id=?",e.deviceId).n,0,'no refresh secret');
 assert.equal(f.q('SELECT count(*) n FROM device_sessions').n,2);f.db.sqlite.close();});
test('mint requires an active WEB device; android/unknown/revoked sources and wrong redirect are refused',async()=>{
 const f=await fixture(),ch=await pkceChallenge(verifier),k=await newKey(),e=await f.bind(k);
 assert.equal(await f.native.mint({sourceDeviceId:e.deviceId,challenge:ch,redirectUri:NATIVE_REDIRECT}),undefined);
 assert.equal(await f.native.mint({sourceDeviceId:'nope',challenge:ch,redirectUri:NATIVE_REDIRECT}),undefined);
 assert.equal(await f.native.mint({sourceDeviceId:f.web.deviceId,challenge:ch,redirectUri:'https://otpanda.github.io/app/'}),undefined);
 assert.equal(await f.native.mint({sourceDeviceId:f.web.deviceId,challenge:'short',redirectUri:NATIVE_REDIRECT}),undefined);
 await f.sessions.revoke({ownerId:f.proof.ownerId,deviceId:f.web.deviceId});
 assert.equal(await f.native.mint({sourceDeviceId:f.web.deviceId,challenge:ch,redirectUri:NATIVE_REDIRECT}),undefined);f.db.sqlite.close();});
test('exchange: bad key refused before the code is spent; wrong verifier/redirect do not consume; one use; expiry; generation change denies',async()=>{
 const f=await fixture(),k=await newKey(),ch=await pkceChallenge(verifier),m=await f.native.mint({sourceDeviceId:f.web.deviceId,challenge:ch,redirectUri:NATIVE_REDIRECT});
 for(const bad of ['x'.repeat(87),k.pub.slice(1),undefined,42])assert.equal(await f.native.exchange({code:m.code,verifier,redirectUri:NATIVE_REDIRECT,renewalKey:bad}),undefined);
 assert.equal(await f.native.exchange({code:m.code,verifier:'m'.repeat(43),redirectUri:NATIVE_REDIRECT,renewalKey:k.pub}),undefined);
 assert.equal(await f.native.exchange({code:m.code,verifier,redirectUri:'https://otpanda.github.io/app/',renewalKey:k.pub}),undefined);
 assert.ok(await f.native.exchange({code:m.code,verifier,redirectUri:NATIVE_REDIRECT,renewalKey:k.pub}),'still redeemable');
 assert.equal(await f.native.exchange({code:m.code,verifier,redirectUri:NATIVE_REDIRECT,renewalKey:k.pub}),undefined,'one use');
 const m2=await f.native.mint({sourceDeviceId:f.web.deviceId,challenge:ch,redirectUri:NATIVE_REDIRECT});f.setNow(NOW+61000);
 assert.equal(await f.native.exchange({code:m2.code,verifier,redirectUri:NATIVE_REDIRECT,renewalKey:k.pub}),undefined,'expired');
 f.setNow(NOW);const m3=await f.native.mint({sourceDeviceId:f.web.deviceId,challenge:ch,redirectUri:NATIVE_REDIRECT});
 f.db.sqlite.prepare('UPDATE account_security SET generation=generation+1').run();
 assert.equal(await f.native.exchange({code:m3.code,verifier,redirectUri:NATIVE_REDIRECT,renewalKey:k.pub}),undefined,'stale generation');
 assert.equal(f.q('SELECT count(*) n FROM device_sessions WHERE client_kind=?','android').n,1,'only the first exchange created a device');f.db.sqlite.close();});
test('exchange is refused when the issuing credential was revoked after mint',async()=>{
 const f=await fixture(),k=await newKey(),m=await f.native.mint({sourceDeviceId:f.web.deviceId,challenge:await pkceChallenge(verifier),redirectUri:NATIVE_REDIRECT});
 f.db.sqlite.prepare('UPDATE passkey_credentials SET revoked_at=?').run(NOW);
 assert.equal(await f.native.exchange({code:m.code,verifier,redirectUri:NATIVE_REDIRECT,renewalKey:k.pub}),undefined);f.db.sqlite.close();});
test('killed-app renewal: signed one-use nonce, new access, idle extended, nothing else minted',async()=>{
 const f=await fixture(),k=await newKey(),e=await f.bind(k);
 f.setNow(NOW+3*3600000);// access long expired, app was dead
 assert.equal(await f.sessions.authenticate(e.access),undefined);
 const r=await f.renew(k,e);assert.equal(r.status,'renewed');assert.equal(r.accessExpiresAt,NOW+3*3600000+900000);
 assert.equal((await f.sessions.authenticate(r.access)).deviceId,e.deviceId);
 assert.equal(f.q('SELECT expires_at e FROM device_sessions WHERE device_id=?',e.deviceId).e,NOW+3*3600000+30*86400000);
 assert.equal(f.q('SELECT count(*) n FROM device_refresh_handles').n,1,'only the web refresh handle exists');f.db.sqlite.close();});
test('bad signatures, wrong key, other device/purpose/nonce/expiry, unknown device spend nothing; nonce still usable',async()=>{
 const f=await fixture(),k=await newKey(),wrong=await newKey(),e=await f.bind(k),e2=await f.bind(await newKey(),'o'.repeat(43));
 const ch=await f.native.challenge({deviceId:e.deviceId,purpose:'renew'}),snap=()=>JSON.stringify([f.db.sqlite.prepare('SELECT challenge_id,used_at FROM native_challenges ORDER BY challenge_id').all(),f.db.sqlite.prepare('SELECT handle_id FROM device_access_handles ORDER BY handle_id').all(),f.db.sqlite.prepare('SELECT device_id,revoked_at,expires_at FROM device_sessions ORDER BY device_id').all()]);const s0=snap();
 const base={deviceId:e.deviceId,nonce:ch.nonce,expiresAt:ch.expiresAt};
 const sigs={wrongKey:await sign(wrong,{purpose:'renew',...base}),logoutPurpose:await sign(k,{purpose:'logout',...base}),otherDevice:await sign(k,{purpose:'renew',...base,deviceId:e2.deviceId}),otherExpiry:await sign(k,{purpose:'renew',...base,expiresAt:base.expiresAt+1}),garbage:'A'.repeat(86),short:'A'.repeat(5)};
 for(const [n,sig] of Object.entries(sigs))assert.equal((await f.native.renew({...base,signature:sig})).status,'denied',n);
 assert.equal((await f.native.renew({...base,expiresAt:base.expiresAt+1,signature:await sign(k,{purpose:'renew',...base,expiresAt:base.expiresAt+1})})).status,'denied','expiry not matching stored row');
 assert.equal((await f.native.renew({...base,deviceId:e2.deviceId,signature:await sign(await newKey(),{purpose:'renew',...base,deviceId:e2.deviceId})})).status,'denied','nonce of another device');
 assert.equal((await f.native.renew({deviceId:'AAAAAAAAAAAA',nonce:ch.nonce,expiresAt:ch.expiresAt,signature:'A'.repeat(86)})).status,'denied');
 assert.equal(snap(),s0,'no state changed by any denial');
 assert.equal((await f.native.renew({...base,signature:await sign(k,{purpose:'renew',...base})})).status,'renewed');f.db.sqlite.close();});
test('replay, concurrency and expiry: exactly one winner; nonce expires; other devices unaffected; no revocation',async()=>{
 const f=await fixture(),k=await newKey(),e=await f.bind(k),ch=await f.native.challenge({deviceId:e.deviceId,purpose:'renew'}),req={deviceId:e.deviceId,nonce:ch.nonce,expiresAt:ch.expiresAt,signature:await sign(k,{purpose:'renew',deviceId:e.deviceId,nonce:ch.nonce,expiresAt:ch.expiresAt})};
 const rs=await Promise.all([f.native.renew(req),f.native.renew(req),f.native.renew(req)]);assert.equal(rs.filter(r=>r.status==='renewed').length,1);
 assert.equal((await f.native.renew(req)).status,'denied');assert.equal(f.q('SELECT revoked_at r FROM device_sessions WHERE device_id=?',e.deviceId).r,null);
 const ch2=await f.native.challenge({deviceId:e.deviceId,purpose:'renew'});f.setNow(ch2.expiresAt);
 assert.equal((await f.native.renew({deviceId:e.deviceId,nonce:ch2.nonce,expiresAt:ch2.expiresAt,signature:await sign(k,{purpose:'renew',deviceId:e.deviceId,nonce:ch2.nonce,expiresAt:ch2.expiresAt})})).status,'denied','expired nonce');f.db.sqlite.close();});
test('challenge is oracle-free, capped per device, and stores nothing for unknown/revoked/web devices',async()=>{
 const f=await fixture(),k=await newKey(),e=await f.bind(k);
 const shape=c=>Object.keys(c).sort().join(),known=await f.native.challenge({deviceId:e.deviceId,purpose:'renew'}),unknown=await f.native.challenge({deviceId:'AAAAAAAAAAAA',purpose:'renew'}),web=await f.native.challenge({deviceId:f.web.deviceId,purpose:'renew'}),junk=await f.native.challenge({deviceId:{},purpose:'x'});
 assert.equal(shape(known),shape(unknown));assert.equal(shape(known),shape(web));assert.equal(shape(known),shape(junk));
 assert.equal(f.q('SELECT count(*) n FROM native_challenges').n,1);
 for(let i=0;i<12;i++)await f.native.challenge({deviceId:e.deviceId,purpose:'renew'});assert.equal(f.q('SELECT count(*) n FROM native_challenges WHERE device_id=?',e.deviceId).n,8);
 // a web device cannot be renewed via the native path even with a bound-looking key
 f.db.sqlite.prepare('INSERT INTO native_keys(device_id,public_key,created_at) VALUES (?,?,?)').run(f.web.deviceId,k.pub,NOW);
 const wc=await f.native.challenge({deviceId:f.web.deviceId,purpose:'renew'});assert.equal((await f.native.renew({deviceId:f.web.deviceId,nonce:wc.nonce,expiresAt:wc.expiresAt,signature:await sign(k,{purpose:'renew',deviceId:f.web.deviceId,nonce:wc.nonce,expiresAt:wc.expiresAt})})).status,'denied');f.db.sqlite.close();});
test('revocation, generation reset and credential revoke end renewal and access immediately',async()=>{
 for(const kill of [db=>db.prepare('UPDATE device_sessions SET revoked_at=? WHERE client_kind=?').run(NOW,'android'),db=>db.prepare('UPDATE account_security SET generation=generation+1').run(),db=>db.prepare('UPDATE passkey_credentials SET revoked_at=?').run(NOW)]){
  const f=await fixture(),k=await newKey(),e=await f.bind(k),ch=await f.native.challenge({deviceId:e.deviceId,purpose:'renew'});kill(f.db.sqlite);
  assert.equal(await f.sessions.authenticate(e.access),undefined);
  assert.equal((await f.native.renew({deviceId:e.deviceId,nonce:ch.nonce,expiresAt:ch.expiresAt,signature:await sign(k,{purpose:'renew',deviceId:e.deviceId,nonce:ch.nonce,expiresAt:ch.expiresAt})})).status,'denied');f.db.sqlite.close();}});
test('signed logout revokes only that device, once; renew nonce cannot log out; access logout is device-scoped',async()=>{
 const f=await fixture(),k=await newKey(),e=await f.bind(k),e2=await f.bind(await newKey(),'p'.repeat(43));
 const r=await f.native.challenge({deviceId:e.deviceId,purpose:'renew'});
 assert.equal(await f.native.logout({deviceId:e.deviceId,nonce:r.nonce,expiresAt:r.expiresAt,signature:await sign(k,{purpose:'logout',deviceId:e.deviceId,nonce:r.nonce,expiresAt:r.expiresAt})}),false);
 const l=await f.native.challenge({deviceId:e.deviceId,purpose:'logout'}),body={deviceId:e.deviceId,nonce:l.nonce,expiresAt:l.expiresAt};
 assert.equal(await f.native.logout({...body,signature:'A'.repeat(86)}),false);assert.equal(f.q('SELECT revoked_at r FROM device_sessions WHERE device_id=?',e.deviceId).r,null);
 const sig=await sign(k,{purpose:'logout',...body});assert.equal(await f.native.logout({...body,signature:sig}),true);assert.equal(await f.native.logout({...body,signature:sig}),false);
 assert.equal(await f.sessions.authenticate(e.access),undefined);assert.ok(await f.sessions.authenticate(e2.access),'other native device untouched');
 assert.equal(await f.native.logoutAccess({deviceId:f.web.deviceId}),false,'web device cannot be revoked via native path');assert.equal(await f.native.logoutAccess({deviceId:e2.deviceId}),true);f.db.sqlite.close();});
test('cleanup is bounded and removes only expired rows',async()=>{
 const f=await fixture(),k=await newKey(),e=await f.bind(k);await f.native.challenge({deviceId:e.deviceId,purpose:'renew'});
 await assert.rejects(()=>f.native.cleanup({limit:0}));assert.deepEqual(await f.native.cleanup({limit:10}),[0,0]);f.setNow(NOW+120000);assert.deepEqual(await f.native.cleanup({limit:10}),[0,1]);f.db.sqlite.close();});
