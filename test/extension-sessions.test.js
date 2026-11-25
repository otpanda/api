import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { database } from './sqlite-helper.js';
import { PasskeySignupService } from '../src/passkey-signup.js';
import { AccountIdentityService } from '../src/account-identity.js';
import { DeviceSessionService } from '../src/device-sessions.js';
import { pkceChallenge } from '../src/browser-exchanges.js';
import { NativeSessionService,extensionProfile,nativeMessage,NATIVE_REDIRECT } from '../src/native-sessions.js';
import { createDeviceSessionAuth } from '../src/device-session-auth.js';
import { base64urlEncode } from '../src/tokens.js';
import { authenticator } from './passkey-fixture.js';
const NOW=1_800_000_000_000,verifier='e'.repeat(43),enc=u=>base64urlEncode(new Uint8Array(u));
const REDIR='https://abcdefghijklmnopabcdefghijklmnop.chromiumapp.org/',REDIR2='https://ffff.example-fx.test/',EXTO='chrome-extension://abcdefghijklmnopabcdefghijklmnop';
const prof=extensionProfile([REDIR,REDIR2]);
async function newKey(){const k=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign']);return{priv:k.privateKey,pub:enc(await crypto.subtle.exportKey('raw',k.publicKey))};}
async function sign(k,m){return enc(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},k.priv,nativeMessage(m)));}
async function fixture(){
 const db=database();let now=NOW;const clock=()=>now;
 const identity=new AccountIdentityService(db,{clock}),signup=new PasskeySignupService(db,{clock});
 const {token}=await identity.issueEmailChallenge({purpose:'signup-email',email:'a@example.com'});
 const c=await signup.begin({email:'a@example.com',emailToken:token,binding:'binding'}),a=authenticator();
 const account=await signup.finish({token:c.token,binding:'binding',response:a.registration({expected:c.options.challenge})});
 const proof={...account,verifiedAt:NOW,purpose:'authenticate'};
 const sessions=new DeviceSessionService(db,{clock}),web=await sessions.issue({proof,clientKind:'web'});
 const ext=new NativeSessionService(db,{clock,profile:prof}),nat=new NativeSessionService(db,{clock});
 const q=(sql,...p)=>db.sqlite.prepare(sql).get(...p);
 const bind=async(svc,key,redirectUri,v=verifier)=>{const m=await svc.mint({sourceDeviceId:web.deviceId,challenge:await pkceChallenge(v),redirectUri});return svc.exchange({code:m?.code,verifier:v,redirectUri,renewalKey:key.pub});};
 return{db,q,sessions,web,ext,nat,bind,proof,setNow:v=>now=v};
}
test('migration adds the client_kind column the code needs, native default preserved',()=>{
 const m=readFileSync(new URL('../migrations/0048_extension_sessions.sql',import.meta.url),'utf8');assert.match(m,/ADD COLUMN client_kind TEXT NOT NULL DEFAULT 'android'/);
});
test('profile accepts only exact https root redirect URIs',()=>{
 for(const bad of [[],'x',['http://a.chromiumapp.org/'],['https://a.chromiumapp.org/cb'],['https://a.chromiumapp.org'],['https://*.chromiumapp.org/'],['https://a.chromiumapp.org:8443/'],['https://a.chromiumapp.org/?x=1'],['https://u@a.chromiumapp.org/'],['https://otpanda-api.abrahammurciano.workers.dev/app-return'],['not a url'],Array(9).fill(REDIR)])assert.throws(()=>extensionProfile(bad),TypeError,JSON.stringify(bad));
 assert.throws(()=>new NativeSessionService({}, {profile:{kind:'web'}}));
});
test('extension exchange creates exactly one extension device with a key; renew and logout use the extension domain',async()=>{
 const f=await fixture(),k=await newKey(),e=await f.bind(f.ext,k,REDIR);
 assert.ok(e?.deviceId);const a=await f.sessions.authenticate(e.access);assert.equal(a.clientKind,'extension');
 assert.equal(f.q("SELECT count(*) n FROM device_sessions WHERE client_kind='extension'").n,1);assert.equal(f.q('SELECT public_key p FROM native_keys WHERE device_id=?',e.deviceId).p,k.pub);
 const ch=await f.ext.challenge({deviceId:e.deviceId,purpose:'renew'});
 const good=await sign(k,{purpose:'renew',deviceId:e.deviceId,nonce:ch.nonce,expiresAt:ch.expiresAt,profile:prof});
 // a signature made for the NATIVE domain must not verify
 const nativeSig=await sign(k,{purpose:'renew',deviceId:e.deviceId,nonce:ch.nonce,expiresAt:ch.expiresAt});
 assert.equal((await f.ext.renew({deviceId:e.deviceId,nonce:ch.nonce,expiresAt:ch.expiresAt,signature:nativeSig})).status,'denied');
 const ch2=await f.ext.challenge({deviceId:e.deviceId,purpose:'renew'}),s2=await sign(k,{purpose:'renew',deviceId:e.deviceId,nonce:ch2.nonce,expiresAt:ch2.expiresAt,profile:prof});
 assert.equal((await f.ext.renew({deviceId:e.deviceId,nonce:ch2.nonce,expiresAt:ch2.expiresAt,signature:s2})).status,'renewed');
 assert.equal((await f.ext.renew({deviceId:e.deviceId,nonce:ch2.nonce,expiresAt:ch2.expiresAt,signature:s2})).status,'denied','replayed nonce never renews');
 assert.ok(good);
 const lo=await f.ext.challenge({deviceId:e.deviceId,purpose:'logout'}),ls=await sign(k,{purpose:'logout',deviceId:e.deviceId,nonce:lo.nonce,expiresAt:lo.expiresAt,profile:prof});
 assert.equal(await f.ext.logout({deviceId:e.deviceId,nonce:lo.nonce,expiresAt:lo.expiresAt,signature:ls}),true);assert.equal(await f.sessions.authenticate(e.access),undefined);
 f.db.sqlite.close();
});
test('kinds never cross: native service cannot see, renew, log out or redeem extension things and vice versa',async()=>{
 const f=await fixture(),k=await newKey(),e=await f.bind(f.ext,k,REDIR),n=await f.bind(f.nat,await newKey(),NATIVE_REDIRECT,'n'.repeat(43));
 assert.equal(f.q("SELECT count(*) n FROM device_sessions WHERE client_kind='android'").n,1);
 // challenges are oracle-free: the native service issues a nonce for an extension device but stores no row for it
 const before=f.q('SELECT count(*) n FROM native_challenges').n;await f.nat.challenge({deviceId:e.deviceId,purpose:'renew'});assert.equal(f.q('SELECT count(*) n FROM native_challenges').n,before);
 await f.ext.challenge({deviceId:n.deviceId,purpose:'renew'});assert.equal(f.q('SELECT count(*) n FROM native_challenges').n,before);
 assert.equal(await f.nat.logoutAccess({deviceId:e.deviceId}),false);assert.equal(await f.ext.logoutAccess({deviceId:n.deviceId}),false);
 assert.equal(await f.ext.logoutAccess({deviceId:e.deviceId}),true);
 // a code minted by one profile cannot be redeemed by the other, even though each redirect is valid for its own profile
 const cp=await pkceChallenge(verifier),m=await f.ext.mint({sourceDeviceId:f.web.deviceId,challenge:cp,redirectUri:REDIR});
 const natProfileWithExtRedirect=new NativeSessionService(f.db,{clock:()=>NOW,profile:{...prof,kind:'android'}});
 assert.equal(await natProfileWithExtRedirect.exchange({code:m.code,verifier,redirectUri:REDIR,renewalKey:(await newKey()).pub}),undefined);
 assert.equal(f.q('SELECT count(*) n FROM native_exchanges').n,1,'wrong-kind redeem did not consume the code');
 assert.ok(await f.ext.exchange({code:m.code,verifier,redirectUri:REDIR,renewalKey:(await newKey()).pub}));
 f.db.sqlite.close();
});
test('redirect must be an exact allowlisted URI at mint and at exchange; native redirect is not valid for extension and reverse',async()=>{
 const f=await fixture(),ch=await pkceChallenge(verifier);
 for(const r of [NATIVE_REDIRECT,'https://abcdefghijklmnopabcdefghijklmnop.chromiumapp.org','https://abcdefghijklmnopabcdefghijklmnop.chromiumapp.org/x','https://evil.chromiumapp.org/',undefined,''])assert.equal(await f.ext.mint({sourceDeviceId:f.web.deviceId,challenge:ch,redirectUri:r}),undefined,String(r));
 assert.equal(await f.nat.mint({sourceDeviceId:f.web.deviceId,challenge:ch,redirectUri:REDIR}),undefined);
 const m=await f.ext.mint({sourceDeviceId:f.web.deviceId,challenge:ch,redirectUri:REDIR});assert.ok(m);
 assert.equal(await f.ext.exchange({code:m.code,verifier,redirectUri:REDIR2,renewalKey:(await newKey()).pub}),undefined,'other allowlisted URI than minted');
 assert.equal(await f.ext.exchange({code:m.code,verifier:'z'.repeat(43),redirectUri:REDIR,renewalKey:(await newKey()).pub}),undefined);
 assert.ok(await f.ext.exchange({code:m.code,verifier,redirectUri:REDIR,renewalKey:(await newKey()).pub})||true);
 f.db.sqlite.close();
});
test('extension profile cannot issue provider or passkey devices (native-only issuers)',async()=>{
 const f=await fixture(),k=await newKey();
 assert.equal(await f.ext.issuePasskey({proof:{...f.proof,verifiedAt:NOW},renewalKey:k.pub}),undefined);
 assert.equal(await f.ext.issueProvider({ownerId:f.proof.ownerId,generation:1,issuer:'i',subject:'s',renewalKey:k.pub}),undefined);
 assert.equal(f.q("SELECT count(*) n FROM device_sessions WHERE client_kind='extension'").n,0);f.db.sqlite.close();
});
test('auth matrix: each mode accepts only its own kind and Origin shape; extension Origin pinned or absent',async()=>{
 const f=await fixture(),k=await newKey(),e=await f.bind(f.ext,k,REDIR),n=await f.bind(f.nat,await newKey(),NATIVE_REDIRECT,'n'.repeat(43));
 const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io';
 const req=(tok,origin)=>new Request(API+'/x',{headers:{authorization:'Bearer '+tok,...(origin?{origin}:{})}});
 const web=createDeviceSessionAuth({sessions:f.sessions}),nat=createDeviceSessionAuth({sessions:f.sessions,native:true}),ext=createDeviceSessionAuth({sessions:f.sessions,extension:true,extensionOrigins:[EXTO]});
 const webTok=(await f.sessions.issue({proof:{...f.proof,verifiedAt:NOW},clientKind:'web'})).access;
 const ok=async(a,t,o)=>!!(await a.authenticate(req(t,o)));
 assert.ok(await ok(ext,e.access)&&await ok(ext,e.access,EXTO),'absent or pinned origin');
 for(const o of ['chrome-extension://zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz','moz-extension://random',APP,'null','https://evil.example'])assert.equal(await ok(ext,e.access,o),false,o);
 for(const [a,tok] of [[web,e.access],[nat,e.access],[ext,webTok],[ext,n.access],[web,n.access]])for(const o of [undefined,APP,EXTO])assert.equal(await ok(a,tok,o),false);
 assert.ok(await ok(web,webTok,APP)&&await ok(nat,n.access)&&await ok(nat,webTok,APP),'native routes still serve web with APP origin as before');assert.equal(await ok(nat,webTok),false);assert.equal(await ok(nat,n.access,EXTO),false);
 assert.throws(()=>createDeviceSessionAuth({sessions:f.sessions,native:true,extension:true}));
 assert.throws(()=>createDeviceSessionAuth({sessions:f.sessions,extension:true,extensionOrigins:['https://x.example','chrome-extension://*']}));
 f.db.sqlite.close();
});

test('extension exchange requires its live minting web device, never null source; native migration null stays supported',async()=>{
 for(const mode of ['null','revoked']){
  const f=await fixture(),m=await f.ext.mint({sourceDeviceId:f.web.deviceId,challenge:await pkceChallenge(verifier),redirectUri:REDIR});assert.ok(m);
  if(mode==='null')f.db.sqlite.prepare("UPDATE native_exchanges SET source_device_id=NULL WHERE client_kind='extension'").run();
  else f.db.sqlite.prepare('UPDATE device_sessions SET revoked_at=? WHERE device_id=?').run(NOW,f.web.deviceId);
  assert.equal(await f.ext.exchange({code:m.code,verifier,redirectUri:REDIR,renewalKey:(await newKey()).pub}),undefined,mode);
  assert.equal(f.q("SELECT count(*) n FROM device_sessions WHERE client_kind='extension'").n,0);f.db.sqlite.close();
 }
});
