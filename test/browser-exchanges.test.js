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
const redirectUri='https://otpanda.github.io/app/',verifier='a'.repeat(43);
async function fixture(){const f=await setup();const d=await f.service.issue({proof:f.proof,clientKind:'web'});let now=NOW;const exchange=new BrowserExchangeService(f.db,{redirectUri,clock:()=>now});return {...f,d,exchange,setTime:v=>{now=v;f.setNow(v);}};}
test('browser exchange is PKCE-bound single-use and stores no raw code/access',async()=>{
 const {db,d,service,exchange}=await fixture(),challenge=await pkceChallenge(verifier);const issued=await exchange.mint({deviceId:d.deviceId,challenge,redirectUri});assert.ok(issued);assert.ok(!JSON.stringify(db.sqlite.prepare('SELECT * FROM browser_exchanges').all()).includes(issued.code));const result=await exchange.exchange({code:issued.code,verifier,redirectUri});assert.ok(result);assert.ok(await service.authenticate(result.access));assert.equal(await exchange.exchange({code:issued.code,verifier,redirectUri}),undefined);db.sqlite.close();
});
test('wrong verifier redirect and secret do not consume a valid browser code',async()=>{
 const {db,d,exchange}=await fixture(),challenge=await pkceChallenge(verifier),issued=await exchange.mint({deviceId:d.deviceId,challenge,redirectUri});assert.equal(await exchange.exchange({code:issued.code,verifier:'b'.repeat(43),redirectUri}),undefined);assert.equal(await exchange.exchange({code:issued.code,verifier,redirectUri:redirectUri+'?next=evil'}),undefined);assert.equal(await exchange.exchange({code:issued.code+'x',verifier,redirectUri}),undefined);assert.ok(await exchange.exchange({code:issued.code,verifier,redirectUri}));db.sqlite.close();
});
test('browser code expiry future time and concurrent exchange deny replay',async()=>{
 const f=await fixture(),challenge=await pkceChallenge(verifier),x=await f.exchange.mint({deviceId:f.d.deviceId,challenge,redirectUri});const results=await Promise.all([f.exchange.exchange({code:x.code,verifier,redirectUri}),f.exchange.exchange({code:x.code,verifier,redirectUri})]);assert.equal(results.filter(Boolean).length,1);const y=await f.exchange.mint({deviceId:f.d.deviceId,challenge,redirectUri});f.setTime(NOW+60000);assert.equal(await f.exchange.exchange({code:y.code,verifier,redirectUri}),undefined);assert.equal(await f.exchange.cleanup(),1);await assert.rejects(f.exchange.cleanup({limit:501}));f.db.sqlite.close();
});
test('revocation and generation race wins after code creation and before access issue',async()=>{
 for(const kind of ['device','generation','credential']){const f=await fixture(),challenge=await pkceChallenge(verifier),x=await f.exchange.mint({deviceId:f.d.deviceId,challenge,redirectUri});if(kind==='device')await f.service.revoke({ownerId:f.proof.ownerId,deviceId:f.d.deviceId});if(kind==='generation')f.db.sqlite.exec('UPDATE account_security SET generation=generation+1');if(kind==='credential')f.db.sqlite.prepare('UPDATE passkey_credentials SET revoked_at=?').run(NOW);assert.equal(await f.exchange.exchange({code:x.code,verifier,redirectUri}),undefined);assert.equal(await f.exchange.mint({deviceId:f.d.deviceId,challenge,redirectUri}),undefined);f.db.sqlite.close();}
});
test('malformed PKCE and nonweb sessions cannot mint browser restore grants',async()=>{
 const f=await fixture();assert.equal(await pkceChallenge('short'),undefined);assert.equal(await pkceChallenge('a'.repeat(129)),undefined);assert.equal(await f.exchange.mint({deviceId:f.d.deviceId,challenge:'a',redirectUri}),undefined);const android=await f.service.issue({proof:f.proof,clientKind:'android'});assert.equal(await f.exchange.mint({deviceId:android.deviceId,challenge:await pkceChallenge(verifier),redirectUri}),undefined);assert.throws(()=>new BrowserExchangeService(f.db,{redirectUri:'https://evil.test/'}));f.db.sqlite.close();
});
test('code expiration is rechecked after claim and asynchronous handle generation',async()=>{
 const f=await fixture(),challenge=await pkceChallenge(verifier),x=await f.exchange.mint({deviceId:f.d.deviceId,challenge,redirectUri});let calls=0;const service=new BrowserExchangeService(f.db,{redirectUri,clock:()=>++calls===1?NOW+59999:NOW+60000});assert.equal(await service.exchange({code:x.code,verifier,redirectUri}),undefined);assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM device_access_handles').get().n,1);f.db.sqlite.close();
});

test('outstanding exchange ceiling is atomic and per-device; expiry frees capacity',async()=>{
 const f=await fixture();try {
 const challenge=await pkceChallenge(verifier),issued=await Promise.all(Array.from({length:36},()=>f.exchange.mint({deviceId:f.d.deviceId,challenge,redirectUri})));
 assert.equal(issued.filter(Boolean).length,32);assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM browser_exchanges').get().n,32);
 const second=await f.service.issue({proof:f.proof,clientKind:'web'});assert.ok(await f.exchange.mint({deviceId:second.deviceId,challenge,redirectUri}));
 f.setTime(NOW+60000);assert.ok(await f.exchange.mint({deviceId:f.d.deviceId,challenge,redirectUri}));
 }finally{f.db.sqlite.close();}
});
test('access ceiling applies to browser exchange and cannot leak a new token',async()=>{
 const f=await fixture();try {
 const challenge=await pkceChallenge(verifier);let refresh=f.d.refresh;
 for(let i=0;i<63;i++){const r=await f.service.rotate(refresh);assert.equal(r.status,'rotated');refresh=r.refresh;}
 const x=await f.exchange.mint({deviceId:f.d.deviceId,challenge,redirectUri});assert.equal(await f.exchange.exchange({code:x.code,verifier,redirectUri}),undefined);
 assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM device_access_handles').get().n,64);assert.equal(await f.exchange.exchange({code:x.code,verifier,redirectUri}),undefined);
 f.setTime(NOW+900001);const y=await f.exchange.mint({deviceId:f.d.deviceId,challenge,redirectUri});const z=await f.exchange.exchange({code:y.code,verifier,redirectUri});assert.ok(z);assert.equal(z.accessExpiresAt,NOW+900001+300000,'browser exchange defaults to the 5 minute web access life');
 }finally{f.db.sqlite.close();}
});
