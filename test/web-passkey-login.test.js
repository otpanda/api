import test from 'node:test';
import assert from 'node:assert/strict';
import {database} from './sqlite-helper.js';
import {AccountIdentityService} from '../src/account-identity.js';
import {PasskeySignupService} from '../src/passkey-signup.js';
import {PasskeyService} from '../src/passkey-service.js';
import {DeviceSessionService} from '../src/device-sessions.js';
import {BrowserExchangeService,pkceChallenge} from '../src/browser-exchanges.js';
import {WebPasskeyLoginService} from '../src/web-passkey-login.js';
import {authenticator} from './passkey-fixture.js';
const NOW=1_800_000_000_000,REDIRECT='https://otpanda.github.io/app/',VERIFIER='a'.repeat(43);
async function setup(){
 const db=database();let now=NOW;const clock=()=>now,identity=new AccountIdentityService(db,{clock}),signup=new PasskeySignupService(db,{clock}),a=authenticator();
 const email='a@example.com',{token}=await identity.issueEmailChallenge({purpose:'signup-email',email});
 const c=await signup.begin({email,emailToken:token,binding:'signup'}),account=await signup.finish({token:c.token,binding:'signup',response:a.registration({expected:c.options.challenge})});
 const passkeys=new PasskeyService(db,{clock}),sessions=new DeviceSessionService(db,{clock}),exchanges=new BrowserExchangeService(db,{clock,redirectUri:REDIRECT}),login=new WebPasskeyLoginService({passkeys,sessions,exchanges});
 const context={binding:'server-browser-binding',challenge:await pkceChallenge(VERIFIER),redirectUri:REDIRECT};
 function assertion(c){const response=a.assertion({expected:c.options.challenge});response.response.userHandle=Buffer.from(account.ownerId).toString('base64url');return response;}
 return {db,login,sessions,exchanges,passkeys,context,assertion,account,setNow:v=>now=v};
}
test('real passkey assertion issues web-only refresh and PKCE exchange without leaking access',async()=>{
 const x=await setup(),c=await x.login.begin(x.context),args={...x.context,token:c.token,response:x.assertion(c)},result=await x.login.finish(args);assert.ok(result);assert.equal(result.access,undefined);assert.equal(result.ownerId,undefined);
 assert.equal(await x.exchanges.exchange({code:result.code,verifier:'b'.repeat(43),redirectUri:REDIRECT}),undefined);
 const access=await x.exchanges.exchange({code:result.code,verifier:VERIFIER,redirectUri:REDIRECT});assert.equal((await x.sessions.authenticate(access.access)).ownerId,x.account.ownerId);
 assert.equal(await x.login.finish(args),undefined);assert.equal((await x.sessions.rotate(result.refresh,{clientKind:'android'})).status,'denied');assert.equal((await x.sessions.rotate(result.refresh,{clientKind:'web'})).status,'rotated');x.db.sqlite.close();
});
test('ceremony binds browser, PKCE challenge and exact redirect, never client proof',async()=>{
 const x=await setup(),c=await x.login.begin(x.context),args={...x.context,token:c.token,response:x.assertion(c)};
 for(const patch of [{binding:'another'},{challenge:'b'.repeat(43)},{redirectUri:'https://evil.example/'}])assert.equal(await x.login.finish({...args,...patch}),undefined);
 assert.ok(await x.login.finish(args));assert.equal(await x.login.finish({...x.context,proof:{...x.account,purpose:'authenticate',verifiedAt:NOW}}),undefined);x.db.sqlite.close();
});
test('invalid contexts and bad assertions create no device',async()=>{
 const x=await setup();for(const patch of [{binding:''},{binding:'x'.repeat(513)},{challenge:'bad'},{redirectUri:REDIRECT+'other'}])assert.equal(await x.login.begin({...x.context,...patch}),undefined);
 const c=await x.login.begin(x.context);assert.equal(await x.login.finish({...x.context,token:c.token,response:{}}),undefined);assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM device_sessions').get().n,0);x.db.sqlite.close();
});
test('expired ceremony and revoked credential never issue a session',async()=>{
 for(const change of ['expiry','revoke']){const x=await setup(),c=await x.login.begin(x.context),response=x.assertion(c);if(change==='expiry')x.setNow(NOW+120000);else x.db.sqlite.prepare('UPDATE passkey_credentials SET revoked_at=?').run(NOW);assert.equal(await x.login.finish({...x.context,token:c.token,response}),undefined);assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM device_sessions').get().n,0);x.db.sqlite.close();}
});
test('exchange failure revokes provisional device and its handles',async()=>{
 for(const throwing of [false,true]){const x=await setup(),c=await x.login.begin(x.context);x.exchanges.mint=async()=>{if(throwing)throw Error('storage unavailable');return undefined;};const finish=()=>x.login.finish({...x.context,token:c.token,response:x.assertion(c)});if(throwing)await assert.rejects(finish,/storage unavailable/);else assert.equal(await finish(),undefined);assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM device_sessions WHERE revoked_at IS NULL').get().n,0);x.db.sqlite.close();}
});
test('security reset during mint revokes candidate and code cannot redeem',async()=>{
 const x=await setup(),c=await x.login.begin(x.context),mint=x.exchanges.mint.bind(x.exchanges);let code;x.exchanges.mint=async args=>{const result=await mint(args);code=result.code;x.db.sqlite.prepare('UPDATE account_security SET generation=generation+1').run();return result;};assert.equal(await x.login.finish({...x.context,token:c.token,response:x.assertion(c)}),undefined);assert.equal(await x.exchanges.exchange({code,verifier:VERIFIER,redirectUri:REDIRECT}),undefined);assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM device_sessions WHERE revoked_at IS NULL').get().n,0);x.db.sqlite.close();
});
