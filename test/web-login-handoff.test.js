import test from 'node:test';
import assert from 'node:assert/strict';
import {database} from './sqlite-helper.js';
import {AccountIdentityService} from '../src/account-identity.js';
import {PasskeySignupService} from '../src/passkey-signup.js';
import {PasskeyService} from '../src/passkey-service.js';
import {DeviceSessionService} from '../src/device-sessions.js';
import {BrowserExchangeService,pkceChallenge} from '../src/browser-exchanges.js';
import {WebLoginHandoffService} from '../src/web-login-handoff.js';
import {authenticator} from './passkey-fixture.js';
const NOW=1_800_000_000_000,REDIRECT='https://otpanda.github.io/app/',VERIFIER='a'.repeat(43);
async function setup(){
 const db=database();let now=NOW;const clock=()=>now,identity=new AccountIdentityService(db,{clock}),signup=new PasskeySignupService(db,{clock}),a=authenticator();
 const email='a@example.com',{token}=await identity.issueEmailChallenge({purpose:'signup-email',email});
 const c=await signup.begin({email,emailToken:token,binding:'signup'}),account=await signup.finish({token:c.token,binding:'signup',response:a.registration({expected:c.options.challenge})});
 const passkeys=new PasskeyService(db,{clock}),sessions=new DeviceSessionService(db,{clock}),exchanges=new BrowserExchangeService(db,{clock,redirectUri:REDIRECT}),login=new WebLoginHandoffService(db,{passkeys,sessions,exchanges,clock});
 const context={binding:'x'.repeat(43),state:'s'.repeat(43),challenge:await pkceChallenge(VERIFIER),redirectUri:REDIRECT};
 let counter=0;function assertion(c){const response=a.assertion({expected:c.options.challenge,counter:++counter});response.response.userHandle=Buffer.from(account.ownerId).toString('base64url');return response;}
 return {db,login,sessions,exchanges,passkeys,context,assertion,account,setNow:v=>now=v};
}
async function verified(x){const c=await x.login.begin(x.context);return x.login.verify({...x.context,token:c.token,response:x.assertion(c)});}
test('handoff stores verified proof hashes, never session material, cookie-bound completion issues web session',async()=>{
 const x=await setup(),h=await verified(x);assert.ok(h);assert.equal(h.refresh,undefined);assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM device_sessions').get().n,0);const stored=JSON.stringify(x.db.sqlite.prepare('SELECT * FROM web_login_handoffs').all());assert.ok(!stored.includes(h.handoff)&&!stored.includes(x.context.binding));
 assert.equal(await x.login.complete({handoff:h.handoff,binding:'y'.repeat(43)}),undefined);
 const result=await x.login.complete({handoff:h.handoff,binding:x.context.binding});assert.ok(result);assert.equal(result.access,undefined);assert.equal(result.state,x.context.state);assert.equal(result.redirectUri,REDIRECT);
 assert.equal(await x.login.complete({handoff:h.handoff,binding:x.context.binding}),undefined);assert.equal(await x.exchanges.exchange({code:result.code,verifier:'b'.repeat(43),redirectUri:REDIRECT}),undefined);const access=await x.exchanges.exchange({code:result.code,verifier:VERIFIER,redirectUri:REDIRECT});assert.equal((await x.sessions.authenticate(access.access)).ownerId,x.account.ownerId);x.db.sqlite.close();
});
test('ceremony binds cookie, tab state, challenge and exact callback',async()=>{
 const x=await setup(),c=await x.login.begin(x.context),args={...x.context,token:c.token,response:x.assertion(c)};for(const patch of [{binding:'z'.repeat(43)},{state:'z'.repeat(43)},{challenge:'z'.repeat(43)},{redirectUri:'https://evil.example/'}])assert.equal(await x.login.verify({...args,...patch}),undefined);assert.ok(await x.login.verify(args));assert.equal(await x.login.verify(args),undefined);x.db.sqlite.close();
});
test('expired/future handoff, generation reset and credential revoke deny without issuing',async()=>{
 for(const change of ['expire','future','generation','revoke']){const x=await setup(),h=await verified(x);if(change==='expire')x.setNow(NOW+60000);if(change==='future')x.setNow(NOW-1);if(change==='generation')x.db.sqlite.prepare('UPDATE account_security SET generation=generation+1').run();if(change==='revoke')x.db.sqlite.prepare('UPDATE passkey_credentials SET revoked_at=?').run(NOW);assert.equal(await x.login.complete({handoff:h.handoff,binding:x.context.binding}),undefined);assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM device_sessions').get().n,0);x.db.sqlite.close();}
});
test('only one concurrent completion can create a session',async()=>{
 const x=await setup(),h=await verified(x),results=await Promise.all([1,2].map(()=>x.login.complete({handoff:h.handoff,binding:x.context.binding})));assert.equal(results.filter(Boolean).length,1);assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM device_sessions').get().n,1);x.db.sqlite.close();
});
test('failed mint or security reset during mint revokes provisional device',async()=>{
 for(const change of ['empty','throw','generation','expire']){const x=await setup(),h=await verified(x),mint=x.exchanges.mint.bind(x.exchanges);x.exchanges.mint=async args=>{if(change==='empty')return undefined;if(change==='throw')throw Error('storage failed');const r=await mint(args);if(change==='generation')x.db.sqlite.prepare('UPDATE account_security SET generation=generation+1').run();if(change==='expire')x.setNow(NOW+60000);return r;};const finish=()=>x.login.complete({handoff:h.handoff,binding:x.context.binding});if(change==='throw')await assert.rejects(finish,/storage failed/);else assert.equal(await finish(),undefined);assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM device_sessions WHERE revoked_at IS NULL').get().n,0);x.db.sqlite.close();}
});
test('malformed context is denied and expiry cleanup is bounded',async()=>{
 const x=await setup();for(const patch of [{binding:''},{challenge:'bad'},{state:'bad'},{redirectUri:REDIRECT+'bad'}])assert.equal(await x.login.begin({...x.context,...patch}),undefined);for(let i=0;i<2;i++)assert.ok(await verified(x));x.setNow(NOW+60000);assert.equal(await x.login.cleanup({limit:1}),1);assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM web_login_handoffs').get().n,1);await assert.rejects(x.login.cleanup({limit:0}));x.db.sqlite.close();
});
test('server-held browser context needs no readable cookie or context claims at verification',async()=>{
 const x=await setup(),cookieBinding='c'.repeat(43),c=await x.login.beginBrowser({...x.context,cookieBinding});assert.ok(c);const h=await x.login.verifyBrowser({token:c.token,response:x.assertion(c),binding:'attacker',state:'attacker'});assert.ok(h);assert.equal(await x.login.verifyBrowser({token:c.token,response:x.assertion(c)}),undefined);assert.equal(await x.login.completeBrowser({handoff:h.handoff,cookieBinding:'d'.repeat(43)}),undefined);assert.ok(await x.login.completeBrowser({handoff:h.handoff,cookieBinding}));x.db.sqlite.close();
});
test('another browser cannot complete stolen ceremony response under its cookie',async()=>{
 const x=await setup(),cookieBinding='c'.repeat(43),c=await x.login.beginBrowser({...x.context,cookieBinding}),h=await x.login.verifyBrowser({token:c.token,response:x.assertion(c)});assert.equal(await x.login.completeBrowser({handoff:h.handoff,cookieBinding:'d'.repeat(43)}),undefined);assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM device_sessions').get().n,0);assert.ok(await x.login.completeBrowser({handoff:h.handoff,cookieBinding}));x.db.sqlite.close();
});
test('logout tombstone wins before or during cookie-bound completion',async()=>{
 for(const phase of ['before','during']) {
 const x=await setup();try {const cookieBinding='c'.repeat(43),c=await x.login.beginBrowser({...x.context,cookieBinding}),h=await x.login.verifyBrowser({token:c.token,response:x.assertion(c)}),row=x.db.sqlite.prepare('SELECT binding_digest FROM web_login_handoffs').get();
 if(phase==='before')await x.sessions.logoutBrowser(undefined,row.binding_digest);
 else {const mint=x.exchanges.mint.bind(x.exchanges);x.exchanges.mint=async args=>{const r=await mint(args);await x.sessions.logoutBrowser(undefined,row.binding_digest);return r;};}
 assert.equal(await x.login.completeBrowser({handoff:h.handoff,cookieBinding}),undefined);
 assert.equal(x.db.sqlite.prepare('SELECT count(*) AS n FROM device_sessions WHERE revoked_at IS NULL').get().n,0);
 }finally{x.db.sqlite.close();}
 }
});
