import test from 'node:test';
import assert from 'node:assert/strict';
import {database} from './sqlite-helper.js';
import {PasskeySignupService} from '../src/passkey-signup.js';
import {AccountIdentityService} from '../src/account-identity.js';
import {BrowserExchangeService,pkceChallenge} from '../src/browser-exchanges.js';
import {DeviceSessionService} from '../src/device-sessions.js';
import {createBrowserSessionHttp,REFRESH_COOKIE} from '../src/browser-session-http.js';
import {authenticator} from './passkey-fixture.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',redirect_uri=APP+'/app/',NOW=1_800_000_000_000,verifier='a'.repeat(43),state='s'.repeat(43);
import {createBrowserLogoutHttp} from '../src/browser-logout-http.js';
async function fixture(){const db=database(),clock=()=>NOW,identity=new AccountIdentityService(db,{clock}),signup=new PasskeySignupService(db,{clock}),e=await identity.issueEmailChallenge({purpose:'signup-email',email:'a@example.com'}),c=await signup.begin({email:'a@example.com',emailToken:e.token,binding:'binding'}),a=authenticator(),account=await signup.finish({token:c.token,binding:'binding',response:a.registration({expected:c.options.challenge})}),sessions=new DeviceSessionService(db,{clock}),d=await sessions.issue({proof:{...account,verifiedAt:NOW,purpose:'authenticate'},clientKind:'web'}),exchanges=new BrowserExchangeService(db,{redirectUri:redirect_uri,clock}),http=createBrowserSessionHttp({sessions,exchanges,db,clock});const params=new URLSearchParams({challenge:await pkceChallenge(verifier),state,redirect_uri});const run=(path,options={},meta={clientAddress:'test-address'})=>http.fetch(new Request(API+path,options),meta);return {db,sessions,d,run,params,exchanges,account};}

async function logout(f,refresh=f.d.refresh) {
 const http=createBrowserLogoutHttp(f),run=(opts={})=>http.fetch(new Request(API+'/auth/device/logout',opts),{clientAddress:'test'});
 const start=await run(),csrf=start.headers.getSetCookie()[0].split(';')[0];
 return {run,csrf,request:(changes={})=>run({method:'POST',headers:{Origin:API,'Content-Type':'application/x-www-form-urlencoded',Cookie:csrf+'; '+REFRESH_COOKIE+'='+refresh,...changes},body:new URLSearchParams({csrf:csrf.split('=')[1]})})};
}
test('logout invalidates device access, refresh and outstanding exchange, not another device',async()=>{
 const f=await fixture();try {
 const row=f.db.sqlite.prepare('SELECT owner_id,credential_id,generation FROM device_sessions WHERE device_id=?').get(f.d.deviceId);
 const other=await f.sessions.issue({proof:{ownerId:row.owner_id,credentialId:row.credential_id,generation:row.generation,purpose:'authenticate',verifiedAt:NOW},clientKind:'web'});
 const grant=await f.exchanges.mint({deviceId:f.d.deviceId,challenge:await pkceChallenge(verifier),redirectUri:redirect_uri});
 const l=await logout(f),r=await l.request();assert.equal(r.status,200);assert.ok((await r.text()).includes('signed out'));assert.equal(r.headers.getSetCookie().length,5);
 assert.equal(await f.sessions.authenticate(f.d.access),undefined);assert.equal((await f.sessions.rotate(f.d.refresh)).status,'denied');assert.equal(await f.exchanges.exchange({code:grant.code,verifier,redirectUri:redirect_uri}),undefined);assert.ok(await f.sessions.authenticate(other.access));
 assert.equal((await l.request()).status,200);
 }finally{f.db.sqlite.close();}
});
test('spent refresh logout wins against concurrent rotation; native handle cannot revoke',async()=>{
 const f=await fixture();try {const successor=await f.sessions.rotate(f.d.refresh),l=await logout(f);await l.request();assert.equal((await f.sessions.rotate(successor.refresh)).status,'denied');assert.equal(await f.sessions.authenticate(successor.access),undefined);
 const row=f.db.sqlite.prepare('SELECT owner_id,credential_id,generation FROM device_sessions WHERE device_id=?').get(f.d.deviceId),native=await f.sessions.issue({proof:{ownerId:row.owner_id,credentialId:row.credential_id,generation:row.generation,purpose:'authenticate',verifiedAt:NOW},clientKind:'android'});assert.equal(await f.sessions.logoutBrowser(native.refresh),false);assert.ok(await f.sessions.authenticate(native.access));
 }finally{f.db.sqlite.close();}
});
test('logout requires exact origin CSRF and bounded strict body; GET cannot revoke',async()=>{
 const f=await fixture();try {const l=await logout(f);assert.ok(await f.sessions.authenticate(f.d.access));for(const Origin of [APP,'https://evil.test','null'])assert.equal((await l.request({Origin})).status,403);assert.equal((await l.request({Cookie:REFRESH_COOKIE+'='+f.d.refresh})).status,403);for(const body of ['csrf=x&csrf=x','csrf=x&extra=1','x'.repeat(513)])assert.ok([400,403].includes((await l.run({method:'POST',headers:{Origin:API,'Content-Type':'application/x-www-form-urlencoded',Cookie:l.csrf},body})).status));assert.ok(await f.sessions.authenticate(f.d.access));assert.equal((await l.request()).status,200);
 }finally{f.db.sqlite.close();}
});
test('logout browser binding cancels issuance before/after completion without affecting independent binding',async()=>{
 const f=await fixture();try {
 const row=f.db.sqlite.prepare('SELECT owner_id,credential_id,generation FROM device_sessions WHERE device_id=?').get(f.d.deviceId),proof={ownerId:row.owner_id,credentialId:row.credential_id,generation:row.generation,purpose:'authenticate',verifiedAt:NOW},binding='a'.repeat(64),other='b'.repeat(64);
 const pending=await f.sessions.issue({proof,clientKind:'web',browserBindingDigest:binding}),independent=await f.sessions.issue({proof,clientKind:'web',browserBindingDigest:other});
 assert.equal(await f.sessions.logoutBrowser(f.d.refresh,binding),true);
 assert.equal(await f.sessions.authenticate(pending.access),undefined);assert.ok(await f.sessions.authenticate(independent.access));
 assert.equal(await f.sessions.issue({proof,clientKind:'web',browserBindingDigest:binding}),undefined);
 assert.equal(await f.sessions.logoutBrowser(undefined,binding),false);
 assert.ok(await f.sessions.authenticate(independent.access));
 }finally{f.db.sqlite.close();}
});
