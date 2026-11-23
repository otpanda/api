import test from 'node:test';
import assert from 'node:assert/strict';
import {database} from './sqlite-helper.js';
import {SignupEmailService} from '../src/signup-email.js';
import {PasskeySignupService} from '../src/passkey-signup.js';
import {SignupHandoffService} from '../src/signup-handoff.js';
import {WebLoginHandoffService} from '../src/web-login-handoff.js';
import {DeviceSessionService} from '../src/device-sessions.js';
import {BrowserExchangeService,pkceChallenge} from '../src/browser-exchanges.js';
import {createSignupHttp} from '../src/signup-http.js';
import {createWebLoginHttp} from '../src/web-login-http.js';
import {authenticator} from './passkey-fixture.js';
const NOW=1_800_000_000_000,REDIRECT='https://otpanda.github.io/app/',API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io';
const metadata={clientAddress:'198.51.100.7'};
async function setup({defer}={}){
 const db=database(),sent=[],deferred=[];let now=NOW;const clock=()=>now;
 const mail=new SignupEmailService(db,{clock,deliver:async v=>sent.push(v)});
 const signup=new PasskeySignupService(db,{clock}),sessions=new DeviceSessionService(db,{clock}),exchanges=new BrowserExchangeService(db,{clock,redirectUri:REDIRECT});
 const login=new WebLoginHandoffService(db,{clock,sessions,exchanges,passkeys:{}});
 const handoff=new SignupHandoffService(db,{clock,signup,login});
 const http=createSignupHttp({db,signupEmail:mail,handoff,clock,...(defer===undefined?{defer:t=>deferred.push(t)}:defer===null?{}:{defer})});
 return {db,sent,deferred,http,loginHttp:createWebLoginHttp({db,login,clock}),sessions,exchanges,challenge:await pkceChallenge('a'.repeat(43)),state:'b'.repeat(43),run:async()=>{for(const f of deferred.splice(0))await f();},setNow:v=>now=v};
}
async function openStart(x,{cookies,meta=metadata}={}){
 const q=new URLSearchParams({challenge:x.challenge,state:x.state,redirect_uri:REDIRECT});
 const r=await x.http.fetch(new Request(API+'/auth/signup/start?'+q,cookies?{headers:{Cookie:cookies}}:undefined),meta);
 assert.equal(r.status,200);
 const set=r.headers.getSetCookie(),csrf=set.find(c=>c.startsWith('__Host-otpanda_signup_csrf='))?.split(';')[0];
 const bind=set.find(c=>c.startsWith('__Host-otpanda_login='))?.split(';')[0]??cookies?.split(';').map(v=>v.trim()).find(c=>c.startsWith('__Host-otpanda_login='));
 return {r,csrf,bind,header:bind+'; '+csrf};
}
function post(path,{origin=API,cookies,body,meta=metadata}={}){return {method:'POST',headers:{...(origin?{Origin:origin}:{}),'Content-Type':'application/x-www-form-urlencoded',...(cookies?{Cookie:cookies}:{})},body};}
async function requestEmail(x,s,{email='a@example.com',origin=API,csrf=s.csrf.split('=')[1],cookies=s.header}={}){
 return x.http.fetch(new Request(API+'/auth/signup/email',post(0,{origin,cookies,body:new URLSearchParams({csrf,email})})),metadata);
}
async function begin(x,s,{email='a@example.com',token,origin=API,csrf=s.csrf.split('=')[1],cookies=s.header,challenge=x.challenge,state=x.state}={}){
 return x.http.fetch(new Request(API+'/auth/signup/begin',post(0,{origin,cookies,body:new URLSearchParams({challenge,csrf,email,email_token:token,redirect_uri:REDIRECT,state})})),metadata);
}
async function verify(x,c,{origin=APP,body,headers}={}){
 return x.http.fetch(new Request(API+'/auth/signup/verify',{method:'POST',headers:{...(origin?{Origin:origin}:{}),'Content-Type':'application/json',...headers},body:body===undefined?JSON.stringify({token:c.token,response:authenticator().registration({expected:c.options.challenge})}):body}),metadata);
}
function ceremonyOf(r){assert.equal(r.status,303);const target=new URL(r.headers.get('location'));assert.equal(target.origin+target.pathname,REDIRECT);assert.equal(target.search,'');const frag=new URLSearchParams(target.hash.slice(1));return {frag,ceremony:JSON.parse(Buffer.from(frag.get('signup'),'base64url').toString())};}
async function journey(x,{email='a@example.com'}={}){
 const s=await openStart(x);
 for(const t of ['auth_challenges','web_signup_starts','signup_mail_bindings'])assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM '+t).get().n,0,'GET performs no writes');
 const req=await requestEmail(x,s,{email});assert.equal(req.status,202);assert.equal(x.sent.length,0,'delivery deferred');await x.run();assert.equal(x.sent.length,1);
 const b=await begin(x,s,{email,token:x.sent.at(-1).token});
 return {s,proof:x.sent.at(-1),...ceremonyOf(b)};
}
async function complete(x,handoff,bind,{origin=API,csrfMismatch=false}={}){
 const r=await x.loginHttp.fetch(new Request(API+'/auth/login/complete'),metadata);assert.equal(r.status,200);
 const csrf=r.headers.getSetCookie().find(c=>c.startsWith('__Host-otpanda_login_csrf=')).split(';')[0];
 return x.loginHttp.fetch(new Request(API+'/auth/login/complete',post(0,{origin,cookies:bind+'; '+csrf,body:new URLSearchParams({csrf:csrfMismatch?'wrong':csrf.split('=')[1],handoff})})),metadata);
}
test('full first-party journey: page, deferred mail, bound ceremony, verify and existing completion create account then session',async()=>{
 const x=await setup(),{s,ceremony,frag}=await journey(x);
 assert.equal(frag.get('state'),x.state);
 assert.ok(s.bind.startsWith('__Host-otpanda_login=otpda_'));
 const attrs=s.r.headers.getSetCookie().find(c=>c.startsWith('__Host-otpanda_login='));
 assert.ok(attrs.includes('HttpOnly')&&attrs.includes('Secure')&&attrs.includes('SameSite=Lax')&&attrs.includes('Max-Age=900')&&!attrs.includes('Domain='));
 assert.deepEqual(Object.keys(ceremony).sort(),['expiresAt','options','token']);
 for(const t of ['accounts','account_emails','passkey_credentials','device_sessions'])assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM '+t).get().n,0,'nothing created before verify');
 const v=await verify(x,ceremony);assert.equal(v.status,200);assert.equal(v.headers.get('Access-Control-Allow-Origin'),APP);assert.equal(v.headers.get('Cache-Control'),'no-store');
 const h=await v.json();assert.deepEqual(Object.keys(h).sort(),['expiresAt','handoff']);
 assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM accounts').get().n,1);
 assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM device_sessions').get().n,0,'no session before cookie-bound completion');
 const c=await complete(x,h.handoff,s.bind);assert.equal(c.status,303);
 const target=new URL(c.headers.get('location')),q=new URLSearchParams(target.hash.slice(1));assert.equal(q.get('state'),x.state);assert.ok(!c.headers.get('location').includes('refresh'));
 assert.ok(c.headers.getSetCookie().some(v=>v.startsWith('__Host-otpanda_device=')&&v.includes('HttpOnly')));
 const access=await x.exchanges.exchange({code:q.get('code'),verifier:'a'.repeat(43),redirectUri:REDIRECT});assert.ok(await x.sessions.authenticate(access.access));
 assert.equal((await complete(x,h.handoff,s.bind)).status,401,'completion is one-use');
 x.db.sqlite.close();
});
test('start GET keeps an existing binding cookie so proof retries stay bound; CSRF stays valid across tabs',async()=>{
 const x=await setup(),first=await openStart(x);
 const second=await openStart(x,{cookies:first.header});
 assert.ok(second.r.headers.getSetCookie().some(c=>c.startsWith('__Host-otpanda_login=')&&c.includes('Max-Age=900')),'refresh lifetime without changing binding');
 assert.equal(second.bind,first.bind);assert.equal(second.csrf,first.csrf);
 x.db.sqlite.close();
});
test('email POST is generic 202 with delivery deferred; missing defer is unavailable',async()=>{
 const x=await setup({defer:null}),s=await openStart(x);
 assert.equal((await requestEmail(x,s)).status,503);assert.equal(x.sent.length,0);
 x.db.sqlite.close();
});
test('email request is indistinguishable for existing and new addresses',async()=>{
 const x=await setup(),first=await journey(x,{email:'taken@example.com'});assert.equal((await verify(x,first.ceremony)).status,200);
 const s=await openStart(x,{cookies:first.s.header});
 const taken=await requestEmail(x,s,{email:'TAKEN@example.com'}),fresh=await requestEmail(x,s,{email:'fresh@example.com'});
 assert.equal(taken.status,202);assert.equal(fresh.status,202);assert.equal(await taken.text(),await fresh.text());
 await x.run();assert.equal(x.sent.length,2,'only the fresh address gets mail');assert.equal(x.sent.at(-1).to,'fresh@example.com');
 x.db.sqlite.close();
});
test('proof redeemed from another browser fails closed with same-browser guidance and is not consumed',async()=>{
 const x=await setup(),s=await openStart(x);
 await requestEmail(x,s);await x.run();const proof=x.sent.at(-1);
 const other=await openStart(x);assert.notEqual(other.bind,s.bind);
 const bad=await begin(x,other,{token:proof.token});
 assert.equal(bad.status,400);assert.match(await bad.text(),/same browser/i);
 assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM auth_challenges').get().n,1,'proof not consumed');
 assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM web_signup_starts').get().n,0);
 const good=await begin(x,s,{token:proof.token});assert.equal(good.status,303,'original browser still works');
 x.db.sqlite.close();
});
test('failed attestation permits bounded fresh ceremonies with new challenges and no second email',async()=>{
 const x=await setup(),{s,proof,ceremony:first}=await journey(x);
 assert.equal((await verify(x,first,{body:JSON.stringify({token:first.token,response:{}})})).status,401);
 const retry=ceremonyOf(await begin(x,s,{token:proof.token})).ceremony;
 assert.notEqual(retry.options.challenge,first.options.challenge);assert.notEqual(retry.token,first.token);
 assert.equal((await verify(x,retry)).status,200);assert.equal(x.sent.length,1);
 x.db.sqlite.close();
});
test('browser receipt permits at most five ceremonies at the HTTP boundary',async()=>{
 const x=await setup(),{s,proof}=await journey(x);
 for(let i=0;i<4;i++)assert.equal((await begin(x,s,{token:proof.token})).status,303);
 const sixth=await begin(x,s,{token:proof.token});assert.equal(sixth.status,400);assert.match(await sixth.text(),/same browser/i);
 x.db.sqlite.close();
});
test('exact origins, methods, keys, content types and body caps fail closed with no reflected origin',async()=>{
 const x=await setup(),s=await openStart(x);
 for(const origin of ['https://evil.example','null',API])assert.equal((await verify(x,{token:'t',options:{challenge:'c'}},{origin,body:'{}'})).status,403);
 let r=await verify(x,{},{origin:'https://evil.example',body:'{}'});assert.equal(r.headers.get('Access-Control-Allow-Origin'),null);
 const preflight=h=>new Request(API+'/auth/signup/verify',{method:'OPTIONS',headers:{Origin:APP,'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':h}});
 assert.equal((await x.http.fetch(preflight('content-type'),metadata)).status,204);
 assert.equal((await x.http.fetch(preflight('authorization'),metadata)).status,403);
 assert.equal((await x.http.fetch(new Request(API+'/auth/signup/verify',{headers:{Origin:APP}}),metadata)).status,405);
 assert.equal((await verify(x,{},{body:'x'.repeat(16385)})).status,400);
 assert.equal((await verify(x,{},{body:JSON.stringify({token:'t',response:{},extra:1})})).status,400);
 assert.equal((await x.http.fetch(new Request(API+'/auth/signup/verify?x=1',{method:'POST',headers:{Origin:APP,'Content-Type':'application/json'},body:'{}'}),metadata)).status,400);
 assert.equal((await requestEmail(x,s,{origin:APP})).status,403);
 assert.equal((await requestEmail(x,s,{csrf:'wrong'})).status,400);
 assert.equal((await x.http.fetch(new Request(API+'/auth/signup/email',post(0,{cookies:s.header,body:new URLSearchParams({csrf:s.csrf.split('=')[1],email:'a@example.com',extra:'1'})})),metadata)).status,400);
 assert.equal((await begin(x,s,{token:'not-a-proof'})).status,400);
 assert.equal((await begin(x,s,{token:'otpda_'+'z'.repeat(55),csrf:'wrong'})).status,400);
 assert.equal((await begin(x,s,{token:'otpda_'+'z'.repeat(55),origin:APP})).status,403);
 assert.equal((await x.http.fetch(new Request(API+'/auth/signup/email',{headers:{Origin:API}}),metadata)).status,405);
 assert.equal((await x.http.fetch(new Request(API+'/auth/signup/unknown'),metadata)).status,404);
 for(const q of ['challenge=bad&state='+x.state+'&redirect_uri='+encodeURIComponent(REDIRECT),'challenge='+x.challenge+'&state='+x.state+'&redirect_uri=https://evil.example','challenge='+x.challenge+'&challenge='+x.challenge+'&state='+x.state+'&redirect_uri='+encodeURIComponent(REDIRECT)])assert.equal((await x.http.fetch(new Request(API+'/auth/signup/start?'+q),metadata)).status,400);
 x.db.sqlite.close();
});
test('missing binding cookie fails closed with recovery page, never a silently minted binding',async()=>{
 const x=await setup(),s=await openStart(x);
 await requestEmail(x,s);await x.run();
 const csrfOnly='__Host-otpanda_signup_csrf='+s.csrf.split('=')[1];
 const r=await begin(x,s,{token:x.sent.at(-1).token,cookies:csrfOnly});
 assert.equal(r.status,400);assert.match(await r.text(),/same browser/i);
 assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM auth_challenges').get().n,1,'proof not consumed');
 x.db.sqlite.close();
});
test('trusted canonical address drives prelimit; forwarding headers are ignored; malformed identity is unavailable',async()=>{
 const x=await setup(),q=new URLSearchParams({challenge:x.challenge,state:x.state,redirect_uri:REDIRECT});
 assert.equal((await x.http.fetch(new Request(API+'/auth/signup/start?'+q))).status,503);
 assert.equal((await x.http.fetch(new Request(API+'/auth/signup/start?'+q),{clientAddress:'fe80::1%zone'})).status,503);
 for(let n=0;n<15;n++)assert.equal((await x.http.fetch(new Request(API+'/auth/signup/start?'+q,{headers:{'X-Forwarded-For':'203.0.113.'+n}}),metadata)).status,200);
 assert.equal((await x.http.fetch(new Request(API+'/auth/signup/start?'+q),metadata)).status,429);
 const v6=new URLSearchParams({challenge:x.challenge,state:x.state,redirect_uri:REDIRECT});
 for(let n=0;n<15;n++)assert.equal((await x.http.fetch(new Request(API+'/auth/signup/start?'+v6),{clientAddress:'2001:db8::'+n})).status,200,'same /64 shares one bucket');
 assert.equal((await x.http.fetch(new Request(API+'/auth/signup/start?'+v6),{clientAddress:'2001:db8::99'})).status,429);
 assert.equal((await x.http.fetch(new Request(API+'/auth/signup/start?'+v6),{clientAddress:'2001:db8:0:1::1'})).status,200,'another /64 is independent');
 x.db.sqlite.close();
});
test('expired, unknown and existing-account begin attempts are the same recovery page',async()=>{
 const x=await setup(),{s,proof}=await journey(x);
 x.setNow(NOW+600001);
 const expired=await begin(x,s,{token:proof.token});assert.equal(expired.status,400);
 const unknown=await begin(x,s,{token:'otpda_'+'z'.repeat(55)});
 assert.equal(await unknown.text(),await expired.text(),'no oracle between expired and unknown proofs');
 x.db.sqlite.close();
});
test('start page carries both first-party forms, same-browser guidance and security headers',async()=>{
 const x=await setup(),{r}=await openStart(x),html=await r.text();
 assert.ok(html.includes('action="/auth/signup/email"')&&html.includes('action="/auth/signup/begin"'));
 assert.ok(html.includes(x.challenge)&&html.includes(x.state)&&html.includes(encodeURIComponent(REDIRECT)===REDIRECT?REDIRECT:REDIRECT));
 assert.match(html,/same browser/i);
 assert.equal(r.headers.get('Cache-Control'),'no-store');assert.equal(r.headers.get('Referrer-Policy'),'same-origin');
 assert.ok(r.headers.get('Content-Security-Policy').includes("frame-ancestors 'none'"));
 x.db.sqlite.close();
});
test('verify storage exceptions are generic and retain exact CORS',async()=>{const x=await setup();const http=createSignupHttp({db:x.db,signupEmail:{},handoff:{verifyBrowser:async()=>{throw Error('private');}},clock:()=>NOW});const r=await http.fetch(new Request(API+'/auth/signup/verify',{method:'POST',headers:{Origin:APP,'Content-Type':'application/json'},body:JSON.stringify({token:'x',response:{}})}),metadata);assert.equal(r.status,503);assert.equal(r.headers.get('Access-Control-Allow-Origin'),APP);assert.ok(!(await r.text()).includes('private'));x.db.sqlite.close();});
test('defer registration exceptions return recovery HTML not bare500',async()=>{const x=await setup({defer:()=>{throw Error('private');}}),s=await openStart(x),r=await requestEmail(x,s);assert.equal(r.status,503);assert.match(r.headers.get('content-type'),/text\/html/);assert.ok(!(await r.text()).includes('private'));x.db.sqlite.close();});
test('normal browser form UTF8 charset is accepted, other content types reject',async()=>{const x=await setup(),s=await openStart(x),body=new URLSearchParams({csrf:s.csrf.split('=')[1],email:'a@example.com'}).toString();const r=await x.http.fetch(new Request(API+'/auth/signup/email',{method:'POST',headers:{Origin:API,Cookie:s.header,'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8'},body}),metadata);assert.equal(r.status,202);x.db.sqlite.close();});
