// Public-entry tests for the INACTIVE realtime activation adapter: they build a synthetic env with the bindings that a deployment WOULD add.
// Nothing here is a platform accounting proof; it counts every call this code makes (edge limiter binding calls, D1 queries, Durable Object stub calls).
import test from 'node:test';
import assert from 'node:assert/strict';
import {createAuthOnlyWorker,RealtimeHub} from '../src/auth-only-worker.js';
import {REALTIME_CRON} from '../src/realtime-outbox.js';
import {database} from './sqlite-helper.js';
import {createQueryMeter} from '../src/query-meter.js';
import {AccountIdentityService} from '../src/account-identity.js';
import {PasskeySignupService} from '../src/passkey-signup.js';
import {DeviceSessionService} from '../src/device-sessions.js';
import {authenticator} from './passkey-fixture.js';
import {COMBINED_CEILING} from '../src/realtime-outbox.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io';
const R1='https://abcdefghijklmnopabcdefghijklmnop.chromiumapp.org/',EXTO='chrome-extension://abcdefghijklmnopabcdefghijklmnop';
const limiter=(name,log,ok=true)=>({limit:async()=>{log.push(name);return {success:ok};}});
const req=(path,{method='GET',headers={},body}={})=>{const r=new Request(API+path,{method,headers:{'CF-Connecting-IP':'192.0.2.1',...headers},...(body?{body}:{})});Object.defineProperty(r,'cf',{value:{colo:'LHR',httpProtocol:'HTTP/2',tlsVersion:'TLSv1.3'}});return r;};
function world({realtime=true,drop=[]}={}){
 const raw=database(),meter=createQueryMeter(raw),calls=[],stub={n:0,connects:0},nsCalls=[];
 const ns={idFromName:n=>n,get:id=>({fetch:async(u,init)=>{const url=typeof u==='string'?u:u.url;if(url.endsWith('/connect'))stub.connects++;else stub.n++;nsCalls.push(url);return new Response(null,{status:url.endsWith('/connect')?200:204});}})};
 const env={DEPLOYMENT_STAGE:'auth-only',AUTH_ONLY_SIGNUP_EMAIL:'owner@example.test',DB:meter.db,BREVO_API_KEY:'synthetic',BREVO_SENDER_EMAIL:'project@example.test',BREVO_REPLY_TO_EMAIL:'project@example.test'};
 for(const k of ['SIGNUP_ADDRESS_LIMIT','SIGNUP_GLOBAL_LIMIT','SIGNUP_VERIFY_ADDRESS_LIMIT','SIGNUP_VERIFY_GLOBAL_LIMIT','IDENTITY_ADDRESS_LIMIT','IDENTITY_AUTH_GLOBAL_LIMIT','IDENTITY_READ_GLOBAL_LIMIT'])env[k]=limiter(k,calls);
 if(realtime){for(const k of ['REALTIME_EXTENSION_ADDRESS_LIMIT','REALTIME_EXTENSION_GLOBAL_LIMIT','REALTIME_EXTENSION_TICKET_LIMIT'])if(!drop.includes(k))env[k]=limiter(k,calls);env.REALTIME_HUB=ns;env.REALTIME_ADDRESS_LIMIT=limiter('REALTIME_ADDRESS_LIMIT',calls);env.REALTIME_GLOBAL_LIMIT=limiter('REALTIME_GLOBAL_LIMIT',calls);env.REALTIME_TICKET_LIMIT=limiter('REALTIME_TICKET_LIMIT',calls);}
 env.EXTENSION_AUTH_ENABLED='1';env.EXTENSION_REDIRECTS=JSON.stringify({chrome:R1});env.EXTENSION_ORIGINS=JSON.stringify([EXTO]);
 for(const k of drop)delete env[k];
 return {raw,meter,calls,stub,env,nsCalls};
}
async function account(raw,email='a@example.com'){
 const identity=new AccountIdentityService(raw),signup=new PasskeySignupService(raw),a=authenticator();
 const e=await identity.issueEmailChallenge({purpose:'signup-email',email}),c=await signup.begin({email,emailToken:e.token,binding:'rt-'+email});
 const proof=await signup.finish({token:c.token,binding:'rt-'+email,response:a.registration({expected:c.options.challenge})});
 const issued=await new DeviceSessionService(raw).issue({proof:{...proof,purpose:'authenticate',verifiedAt:Date.now()},clientKind:'web'});
 const ext=await new DeviceSessionService(raw).issue({proof:{...proof,purpose:'authenticate',verifiedAt:Date.now()},clientKind:'extension'});
 return {ownerId:proof.ownerId,access:issued.access,extAccess:ext.access,authenticator:a};
}
const pre=(worker,env,path,method='POST',headers='authorization')=>worker.fetch(req(path,{method:'OPTIONS',headers:{Origin:APP,'Access-Control-Request-Method':method,'Access-Control-Request-Headers':headers}}),env,{waitUntil(){}});
const P1='/auth/extension/realtime/ticket',P2='/auth/extension/realtime';
const hdr=(o,extra={})=>({...(o?{Origin:o}:{}),...extra});
const run=(worker,env,path,method,headers)=>worker.fetch(req(path,{method,headers}),env,{waitUntil(){}});
test('extension realtime paths do not exist unless extension auth AND all three own limiter bindings exist; web/android realtime is unaffected; nothing is charged',async()=>{
 for(const [drop,env2] of [[[],{EXTENSION_AUTH_ENABLED:'0'}],[['REALTIME_EXTENSION_ADDRESS_LIMIT'],{}],[['REALTIME_EXTENSION_GLOBAL_LIMIT'],{}],[['REALTIME_EXTENSION_TICKET_LIMIT'],{}],[['REALTIME_HUB'],{}]]){
  const w=world({drop});Object.assign(w.env,env2);const worker=createAuthOnlyWorker();w.calls.length=0;const q0=w.meter.count();
  for(const [p,m] of [[P1,'POST'],[P2,'GET'],[P1,'OPTIONS']])assert.equal((await run(worker,w.env,p,m,hdr(m==='OPTIONS'?APP:null))).status,404,p+m+drop+JSON.stringify(env2));
  assert.equal(w.calls.length+w.meter.count()-q0+w.stub.n,0,'nothing charged');
  if(!drop.includes('REALTIME_HUB')){assert.equal((await pre(worker,w.env,'/auth/realtime/ticket')).status,204,'web realtime preflight still works');}
  w.raw.sqlite.close();}
});
test('extension realtime through the public entry: no CORS or preflight, exact origin pin, own limiters only (2 edge + 1 ticket), hub gets the upgrade, one use, kinds never cross',async()=>{
 const w=world(),worker=createAuthOnlyWorker(),{access,extAccess}=await account(w.raw),ctx={waitUntil(){}};w.calls.length=0;const q0=w.meter.count();
 for(const o of [APP,'https://evil.test','chrome-extension://ponmlkjihgfedcbaponmlkjihgfedcba','moz-extension://abcd-1234']){
  for(const [p,m] of [[P1,'POST'],[P2,'GET'],[P1,'OPTIONS']]){const r=await run(worker,w.env,p,m,hdr(o,{Authorization:'Bearer '+extAccess}));assert.equal(r.status,403,o+p+m);assert.deepEqual([...r.headers.keys()].filter(k=>k.startsWith('access-control')),[],'no CORS');}}
 assert.equal((await run(worker,w.env,P1,'OPTIONS',hdr(EXTO))).status,403);assert.equal((await run(worker,w.env,P1,'GET',hdr(EXTO))).status,405);
 assert.equal(w.calls.length+w.meter.count()-q0+w.stub.n,0,'refusals are pure: no limiter, D1 or hub');
 const m=await run(worker,w.env,P1,'POST',hdr(EXTO,{Authorization:'Bearer '+extAccess}));assert.equal(m.status,200);const t=await m.json();
 assert.deepEqual([...m.headers.keys()].filter(k=>k.startsWith('access-control')),[]);
 assert.deepEqual(w.calls.sort(),['REALTIME_EXTENSION_ADDRESS_LIMIT','REALTIME_EXTENSION_GLOBAL_LIMIT','REALTIME_EXTENSION_TICKET_LIMIT'],'only the three extension limiters');
 assert.equal((await run(worker,w.env,P1,'POST',hdr(null,{Authorization:'Bearer '+access}))).status,401,'web handle on extension path');
 const webMint=await worker.fetch(req('/auth/realtime/ticket',{method:'POST',headers:{Origin:APP,Authorization:'Bearer '+access}}),w.env,ctx);assert.equal(webMint.status,200);const wt=await webMint.json();
 assert.equal((await worker.fetch(req('/auth/realtime/ticket',{method:'POST',headers:{Origin:APP,Authorization:'Bearer '+extAccess}}),w.env,ctx)).status,401,'extension handle on web path');
 const sp=ticket=>({Upgrade:'websocket','Sec-WebSocket-Protocol':'otpanda.v1, '+ticket});
 assert.equal((await run(worker,w.env,P2,'GET',hdr(null,sp(wt.ticket)))).status,401,'web ticket on extension upgrade');
 assert.equal((await worker.fetch(req('/auth/realtime',{headers:{Origin:APP,...sp(t.ticket)}}),w.env,ctx)).status,401,'extension ticket on web upgrade');
 assert.equal(w.stub.connects,0);
 assert.equal((await run(worker,w.env,P2,'GET',hdr(EXTO,sp(t.ticket)))).status,200);assert.equal(w.stub.connects,1);
 assert.equal((await run(worker,w.env,P2,'GET',hdr(EXTO,sp(t.ticket)))).status,401,'single use');
 w.raw.sqlite.close();});
test('extension realtime edge limiter exhaustion returns 429 before any D1 or hub work',async()=>{
 const w=world();w.env.REALTIME_EXTENSION_GLOBAL_LIMIT=limiter('REALTIME_EXTENSION_GLOBAL_LIMIT',w.calls,false);const worker=createAuthOnlyWorker(),{extAccess}=await account(w.raw);w.calls.length=0;const q0=w.meter.count();
 const r=await run(worker,w.env,P1,'POST',hdr(null,{Authorization:'Bearer '+extAccess}));assert.equal(r.status,429);assert.equal(w.meter.count()-q0,0);assert.equal(w.raw.sqlite.prepare('SELECT count(*) n FROM realtime_tickets').get().n,0);
 assert.ok(!w.calls.some(c=>c.startsWith('IDENTITY')||c==='REALTIME_TICKET_LIMIT'||c==='REALTIME_ADDRESS_LIMIT'));w.raw.sqlite.close();});
