import test from 'node:test';import assert from 'node:assert/strict';
import * as oauth from 'oauth4webapi';
import {database} from './sqlite-helper.js';import {authenticator} from './passkey-fixture.js';
import {DeviceSessionService} from '../src/device-sessions.js';import {createGoogleBrowserRuntime} from '../src/google-browser-runtime.js';
import {createGoogleLinkTicketHttp} from '../src/google-link-http.js';import {base64urlEncode} from '../src/tokens.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',enc=new TextEncoder(),STATE='s'.repeat(43);
async function setup({email='a@gmail.com',passkey=true,linked=false}={}){
 const db=database();let now=Date.now();const clock=()=>now;
 db.sqlite.prepare('INSERT INTO accounts(owner_id,created_at) VALUES(?,?)').run('owner',now);db.sqlite.prepare('INSERT INTO account_emails VALUES(?,?,?,?)').run('owner','a@gmail.com',now,now);db.sqlite.prepare('INSERT INTO account_security(owner_id) VALUES(?)').run('owner');
 const a=authenticator();db.sqlite.prepare('INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) VALUES(?,?,?,?,?,?,?,?)').run(a.credential.id,'owner',a.credential.publicKey,0,'[]','singleDevice',0,now);
 if(linked)db.sqlite.prepare("INSERT INTO provider_identities(identity_id,owner_id,provider,issuer,subject,email,created_at) VALUES('one','owner','google','https://accounts.google.com','sub-1','a@gmail.com',?)").run(now);
 const sessions=new DeviceSessionService(db,{clock}),pk=await sessions.issue({proof:{authMethod:'passkey',credentialId:a.credential.id,ownerId:'owner',generation:0,purpose:'authenticate',verifiedAt:now},clientKind:'web'});
 if(!passkey)db.sqlite.prepare('UPDATE passkey_credentials SET revoked_at=1').run();
 const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']),signing=await crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['sign','verify']);
 const jwk={...await crypto.subtle.exportKey('jwk',signing.publicKey),kid:'key-1',alg:'RS256',use:'sig'},server={issuer:'https://accounts.google.com',authorization_endpoint:'https://id.test/auth',token_endpoint:'https://id.test/token',jwks_uri:'https://id.test/jwks',id_token_signing_alg_values_supported:['RS256']};
 let nonce,googleEmail=email,tokenCalls=0;
 const fetchMock=async(url,options)=>{
  if(String(url)==='https://accounts.google.com/.well-known/openid-configuration')return Response.json({...server,code_challenge_methods_supported:['S256'],token_endpoint_auth_methods_supported:['client_secret_post']});
  if(String(url)===server.jwks_uri)return Response.json({keys:[jwk]});tokenCalls++;
  const t=Math.floor(Date.now()/1000),h=base64urlEncode(enc.encode(JSON.stringify({alg:'RS256',kid:'key-1'}))),p=base64urlEncode(enc.encode(JSON.stringify({iss:server.issuer,sub:'sub-1',aud:'client.apps.googleusercontent.com',iat:t,exp:t+300,email:googleEmail,email_verified:true,picture:'https://lh3.googleusercontent.com/a/linked=s96-c',nonce})));
  const sig=new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5',signing.privateKey,enc.encode(h+'.'+p)));return Response.json({access_token:'x',token_type:'Bearer',id_token:h+'.'+p+'.'+base64urlEncode(sig)});};
 const runtime=await createGoogleBrowserRuntime({db,keys:new Map([['test',key]]),activeKeyId:'test',clientId:'client.apps.googleusercontent.com',clientSecret:'synthetic-secret',clock,oauthOptions:{[oauth.customFetch]:fetchMock}});
 const ticketHttp=createGoogleLinkTicketHttp({db,sessions,clock});
 const ticket=(o={})=>ticketHttp.fetch(new Request(API+'/v1/manage/google/link/ticket',{method:'POST',headers:{Origin:APP,'Content-Type':'application/json',...(o.auth===null?{}:{Authorization:'Bearer '+(o.auth??pk.access)}),...(o.headers??{})},body:JSON.stringify(o.body??{state:STATE})}),{clientAddress:o.address??'192.0.2.1'});
 const start=(t,o={})=>runtime.fetch(new Request(API+'/auth/google/link/start?ticket='+encodeURIComponent(t)),o.noAddress?{}:{clientAddress:o.address??'192.0.2.1'});
 const callback=async(s)=>{const target=new URL(s.headers.get('location'));nonce=target.searchParams.get('nonce');const cookie=s.headers.getSetCookie().map(c=>c.split(';')[0]).filter(c=>c.startsWith('__Host-otpanda_google')).join('; ');return runtime.fetch(new Request(API+'/auth/callback?'+new URLSearchParams({code:'c',state:target.searchParams.get('state')}),{headers:{cookie}}));};
 const q=(sql,...p)=>db.sqlite.prepare(sql).get(...p);
 return{db,a,pk,sessions,runtime,ticket,start,callback,q,tokenCalls:()=>tokenCalls,setEmail:e=>googleEmail=e,advance:ms=>now+=ms,clock};
}
const pendingOf=r=>{const h=new URLSearchParams(new URL(r.headers.get('location')).hash.slice(1));return h.get('google')?JSON.parse(h.get('google')):undefined;};
const noSessionCookies=r=>{const c=r.headers.getSetCookie().join(';');assert.equal(c.includes('__Host-otpanda_device'),false);assert.equal(c.includes('__Host-otpanda_recognition'),false);assert.equal(c.includes('__Host-otpanda_browser'),false);};
async function full(x){const t=(await(await x.ticket()).json()).ticket,s=await x.start(t);return{t,s,cb:await x.callback(s)};}
test('signed-in link: ticket, start, callback make an owner-bound pending link with no session and no device cookie; passkey verify links once',async()=>{
 const x=await setup(),before=x.q('SELECT count(*) n FROM device_sessions').n,r=await x.ticket();assert.equal(r.status,200);const t=(await r.json()).ticket;assert.match(t,/^[A-Za-z0-9_-]{43}$/);
 assert.equal(x.q('SELECT count(*) n FROM google_link_tickets WHERE ticket_digest=?',t).n,0,'only a digest is stored');
 const s=await x.start(t);assert.equal(s.status,303);assert.equal(new URL(s.headers.get('location')).origin,'https://id.test');noSessionCookies(s);assert.equal(s.headers.getSetCookie().length,2,'binding and link marker only');assert.ok(s.headers.getSetCookie().some(c=>c.startsWith('__Host-otpanda_google_link=1')&&/HttpOnly/i.test(c)&&/Max-Age=1800/i.test(c)));
 const cb=await x.callback(s);assert.equal(cb.status,303);noSessionCookies(cb);const target=new URL(cb.headers.get('location'));assert.equal(target.origin+target.pathname,APP+'/app/');
 const p=pendingOf(cb);assert.equal(p.kind,'link-only');assert.equal(x.q('SELECT count(*) n FROM device_sessions').n,before);assert.equal(x.q('SELECT count(*) n FROM provider_identities').n,0);assert.equal(x.q('SELECT count(*) n FROM pending_logins').n,0);
 const c=x.runtime.continuations,ceremony=await c.beginLink(p.token);assert.ok(ceremony);
 assert.equal(await c.verify({token:p.token,ceremony:ceremony.token,response:x.a.assertion({expected:ceremony.options.challenge,counter:1})}),true);
 assert.equal(x.q("SELECT count(*) n FROM provider_identities WHERE owner_id='owner' AND revoked_at IS NULL").n,1);assert.equal(x.q('SELECT picture FROM provider_identities WHERE owner_id=\'owner\' AND revoked_at IS NULL').picture,'https://lh3.googleusercontent.com/a/linked=s96-c','link stores the validated picture');assert.equal(x.q('SELECT count(*) n FROM google_continuations').n,0,'single use');
 assert.equal(await c.consume({token:p.token,binding:'x'}),undefined);assert.equal(await c.verify({token:p.token,ceremony:ceremony.token,response:{}}),false,'replay');
 assert.ok(await x.sessions.authenticate(x.pk.access),'existing session untouched');
});
test('ticket issue: auth, origin, shape, already linked, no passkey, address and owner rate limits',async()=>{
 const x=await setup();assert.equal((await x.ticket({auth:null})).status,401);assert.equal((await x.ticket({headers:{Origin:'https://evil.test'}})).status,403);assert.equal((await x.ticket({body:{state:'short'}})).status,400);assert.equal((await x.ticket({body:{state:STATE,extra:1}})).status,400);
 const l=await setup({linked:true});const r=await l.ticket();assert.equal(r.status,409);assert.equal((await r.json()).error,'already_linked');
 const n=await setup({passkey:false}),stub=createGoogleLinkTicketHttp({db:n.db,sessions:{authenticate:async()=>({ownerId:'owner',deviceId:'d',generation:0,clientKind:'web'})},clock:n.clock});assert.equal((await n.ticket()).status,401,'a passkey session dies with its credential');const r2=await stub.fetch(new Request(API+'/v1/manage/google/link/ticket',{method:'POST',headers:{Origin:APP,'Content-Type':'application/json',Authorization:'Bearer otpda_x'},body:JSON.stringify({state:STATE})}),{clientAddress:'192.0.2.1'});assert.equal(r2.status,409);assert.equal((await r2.json()).error,'no_passkey');assert.equal(n.q('SELECT count(*) n FROM google_link_tickets').n,0);
 const y=await setup();for(let i=0;i<10;i++)assert.equal((await y.ticket({address:'192.0.2.'+(i+1)})).status,200);assert.equal((await y.ticket({address:'192.0.2.99'})).status,429,'owner limit');
 const z=await setup();for(let i=0;i<60;i++)await z.ticket({auth:'otpda_bad'+i});assert.equal((await z.ticket()).status,429,'address limit');
});
test('ticket is single use, short lived, and dies with its session or generation',async()=>{
 const x=await setup(),t=(await(await x.ticket()).json()).ticket;assert.equal((await x.start(t)).headers.get('location').startsWith('https://id.test/'),true);
 const again=await x.start(t);assert.equal(new URL(again.headers.get('location')).hash.includes('link=restart'),true);noSessionCookies(again);assert.equal(again.headers.getSetCookie().length,0,'a failed start touches no cookies');
 const e=await setup(),te=(await(await e.ticket()).json()).ticket;e.advance(61000);assert.equal(new URL((await e.start(te)).headers.get('location')).hash.includes('link=restart'),true);
 const r=await setup(),tr=(await(await r.ticket()).json()).ticket;r.db.sqlite.prepare('UPDATE device_sessions SET revoked_at=1').run();assert.equal(new URL((await r.start(tr)).headers.get('location')).hash.includes('link=restart'),true);
 const g=await setup(),tg=(await(await g.ticket()).json()).ticket;g.db.sqlite.prepare("UPDATE account_security SET generation=generation+1 WHERE owner_id='owner'").run();assert.equal(new URL((await g.start(tg)).headers.get('location')).hash.includes('link=restart'),true);
 const w=await setup();assert.equal(new URL((await w.start('x'.repeat(43))).headers.get('location')).hash.includes('link=restart'),true);assert.equal((await w.runtime.fetch(new Request(API+'/auth/google/link/start?ticket='+'x'.repeat(43)+'&x=1'))).status,303);
});
test('callback: email mismatch, other owner mailbox and replayed state create no pending link and no session',async()=>{
 const x=await setup(),t=(await(await x.ticket()).json()).ticket,s=await x.start(t);x.setEmail('someone-else@gmail.com');const cb=await x.callback(s);assert.equal(new URL(cb.headers.get('location')).hash.includes('link=mismatch'),true);noSessionCookies(cb);
 assert.equal(x.q('SELECT count(*) n FROM google_continuations').n,0);assert.equal(x.q('SELECT count(*) n FROM provider_identities').n,0);assert.equal(x.q('SELECT count(*) n FROM device_sessions').n,1);
 const o=await setup();o.db.sqlite.prepare('INSERT INTO accounts(owner_id,created_at) VALUES(?,?)').run('other',1);o.db.sqlite.prepare('INSERT INTO account_emails VALUES(?,?,?,?)').run('other','b@gmail.com',1,1);o.db.sqlite.prepare('INSERT INTO account_security(owner_id) VALUES(?)').run('other');o.setEmail('b@gmail.com');
 const to=(await(await o.ticket()).json()).ticket,so=await o.start(to),co=await o.callback(so);assert.equal(new URL(co.headers.get('location')).hash.includes('link=mismatch'),true);assert.equal(o.q('SELECT count(*) n FROM google_continuations').n,0);
 const rp=await setup(),tr=(await(await rp.ticket()).json()).ticket,sr=await rp.start(tr);await rp.callback(sr);const st=new URL(sr.headers.get('location')).searchParams.get('state');const again=await rp.runtime.fetch(new Request(API+'/auth/callback?'+new URLSearchParams({code:'c',state:st}),{headers:{cookie:sr.headers.getSetCookie().map(c=>c.split(';')[0]).join('; ')}}));assert.equal(again.status,303);assert.equal(rp.q('SELECT count(*) n FROM google_continuations').n,1,'second callback creates nothing');
});
test('verify rechecks the bound session, generation, passkey and already-active link atomically',async()=>{
 for(const race of ['session','generation','passkey','link']){
  const x=await setup(),{cb}=await full(x),p=pendingOf(cb);assert.equal(p.kind,'link-only');const c=x.runtime.continuations,ceremony=await c.beginLink(p.token);assert.ok(ceremony);
  const response=x.a.assertion({expected:ceremony.options.challenge,counter:1});
  if(race==='session')x.db.sqlite.prepare('UPDATE device_sessions SET revoked_at=1').run();
  if(race==='generation')x.db.sqlite.prepare("UPDATE account_security SET generation=generation+1 WHERE owner_id='owner'").run();
  if(race==='passkey')x.db.sqlite.prepare('UPDATE passkey_credentials SET revoked_at=1').run();
  if(race==='link')x.db.sqlite.prepare("INSERT INTO provider_identities(identity_id,owner_id,provider,issuer,subject,email,created_at) VALUES('other','owner','google','https://accounts.google.com','sub-1','a@gmail.com',1)").run();
  assert.equal(await c.verify({token:p.token,ceremony:ceremony.token,response}),false,race);
  assert.equal(x.q("SELECT count(*) n FROM provider_identities WHERE owner_id='owner' AND revoked_at IS NULL").n,race==='link'?1:0,race);
 }
});
test('a link-only continuation can never be consumed into a sign-in',async()=>{
 const x=await setup(),{cb}=await full(x),p=pendingOf(cb),c=x.runtime.continuations,ceremony=await c.beginLink(p.token);
 await c.verify({token:p.token,ceremony:ceremony.token,response:x.a.assertion({expected:ceremony.options.challenge,counter:1})});
 const complete=await x.runtime.fetch(new Request(API+'/auth/google/continue/complete'),{clientAddress:'192.0.2.1'});assert.equal(complete.status,200);
 assert.equal(x.q('SELECT count(*) n FROM device_sessions').n,1);assert.equal(x.q('SELECT count(*) n FROM pending_logins').n,0);
});

test('early callback failure of a link start returns the fixed #link=restart with empty state, never #auth, and clears both cookies',async()=>{
 const x=await setup(),t=(await(await x.ticket()).json()).ticket,s=await x.start(t),cookies=s.headers.getSetCookie().map(c=>c.split(';')[0]).join('; ');
 const cases={'unknown state':[API+'/auth/callback?'+new URLSearchParams({code:'c',state:'z'.repeat(43)}),cookies],'missing state':[API+'/auth/callback?code=c',cookies],'no binding cookie':[API+'/auth/callback?'+new URLSearchParams({code:'c',state:new URL(s.headers.get('location')).searchParams.get('state')}),'__Host-otpanda_google_link=1']};
 for(const [name,[url,cookie]] of Object.entries(cases)){const r=await x.runtime.fetch(new Request(url,{headers:{cookie}}));assert.equal(r.status,303,name);const h=new URL(r.headers.get('location')).hash;assert.equal(h,'#link=restart&state=',name);assert.equal(h.includes('auth'),false);const c=r.headers.getSetCookie().join(';');assert.ok(c.includes('__Host-otpanda_google_link=;'),name);assert.ok(c.includes('__Host-otpanda_google=;'),name);noSessionCookies(r);}
 // provider cancel after the row is found: still a link failure with the app state, marker cleared
 const x2=await setup(),t2=(await(await x2.ticket()).json()).ticket,s2=await x2.start(t2),st=new URL(s2.headers.get('location')).searchParams.get('state'),r2=await x2.runtime.fetch(new Request(API+'/auth/callback?'+new URLSearchParams({error:'access_denied',state:st}),{headers:{cookie:s2.headers.getSetCookie().map(c=>c.split(';')[0]).join('; ')}}));assert.equal(new URL(r2.headers.get('location')).hash,'#link=restart&state='+STATE);assert.ok(r2.headers.getSetCookie().join(';').includes('__Host-otpanda_google_link=;'));
});
test('start address limit fails closed before the ticket is spent; missing address fails closed too',async()=>{
 const x=await setup(),t=(await(await x.ticket()).json()).ticket,r=await x.start(t,{noAddress:true});assert.equal(new URL(r.headers.get('location')).hash,'#link=restart&state=');assert.equal(x.q('SELECT count(*) n FROM google_link_tickets').n,1,'ticket not spent');
 const y=await setup();for(let i=0;i<60;i++)await y.start('y'.repeat(43));const t2=(await(await y.ticket()).json()).ticket;assert.equal(new URL((await y.start(t2)).headers.get('location')).hash,'#link=restart&state=');assert.equal(y.q('SELECT count(*) n FROM google_link_tickets').n,1);
});
test('ordinary sign-in is unaffected by a stale or parallel link marker, and an ordinary start clears the marker',async()=>{
 const x=await setup({linked:true}),start=await x.runtime.fetch(new Request(API+'/auth/google/start?'+new URLSearchParams({challenge:await oauth.calculatePKCECodeChallenge('v'.repeat(43)),state:'q'.repeat(43),redirect_uri:APP+'/app/',remember:'no'}),{headers:{cookie:'__Host-otpanda_google_link=1'}}));
 assert.equal(start.status,303);assert.ok(start.headers.getSetCookie().join(';').includes('__Host-otpanda_google_link=;'));
 const cookies=start.headers.getSetCookie().map(c=>c.split(';')[0]).filter(c=>c.startsWith('__Host-otpanda_google=')).join('; ');
 // an ordinary transaction that fails (provider error) after its row is found keeps the ordinary #auth result even if a marker is present
 const st=new URL(start.headers.get('location')).searchParams.get('state'),r=await x.runtime.fetch(new Request(API+'/auth/callback?'+new URLSearchParams({error:'access_denied',state:st}),{headers:{cookie:cookies+'; __Host-otpanda_google_link=1'}}));
 assert.equal(new URL(r.headers.get('location')).hash.startsWith('#auth=restart'),true);
});

test('a callback after the 300s transaction TTL but inside the 1800s marker life is a link restart, never #auth',async()=>{
 const x=await setup(),t=(await(await x.ticket()).json()).ticket,s=await x.start(t),sc=s.headers.getSetCookie(),max=n=>Number(/Max-Age=(\d+)/i.exec(sc.find(c=>c.startsWith(n)))[1]);
 assert.equal(max('__Host-otpanda_google='),300);assert.equal(max('__Host-otpanda_google_link='),1800);
 x.advance(400000); // binding cookie has expired in a real browser (300s), the marker has not (600s)
 const state=new URL(s.headers.get('location')).searchParams.get('state'),url=API+'/auth/callback?'+new URLSearchParams({code:'c',state});
 for(const cookie of ['__Host-otpanda_google_link=1','__Host-otpanda_google_link=1; '+sc.map(c=>c.split(';')[0]).find(c=>c.startsWith('__Host-otpanda_google='))]){const r=await x.runtime.fetch(new Request(url,{headers:{cookie}}));assert.equal(new URL(r.headers.get('location')).hash,'#link=restart&state=');}
});

test('a junk or replayed link start clears no cookie, so it cannot disturb an ordinary login in progress',async()=>{
 const x=await setup(),ordinary='__Host-otpanda_google=ordinary-binding; __Host-otpanda_browser=b; __Host-otpanda_device=d';
 for(const url of [API+'/auth/google/link/start?ticket='+'j'.repeat(43),API+'/auth/google/link/start',API+'/auth/google/link/start?ticket=x&y=1']){const r=await x.runtime.fetch(new Request(url,{headers:{cookie:ordinary}}),{clientAddress:'192.0.2.1'});assert.equal(r.status,303);assert.equal(r.headers.get('location').includes('link=restart'),true);assert.equal(r.headers.getSetCookie().length,0,url);}
 const none=await x.runtime.fetch(new Request(API+'/auth/google/link/start?ticket='+'j'.repeat(43)),{});assert.equal(none.headers.getSetCookie().length,0);
});
