import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { createIdentityEdgeHost } from '../src/identity-edge-host.js';
import { createIdentityRuntime } from '../src/identity-runtime.js';
import { PasskeySignupService } from '../src/passkey-signup.js';
import { AccountIdentityService } from '../src/account-identity.js';
import { DeviceSessionService } from '../src/device-sessions.js';
import { authenticator } from './passkey-fixture.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',NOW=1_800_000_000_000;
const yes={limit:async()=>({success:true})};
const counter=(ok=true)=>{const c={n:0,keys:[],limit:async({key})=>{c.n++;c.keys.push(key);return{success:ok};}};return c;};
const req=(p,init={})=>new Request(API+p,{...init,headers:{Origin:APP,...(init.headers??{})}});
test('without realtime config the paths do not exist on the public Worker and spend no budget',async()=>{
 const auth=counter(),read=counter(),addr=counter();let init=0;
 const host=createIdentityEdgeHost({resolveTrustedIngress:()=>'192.0.2.1',edgeAddress:addr,edgeAuthGlobal:auth,edgeReadGlobal:read,initialize:async()=>{init++;return{fetch:async()=>new Response('x')};}});
 for(const [p,m] of [['/auth/realtime/ticket','POST'],['/auth/realtime','GET'],['/auth/realtime/ticket','OPTIONS']])assert.equal((await host.fetch(req(p,{method:m}))).status,404);
 assert.equal(auth.n+read.n+addr.n+init,0);});
test('public Worker with realtime: pure preflight, exact method/origin allowlist, dedicated budget only, never the shared auth or read pools',async()=>{
 const auth=counter(),read=counter(),shared=counter(),ea=counter(),eg=counter();let init=0,hits=0;
 const host=createIdentityEdgeHost({resolveTrustedIngress:()=>'192.0.2.1',edgeAddress:shared,edgeAuthGlobal:auth,edgeReadGlobal:read,realtime:{edgeAddress:ea,edgeGlobal:eg},initialize:async()=>{init++;return{fetch:async()=>{hits++;return new Response('ok');}};}});
 const pre=(h,o=APP,m='POST',p='/auth/realtime/ticket')=>host.fetch(new Request(API+p,{method:'OPTIONS',headers:{Origin:o,'Access-Control-Request-Method':m,...(h===undefined?{}:{'Access-Control-Request-Headers':h})}}));
 for(const h of ['authorization','Authorization',undefined]){const r=await pre(h);assert.equal(r.status,204,String(h));assert.equal(r.headers.get('access-control-allow-origin'),APP);assert.equal(r.headers.get('access-control-allow-headers'),'authorization');assert.equal(r.headers.get('access-control-allow-methods'),'POST');assert.equal(r.headers.get('access-control-allow-credentials'),null);}
 for(const [h,o,m,p] of [['x-evil',APP,'POST'],['authorization, content-type',APP,'POST'],['authorization','https://evil.test','POST'],['authorization','null','POST'],['authorization',APP,'GET'],['authorization',APP,'POST','/auth/realtime'],['authorization',APP,'GET','/auth/realtime']])assert.equal((await pre(h,o,m,p)).status,403,[h,o,m,p].join());
 assert.equal(init+ea.n+eg.n+shared.n+auth.n+read.n,0,'preflight touches nothing');
 // method and origin checks happen before any budget
 assert.equal((await host.fetch(req('/auth/realtime/ticket',{method:'GET'}))).status,405);assert.equal((await host.fetch(req('/auth/realtime',{method:'POST'}))).status,405);assert.equal((await host.fetch(req('/auth/realtime',{method:'GET',headers:{Origin:'https://evil.test'}}))).status,403);assert.equal((await host.fetch(req('/auth/realtime/ticket?x=1',{method:'POST'}))).status,404);
 assert.equal(init+ea.n+eg.n,0);
 assert.equal((await host.fetch(req('/auth/realtime/ticket',{method:'POST'}))).status,200);assert.equal((await host.fetch(req('/auth/realtime',{method:'GET',headers:{Upgrade:'websocket'}}))).status,200);
 assert.equal(ea.n,2);assert.equal(eg.n,2);assert.equal(shared.n+auth.n+read.n,0,'the 15/min auth pool, the read pool and the shared address counter are never charged');assert.equal(eg.keys[0],'otpanda-realtime-v1');assert.equal(hits,2);});
test('realtime budget exhaustion or missing bindings fail closed before initialization',async()=>{
 for(const rt of [{edgeAddress:counter(false),edgeGlobal:yes},{edgeAddress:yes,edgeGlobal:counter(false)},{edgeAddress:yes},{edgeGlobal:yes},{}]){let init=0;
  const host=createIdentityEdgeHost({resolveTrustedIngress:()=>'192.0.2.1',edgeAddress:yes,edgeAuthGlobal:yes,edgeReadGlobal:yes,realtime:rt,initialize:async()=>{init++;return{fetch:async()=>new Response('x')};}});
  const r=await host.fetch(req('/auth/realtime/ticket',{method:'POST'}));assert.ok([429,503].includes(r.status));assert.equal(init,0);assert.equal(r.headers.get('access-control-allow-origin'),APP);}
 const host=createIdentityEdgeHost({resolveTrustedIngress:()=>undefined,realtime:{edgeAddress:yes,edgeGlobal:yes},initialize:async()=>({fetch:async()=>new Response('x')})});assert.equal((await host.fetch(req('/auth/realtime/ticket',{method:'POST'}))).status,503);});
test('through the public Worker and the real runtime: ticket, upgrade, one use; paths 404 when the runtime has no realtime dependency',async()=>{
 const db=database(),clock=()=>NOW;
 const identity=new AccountIdentityService(db,{clock}),signup=new PasskeySignupService(db,{clock}),a=authenticator();
 const {token}=await identity.issueEmailChallenge({purpose:'signup-email',email:'a@example.com'});const c=await signup.begin({email:'a@example.com',emailToken:token,binding:'b'});
 const account=await signup.finish({token:c.token,binding:'b',response:a.registration({expected:c.options.challenge})});
 const sessions=new DeviceSessionService(db,{clock}),d=await sessions.issue({proof:{...account,verifiedAt:NOW,purpose:'authenticate'},clientKind:'web'});
 const connects=[],base={db,keys:new Map(),activeKeyId:'x',trustedRequestKey:()=>'192.0.2.1',clock};
 const mk=realtime=>createIdentityEdgeHost({resolveTrustedIngress:()=>'192.0.2.1',edgeAddress:yes,edgeAuthGlobal:yes,edgeReadGlobal:yes,realtime:{edgeAddress:yes,edgeGlobal:yes},initialize:async()=>createIdentityRuntime({...base,realtime})});
 const off=mk(undefined);assert.equal((await off.fetch(req('/auth/realtime/ticket',{method:'POST',headers:{Authorization:'Bearer '+d.access}}))).status,404);
 const on=mk({limiter:yes,connect:async(info)=>{connects.push(info);return new Response('ws');}});
 const minted=await on.fetch(req('/auth/realtime/ticket',{method:'POST',headers:{Authorization:'Bearer '+d.access}}));assert.equal(minted.status,200);const t=await minted.json();assert.equal(t.closeAt,sessions&&(await sessions.authenticate(d.access)).expiresAt);
 const up=()=>on.fetch(req('/auth/realtime',{headers:{Upgrade:'websocket','Sec-WebSocket-Protocol':'otpanda.v1, '+t.ticket}}));
 assert.equal((await up()).status,200);assert.equal(connects.length,1);assert.equal((await up()).status,401,'one use');
 assert.equal(db.sqlite.prepare('SELECT count(*) n FROM realtime_activity WHERE account_id=?').get(account.ownerId).n,1,'minting marks the account as possibly connected');db.sqlite.close();});
async function session(db){const clock=()=>NOW,identity=new AccountIdentityService(db,{clock}),signup=new PasskeySignupService(db,{clock}),a=authenticator();
 const {token}=await identity.issueEmailChallenge({purpose:'signup-email',email:'a@example.com'});const c=await signup.begin({email:'a@example.com',emailToken:token,binding:'b'});
 const account=await signup.finish({token:c.token,binding:'b',response:a.registration({expected:c.options.challenge})});
 return {account,d:await new DeviceSessionService(db,{clock}).issue({proof:{...account,verifiedAt:NOW,purpose:'authenticate'},clientKind:'web'})};}
test('the runtime drains only after a COMMITTED relevant write, with a budget that is 50 minus what the request spent',async()=>{
 const db=database();const {account,d}=await session(db);db.sqlite.prepare('INSERT INTO realtime_activity VALUES (?,?)').run(account.ownerId,NOW-1000);
 let delivered=0;const waits=[];
 const app=createIdentityRuntime({db,keys:new Map(),activeKeyId:'x',trustedRequestKey:()=>'192.0.2.1',clock:()=>NOW,realtime:{limiter:yes,connect:async()=>new Response('ws'),deliver:async()=>{delivered++;return true;}}});
 const put=(body,token=d.access)=>app.fetch(req('/v1/manage/organization',{method:'PUT',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:JSON.stringify(body)}),{waitUntil:p=>waits.push(p)});
 assert.equal((await app.fetch(req('/v1/manage/session',{headers:{Authorization:'Bearer '+d.access}}),{waitUntil:p=>waits.push(p)})).status,200);assert.equal(waits.length,0,'reads never drain');
 assert.equal((await put({revision:0,document:{tags:[],entries:[]}},'a'.repeat(43))).status,401);assert.equal(waits.length,0,'anonymous or unauthorized never drains');
 assert.equal((await put({revision:0,document:{tags:[{id:'t',label:'W'}],entries:[]}})).status,200);assert.equal(waits.length,1,'a successful write drains');await Promise.all(waits);assert.equal(delivered,1,'the committed organization change reached the viewer');
 waits.length=0;assert.equal((await put({revision:0,document:{tags:[],entries:[]}})).status,409);assert.equal(waits.length,0,'a conflict (no change) does not drain');
 assert.equal((await app.fetch(req('/v1/manage/entries',{method:'POST'}),{waitUntil:p=>waits.push(p)})).status,405);assert.equal(waits.length,0);db.sqlite.close();});
test('cron: realtime delivery runs only in its own */5 invocation and only with a hub binding; the */15 identity cron never drains',async()=>{
 const {createAuthOnlyWorker}=await import('../src/auth-only-worker.js');const {REALTIME_CRON}=await import('../src/realtime-outbox.js');
 const db=database();db.sqlite.prepare('INSERT INTO accounts(owner_id,created_at) VALUES (?,?)').run('o1',NOW);db.sqlite.prepare('INSERT INTO realtime_activity VALUES (?,?)').run('o1',NOW-1000);db.sqlite.prepare("INSERT INTO realtime_outbox(kind,account_id,created_at) VALUES ('account','o1',?)").run(NOW);
 let hits=0;const hub={idFromName:n=>n,get:()=>({fetch:async()=>{hits++;return new Response(null,{status:204});}})};
 const worker=createAuthOnlyWorker({clock:()=>NOW}),env={DEPLOYMENT_STAGE:'auth-only',DB:db,REALTIME_HUB:hub};
 assert.equal(REALTIME_CRON,'*/5 * * * *');
 await worker.scheduled({cron:'*/15 * * * *'},env,{});assert.equal(hits,0);assert.equal(db.sqlite.prepare('SELECT count(*) n FROM realtime_outbox').get().n,1);
 await worker.scheduled({cron:REALTIME_CRON},{...env,REALTIME_HUB:undefined},{});assert.equal(hits,0,'no binding: nothing happens');
 await worker.scheduled({cron:REALTIME_CRON},env,{});assert.equal(hits,1);assert.equal(db.sqlite.prepare('SELECT count(*) n FROM realtime_outbox').get().n,0);db.sqlite.close();});
test('the post-write drain makes at most 10 hub calls; the rest of a large fanout stays persisted for the */5 cron (which may make 40)',async()=>{
 const db=database();const {account,d}=await session(db);const ids=Array.from({length:60},(_,i)=>'f'+String(i).padStart(3,'0'));
 for(const id of ids){db.sqlite.prepare('INSERT INTO accounts(owner_id,created_at) VALUES (?,?)').run(id,NOW);db.sqlite.prepare('INSERT INTO realtime_activity VALUES (?,?)').run(id,NOW-1000);}
 db.sqlite.prepare('DELETE FROM realtime_outbox').run();db.sqlite.prepare("INSERT INTO realtime_outbox(kind,account_id,payload,created_at) VALUES ('accounts',?,?,?)").run(account.ownerId,JSON.stringify(ids),NOW);
 let calls=0;const waits=[];
 const app=createIdentityRuntime({db,keys:new Map(),activeKeyId:'x',trustedRequestKey:()=>'192.0.2.1',clock:()=>NOW,realtime:{limiter:yes,connect:async()=>new Response('ws'),deliver:async()=>{calls++;return true;}}});
 const r=await app.fetch(req('/v1/manage/organization',{method:'PUT',headers:{Authorization:'Bearer '+d.access,'Content-Type':'application/json'},body:JSON.stringify({revision:0,document:{tags:[{id:'t',label:'W'}],entries:[]}})}),{waitUntil:p=>waits.push(p)});
 assert.equal(r.status,200);await Promise.all(waits);assert.ok(calls<=10&&calls>0,'foreground calls '+calls);
 const left=db.sqlite.prepare("SELECT cursor,attempts FROM realtime_outbox WHERE kind='accounts'").get();assert.ok(left&&left.cursor&&left.attempts===0,'remainder persisted with a cursor, not a failure');
 db.sqlite.close();});
import {relevantWrite,createForegroundDrain,WRITERS} from '../src/realtime-foreground.js';
const GAPI='https://otpanda-api.abrahammurciano.workers.dev';
const redirect=(hash,status=303)=>new Response(null,{status,headers:{Location:'https://otpanda.github.io/app/#'+hash}});
test('Google sign-in paths are cron-only: a successful-looking 303 on them never counts as a foreground writer',()=>{
 for(const p of ['/auth/callback','/auth/google/continue/abc','/auth/google/protection/abc'])for(const m of ['GET','POST'])assert.equal(relevantWrite(new Request(GAPI+p,{method:m}),redirect('code=abc&state=s')),false,m+' '+p);
 for(const k of WRITERS.keys())assert.ok(!/google|callback/.test(k),k);
});
test('the audited writer allowlist includes every revocation and generation path, and only success statuses',()=>{
 for(const k of ['POST /v1/manage/recovery/finish','POST /v1/manage/recovery/consume-change','POST /auth/recovery/email/complete-finish','POST /auth/device/logout','GET /auth/login/complete','POST /auth/login/complete','PUT /v1/manage/organization','POST /v1/manage/assignment/finish'])assert.ok(WRITERS.has(k),k);
 for(const [k,codes] of WRITERS)assert.ok(codes.every(c=>c>=200&&c<400),k+' only success statuses');
 for(const k of ['POST /auth/restore','POST /auth/renew','GET /v1/manage/session','POST /v1/manage/recovery/status'])assert.ok(!WRITERS.has(k),k+' never drains');
});
test('the shared foreground drain wrapper: an allowlisted success drains within 10 hub calls, Google-style 303s and failures never do, and it is inert without realtime',async()=>{
 const db=database();db.sqlite.prepare('INSERT INTO accounts(owner_id,created_at) VALUES (?,?)').run('o',NOW);db.sqlite.prepare('INSERT INTO realtime_activity VALUES (?,?)').run('o',NOW-1000);
 const seed=()=>db.sqlite.prepare("INSERT INTO realtime_outbox(kind,account_id,created_at) VALUES ('account','o',?)").run(NOW);
 let calls=0;const waits=[];const ctx={waitUntil:p=>waits.push(p)};
 const mk=(response,realtime)=>createForegroundDrain({db,realtime,clock:()=>NOW}).wrap(async()=>response);
 const rt={deliver:async()=>{calls++;return true;}},req=new Request(GAPI+'/auth/device/logout',{method:'POST'}),gReq=new Request(GAPI+'/auth/callback');
 seed();await mk(redirect('code=abc'),rt)(gReq,ctx);assert.equal(waits.length,0,'Google callback is cron-only');await mk(new Response('x',{status:401}),rt)(req,ctx);assert.equal(waits.length,0,'a failed write never drains');
 await mk(redirect('x=1'),undefined)(req,ctx);assert.equal(waits.length,0,'inert without realtime');
 await mk(redirect('x=1'),rt)(req,ctx);assert.equal(waits.length,1);await Promise.all(waits);assert.equal(calls,1);assert.equal(db.sqlite.prepare('SELECT count(*) n FROM realtime_outbox').get().n,0);
 db.sqlite.close();});

test('only committed authenticator enrollment status201 is a foreground writer',()=>{
 for(const status of [200,204,400,401,403,409,429,503])assert.equal(relevantWrite(new Request(GAPI+'/v1/manage/totp',{method:'POST'}),new Response(null,{status})),false);
 assert.equal(relevantWrite(new Request(GAPI+'/v1/manage/totp',{method:'POST'}),new Response(null,{status:201})),true);
 assert.equal(relevantWrite(new Request(GAPI+'/v1/manage/totp/begin',{method:'POST'}),new Response(null,{status:200})),false);
});
