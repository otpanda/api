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
const limiter=(name,log,ok=true)=>({limit:async()=>{log.push(name);return {success:ok};}});
const req=(path,{method='GET',headers={},body}={})=>{const r=new Request(API+path,{method,headers:{'CF-Connecting-IP':'192.0.2.1',...headers},...(body?{body}:{})});Object.defineProperty(r,'cf',{value:{colo:'LHR',httpProtocol:'HTTP/2',tlsVersion:'TLSv1.3'}});return r;};
function world({realtime=true,drop=[]}={}){
 const raw=database(),meter=createQueryMeter(raw),calls=[],stub={n:0,connects:0},nsCalls=[];
 const ns={idFromName:n=>n,get:id=>({fetch:async(u,init)=>{const url=typeof u==='string'?u:u.url;if(url.endsWith('/connect'))stub.connects++;else stub.n++;nsCalls.push(url);return new Response(null,{status:url.endsWith('/connect')?200:204});}})};
 const env={DEPLOYMENT_STAGE:'auth-only',AUTH_ONLY_SIGNUP_EMAIL:'owner@example.test',DB:meter.db,BREVO_API_KEY:'synthetic',BREVO_SENDER_EMAIL:'project@example.test',BREVO_REPLY_TO_EMAIL:'project@example.test'};
 for(const k of ['SIGNUP_ADDRESS_LIMIT','SIGNUP_GLOBAL_LIMIT','SIGNUP_VERIFY_ADDRESS_LIMIT','SIGNUP_VERIFY_GLOBAL_LIMIT','IDENTITY_ADDRESS_LIMIT','IDENTITY_AUTH_GLOBAL_LIMIT','IDENTITY_READ_GLOBAL_LIMIT'])env[k]=limiter(k,calls);
 if(realtime){env.REALTIME_HUB=ns;env.REALTIME_ADDRESS_LIMIT=limiter('REALTIME_ADDRESS_LIMIT',calls);env.REALTIME_GLOBAL_LIMIT=limiter('REALTIME_GLOBAL_LIMIT',calls);env.REALTIME_TICKET_LIMIT=limiter('REALTIME_TICKET_LIMIT',calls);}
 for(const k of drop)delete env[k];
 return {raw,meter,calls,stub,env,nsCalls};
}
async function account(raw,email='a@example.com'){
 const identity=new AccountIdentityService(raw),signup=new PasskeySignupService(raw),a=authenticator();
 const e=await identity.issueEmailChallenge({purpose:'signup-email',email}),c=await signup.begin({email,emailToken:e.token,binding:'rt-'+email});
 const proof=await signup.finish({token:c.token,binding:'rt-'+email,response:a.registration({expected:c.options.challenge})});
 const issued=await new DeviceSessionService(raw).issue({proof:{...proof,purpose:'authenticate',verifiedAt:Date.now()},clientKind:'web'});
 return {ownerId:proof.ownerId,access:issued.access};
}
const pre=(worker,env,path,method='POST',headers='authorization')=>worker.fetch(req(path,{method:'OPTIONS',headers:{Origin:APP,'Access-Control-Request-Method':method,'Access-Control-Request-Headers':headers}}),env,{waitUntil(){}});
test('without the full set of realtime bindings the realtime paths do not exist, preflight included, and nothing is charged',async()=>{
 for(const drop of [[],['REALTIME_HUB'],['REALTIME_ADDRESS_LIMIT'],['REALTIME_GLOBAL_LIMIT'],['REALTIME_TICKET_LIMIT']]){
  const w=world({realtime:drop.length===0?false:true,drop}),worker=createAuthOnlyWorker();
  for(const path of ['/auth/realtime/ticket','/auth/realtime']){assert.equal((await pre(worker,w.env,path)).status,404,path+' preflight '+drop);assert.equal((await worker.fetch(req(path,{method:path.endsWith('ticket')?'POST':'GET',headers:{Origin:APP}}),w.env,{waitUntil(){}})).status,404,path+drop);}
  assert.equal(w.calls.length+w.meter.count()+w.stub.n,0,'nothing charged: '+drop);w.raw.sqlite.close();}
});
test('with all bindings: pure preflight, dedicated limiters only (2 edge + 1 ticket), the hub receives the upgrade, one use, other routes unchanged',async()=>{
 const w=world(),worker=createAuthOnlyWorker(),{access}=await account(w.raw);w.calls.length=0;const q0=w.meter.count();
 assert.equal((await pre(worker,w.env,'/auth/realtime/ticket')).status,204);assert.equal(w.calls.length+w.meter.count()-q0,0,'preflight is pure');
 assert.equal((await pre(worker,w.env,'/auth/realtime/ticket','POST','authorization, content-type')).status,403);
 const ctx={waitUntil(){}};
 const minted=await worker.fetch(req('/auth/realtime/ticket',{method:'POST',headers:{Origin:APP,Authorization:'Bearer '+access}}),w.env,ctx);assert.equal(minted.status,200);const t=await minted.json();
 assert.deepEqual(w.calls.filter(c=>c.startsWith('REALTIME')).sort(),['REALTIME_ADDRESS_LIMIT','REALTIME_GLOBAL_LIMIT','REALTIME_TICKET_LIMIT'],'one of each dedicated limiter');
 assert.equal(w.calls.filter(c=>c.startsWith('IDENTITY')||c.startsWith('SIGNUP')).length,0,'the shared auth/read/signup pools are never charged');
 const up=await worker.fetch(req('/auth/realtime',{headers:{Origin:APP,Upgrade:'websocket','Sec-WebSocket-Protocol':'otpanda.v1, '+t.ticket}}),w.env,ctx);assert.equal(up.status,200);assert.equal(w.stub.connects,1);
 assert.equal((await worker.fetch(req('/auth/realtime',{headers:{Origin:APP,Upgrade:'websocket','Sec-WebSocket-Protocol':'otpanda.v1, '+t.ticket}}),w.env,ctx)).status,401,'ticket is single use');
 assert.equal(typeof RealtimeHub,'function');assert.equal(REALTIME_CRON,'*/5 * * * *');w.raw.sqlite.close();});
test('relevant identity write through the PUBLIC entry: every counted call (edge limiter bindings + D1 + hub stubs) stays within the combined 45, at the foreground ceiling of 10 hub calls',async()=>{
 const w=world(),worker=createAuthOnlyWorker(),{ownerId,access}=await account(w.raw);
 const ids=Array.from({length:60},(_,i)=>'f'+String(i).padStart(3,'0'));
 for(const id of ids){w.raw.sqlite.prepare('INSERT INTO accounts(owner_id,created_at) VALUES (?,?)').run(id,Date.now());w.raw.sqlite.prepare('INSERT INTO realtime_activity VALUES (?,?)').run(id,Date.now()-1000);}
 w.raw.sqlite.prepare('INSERT OR REPLACE INTO realtime_activity VALUES (?,?)').run(ownerId,Date.now()-1000);
 w.raw.sqlite.prepare('DELETE FROM realtime_outbox').run();w.raw.sqlite.prepare("INSERT INTO realtime_outbox(kind,account_id,payload,created_at) VALUES ('accounts',?,?,?)").run(ownerId,JSON.stringify(ids),Date.now());
 const waits=[],ctx={waitUntil:p=>waits.push(p)};w.calls.length=0;const q0=w.meter.count();
 const res=await worker.fetch(req('/v1/manage/organization',{method:'PUT',headers:{Origin:APP,Authorization:'Bearer '+access,'Content-Type':'application/json'},body:JSON.stringify({revision:0,document:{tags:[{id:'t',label:'W'}],entries:[]}})}),w.env,ctx);
 assert.equal(res.status,200);await Promise.all(waits);
 const edge=w.calls.length,d1=w.meter.count()-q0,hub=w.stub.n,total=edge+d1+hub;
 assert.equal(w.calls.filter(c=>c.startsWith('REALTIME')).length,0,'the drain never touches the ticket/upgrade limiters');
 assert.ok(edge<=3,'identity pre-runtime overhead is the shared edge limiter calls, counted: '+w.calls.join());
 assert.ok(hub>0&&hub<=10,'foreground hub calls '+hub);assert.ok(total<=COMBINED_CEILING,`measured ${edge} edge + ${d1} D1 + ${hub} hub = ${total}`);
 console.log(`# measured through public entry: ${edge} edge limiter calls (${[...new Set(w.calls)].join('+')}), ${d1} D1 queries, ${hub} hub calls = ${total} of 45`);
 w.raw.sqlite.close();});
test('Google routes and refresh-replay paths are not foreground writers: no drain is scheduled for them (cron-only)',async()=>{
 const w=world(),worker=createAuthOnlyWorker(),waits=[],ctx={waitUntil:p=>waits.push(p)};
 for(const [p,m] of [['/auth/restore','GET'],['/auth/callback','GET'],['/v1/manage/session','GET']])await worker.fetch(req(p,{method:m,headers:{Origin:APP}}),w.env,ctx);
 assert.equal(waits.length,0);w.raw.sqlite.close();});
test('cron: */5 drains only with the hub bound, in its own invocation, within 20 D1 + 25 hub; */15 never drains',async()=>{
 const w=world(),worker=createAuthOnlyWorker(),{ownerId}=await account(w.raw);
 const ids=Array.from({length:80},(_,i)=>'g'+String(i).padStart(3,'0'));
 for(const id of ids){w.raw.sqlite.prepare('INSERT INTO accounts(owner_id,created_at) VALUES (?,?)').run(id,Date.now());w.raw.sqlite.prepare('INSERT INTO realtime_activity VALUES (?,?)').run(id,Date.now()-1000);}
 w.raw.sqlite.prepare('DELETE FROM realtime_outbox').run();w.raw.sqlite.prepare("INSERT INTO realtime_outbox(kind,account_id,payload,created_at) VALUES ('accounts',?,?,?)").run(ownerId,JSON.stringify(ids),Date.now());
 const waits=[],ctx={waitUntil:p=>waits.push(p)},q0=w.meter.count();
 await worker.scheduled({cron:'*/15 * * * *'},w.env,ctx);await Promise.all(waits);assert.equal(w.stub.n,0,'*/15 cleanup never delivers');waits.length=0;
 const noHub={...w.env};delete noHub.REALTIME_HUB;await worker.scheduled({cron:REALTIME_CRON},noHub,ctx);await Promise.all(waits);assert.equal(w.stub.n,0,'no hub bound: nothing runs');waits.length=0;
 const q1=w.meter.count();await worker.scheduled({cron:REALTIME_CRON},w.env,ctx);await Promise.all(waits);
 assert.ok(w.meter.count()-q1<=20,'cron D1 '+(w.meter.count()-q1));assert.ok(w.stub.n>0&&w.stub.n<=25,'cron hub '+w.stub.n);assert.ok((w.meter.count()-q1)+w.stub.n<=COMBINED_CEILING);w.raw.sqlite.close();});
