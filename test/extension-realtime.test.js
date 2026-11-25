import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { PasskeySignupService } from '../src/passkey-signup.js';
import { AccountIdentityService } from '../src/account-identity.js';
import { DeviceSessionService } from '../src/device-sessions.js';
import { authenticator } from './passkey-fixture.js';
import { createRealtimeHttp,MAX_TICKETS } from '../src/realtime-http.js';
const NOW=1_800_000_000_000,API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io';
const EXT='chrome-extension://abcdefghijklmnopabcdefghijklmnop',OTHER='chrome-extension://ponmlkjihgfedcbaponmlkjihgfedcba';
async function fx(limit=async()=>({success:true})){
 const db=database(),clock=()=>NOW,keys=[];
 const identity=new AccountIdentityService(db,{clock}),signup=new PasskeySignupService(db,{clock});const {token}=await identity.issueEmailChallenge({purpose:'signup-email',email:'a@example.com'});
 const c=await signup.begin({email:'a@example.com',emailToken:token,binding:'binding'}),a=authenticator();
 const account=await signup.finish({token:c.token,binding:'binding',response:a.registration({expected:c.options.challenge})});
 const sessions=new DeviceSessionService(db,{clock}),proof={...account,verifiedAt:NOW,purpose:'authenticate'};
 const web=await sessions.issue({proof,clientKind:'web'}),android=await sessions.issue({proof,clientKind:'android'}),ext=await sessions.issue({proof,clientKind:'extension'});
 const limiter={limit:async({key})=>{keys.push(key);return limit({key});}},connects=[];
 const connect=async(info)=>{connects.push(info);return new Response('ws');};
 const mk=o=>createRealtimeHttp({db,sessions,limiter,clock,connect,...o});
 const extH=mk({extension:true,extensionOrigins:[EXT]}),webH=mk({}),natH=mk({native:true});
 const call=(h,path,init={},origin)=>h.fetch(new Request(API+path,{...init,headers:{...(origin?{Origin:origin}:{}),...(init.headers??{})}}),{clientAddress:'t'});
 const mint=(tok,origin,h=extH,path='/auth/extension/realtime/ticket')=>call(h,path,{method:'POST',headers:{Authorization:'Bearer '+tok}},origin);
 const up=(ticket,origin,h=extH,path='/auth/extension/realtime')=>call(h,path,{method:'GET',headers:{Upgrade:'websocket','Sec-WebSocket-Protocol':'otpanda.v1, '+ticket}},origin);
 const n=()=>db.sqlite.prepare('SELECT count(*) n FROM realtime_tickets').get().n;
 return {db,sessions,web,android,ext,proof,extH,webH,natH,mint,up,n,keys,connects,call};
}
test('extension mint: extension-kind handle only; no CORS headers or preflight; Origin absent or exactly the pinned one; web/android handles and other origins mint nothing',async()=>{
 const f=await fx();
 for(const o of [undefined,EXT]){const r=await f.mint(f.ext.access,o);assert.equal(r.status,200);assert.equal(r.headers.get('cache-control'),'no-store');assert.deepEqual([...r.headers.keys()].filter(k=>k.startsWith('access-control')||k==='vary'),[]);const t=await r.json();assert.match(t.ticket,/^rt1\./);assert.equal(t.closeAt,f.ext.accessExpiresAt);}
 const before=f.n();assert.equal(before,2);
 for(const o of [APP,'https://evil.test',OTHER,'moz-extension://abcdefgh-1234','null'])assert.equal((await f.mint(f.ext.access,o)).status,403,String(o));
 for(const t of [f.web.access,f.android.access])for(const o of [undefined,EXT])assert.equal((await f.mint(t,o)).status,401);
 const pre=await f.call(f.extH,'/auth/extension/realtime/ticket',{method:'OPTIONS',headers:{'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'authorization'}},EXT);assert.equal(pre.status,403);assert.deepEqual([...pre.headers.keys()].filter(k=>k.startsWith('access-control')),[]);
 assert.equal((await f.call(f.extH,'/auth/extension/realtime/ticket?x=1',{method:'POST',headers:{Authorization:'Bearer '+f.ext.access}})).status,404);
 assert.equal((await f.call(f.extH,'/auth/realtime/ticket',{method:'POST',headers:{Authorization:'Bearer '+f.ext.access}})).status,404,'extension instance does not serve the old paths');
 assert.equal(f.n(),before,'refusals mint nothing');f.db.sqlite.close();});
test('kind crossings: an extension handle never mints on web/android paths; web/android handles never on the extension path; tickets never redeem across kinds',async()=>{
 const f=await fx();
 assert.equal((await f.mint(f.ext.access,APP,f.webH,'/auth/realtime/ticket')).status,401);assert.equal((await f.mint(f.ext.access,undefined,f.natH,'/auth/realtime/ticket')).status,401);
 assert.equal(f.n(),0);
 const extT=(await (await f.mint(f.ext.access)).json()).ticket,webT=(await (await f.mint(f.web.access,APP,f.webH,'/auth/realtime/ticket')).json()).ticket,andT=(await (await f.mint(f.android.access,undefined,f.natH,'/auth/realtime/ticket')).json()).ticket;
 assert.equal(f.n(),3);
 assert.equal((await f.up(extT,APP,f.webH,'/auth/realtime')).status,401,'extension ticket on web upgrade');assert.equal((await f.up(extT,undefined,f.natH,'/auth/realtime')).status,401,'extension ticket on native upgrade');
 assert.equal((await f.up(webT)).status,401);assert.equal((await f.up(andT)).status,401);
 assert.equal(f.n(),3,'a refused cross-kind redeem burns nothing');assert.equal(f.connects.length,0);
 assert.equal((await f.up(extT)).status,200);assert.equal(f.n(),2);f.db.sqlite.close();});
test('extension upgrade: Origin absent or exactly pinned; APP, http(s), other extension, moz-extension refused without burning the ticket; ticket never reaches the hub or a CORS header; one winner',async()=>{
 const f=await fx(),t=(await (await f.mint(f.ext.access)).json()).ticket;
 for(const o of [APP,'https://evil.test',OTHER,'moz-extension://abcdefgh-1234'])assert.equal((await f.up(t,o)).status,403,o);
 assert.equal(f.n(),1,'refused origin does not burn the ticket');
 const rs=await Promise.all([f.up(t,EXT),f.up(t),f.up(t,EXT)]);assert.equal(rs.filter(r=>r.status===200).length,1);
 assert.deepEqual(f.connects,[{ownerId:f.proof.ownerId,deviceId:f.ext.deviceId,closeAt:f.ext.accessExpiresAt}],'the hub gets only owner, device and closeAt, never the ticket');
 for(const r of rs)assert.deepEqual([...r.headers.keys()].filter(k=>k.startsWith('access-control')||k==='sec-websocket-protocol'),[],'no CORS and the handler never echoes a subprotocol (the hub selects otpanda.v1 alone)');
 for(const proto of ['rt1.'+'a'.repeat(16)+'.'+'b'.repeat(43),'otpanda.v1','otpanda.v1, x, y','other, rt1.'+'a'.repeat(16)+'.'+'b'.repeat(43)])assert.equal((await f.call(f.extH,'/auth/extension/realtime',{method:'GET',headers:{Upgrade:'websocket','Sec-WebSocket-Protocol':proto}})).status,400,proto);
 assert.equal((await f.call(f.extH,'/auth/extension/realtime?ticket='+t,{method:'GET',headers:{Upgrade:'websocket'}})).status,404);
 f.db.sqlite.close();});
test('extension tickets: revoked device and security generation bump refuse redeem; revoke queues the device close; cap and per-extension limiter keys',async()=>{
 let f=await fx(),t=(await (await f.mint(f.ext.access)).json()).ticket;
 assert.equal(await f.sessions.revoke({ownerId:f.proof.ownerId,deviceId:f.ext.deviceId}),true);assert.equal((await f.up(t)).status,401);assert.equal(f.connects.length,0);
 assert.ok(f.db.sqlite.prepare("SELECT count(*) n FROM realtime_outbox WHERE kind='device' AND device_id=?").get(f.ext.deviceId).n>=1,'device close hint queued for the extension device');f.db.sqlite.close();
 f=await fx();t=(await (await f.mint(f.ext.access)).json()).ticket;f.db.sqlite.prepare('UPDATE account_security SET generation=generation+1').run();assert.equal((await f.up(t)).status,401);assert.equal((await f.mint(f.ext.access)).status,401);f.db.sqlite.close();
 f=await fx();for(let i=0;i<MAX_TICKETS;i++)assert.equal((await f.mint(f.ext.access)).status,200);assert.equal((await f.mint(f.ext.access)).status,429);
 assert.equal((await f.mint(f.web.access,APP,f.webH,'/auth/realtime/ticket')).status,200,'extension cap does not consume the web device cap');
 assert.ok(f.keys.filter(k=>k.startsWith('ext-')).length>=MAX_TICKETS&&f.keys.some(k=>!k.startsWith('ext-')),'extension limiter keys are prefixed apart from web/android');f.db.sqlite.close();
 f=await fx(async()=>({success:false}));assert.equal((await f.mint(f.ext.access)).status,429);assert.equal(f.n(),0);f.db.sqlite.close();
 const g=await fx();const bare=createRealtimeHttp({db:g.db,sessions:g.sessions,clock:()=>NOW,connect:async()=>new Response(),extension:true,extensionOrigins:[EXT]});
 assert.equal((await g.mint(g.ext.access,undefined,bare)).status,503,'no limiter binding fails closed');g.db.sqlite.close();});
test('extension mode misconfiguration fails at construction',async()=>{
 const f=await fx();assert.throws(()=>createRealtimeHttp({db:f.db,sessions:f.sessions,connect:async()=>{},extension:true,native:true,extensionOrigins:[EXT]}),TypeError);
 assert.throws(()=>createRealtimeHttp({db:f.db,sessions:f.sessions,connect:async()=>{},extension:true,extensionOrigins:['https://x.test']}),TypeError);f.db.sqlite.close();});
