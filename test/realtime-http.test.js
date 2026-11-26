import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { PasskeySignupService } from '../src/passkey-signup.js';
import { AccountIdentityService } from '../src/account-identity.js';
import { DeviceSessionService } from '../src/device-sessions.js';
import { authenticator } from './passkey-fixture.js';
import { createRealtimeHttp,MAX_TICKETS,TICKET_TTL_MS,SOCKET_MAX_MS } from '../src/realtime-http.js';
import { drainOutbox } from '../src/realtime-outbox.js';
const NOW=1_800_000_000_000,API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io';
async function fixture(limiter={limit:async()=>({success:true})}){
 const db=database();let now=NOW;const clock=()=>now;
 const identity=new AccountIdentityService(db,{clock}),signup=new PasskeySignupService(db,{clock});const {token}=await identity.issueEmailChallenge({purpose:'signup-email',email:'a@example.com'});
 const c=await signup.begin({email:'a@example.com',emailToken:token,binding:'binding'}),a=authenticator();
 const account=await signup.finish({token:c.token,binding:'binding',response:a.registration({expected:c.options.challenge})});
 const sessions=new DeviceSessionService(db,{clock}),proof={...account,verifiedAt:NOW,purpose:'authenticate'},d=await sessions.issue({proof,clientKind:'web'});
 const connects=[],http=createRealtimeHttp({db,sessions,limiter,clock,connect:async(info,req)=>{connects.push(info);return new Response('ws',{status:200});}});
 const run=(path,init={},headers={})=>http.fetch(new Request(API+path,{...init,headers:{Origin:APP,...(init.headers??{}),...headers}}),{clientAddress:'t'});
 const mint=(token=d.access)=>run('/auth/realtime/ticket',{method:'POST',headers:{Authorization:'Bearer '+token}});
 const upgrade=(ticket,extra={})=>run('/auth/realtime',{method:'GET',headers:{Upgrade:'websocket','Sec-WebSocket-Protocol':'otpanda.v1, '+ticket,...extra}});
 return {db,sessions,d,proof,http,connects,run,mint,upgrade,setNow:v=>now=v,clock,account};
}
test('mint: strict Origin/method/no body/bearer, CORS preflight, returns a one-use ticket bound to the access handle expiry; only a digest is stored',async()=>{
 const f=await fixture();
 let r=await f.run('/auth/realtime/ticket',{method:'OPTIONS',headers:{'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'authorization'}});assert.equal(r.status,204);assert.equal(r.headers.get('access-control-allow-headers'),'Authorization');assert.equal(r.headers.get('access-control-allow-credentials'),null);
 for(const bad of ['x-evil','authorization, content-type'])assert.equal((await f.run('/auth/realtime/ticket',{method:'OPTIONS',headers:{'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':bad}})).status,403);
 assert.equal((await f.run('/auth/realtime/ticket',{method:'POST',headers:{Authorization:'Bearer '+f.d.access,Origin:'https://evil.test'}})).status,403);
 assert.equal((await f.run('/auth/realtime/ticket',{method:'GET',headers:{Authorization:'Bearer '+f.d.access}})).status,405);
 assert.equal((await f.run('/auth/realtime/ticket',{method:'POST'})).status,401);assert.equal((await f.mint('otpda_'+'A'.repeat(60))).status,401);
 assert.equal((await f.run('/auth/realtime/ticket?x=1',{method:'POST',headers:{Authorization:'Bearer '+f.d.access}})).status,404);
 assert.equal((await f.run('/auth/realtime/ticket',{method:'POST',headers:{Authorization:'Bearer '+f.d.access,'content-type':'text/plain'},body:'hi'})).status,400);
 r=await f.mint();assert.equal(r.status,200);const t=await r.json();assert.match(t.ticket,/^rt1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{43}$/);
 assert.equal(t.closeAt,Math.min(f.d.accessExpiresAt,t.serverTime+SOCKET_MAX_MS));assert.equal(t.expiresAt,NOW+TICKET_TTL_MS);assert.equal(t.serverTime,NOW);assert.equal(r.headers.get('cache-control'),'no-store');
 const row=f.db.sqlite.prepare('SELECT * FROM realtime_tickets').get();assert.equal(row.close_at,t.closeAt);assert.ok(!JSON.stringify(row).includes(t.ticket.split('.')[2]),'raw secret never stored');assert.equal(row.secret_digest.length,64);
 f.db.sqlite.close();});
test('socket close time is capped at 5 minutes even though access lives 15, and never outlives access',async()=>{
 const f=await fixture();
 assert.equal(f.d.accessExpiresAt-NOW,15*60*1000);
 let t=await (await f.mint()).json();
 assert.equal(t.closeAt,NOW+SOCKET_MAX_MS,'early in access life: capped at 5 min');assert.ok(t.closeAt<f.d.accessExpiresAt);
 assert.equal(f.db.sqlite.prepare('SELECT close_at FROM realtime_tickets WHERE ticket_id=?').get(t.ticket.split('.')[1]).close_at,t.closeAt);
 f.setNow(NOW+13*60*1000);
 t=await (await f.mint()).json();
 assert.equal(t.closeAt,f.d.accessExpiresAt,'late in access life: the access expiry is sooner than the cap');
 f.setNow(NOW+15*60*1000);assert.equal((await f.mint()).status,401,'expired access mints nothing');
 f.db.sqlite.close();});
test('mint fails closed without a dedicated limiter, honors it, and bounds outstanding tickets per device',async()=>{
 let f=await fixture(undefined);f.http=null;const g=createRealtimeHttp({db:f.db,sessions:f.sessions,clock:f.clock,connect:async()=>new Response()});
 assert.equal((await g.fetch(new Request(API+'/auth/realtime/ticket',{method:'POST',headers:{Origin:APP,Authorization:'Bearer '+f.d.access}}),{clientAddress:'t'})).status,503);
 assert.equal((await g.fetch(new Request(API+'/auth/realtime',{headers:{Origin:APP,Upgrade:'websocket','Sec-WebSocket-Protocol':'otpanda.v1, rt1.'+'a'.repeat(16)+'.'+'b'.repeat(43)}}),{clientAddress:'t'})).status,503);
 f.db.sqlite.close();
 f=await fixture({limit:async()=>({success:false})});assert.equal((await f.mint()).status,429);assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM realtime_tickets').get().n,0);f.db.sqlite.close();
 f=await fixture();for(let i=0;i<MAX_TICKETS;i++)assert.equal((await f.mint()).status,200);const r=await f.mint();assert.equal(r.status,429);assert.equal((await r.json()).error,'busy');
 f.setNow(NOW+TICKET_TTL_MS+1);assert.equal((await f.mint(f.d.access)).status,200,'expired tickets free the cap (access still valid)');f.db.sqlite.close();});
test('upgrade: exactly one winner under parallel use; replay, wrong secret, query-string and malformed protocol are refused',async()=>{
 const f=await fixture(),{ticket}=await (await f.mint()).json();
 const results=await Promise.all(Array.from({length:6},()=>f.upgrade(ticket)));assert.equal(results.filter(r=>r.status===200).length,1);assert.equal(f.connects.length,1);
 assert.deepEqual(f.connects[0],{ownerId:f.proof.ownerId,deviceId:f.d.deviceId,closeAt:Math.min(f.d.accessExpiresAt,NOW+SOCKET_MAX_MS)});
 assert.equal((await f.upgrade(ticket)).status,401,'replay');
 const t2=(await (await f.mint()).json()).ticket,parts=t2.split('.');
 assert.equal((await f.upgrade(parts.slice(0,2).join('.')+'.'+'A'.repeat(43))).status,401);assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM realtime_tickets').get().n,1,'a wrong secret does not burn the real ticket');
 assert.equal((await f.run('/auth/realtime?ticket='+t2,{method:'GET',headers:{Upgrade:'websocket'}})).status,404);
 for(const proto of [t2,'otpanda.v1','otpanda.v1, '+t2+', x','other, '+t2,'otpanda.v1, rt1.short.'+'A'.repeat(43)])assert.equal((await f.run('/auth/realtime',{method:'GET',headers:{Upgrade:'websocket','Sec-WebSocket-Protocol':proto}})).status,400,proto);
 assert.equal((await f.run('/auth/realtime',{method:'GET',headers:{'Sec-WebSocket-Protocol':'otpanda.v1, '+t2}})).status,405,'not an upgrade');
 assert.equal((await f.run('/auth/realtime',{method:'GET',headers:{Upgrade:'websocket','Sec-WebSocket-Protocol':'otpanda.v1, '+t2,Origin:'https://evil.test'}})).status,403);
 assert.equal((await f.upgrade(t2)).status,200);f.db.sqlite.close();});
test('upgrade respects the ticket TTL, the access-handle expiry, device revocation and a changed security generation',async()=>{
 let f=await fixture(),{ticket}=await (await f.mint()).json();f.setNow(NOW+TICKET_TTL_MS+1);assert.equal((await f.upgrade(ticket)).status,401);f.db.sqlite.close();
 f=await fixture();ticket=(await (await f.mint()).json()).ticket;f.db.sqlite.prepare('UPDATE realtime_tickets SET close_at=?').run(NOW+5);f.setNow(NOW+10);assert.equal((await f.upgrade(ticket)).status,401,'cannot connect after its access handle expired');f.db.sqlite.close();
 f=await fixture();ticket=(await (await f.mint()).json()).ticket;assert.equal(await f.sessions.revoke({ownerId:f.proof.ownerId,deviceId:f.d.deviceId}),true);assert.equal((await f.upgrade(ticket)).status,401,'revoked device');assert.equal(f.connects.length,0);f.db.sqlite.close();
 f=await fixture();ticket=(await (await f.mint()).json()).ticket;f.db.sqlite.prepare('UPDATE account_security SET generation=generation+1').run();assert.equal((await f.upgrade(ticket)).status,401,'generation changed');
 assert.equal((await f.mint()).status,401,'and the old access handle can no longer mint');f.db.sqlite.close();
 f=await fixture();ticket=(await (await f.mint()).json()).ticket;f.db.sqlite.prepare('UPDATE passkey_credentials SET revoked_at=1').run();assert.equal((await f.upgrade(ticket)).status,401,'credential revoked ends the method');f.db.sqlite.close();});
test('the device-revoke trigger queues a close for exactly that device and the drain delivers it',async()=>{
 const f=await fixture(),second=await f.sessions.issue({proof:f.proof,clientKind:'web'});f.db.sqlite.prepare('DELETE FROM realtime_outbox').run();
 await f.sessions.revoke({ownerId:f.proof.ownerId,deviceId:f.d.deviceId});
 const rows=f.db.sqlite.prepare('SELECT kind,account_id,device_id FROM realtime_outbox').all().map(r=>({...r}));assert.deepEqual(rows,[{kind:'device',account_id:f.proof.ownerId,device_id:f.d.deviceId}]);
 f.db.sqlite.prepare('INSERT INTO realtime_activity(account_id,last_ticket_at) VALUES (?,?)').run(f.proof.ownerId,NOW);
 const log=[];await drainOutbox({db:f.db,clock:()=>NOW,deliver:async(a,m)=>{log.push([a,m]);return true;}});assert.deepEqual(log,[[f.proof.ownerId,{v:1,t:'close',deviceId:f.d.deviceId}]]);
 assert.ok(await f.sessions.authenticate(second.access),'the other device is untouched');f.db.sqlite.close();});
