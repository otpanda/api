import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { PasskeySignupService } from '../src/passkey-signup.js';
import { AccountIdentityService } from '../src/account-identity.js';
import { DeviceSessionService } from '../src/device-sessions.js';
import { createRealtimeHttp } from '../src/realtime-http.js';
import { createIdentityEdgeHost } from '../src/identity-edge-host.js';
import { authenticator } from './passkey-fixture.js';
const NOW=1_800_000_000_000,API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io';
async function fixture(native){
 const db=database();const clock=()=>NOW;
 const identity=new AccountIdentityService(db,{clock}),signup=new PasskeySignupService(db,{clock});const {token}=await identity.issueEmailChallenge({purpose:'signup-email',email:'a@example.com'});
 const c=await signup.begin({email:'a@example.com',emailToken:token,binding:'binding'}),a=authenticator();
 const account=await signup.finish({token:c.token,binding:'binding',response:a.registration({expected:c.options.challenge})});
 const sessions=new DeviceSessionService(db,{clock}),proof={...account,verifiedAt:NOW,purpose:'authenticate'};
 const web=await sessions.issue({proof,clientKind:'web'}),and=await sessions.issue({proof,clientKind:'android'});
 const connects=[],http=createRealtimeHttp({db,sessions,limiter:{limit:async()=>({success:true})},clock,native,connect:async(info,req)=>{connects.push(info);return new Response('ws',{status:200});}});
 const run=(path,init={},origin)=>http.fetch(new Request(API+path,{...init,headers:{...(origin?{Origin:origin}:{}),...(init.headers??{})}}),{clientAddress:'t'});
 const mint=(tok,origin)=>run('/auth/realtime/ticket',{method:'POST',headers:{Authorization:'Bearer '+tok}},origin);
 const up=(ticket,origin)=>run('/auth/realtime',{method:'GET',headers:{Upgrade:'websocket','Sec-WebSocket-Protocol':'otpanda.v1, '+ticket}},origin);
 return {db,web,and,connects,run,mint,up,sessions};
}
test('native on: android token with NO Origin mints a ticket and upgrades; the ticket is one use',async()=>{
 const f=await fixture(true);const r=await f.mint(f.and.access);assert.equal(r.status,200);const b=await r.json();assert.match(b.ticket,/^rt1\./);
 assert.equal((await f.up(b.ticket)).status,200);assert.equal(f.connects.length,1);assert.equal((await f.up(b.ticket)).status,401,'replay');});
test('native off (default): no-Origin requests are refused on both routes, web unchanged',async()=>{
 for(const native of [false,undefined]){const f=await fixture(native);assert.equal((await f.mint(f.and.access)).status,403);assert.equal((await f.up('rt1.'+'A'.repeat(16)+'.'+'B'.repeat(43))).status,403);
  const r=await f.mint(f.web.access,APP);assert.equal(r.status,200);assert.equal((await f.up((await r.json()).ticket,APP)).status,200);}});
test('kinds never cross: android token with Origin, web token without Origin, and tickets redeemed by the other kind',async()=>{
 const f=await fixture(true);
 assert.equal((await f.mint(f.and.access,APP)).status,401,'android token with a browser Origin');
 assert.equal((await f.mint(f.web.access)).status,401,'web token without Origin');
 assert.equal((await f.mint(f.and.access,'https://evil.test')).status,403);assert.equal((await f.mint(f.and.access,'null')).status,403);
 const wt=(await(await f.mint(f.web.access,APP)).json()).ticket,at=(await(await f.mint(f.and.access)).json()).ticket;
 assert.equal((await f.up(wt)).status,401,'web ticket without Origin');assert.equal((await f.up(at,APP)).status,401,'android ticket with the browser Origin');
 assert.equal(f.connects.length,0);assert.equal((await f.up(at)).status,200,'the right kind still works after the failed attempt');});
test('native never answers a preflight; browser preflight unchanged',async()=>{
 const f=await fixture(true);
 let r=await f.run('/auth/realtime/ticket',{method:'OPTIONS',headers:{'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'authorization'}});assert.equal(r.status,403);
 r=await f.run('/auth/realtime/ticket',{method:'OPTIONS',headers:{'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'authorization'}},APP);assert.equal(r.status,204);});
test('revoked or replaced android device, expired access: no ticket, and an issued ticket stops working',async()=>{
 const f=await fixture(true);const t=(await(await f.mint(f.and.access)).json()).ticket;
 f.db.sqlite.prepare("UPDATE device_sessions SET revoked_at=? WHERE client_kind='android'").run(NOW);
 assert.equal((await f.up(t)).status,401);assert.equal((await f.mint(f.and.access)).status,401);
 assert.equal((await f.mint(f.web.access,APP)).status,200,'web device unaffected');});
test('edge host: native realtime needs nativeApi=true, no Origin, never OPTIONS; dedicated budgets only; foreign Origin refused first',async()=>{
 const counter=()=>{const c={n:0,limit:async()=>{c.n++;return{success:true};}};return c;};
 for(const nativeApi of [true,false,undefined]){
  const ea=counter(),eg=counter();let init=0,hits=0;
  const host=createIdentityEdgeHost({nativeApi,resolveTrustedIngress:()=>'192.0.2.1',edgeAddress:counter(),edgeAuthGlobal:counter(),edgeReadGlobal:counter(),realtime:{edgeAddress:ea,edgeGlobal:eg},initialize:async()=>{init++;return{fetch:async()=>{hits++;return new Response('ok');}};}});
  const nat=await host.fetch(new Request(API+'/auth/realtime/ticket',{method:'POST'}));
  if(nativeApi===true){assert.equal(nat.status,200);assert.equal(ea.n,1);assert.equal(eg.n,1);assert.equal(hits,1);}
  else{assert.equal(nat.status,403);assert.equal(ea.n+eg.n+init+hits,0,'refused before any limiter, resolver or D1');}
  const before=ea.n+init;
  for(const [m,o] of [['POST','https://evil.test'],['POST','null'],['OPTIONS',undefined]]){const r=await host.fetch(new Request(API+'/auth/realtime/ticket',{method:m,headers:{...(o?{Origin:o}:{}),'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'authorization'}}));assert.equal(r.status,403,m+String(o));}
  assert.equal(ea.n+init,before,'refusals spend nothing');
  const web=await host.fetch(new Request(API+'/auth/realtime/ticket',{method:'POST',headers:{Origin:APP}}));assert.equal(web.status,200);}});
