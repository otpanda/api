import test from 'node:test';
import assert from 'node:assert/strict';
import { RealtimeHub,HUB_MESSAGE,MAX_SOCKETS,CLOSE_REVOKED,CLOSE_EXPIRED,CLOSE_REPLACED,hubDeliver,hubConnect } from '../src/realtime-hub.js';
const NOW=1_800_000_000_000;
let h_listClosed=false;
function harness(listClosed=false){h_listClosed=listClosed;
 const sockets=[],alarms=[];let alarm,time=NOW;
 const state={getWebSockets:tag=>sockets.filter(s=>(h_listClosed||!s.closed)&&(tag===undefined||s.tags.includes(tag))),acceptWebSocket(ws,tags){ws.tags=tags;sockets.push(ws);},storage:{async setAlarm(v){alarms.push(v);alarm=v;},async deleteAlarm(){alarm=undefined;}}};
 const mk=()=>({sent:[],closed:null,att:null,send(m){this.sent.push(m);},close(c,r){this.closed=[c,r];},serializeAttachment(v){this.att=v;},deserializeAttachment(){return this.att;}});
 const hub=new RealtimeHub(state,{}, {now:()=>time,createPair:()=>[{client:true},mk()],upgrade:client=>({status:101,client})});
 const connect=(device='dev_abcdefgh',closeAt=NOW+300000,headers={})=>hub.fetch(new Request('https://hub/connect',{headers:{upgrade:'websocket','x-hub-device':device,'x-hub-close-at':String(closeAt),...headers}}));
 return {hub,sockets,alarms,connect,alarm:()=>alarm,setTime:v=>time=v};
}
test('connect accepts a tagged hibernatable socket, stores nothing but device and close time, and schedules the alarm at the earliest close',async()=>{
 const h=harness();const r=await h.connect('dev_aaaaaaaa',NOW+200000);assert.equal(r.status,101);assert.equal(h.sockets.length,1);assert.deepEqual(h.sockets[0].att,{d:'dev_aaaaaaaa',c:NOW+200000});assert.deepEqual(h.sockets[0].tags,['d:dev_aaaaaaaa']);assert.equal(h.alarm(),NOW+200000);
 await h.connect('dev_bbbbbbbb',NOW+100000);assert.equal(h.alarm(),NOW+100000);});
test('connect refuses non-upgrade, bad device id, past or too-far close time',async()=>{
 const h=harness();assert.equal((await h.hub.fetch(new Request('https://hub/connect',{headers:{'x-hub-device':'dev_abcdefgh','x-hub-close-at':String(NOW+1000)}}))).status,426);
 for(const [d,c] of [['bad id',NOW+1000],['dev_abcdefgh',NOW-1],['dev_abcdefgh',NOW+11*60*1000],['dev_abcdefgh','x'],['',NOW+1000]])assert.equal((await h.connect(d,c)).status,400,String([d,c]));assert.equal(h.sockets.length,0);
 assert.equal((await h.hub.fetch(new Request('https://hub/nope'))).status,404);});
test('changed goes to every open socket as exactly the content-free message; close targets only that device',async()=>{
 const h=harness();await h.connect('dev_aaaaaaaa');await h.connect('dev_bbbbbbbb');
 const post=b=>h.hub.fetch(new Request('https://hub/notify',{method:'POST',body:JSON.stringify(b)}));
 assert.equal((await post({v:1,t:'changed'})).status,204);for(const s of h.sockets)assert.deepEqual(s.sent,[HUB_MESSAGE]);assert.equal(HUB_MESSAGE,'{"v":1,"t":"changed"}');
 assert.equal((await post({v:1,t:'close',deviceId:'dev_aaaaaaaa'})).status,204);assert.deepEqual(h.sockets[0].closed,[CLOSE_REVOKED,'revoked']);assert.equal(h.sockets[1].closed,null);
 for(const bad of [{t:'changed'},{v:2,t:'changed'},{v:1,t:'x'},{v:1,t:'close'},{v:1,t:'close',deviceId:'a b'}])assert.equal((await post(bad)).status,400);
 assert.equal((await h.hub.fetch(new Request('https://hub/notify',{method:'POST',body:'nope'}))).status,400);assert.equal((await h.hub.fetch(new Request('https://hub/notify',{method:'GET'}))).status,404);});
test('alarm closes sockets at their access-handle expiry and reschedules for the rest',async()=>{
 const h=harness();await h.connect('dev_aaaaaaaa',NOW+100000);await h.connect('dev_bbbbbbbb',NOW+250000);
 h.setTime(NOW+100000);await h.hub.alarm();assert.deepEqual(h.sockets[0].closed,[CLOSE_EXPIRED,'expired']);assert.equal(h.sockets[1].closed,null);assert.equal(h.alarm(),NOW+250000);
 h.setTime(NOW+250000);await h.hub.alarm();assert.deepEqual(h.sockets[1].closed,[CLOSE_EXPIRED,'expired']);});
test('at the socket cap the oldest is replaced, so a reconnect loop never locks the user out; clients cannot send',async()=>{
 const h=harness();for(let i=0;i<MAX_SOCKETS;i++)await h.connect('dev_'+String(i).padStart(8,'0'),NOW+1000+i);
 await h.connect('dev_newnewnew',NOW+5000);assert.deepEqual(h.sockets[0].closed,[CLOSE_REPLACED,'replaced']);assert.equal(h.sockets.filter(s=>!s.closed).length,MAX_SOCKETS);
 const s=h.sockets.at(-1);await h.hub.webSocketMessage(s,'hello');assert.equal(s.closed[0],1008);});
test('hubDeliver and hubConnect address the per-account object and pass only the trusted headers',async()=>{
 const calls=[];const ns={idFromName:n=>'id:'+n,get:id=>({fetch:async(url,init)=>{calls.push([id,String(url instanceof Request?url.url:url),url instanceof Request?Object.fromEntries(url.headers):init]);return new Response(null,{status:204});}})};
 assert.equal(await hubDeliver(ns)('acct1',{v:1,t:'changed'}),true);assert.equal(calls[0][0],'id:acct1');assert.equal(calls[0][1],'https://hub/notify');
 await hubConnect(ns,{ownerId:'acct1',deviceId:'dev_abcdefgh',closeAt:NOW+1},new Request('https://x/auth/realtime',{headers:{upgrade:'websocket',authorization:'Bearer secret',cookie:'c=1','sec-websocket-protocol':'otpanda.v1, rt1.x'}}));
 const h=calls[1][2];assert.equal(h['x-hub-device'],'dev_abcdefgh');assert.equal(h['x-hub-close-at'],String(NOW+1));assert.equal(h.authorization,undefined);assert.equal(h.cookie,undefined);assert.equal(h['sec-websocket-protocol'],undefined,'the ticket is never forwarded');
 const bad={idFromName:n=>n,get:()=>({fetch:async()=>new Response(null,{status:500})})};assert.equal(await hubDeliver(bad)('a',{}),false);});

test('closed-but-still-listed sockets never re-arm the alarm in the past; with nothing left the alarm is cleared',async()=>{
 const h=harness(true);await h.connect('dev_aaaaaaaa',NOW+100000);await h.connect('dev_bbbbbbbb',NOW+250000);
 h.setTime(NOW+100000);h.alarms.length=0;await h.hub.alarm();assert.deepEqual(h.alarms,[NOW+250000],'armed once, in the future, for the live socket');
 await h.hub.alarm();assert.deepEqual(h.alarms,[NOW+250000,NOW+250000],'repeated alarm does not move to the closed socket time');
 h.setTime(NOW+250000);h.alarms.length=0;await h.hub.alarm();assert.deepEqual(h.alarms,[]);assert.equal(h.alarm(),undefined,'no socket left: alarm cleared, no loop');
 assert.ok(h.sockets.every(s=>s.closed));});
test('an expired socket still listed at connect time is closed by the sweep, not trusted',async()=>{
 const h=harness();await h.connect('dev_aaaaaaaa',NOW+1000);h.setTime(NOW+2000);await h.connect('dev_bbbbbbbb',NOW+50000);assert.deepEqual(h.sockets[0].closed,[CLOSE_EXPIRED,'expired']);assert.equal(h.alarm(),NOW+50000);});
test('closeAll closes every socket of the account for a security-generation change and clears the alarm',async()=>{
 const h=harness();await h.connect('dev_aaaaaaaa');await h.connect('dev_bbbbbbbb');
 assert.equal((await h.hub.fetch(new Request('https://hub/notify',{method:'POST',body:JSON.stringify({v:1,t:'closeAll'})}))).status,204);
 assert.ok(h.sockets.every(s=>s.closed?.[0]===CLOSE_REVOKED));assert.equal(h.alarm(),undefined);});
