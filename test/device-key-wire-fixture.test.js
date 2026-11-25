import test from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';
import {createDeviceKeyHttp} from '../src/device-key-http.js';
const fx=JSON.parse(readFileSync(new URL('../fixtures/device-key-wire-bodies.json',import.meta.url),'utf8')),API='https://otpanda-api.abrahammurciano.workers.dev';
test('wire fixture: every device-key body is accepted by the exact key-set check (reaches the service, never 400)',async()=>{
 const seen=[],svc=new Proxy({},{get:(_,k)=>async()=>{seen.push(k);return undefined;}}),sessions={authenticate:async()=>({ownerId:'o',deviceId:'d',generation:0,clientKind:'android',expiresAt:Date.now()+1e5})},db={prepare:()=>({bind:()=>({first:async()=>({n:0,resets_at:Date.now()+1e5,count:0}),run:async()=>({meta:{changes:1}}),all:async()=>({results:[]})})}),batch:async()=>[]};
 const http=createDeviceKeyHttp({db,sessions,enrollment:svc,keys:{},clock:()=>Date.now()});
 for(const [path,body] of Object.entries(fx).filter(([k])=>k.startsWith('/v1/manage/device-key/'))){
  const r=await http.fetch(new Request(API+path,{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer x'},body:JSON.stringify(body)}),{clientAddress:'1.1.1.1'});
  assert.notEqual(r.status,400,path);
  const bad=await http.fetch(new Request(API+path,{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer x'},body:JSON.stringify({...body,extra:1})}),{clientAddress:'1.1.1.1'});assert.equal(bad.status,400,path);}
});
