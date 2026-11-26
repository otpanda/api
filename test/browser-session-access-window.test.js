import test from 'node:test';
import assert from 'node:assert/strict';
import {database} from './sqlite-helper.js';
import {createBrowserSessionHttp} from '../src/browser-session-http.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',NOW=1_800_000_000_000;
function setup(){
 const db=database(),seen=[];
 const exchanges={exchange:async a=>{seen.push(['exchange',a]);return {access:'x',accessExpiresAt:NOW+a.accessMs};},mint:async()=>undefined};
 const renewals={renew:async a=>{seen.push(['renew',a]);return {status:'renewed',access:'x',accessExpiresAt:NOW+a.accessMs,renewal:{}};},resume:async a=>{seen.push(['resume',a]);return {status:'renewed',access:'x',accessExpiresAt:NOW+a.accessMs,renewal:{}};}};
 const http=createBrowserSessionHttp({sessions:{},exchanges,renewals,db,clock:()=>NOW});
 const post=(path,body,headers={})=>http.fetch(new Request(API+path,{method:'POST',headers:{Origin:APP,'Content-Type':'application/json',...headers},body:JSON.stringify(body)}),{clientAddress:'t'});
 return {db,seen,post};
}
const EX={code:'c'.repeat(43),verifier:'v'.repeat(43),redirect_uri:APP+'/app/'};
const RN={lineage_id:'lineage_12345',signature:'s'.repeat(86),expires_at:NOW+1000};
const BEARER={Authorization:'Bearer otpda_'+'a'.repeat(55)};
test('a browser that sends no opt-in keeps the 5 minute access life (older open tabs validate exactly 5 minutes)',async()=>{
 const f=setup();try{
  assert.equal((await f.post('/auth/exchange',EX)).status,200);
  assert.equal((await f.post('/auth/renew',RN,BEARER)).status,200);
  assert.equal((await f.post('/auth/renew',{...RN,handle_id:'handle_12345'})).status,200);
  assert.deepEqual(f.seen.map(([k,a])=>[k,a.accessMs]),[['exchange',300000],['renew',300000],['resume',300000]]);
 }finally{f.db.sqlite.close();}});
test('access_window 900 opts in to 15 minutes on exchange, renew and resume; the field never reaches the services otherwise',async()=>{
 const f=setup();try{
  assert.equal((await f.post('/auth/exchange',{...EX,access_window:900})).status,200);
  assert.equal((await f.post('/auth/renew',{...RN,access_window:900},BEARER)).status,200);
  assert.equal((await f.post('/auth/renew',{...RN,handle_id:'handle_12345',access_window:900})).status,200);
  assert.deepEqual(f.seen.map(([k,a])=>[k,a.accessMs]),[['exchange',900000],['renew',900000],['resume',900000]]);
  for(const [,a] of f.seen)assert.ok(!('access_window' in a));
 }finally{f.db.sqlite.close();}});
test('any other access_window value, type or extra field is rejected',async()=>{
 const f=setup();try{
  for(const v of [300,600,901,'900',900.5,null,true,[900],{},0,-900,1e9]){
   assert.equal((await f.post('/auth/exchange',{...EX,access_window:v})).status,400,String(JSON.stringify(v)));
   assert.equal((await f.post('/auth/renew',{...RN,access_window:v},BEARER)).status,400,String(JSON.stringify(v)));
  }
  assert.equal((await f.post('/auth/exchange',{...EX,access_window:900,extra:1})).status,400);
  assert.equal((await f.post('/auth/renew',{...RN,access_window:900,extra:1},BEARER)).status,400);
  assert.deepEqual(f.seen,[]);
 }finally{f.db.sqlite.close();}});
