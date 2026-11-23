import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/cloudflare-worker.js';
import {database} from './sqlite-helper.js';

test('deployment health reports setup status without claiming working auth',async()=>{
 for(const method of ['GET','HEAD']){
  const response=await worker.fetch(new Request('https://api.test/health',{method}));
  assert.equal(response.status,200);
  assert.equal(response.headers.get('cache-control'),'no-store');
  assert.equal(response.headers.get('access-control-allow-origin'),null);
  assert.deepEqual(await response.json(),{service:'otpanda-api',status:'setup-required',authentication:'disabled'});
 }
});
test('deployment readiness checks migrated database and never creates records',async()=>{
 const db=database();
 try{
  assert.equal((await worker.fetch(new Request('https://api.test/ready'),{DB:db,DEPLOYMENT_STAGE:'bootstrap'})).status,200);
  for(const table of ['accounts','identities','sources','entries','entry_shares','entry_tokens','service_routes']){
   assert.equal(db.sqlite.prepare(`SELECT count(*) AS n FROM ${table}`).get().n,0);
  }
 }finally{db.sqlite.close();}
});
test('missing schema, bindings and wrong stage fail readiness with no internal details',async()=>{
 for(const env of [undefined,{}, {DEPLOYMENT_STAGE:'active'}, {DEPLOYMENT_STAGE:'bootstrap',DB:{prepare(){throw new Error('private details');}}}]){
  const response=await worker.fetch(new Request('https://api.test/ready'),env);
  assert.equal(response.status,503);assert.deepEqual(await response.json(),{error:'unavailable'});
 }
});
test('all authentication and data paths remain closed, no redirects or CORS bypass',async()=>{
 for(const path of ['/auth','/auth/start','/auth/callback?code=synthetic','/v1','/v1/manage/session','/v1/codes/latest']){
  for(const method of ['GET','POST','OPTIONS']){
   const response=await worker.fetch(new Request('https://api.test'+path,{method,headers:{Origin:'https://otpanda.github.io',Authorization:'Bearer synthetic'}}),{});
   assert.equal(response.status,503);assert.equal(response.headers.get('location'),null);
   assert.equal(response.headers.get('set-cookie'),null);assert.equal(response.headers.get('access-control-allow-origin'),null);
   assert.deepEqual(await response.json(),{error:'setup_required'});
  }
 }
 assert.equal((await worker.fetch(new Request('https://api.test/'))).status,404);
 assert.equal((await worker.fetch(new Request('https://api.test/health',{method:'POST'}))).status,404);
});
test('scheduled housekeeping is mounted and bounded without opening auth',async()=>{
 const db=database();try {
 const now=Date.now();for(let i=0;i<105;i++)await db.prepare('INSERT INTO browser_logout_bindings VALUES (?,?)').bind('synthetic-'+i,now-1).run();
 let job;await worker.scheduled({}, {DB:db,DEPLOYMENT_STAGE:'bootstrap'},{waitUntil(p){job=p;}});assert.ok(job);await job;
 assert.equal(db.sqlite.prepare('SELECT count(*) AS n FROM browser_logout_bindings').get().n,5);
 await worker.scheduled({}, {DB:db,DEPLOYMENT_STAGE:'bootstrap'});assert.equal(db.sqlite.prepare('SELECT count(*) AS n FROM browser_logout_bindings').get().n,0);
 assert.equal((await worker.fetch(new Request('https://api.test/auth/login/start'),{DB:db,DEPLOYMENT_STAGE:'bootstrap'})).status,503);
 }finally{db.sqlite.close();}
});
test('scheduled housekeeping rejects wrong deployment stage without touching DB',async()=>{
 for(const env of [undefined,{}, {DEPLOYMENT_STAGE:'active',DB:{prepare(){throw Error('must not run');}}}])await worker.scheduled({},env);
});
