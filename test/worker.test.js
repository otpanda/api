import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/worker.js';
test('health endpoint makes no readiness claim and caches nothing',async()=>{
 const res=await worker.fetch(new Request('https://test.invalid/health'));
 assert.equal(res.status,200); assert.equal(res.headers.get('Cache-Control'),'no-store');
 assert.equal((await res.json()).status,'foundation-only');
});
test('all versioned endpoints are inert, even with a bearer header',async()=>{
 for (const path of ['/v1/codes','/v1/totp','/v1/grants']) {
  const res=await worker.fetch(new Request('https://test.invalid'+path,{headers:{Authorization:'Bearer synthetic-test-token'}}));
  assert.equal(res.status,501); assert.deepEqual(await res.json(),{error:'not_implemented'});
 }
});
