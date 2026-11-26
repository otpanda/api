import test from 'node:test';
import assert from 'node:assert/strict';
import {createGmailJwksCache} from '../src/gmail-jwks-cache.js';
test('JWKS cache shares concurrent work, expires at five minutes and charges the calling fetch',async()=>{
 let now=100000,calls=0,release;const cache=createGmailJwksCache({clock:()=>now});
 const f=async(url,init)=>{calls++;assert.equal(url,'https://www.googleapis.com/oauth2/v3/certs');assert.equal(init.redirect,'error');await new Promise(r=>release=r);return Response.json({keys:[{kid:String(calls)}]});};
 const a=cache(f),b=cache(()=>{throw Error('must share');});release();assert.deepEqual(await a,await b);assert.equal(calls,1);
 assert.equal((await cache(()=>{throw Error('cached');})).keys[0].kid,'1');now+=300000;const c=cache(f);release();assert.equal((await c).keys[0].kid,'2');assert.equal(calls,2);
});
test('JWKS failed refresh cooldown does not serve stale keys and permits retry after a minute',async()=>{
 let now=100000,calls=0;const cache=createGmailJwksCache({clock:()=>now});const fail=async()=>{calls++;throw Error('offline');};
 await assert.rejects(cache(fail));await assert.rejects(cache(fail),/cooldown/);assert.equal(calls,1);now+=60000;
 assert.deepEqual(await cache(async()=>Response.json({keys:[]})),{keys:[]});now+=300000;await assert.rejects(cache(fail));assert.equal(calls,2);
});
test('JWKS bounds reject oversized and malformed responses and recover after cooldown',async()=>{
 for(const response of [new Response('x'.repeat(65537)),Response.json({keys:Array(17).fill({})}),new Response('{'),new Response('{}',{status:503})]){
  let now=100000;const cache=createGmailJwksCache({clock:()=>now});await assert.rejects(cache(async()=>response));now+=60000;assert.deepEqual(await cache(async()=>Response.json({keys:[]})),{keys:[]});
 }
});
