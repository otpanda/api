import test from 'node:test';
import assert from 'node:assert/strict';
import {snapshotEnvironment,createConfiguredHost} from '../src/environment.js';
import {database} from './sqlite-helper.js';
import {base64urlEncode} from '../src/tokens.js';
const origin='https://app.test';
const syntheticKey=base64urlEncode(new Uint8Array(32).fill(7));
function env(db){return {DB:db,APP_ORIGIN:origin,ACTIVE_KEY_ID:'test',ENCRYPTION_KEYRING:JSON.stringify([{id:'test',key:syntheticKey}])};}
const metadata={issuer:'https://accounts.google.com',authorization_endpoint:'https://accounts.google.com/o/oauth2/v2/auth',token_endpoint:'https://oauth2.googleapis.com/token',jwks_uri:'https://www.googleapis.com/oauth2/v3/certs',code_challenge_methods_supported:['S256'],id_token_signing_alg_values_supported:['RS256'],token_endpoint_auth_methods_supported:['client_secret_post']};
test('environment rejects missing bindings, unsafe origins, invalid registration and malformed rotation keys',()=>{
 const db=database();try{
 const good=env(db);
 for(const change of [{DB:null},{ASSETS:{}},{APP_ORIGIN:'http://app.test'},{APP_ORIGIN:origin+'/'},{APP_ORIGIN:origin+'/path'},{APP_ORIGIN:'https://user@app.test'},{ACTIVE_KEY_ID:'missing'},{ENCRYPTION_KEYRING:'{}'},{ENCRYPTION_KEYRING:'[]'},{ENCRYPTION_KEYRING:JSON.stringify([{id:'test',key:syntheticKey+'='}])},{ENCRYPTION_KEYRING:JSON.stringify([{id:'test',key:syntheticKey},{id:'test',key:syntheticKey}])},{ENCRYPTION_KEYRING:JSON.stringify([{id:'test',key:syntheticKey,extra:true}])}])assert.throws(()=>snapshotEnvironment({...good,...change}));
 assert.throws(()=>createConfiguredHost(good));
 }finally{db.sqlite.close();}
});
test('configured host snapshots credentials, isolates assets, initializes once and mounts integrated routes',async()=>{
 const db=database(),savedFetch=globalThis.fetch;let discoveries=0,assets=0;
 globalThis.fetch=async()=>{discoveries++;throw new Error('legacy sign-in must not use the network');};
 try{
 const source=env(db);source.ASSETS={fetch:async()=>{assets++;return new Response('asset');}};
 const snapshot=snapshotEnvironment(source);const serialized=JSON.stringify(snapshot);
 assert.equal(serialized.includes(syntheticKey),false);
 const host=createConfiguredHost(source,{trustedRequestKey:()=> 'verified-host'});
 source.APP_ORIGIN='http://wrong.test';source.ENCRYPTION_KEYRING='bad';
 assert.equal(await (await host.fetch(new Request(origin+'/'))).text(),'asset');assert.equal(discoveries,0);
 assert.equal((await host.fetch(new Request('https://wrong.test/health'))).status,404);
 const replies=await Promise.all(['/health','/v1/manage/session','/v1/codes/latest'].map(path=>host.fetch(new Request(origin+path))));
 assert.equal(replies[0].status,200);assert.equal(replies[1].status,401);assert.equal(replies[2].status,404);assert.equal(discoveries,0);assert.equal(assets,1);
 for(const p of ['/auth/start','/auth/callback'])assert.equal((await host.fetch(new Request(origin+p,{method:'POST',headers:{origin}}))).status,404);
 assert.equal(db.sqlite.prepare('SELECT count(*) AS n FROM accounts').get().n,0);
 assert.equal(db.sqlite.prepare('SELECT count(*) AS n FROM sources').get().n,0);
 await host.scheduled();
 }finally{globalThis.fetch=savedFetch;db.sqlite.close();}
});
test('missing trusted request metadata fails closed',async()=>{
 const db=database();try{
 const host=createConfiguredHost(env(db),{trustedRequestKey:()=>undefined});
 const first=await host.fetch(new Request(origin+'/health'));assert.equal(first.status,503);assert.deepEqual(await first.json(),{error:'unavailable'});
 }finally{db.sqlite.close();}
});
