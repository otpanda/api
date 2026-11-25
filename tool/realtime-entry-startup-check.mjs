// Local workerd proof: the BUNDLED public entry (wrangler dry-run output) starts with REALTIME_HUB bound and serves the realtime preflight.
import assert from 'node:assert/strict';import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);const {Miniflare}=require('miniflare');
const bundle=process.argv[2]||'dist/auth-only-worker.js';
const names=['IDENTITY_ADDRESS_LIMIT','IDENTITY_AUTH_GLOBAL_LIMIT','IDENTITY_READ_GLOBAL_LIMIT','REALTIME_ADDRESS_LIMIT','REALTIME_GLOBAL_LIMIT','REALTIME_TICKET_LIMIT'];
const {convertV4MiniflareOptions}=require('miniflare');
const options=await convertV4MiniflareOptions({modules:[{type:'ESModule',path:new URL('../'+bundle,import.meta.url).pathname}],modulesRoot:new URL('../'+bundle.replace(/[^/]*$/,''),import.meta.url).pathname,compatibilityDate:'2026-11-23',compatibilityFlags:['nodejs_compat'],d1Databases:['DB'],ratelimits:Object.fromEntries(names.map((n,i)=>[n,{namespace_id:String(1+i),simple:{limit:100,period:60}}])),bindings:{DEPLOYMENT_STAGE:'auth-only'},durableObjects:{REALTIME_HUB:{className:'RealtimeHub',useSQLite:true}}});
const withHub=new Miniflare(options);
try{
 const r=await withHub.dispatchFetch('https://otpanda-api.abrahammurciano.workers.dev/auth/realtime/ticket',{method:'OPTIONS',headers:{origin:'https://x','access-control-request-method':'POST'}});
 console.log('with hub: status',r.status);assert.ok(r.status!==404&&r.status<500,'preflight reached the realtime edge (403 for an unlisted origin is expected): '+r.status);
 const r2=await withHub.dispatchFetch('https://otpanda-api.abrahammurciano.workers.dev/auth/realtime/ticket',{method:'POST'});console.log('ticket no auth status',r2.status);assert.ok([400,401,403].includes(r2.status),'ticket route reached auth, not 404/500: '+r2.status);
 console.log('PASS: bundled entry starts with REALTIME_HUB bound');
}finally{await withHub.dispose();}
