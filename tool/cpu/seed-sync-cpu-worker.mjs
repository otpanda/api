// SYNTHETIC qualification worker. Never a production entry, never mounted by the real worker. Runs the real SeedSync service against a D1 binding
// so the CPU of its real code paths (ECDSA verify, ECDH+HKDF+AES-GCM seal, AES-GCM seed decrypt, D1) can be measured inside workerd.
import {SeedSync} from '../../src/seed-sync.js';
import {SeedCipher} from '../../src/seed-cipher.js';
import {TotpSeedStore} from '../../src/totp-seeds.js';
import {createSeedSyncHttp} from '../../src/seed-sync-http.js';
import {DeviceSessionService} from '../../src/device-sessions.js';
import {PasskeyService} from '../../src/passkey-service.js';
import {generateAccessToken,digestSecret,digestToHex} from '../../src/tokens.js';
const API='https://otpanda-api.abrahammurciano.workers.dev'; // the real route only serves this origin; the harness builds the inner Request with it
const OWNER='cpu_owner',DEVICE='cpu_device',CRED='cpu_cred',KEY_ID='00000000-0000-4000-8000-0000000000aa',INSTALL='c'.repeat(22);
let cipher;
async function parts(env){
 cipher??=new SeedCipher({keys:new Map([['t',await crypto.subtle.importKey('raw',new Uint8Array(32).fill(7),'AES-GCM',false,['encrypt','decrypt'])]]),activeKeyId:'t'});
 return {svc:new SeedSync({db:env.DB,cipher}),seeds:new TotpSeedStore(env.DB,cipher)};
}
// Meters D1 rows_read / rows_written from each query's meta (the numbers Cloudflare bills against the Free daily limits, index rows included) and reports them in
// response headers, so the driver can hard-stop before the account-wide daily limits. first() is served through all() so its meta is visible.
function metered(db,acc){
 const ok=x=>Number.isInteger(x)&&x>=0,add=m=>{if(!ok(m?.rows_read)||!ok(m?.rows_written)){acc.bad=true;return;}acc.r+=m.rows_read;acc.w+=m.rows_written;}; // a missing or malformed meta field is never counted as 0: the headers say 'invalid' and the driver aborts
 const wrap=st=>({__s:st,bind:(...a)=>wrap(st.bind(...a)),
  run:async()=>{const r=await st.run();add(r.meta);return r;},
  all:async()=>{const r=await st.all();add(r.meta);return r;},
  first:async col=>{const r=await st.all();add(r.meta);const row=r.results[0]??null;return col?(row?row[col]:null):row;},
  raw:(...a)=>st.raw(...a)});
 return {prepare:sql=>wrap(db.prepare(sql)),batch:async list=>{const rs=await db.batch(list.map(x=>x.__s??x));for(const r of rs)add(r.meta);return rs;}};
}
export default {async fetch(request,env){
 const acc={r:0,w:0,bad:false};let resp;try{resp=await handle(request,{...env,DB:metered(env.DB,acc)});}catch(e){resp=new Response('worker error',{status:500});} // error paths still report the rows they used; a platform kill (1102) cannot, the driver treats missing headers as usage unknown
 const out=new Response(resp.body,resp);out.headers.set('x-cpu-rows-r',acc.bad?'invalid':String(acc.r));out.headers.set('x-cpu-rows-w',acc.bad?'invalid':String(acc.w));return out;
}};
async function handle(request,env){
 if(!env.CPU_KEY||(request.headers.get('x-cpu-key')??request.headers.get('authorization')?.replace(/^Bearer /,''))!==env.CPU_KEY)return new Response(null,{status:404});
 const url=new URL(request.url);
 if(url.pathname.startsWith('/route/')){
  // The REAL route layer: per-address and per-owner rate-limit writes, real DeviceSessionService token digest + D1 session query (first auth),
  // JSON read and validation, the service, the second auth after the work, and real PasskeyService/verifier for enroll. clientAddress varies per call.
  const http=createSeedSyncHttp({db:env.DB,sessions:new DeviceSessionService(env.DB),service:(await parts(env)).svc,passkeys:new PasskeyService(env.DB),enabled:true});
  const inner=new Request(API+'/v1/manage/seed-sync/'+url.pathname.slice(7),{method:'POST',headers:{authorization:request.headers.get('authorization')??'','content-type':'application/json'},body:await request.text()});
  const r=await http.fetch(inner,{clientAddress:'cpu-'+(request.headers.get('x-cpu-addr')??'a')});
  return new Response(await r.text(),{status:r.status,headers:{'content-type':'application/json'}});
 }
 if(url.pathname==='/ping')return new Response(await request.text()); // per-request baseline (same body size as a call)
 const body=await request.json(),{svc,seeds}=await parts(env),now=Date.now();
 if(url.pathname==='/prepare'){
  const db=env.DB,cred=body.cred;
  const t=generateAccessToken(),th=digestToHex(await digestSecret(t.secret));
  if(body.setup){await db.batch([
   db.prepare('INSERT OR IGNORE INTO accounts(owner_id,created_at) VALUES(?1,?2)').bind(OWNER,now),
   db.prepare('INSERT OR IGNORE INTO account_security(owner_id) VALUES(?1)').bind(OWNER),
   db.prepare('INSERT OR IGNORE INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) VALUES(?1,?2,?3,0,\'[]\',\'singleDevice\',0,?4)').bind(cred?.id??CRED,OWNER,cred?Array.from(cred.cose):new Uint8Array([1]),now),
   db.prepare('INSERT OR IGNORE INTO account_emails(owner_id,email,verified_at,updated_at) VALUES(?1,\'cpu@example.test\',1,1)').bind(OWNER),
   db.prepare("INSERT OR IGNORE INTO device_sessions(device_id,owner_id,credential_id,provider_identity_id,generation,client_kind,created_at,last_used_at,expires_at) VALUES(?1,?2,?3,NULL,0,'android',0,0,9999999999999)").bind(DEVICE,OWNER,cred?.id??CRED),
   db.prepare('INSERT OR REPLACE INTO device_access_handles(handle_id,secret_digest,device_id,created_at,expires_at) VALUES(?1,?2,?3,?4,9999999999999)').bind(t.tokenId,th,DEVICE,now),
   db.prepare("INSERT OR IGNORE INTO services(service_id,name) VALUES('custom-totp','A')"),
   db.prepare('INSERT OR IGNORE INTO seed_sync_keys(key_id,owner_id,install_id,public_jwk,public_key_digest,generation,created_at,last_device_id) VALUES(?1,?2,?3,?4,?5,0,?6,?7)').bind(KEY_ID,OWNER,INSTALL,JSON.stringify(body.jwk),'cpu-digest',now,DEVICE),
  ]);return Response.json({keyId:KEY_ID,token:t.token});}
  // chunked seeding: a Free-plan invocation allows 50 subrequests (D1 queries), so the driver seeds a few entries per call
  for(let i=body.from;i<body.from+body.count;i++){const id='cpu-entry-'+i;await db.prepare("INSERT OR IGNORE INTO entries(entry_id,owner_id,service_id,label,created_at) VALUES(?1,?2,'custom-totp','L',?3)").bind(id,OWNER,now).run();await seeds.putSeed(OWNER,id,{secret:Uint8Array.from({length:20},(_,j)=>j+1),algorithm:'SHA-1',digits:6,period:30},now);}
  return Response.json({ok:true});
 }
 if(url.pathname==='/restore'){ // put the owner back to exactly the one prepared key (after enroll or revoke scenarios), clear limiter and challenges
  await env.DB.batch([env.DB.prepare('DELETE FROM seed_sync_keys WHERE owner_id=?1').bind(OWNER),env.DB.prepare('INSERT INTO seed_sync_keys(key_id,owner_id,install_id,public_jwk,public_key_digest,generation,created_at,last_device_id) VALUES(?1,?2,?3,?4,?5,0,?6,?7)').bind(KEY_ID,OWNER,INSTALL,JSON.stringify(body.jwk),'cpu-digest',now,DEVICE),env.DB.prepare('DELETE FROM rate_buckets'),env.DB.prepare('DELETE FROM seed_sync_challenges'),env.DB.prepare('DELETE FROM seed_sync_notices')]);return Response.json({ok:true});}
 if(url.pathname==='/stats')return Response.json({changes:(await env.DB.prepare('SELECT total_changes() n').first()).n});
 if(url.pathname==='/reset'){await env.DB.batch([env.DB.prepare('DELETE FROM rate_buckets'),env.DB.prepare('DELETE FROM seed_sync_challenges')]);return Response.json({ok:true});}
 if(url.pathname==='/versions'){return Response.json((await env.DB.prepare('SELECT entry_id,seed_version FROM totp_seeds WHERE owner_id=?1 ORDER BY entry_id').bind(OWNER).all()).results);}
 if(url.pathname==='/call'){
  const user={ownerId:OWNER,deviceId:DEVICE,generation:0};
  if(!['snapshotBegin','snapshotFinish','batchBegin','batchFinish','statusBegin','statusFinish'].includes(body.fn))return new Response(null,{status:404});
  const r=await svc[body.fn]({user,...body.args});
  return Response.json(r??{unavailable:true});
 }
 return new Response(null,{status:404});
}
