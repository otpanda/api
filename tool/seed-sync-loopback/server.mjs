// DEBUG/LOCAL ONLY loopback host for the installed seed-sync fixture. Never imported by the Worker, never deployed, never given production resources.
// It runs the REAL createIdentityRuntime (native on, seedSync on, real managedPasskeys android-origin verification, real SeedCipher and seed-sync services)
// on in-memory SQLite, behind a plain-HTTP loopback listener (emulator host alias 10.0.2.2). Three synthetic control routes exist ONLY here:
//   POST /__loopback/session  -> issues a real android DeviceSession (real bearer) for the synthetic owner
//   POST /__loopback/assert   -> synthetic authenticator: signs the Credential Manager request JSON with a P-256 key registered as the owner's passkey
//   GET  /__loopback/state    -> non-secret server state for assertions (key rows, notices, owner revision, versions). Never returns seed bytes or tokens.
// Everything else is forwarded unchanged to the runtime as https://otpanda-api... so the app's own routes, shapes and gates are exercised.
import http from 'node:http';
import {database} from '../../test/sqlite-helper.js';import {authenticator} from '../../test/passkey-fixture.js';
import {createIdentityRuntime} from '../../src/identity-runtime.js';import {DeviceSessionService} from '../../src/device-sessions.js';
import {SeedCipher} from '../../src/seed-cipher.js';import {TotpSeedStore} from '../../src/totp-seeds.js';import {base64urlEncode} from '../../src/tokens.js';
const API='https://otpanda-api.abrahammurciano.workers.dev';
export const OWNER='fixture-owner';
// RFC 6238 public test seed (SHA-1, 8 digits, 30 s): code at unix 59 is 94287082. Never an account seed.
export const RFC_SEED=Uint8Array.from('12345678901234567890',c=>c.charCodeAt(0));
// Fixed synthetic debug signer fingerprint unless the caller passes the installed debug APK's SHA-256 (then the assertion origin matches the real apk-key-hash).
export const DEFAULT_FP=Array.from({length:32},(_,i)=>((i*11+5)%256).toString(16).padStart(2,'0').toUpperCase()).join(':');
const originFor=fp=>'android:apk-key-hash:'+base64urlEncode(Uint8Array.from(fp.split(':').map(h=>parseInt(h,16))));
export async function startLoopback({port=0,host='127.0.0.1',fingerprint=DEFAULT_FP,entries=[{id:'sealed-entry',seed:RFC_SEED,algorithm:'SHA-1',digits:8,period:30}],clock=Date.now}={}){
 const db=database(),sq=db.sqlite,auth=authenticator(),cred=auth.credential,origin=originFor(fingerprint);
 const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']),config={keys:new Map([['k',key]]),activeKeyId:'k'},cipher=new SeedCipher(config);
 const t0=clock();
 sq.prepare('INSERT INTO accounts(owner_id,created_at) VALUES(?,?)').run(OWNER,t0);sq.prepare('INSERT INTO account_security(owner_id) VALUES(?)').run(OWNER);
 sq.prepare("INSERT INTO account_emails(owner_id,email,verified_at,updated_at) VALUES(?,'synthetic@example.test',0,0)").run(OWNER);
 sq.prepare('INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) VALUES(?,?,?,?,?,?,?,?)').run(cred.id,OWNER,cred.publicKey,0,'[]','singleDevice',0,t0);
 sq.prepare("INSERT OR IGNORE INTO services(service_id,name) VALUES('custom-totp','Authenticator')").run();
 const store=new TotpSeedStore(db,cipher);
 for(const e of entries){sq.prepare('INSERT INTO entries(entry_id,owner_id,service_id,label,created_at) VALUES(?,?,?,?,?)').run(e.id,OWNER,'custom-totp','Synthetic offline service',t0);
  if(!await store.putSeed(OWNER,e.id,{secret:e.seed,algorithm:e.algorithm,digits:e.digits,period:e.period},t0))throw Error('seed not stored');}
 const sessions=new DeviceSessionService(db,{clock});
 const rt=createIdentityRuntime({db,loadCodeKeys:async()=>config,trustedRequestKey:()=>'127.0.0.1',clock,native:{enabled:true,assetFingerprints:[fingerprint]},seedSync:{enabled:true}});
 let counter=0,n=0;const sent=new Set();
 const json=(res,s,b)=>{res.writeHead(s,{'content-type':'application/json','cache-control':'no-store'});res.end(JSON.stringify(b));};
 const server=http.createServer(async(req,res)=>{try{
  const chunks=[];for await(const c of req)chunks.push(c);const body=Buffer.concat(chunks);const url=new URL(req.url,'http://loopback');
  if(url.pathname.startsWith('/__loopback/')){
   if(url.pathname==='/__loopback/session'&&req.method==='POST'){const s=await sessions.issue({proof:{ownerId:OWNER,credentialId:cred.id,generation:0,purpose:'authenticate',verifiedAt:clock()},clientKind:'android'});return json(res,200,{access:s.access,deviceId:s.deviceId,ownerId:OWNER});}
   if(url.pathname==='/__loopback/assert'&&req.method==='POST'){
    const r=JSON.parse(body.toString());
    // Same checks the app's passkeyRequestJson already made: refuse anything but the app's rpId and a 43-char challenge, user verification required.
    if(r.rpId!=='otpanda.github.io'||r.userVerification!=='required'||!/^[A-Za-z0-9_-]{43}$/.test(r.challenge??''))return json(res,400,{error:'refused'});
    if(Array.isArray(r.allowCredentials)&&r.allowCredentials.length&&!r.allowCredentials.some(c=>c.id===cred.id))return json(res,404,{error:'no credential'});
    const a=auth.assertion({expected:r.challenge,origin,counter:++counter});
    return json(res,200,{id:a.id,rawId:a.rawId,type:'public-key',authenticatorAttachment:'platform',clientExtensionResults:{},response:{...a.response,userHandle:null}});
   }
   if(url.pathname==='/__loopback/state'&&req.method==='GET'){
    const keys=sq.prepare('SELECT key_id,install_id,generation,revoked_at,revoked_reason FROM seed_sync_keys ORDER BY rowid').all().map(k=>({keyId:k.key_id,installId:k.install_id,generation:k.generation,revoked:k.revoked_at!=null,reason:k.revoked_reason}));
    return json(res,200,{keys,notices:sq.prepare('SELECT count(*) n FROM seed_sync_notices').get().n,ownerRevision:sq.prepare('SELECT revision r FROM seed_sync_owner WHERE owner_id=?').get(OWNER)?.r??null,seeds:sq.prepare('SELECT entry_id,seed_version,algorithm,digits,period,seed_bytes FROM totp_seeds ORDER BY entry_id').all(),assertionsSigned:counter});
   }
   return json(res,404,{error:'not_found'});
  }
  const headers=new Headers();for(const[k,v]of Object.entries(req.headers))if(typeof v==='string'&&!['host','connection','content-length'].includes(k))headers.set(k,v);
  const r=await rt.fetch(new Request(API+req.url,{method:req.method,headers,body:req.method==='GET'||req.method==='HEAD'?undefined:body}),{clientAddress:'127.0.0.'+(1+(++n%200)),waitUntil(){}});
  const out=Buffer.from(await r.arrayBuffer()),h={};r.headers.forEach((v,k)=>{h[k]=v;});delete h['content-length'];delete h['content-encoding'];
  res.writeHead(r.status,h);res.end(out);
 }catch(e){json(res,500,{error:'loopback'});}});
 await new Promise(ok=>server.listen(port,host,ok));
 return{url:'http://'+host+':'+server.address().port,port:server.address().port,origin,fingerprint,cipher,db,close:()=>new Promise(ok=>server.close(()=>{sq.close();ok();}))};
}
if(process.argv[1]&&import.meta.url===new URL('file://'+process.argv[1]).href){
 // Standalone: node tool/seed-sync-loopback/server.mjs [port] [host] [apk-sha256-fingerprint]. Host 0.0.0.0 only for a disposable emulator reaching 10.0.2.2.
 const [,,p='8787',h='127.0.0.1',fp]=process.argv,s=await startLoopback({port:Number(p),host:h,fingerprint:fp??DEFAULT_FP});
 console.log(JSON.stringify({loopback:s.url,assertionOrigin:s.origin,owner:OWNER,note:'synthetic, in-memory, debug only'}));
}
