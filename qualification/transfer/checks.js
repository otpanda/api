// Synthetic-only qualification against the supplied D1 binding. Never mounted by production.
import {createTotpBatchImportHttp} from '../../src/totp-batch-import-http.js';
import {createTotpExportHttp} from '../../src/totp-export-http.js';
import {openExport,sha256Hex,sealExport} from '../../src/totp-export-seal.js';
import {base64urlEncode} from '../../src/tokens.js';
import {SeedCipher} from '../../src/seed-cipher.js';
const API='https://otpanda-api.abrahammurciano.workers.dev', APP='https://otpanda.github.io';
const NOW=1800000000000, SECRET='GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const eq=(a,b)=>{if(JSON.stringify(a)!==JSON.stringify(b))throw Error('synthetic assertion mismatch');};
export async function runChecks(db){
 const checks=[];
 async function check(name,fn){try{await fn();checks.push({name,pass:true});}catch(e){checks.push({name,pass:false,error:String(e?.message??e).slice(0,300)});}}
 const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);
 const cipher=new SeedCipher({keys:new Map([['synthetic',key]]),activeKeyId:'synthetic'});
 await db.prepare("INSERT INTO accounts VALUES ('batch-owner',?)").bind(NOW).run();
 await db.prepare("INSERT INTO account_security(owner_id) VALUES ('batch-owner')").run();
 await db.prepare("INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) VALUES ('batch-cred','batch-owner',x'00',0,'[]','singleDevice',0,?)").bind(NOW).run();
 await db.prepare("INSERT INTO device_sessions(device_id,owner_id,credential_id,generation,client_kind,created_at,last_used_at,expires_at) VALUES ('batch-device','batch-owner','batch-cred',0,'web',?,?,?)").bind(NOW,NOW,NOW+1e9).run();
 const actor={ownerId:'batch-owner',deviceId:'batch-device',generation:0,clientKind:'web',expiresAt:NOW+1e9};
 let beforeCipher=async()=>{},beforeBatch=async()=>{};
 const wrapped={prepare:sql=>db.prepare(sql),batch:async statements=>{await beforeBatch();return db.batch(statements);}};
 const http=createTotpBatchImportHttp({db:wrapped,sessions:{authenticate:async()=>actor},getSeedCipher:async()=>{await beforeCipher();return cipher;},clock:()=>NOW,
 // Synthetic ceremony seam only. Actual action-bound passkey crypto has its own unit qualification.
 passkeys:{begin:async()=>({token:'synthetic'}),finishAuthentication:async()=>({generation:0})}});
 let requestCount=0;
 const send=async(step,body)=>{const r=await http.fetch(new Request(API+'/v1/manage/totp/'+step,{method:'POST',headers:{Origin:APP,Authorization:'Bearer synthetic','Content-Type':'application/json'},body:JSON.stringify(body)}),{clientAddress:'synthetic-'+(++requestCount)});return{status:r.status,body:await r.json()};};
 const nonce=n=>'synthetic_batch_nonce_'+String(n).padStart(6,'0');
 const items=n=>Array.from({length:n},(_,i)=>({label:'Synthetic '+i,account:'synthetic@example.test',secret:'otpauth://totp/Synthetic:'+i+'?secret='+SECRET+'&digits=7&period=60'}));
 const finish=(n,count=2)=>({batchNonce:nonce(n),items:items(count),token:'synthetic',response:{}});
 const count=async table=>(await db.prepare('SELECT count(*) n FROM '+table).first()).n;
 let first;
 await check('50 items commit in one D1 batch and real AES-GCM decrypt preserves parameters',async()=>{
  first=await send('batch-finish',finish(1,50));eq(first.status,201);eq(first.body.entryIds.length,50);eq(await count('entries'),50);eq(await count('totp_seeds'),50);
  const id=first.body.entryIds[0],row=await db.prepare('SELECT envelope FROM totp_seeds WHERE entry_id=?').bind(id).first();
  const plain=JSON.parse(await cipher.decrypt(JSON.parse(row.envelope),{ownerId:'batch-owner',entryId:id}));eq(plain.digits,7);eq(plain.period,60);
  eq(JSON.stringify(first).includes(SECRET),false);
 });
 await check('same nonce is idempotent and changed batch is refused',async()=>{
  const again=await send('batch-finish',finish(1,50));eq(again.status,200);eq(again.body,first.body);eq((await send('batch-finish',finish(1,1))).status,409);eq(await count('entries'),50);
 });
 await check('unknown reply recovery reads the exact committed ids',async()=>{eq((await send('batch-outcome',{batchNonce:nonce(1)})).body,first.body);});
 await check('invalid item rejects the whole batch',async()=>{
  const body=finish(2);body.items.push({label:'invalid',account:'a',secret:'bad'});eq((await send('batch-finish',body)).status,400);eq(await count('entries'),50);
 });
 await check('seed insertion fault rolls back entries and nonce record',async()=>{
  await db.prepare("CREATE TRIGGER synthetic_batch_abort BEFORE INSERT ON totp_seeds BEGIN SELECT RAISE(ABORT,'synthetic failure'); END").run();
  try{eq((await send('batch-finish',finish(3))).status,503);eq(await count('entries'),50);eq((await send('batch-outcome',{batchNonce:nonce(3)})).body,{status:'none'});}finally{await db.prepare('DROP TRIGGER synthetic_batch_abort').run();}
 });
 await check('session revocation between authentication and D1 batch rolls back everything',async()=>{
  beforeBatch=async()=>{await db.prepare("UPDATE device_sessions SET revoked_at=? WHERE device_id='batch-device'").bind(NOW).run();};
  try{eq((await send('batch-finish',finish(4))).status,401);eq(await count('entries'),50);}finally{beforeBatch=async()=>{};await db.prepare("UPDATE device_sessions SET revoked_at=NULL WHERE device_id='batch-device'").run();}
 });
 await check('concurrent duplicate finish creates one batch and returns same ids',async()=>{
  const body=finish(5,3);const pair=await Promise.all([send('batch-finish',body),send('batch-finish',body)]);
  eq(pair.map(x=>x.status).sort(),[200,201]);eq(pair[0].body,pair[1].body);eq(await count('entries'),53);eq(await count('totp_batch_imports'),2);
 });
 await check('replay tombstone survives old creation date and imported entry deletion',async()=>{
  await db.prepare('UPDATE totp_batch_imports SET created_at=0').run();
  await db.prepare('DELETE FROM entries WHERE entry_id=?').bind(first.body.entryIds[0]).run();
  eq((await send('batch-finish',finish(1,50))).status,200);eq(await count('entries'),52);eq(await count('totp_batch_imports'),2);
 });
 await check('sealed export exact frozen set opens and method revocation during sealing refuses',async()=>{
  await db.prepare("INSERT INTO account_emails(owner_id,email,verified_at,updated_at) VALUES ('batch-owner','synthetic@example.test',0,0)").run();
  const pair=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']);
  const raw=new Uint8Array(await crypto.subtle.exportKey('raw',pair.publicKey)),pub=base64urlEncode(raw);
  let action;
  const passkeys={begin:async a=>{action=a.action;return{token:'synthetic',options:{}};},finishAuthentication:async()=>({generation:0})};
  const http=createTotpExportHttp({db,sessions:{authenticate:async()=>actor},getSeedCipher:async()=>cipher,clock:()=>NOW,passkeys});
  let n=0;const send=async(step,body)=>{const r=await http.fetch(new Request(API+'/v1/manage/totp/'+step,{method:'POST',headers:{Origin:APP,Authorization:'Bearer synthetic','Content-Type':'application/json'},body:JSON.stringify(body)}),{clientAddress:'export-'+n++});return{status:r.status,body:await r.json()};};
  const b=await send('export-begin',{ephemeralKey:pub});eq(b.status,200);eq(b.body.entries.length,52);
  const r=await send('export-finish',{ephemeralKey:pub,entries:b.body.entries.map(e=>({entryId:e.entryId,version:e.version})),token:'synthetic',response:{}});eq(r.status,200);eq(r.body.entries.length,52);
  const e=r.body.entries[0];const opened=await openExport({clientPrivateKey:pair.privateKey,serverPublicKey:r.body.serverPublicKey,actionDigest:action.slice('totp-export:'.length),ephemeralDigest:await sha256Hex(raw),aad:{ownerId:'batch-owner',deviceId:'batch-device',generation:0,entryId:e.entryId,seedVersion:e.version,algorithm:e.algorithm,digits:e.digits,period:e.period,label:e.label,account:e.account,issuer:e.issuer,catalogId:e.catalogId},nonce:e.nonce,ciphertext:e.ciphertext});eq(opened.length,20);
  const racing=createTotpExportHttp({db,sessions:{authenticate:async()=>actor},getSeedCipher:async()=>cipher,clock:()=>NOW,passkeys,
    seal:async args=>{const out=await sealExport(args);await db.prepare("UPDATE passkey_credentials SET revoked_at=? WHERE credential_id='batch-cred'").bind(NOW).run();return out;}});
  const refused=await racing.fetch(new Request(API+'/v1/manage/totp/export-finish',{method:'POST',headers:{Origin:APP,Authorization:'Bearer synthetic','Content-Type':'application/json'},body:JSON.stringify({ephemeralKey:pub,entries:b.body.entries.map(e=>({entryId:e.entryId,version:e.version})),token:'synthetic',response:{}})}),{clientAddress:'export-race'});
  eq(refused.status,409);eq(JSON.stringify(await refused.json()).includes('ciphertext'),false);
 });
 return{synthetic:true,pass:checks.every(c=>c.pass),checks,proof:'Real D1 transaction/error semantics and AES-GCM. Synthetic ceremony seam, not installed client proof.'};
}
