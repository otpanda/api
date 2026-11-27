// Synthetic-only qualification against the supplied D1 binding. Never mounted by production.
import {createTotpBatchImportHttp} from '../../src/totp-batch-import-http.js';
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
 return{synthetic:true,pass:checks.every(c=>c.pass),checks,proof:'Real D1 transaction/error semantics and AES-GCM. Synthetic ceremony seam, not installed client proof.'};
}
