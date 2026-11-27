// Synthetic-only seed-sync qualification against the supplied D1 binding (remote scratch D1 in the workflow, local workerd in tool/d1-qualify-seed-sync.mjs).
// Never mounted by production. Needs migrations 0052 and 0053 applied. Groups: fence scenarios (ported from tool/seed-sync-d1-fence-check.mjs),
// trigger-row meta.changes, and metadata writers.
import {SeedCipher} from '../../src/seed-cipher.js';import {TotpSeedStore} from '../../src/totp-seeds.js';
import {SeedSync,seedSyncEnrollAction} from '../../src/seed-sync.js';import {seedSyncProofMessage} from '../../src/seed-sync-proof.js';import {base64urlEncode} from '../../src/tokens.js';
import {createTotpBatchImportHttp} from '../../src/totp-batch-import-http.js';
import {createTotpManagementHttp} from '../../src/totp-management-http.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',SECRET32='GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const NOW=1800000000000,INSTALL='i'.repeat(22);
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const assert={ok:(v,m)=>{if(!v)throw Error(m||'assertion failed');},equal:(a,b,m)=>{if(a!==b)throw Error((m||'not equal')+': '+String(a)+' vs '+String(b));},deepEqual:(a,b,m)=>{if(!same(a,b))throw Error((m||'not deep equal')+': '+JSON.stringify(a)+' vs '+JSON.stringify(b));}};
export const GROUPS=Array.from({length:14},(_,i)=>'c'+String(i+1).padStart(2,'0'));
// Counts D1 round trips (each run/first/all/raw call and each batch call is one query against the per-invocation limit).
function counted(raw){const real=new WeakMap(),c={n:0};
 const wrap=st=>{const p=new Proxy(st,{get(t,k){if(k==='bind')return(...a)=>wrap(t.bind(...a));if(['run','first','all','raw'].includes(k))return(...a)=>{c.n++;return t[k](...a);};const v=t[k];return typeof v==='function'?v.bind(t):v;}});real.set(p,st);return p;};
 return{c,db:{prepare:sql=>wrap(raw.prepare(sql)),batch:s=>{c.n++;return raw.batch(s.map(x=>real.get(x)??x));}}};}
// group: one check id from GROUPS, c01..c14 in source order (each runs in its own Worker request so it gets its own CPU and D1 query budget; the busiest check used 23 queries locally), or undefined for all.
export async function runChecks(rawDb,group){
 const {c,db}=counted(rawDb);
 if(group!==undefined&&!GROUPS.includes(group))throw Error('unknown group');
 const checks=[],info={};let seq=0;
 async function check(name,fn){const g='c'+String(++seq).padStart(2,'0');if(group!==undefined&&g!==group)return;const q0=c.n;try{await fn();checks.push({name,group:g,pass:true,queries:c.n-q0});}catch(e){checks.push({name,group:g,pass:false,queries:c.n-q0,error:String(e?.message??e).slice(0,300)});}}
 const note=()=>{};
 await db.batch([db.prepare('INSERT OR IGNORE INTO accounts(owner_id,created_at) VALUES(?,?)').bind('owner',NOW),db.prepare('INSERT OR IGNORE INTO account_security(owner_id) VALUES(?)').bind('owner'),
  db.prepare('INSERT OR IGNORE INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) VALUES(?,?,?,?,?,?,?,?)').bind('cred','owner',new Uint8Array([1]),0,'[]','singleDevice',0,NOW),
  db.prepare("INSERT OR IGNORE INTO device_sessions(device_id,owner_id,credential_id,provider_identity_id,generation,client_kind,created_at,last_used_at,expires_at) VALUES('dev','owner','cred',NULL,0,'android',0,0,9999999999999)")]);
 const cipher=new SeedCipher({keys:new Map([['t',await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt'])]]),activeKeyId:'t'});
 const svc=new SeedSync({db,cipher,clock:()=>NOW}),user={ownerId:'owner',deviceId:'dev',generation:0};
 const kid=()=>[...crypto.getRandomValues(new Uint8Array(16))].map(b=>b.toString(16).padStart(2,'0')).join('');
 const newKey=async()=>{const k=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']),j=await crypto.subtle.exportKey('jwk',k.publicKey);return {k,j:{kty:j.kty,crv:j.crv,x:j.x,y:j.y}};};
 const begin=async({j,keyId=kid()})=>{const action=await seedSyncEnrollAction({ownerId:'owner',installId:INSTALL,keyId,publicJwk:j,generation:0});const c=await svc.enrollBegin({user,installId:INSTALL,keyId,publicJwk:j,strongProof:{purpose:'step-up',ownerId:'owner',generation:0,credentialId:'cred',actionDigest:action,verifiedAt:NOW}});return c&&{...c,keyId};};
 const finish=async(c,key)=>svc.enrollFinish({user,token:c.token,signature:base64urlEncode(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key.k.privateKey,seedSyncProofMessage('seed-sync-enroll',c.challenge))))});
 const state=async()=>(await db.prepare('SELECT key_id,revoked_at a,revoked_reason r FROM seed_sync_keys ORDER BY rowid').all()).results.map(r=>[r.key_id,r.a==null?'active':r.r]);
 const reset=()=>db.batch([db.prepare('DELETE FROM seed_sync_notices'),db.prepare('DELETE FROM seed_sync_keys'),db.prepare('DELETE FROM seed_sync_challenges')]);
 
 await check('fence 1: late finish after newer enrollment',async()=>{await reset();const a=await newKey(),b=await newKey(),c1=await begin({j:a.j}),c2=await begin({j:b.j});assert.ok(await finish(c2,b));assert.equal(await finish(c1,a),undefined);assert.deepEqual(await state(),[[c2.keyId,'active']]);note('late finish after newer enrollment fails, winner active');});
 await check('fence 2: predecessor revoked after begin, same millisecond; then re-enable',async()=>{await reset();const a=await newKey(),b=await newKey(),d=await newKey(),c0=await begin({j:a.j});const k0=await finish(c0,a);assert.ok(k0);
 const c1=await begin({j:b.j});assert.equal(await svc.revoke({ownerId:'owner',keyId:k0.keyId,reason:'disabled'}),true);assert.equal(await finish(c1,b),undefined);assert.deepEqual(await state(),[[k0.keyId,'disabled']]);
 const c2=await begin({j:d.j});assert.ok(await finish(c2,d));assert.deepEqual(await state(),[[k0.keyId,'disabled'],[c2.keyId,'active']]);assert.equal(await finish(c1,b),undefined);note('revoked predecessor blocks late finish (same ms); re-enable works');});
 await check('fence 3: supersede in the same batch and key rows/notices consistent',async()=>{await reset();const a=await newKey(),b=await newKey(),c0=await begin({j:a.j});const k0=await finish(c0,a);const c1=await begin({j:b.j});assert.ok(await finish(c1,b));
 assert.deepEqual(await state(),[[k0.keyId,'superseded'],[c1.keyId,'active']]);assert.equal((await db.prepare('SELECT count(*) n FROM seed_sync_notices').first()).n,2);note('supersede + insert + notice commit together (changes() chain)');});
 await check('fence 4: id collision at finish rolls back with no effect on the winner, and the loser leaves no partial rows',async()=>{await reset();const a=await newKey(),b=await newKey(),c=await newKey(),ID=kid();const c0=await begin({j:a.j});const k0=await finish(c0,a);
 const c1=await begin({j:b.j,keyId:ID}),c2=await begin({j:c.j,keyId:ID});assert.ok(await finish(c1,b));assert.equal(await finish(c2,c),undefined);
 assert.deepEqual(await state(),[[k0.keyId,'superseded'],[ID,'active']]);assert.equal((await db.prepare('SELECT count(*) n FROM seed_sync_notices').first()).n,2);note('id collision at finish: winner untouched, no stray rows');});
 await check('fence 5: concurrent finishes from the same pre-state: exactly one commits',async()=>{await reset();const a=await newKey(),b=await newKey(),c=await newKey(),c0=await begin({j:a.j});const k0=await finish(c0,a);
 const c1=await begin({j:b.j}),c2=await begin({j:c.j});const r=await Promise.all([finish(c1,b),finish(c2,c)]);
 assert.equal(r.filter(Boolean).length,1,'exactly one wins');const st=await state();assert.equal(st.filter(x=>x[1]==='active').length,1);assert.equal(st.length,2);assert.equal(st[0][1],'superseded');note('concurrent finishes: exactly one commits ('+JSON.stringify(r.map(x=>!!x))+')');});
 await check('fence 6: raw batch rollback: a failing INSERT inside db.batch rolls back the earlier UPDATE (the premise the guards no longer depend on)',async()=>{await reset();const a=await newKey(),c0=await begin({j:a.j});const k0=await finish(c0,a);
 let threw=false;try{await db.batch([db.prepare("UPDATE seed_sync_keys SET revoked_at=1,revoked_reason='disabled' WHERE key_id=?").bind(k0.keyId),db.prepare("INSERT INTO seed_sync_keys(key_id,owner_id,install_id,public_jwk,public_key_digest,generation,created_at) VALUES(?,?,?,?,?,0,1)").bind(k0.keyId,'owner','z'.repeat(22),'{}','dd')]);}catch{threw=true;}
 assert.ok(threw);assert.deepEqual(await state(),[[k0.keyId,'active']]);note('D1 batch rolls back earlier statements when a later one fails');});
 await check('fence 7: changes() semantic: after an UPDATE matching 0 rows changes()=0, after matching 1 row changes()=1, inside a batch',async()=>{await reset();const a=await newKey(),c0=await begin({j:a.j});const k0=await finish(c0,a);
 const r=await db.batch([db.prepare("UPDATE seed_sync_keys SET last_used_at=5 WHERE key_id='none'"),db.prepare("SELECT changes() AS c"),db.prepare("UPDATE seed_sync_keys SET last_used_at=6 WHERE key_id=?").bind(k0.keyId),db.prepare("SELECT changes() AS c")]);
 assert.equal(r[1].results[0].c,0);assert.equal(r[3].results[0].c,1);note('changes() after the previous batch statement: 0 then 1');});
 // ---- trigger-row meta.changes ----
 const store=new TotpSeedStore(db,cipher),sec=n=>new Uint8Array(n).map((_,i)=>(i*7+n)%251);
 const addEntry=async(id,owner='owner')=>{await db.prepare("INSERT OR IGNORE INTO services(service_id,name) VALUES ('custom-totp','Authenticator')").run();await db.prepare('INSERT INTO entries(entry_id,owner_id,service_id,label,created_at) VALUES(?,?,?,?,?)').bind(id,owner,'custom-totp','Synthetic '+id,NOW).run();};
 const seedRow=id=>db.prepare('SELECT algorithm,digits,period,seed_bytes,seed_version,envelope FROM totp_seeds WHERE entry_id=?').bind(id).first();
 await check('meta.changes: totp_seeds writes report trigger rows, the code treats >=1 as success, and a plain table counts exactly 1',async()=>{
  await db.prepare('CREATE TABLE IF NOT EXISTS qual_plain(id TEXT PRIMARY KEY,v TEXT)').run();
  const plain=await db.prepare("INSERT INTO qual_plain(id,v) VALUES('p','1')").run();assert.equal(plain.meta.changes,1,'plain insert');
  await addEntry('mc1');const env=JSON.stringify(await cipher.encrypt('{}',{ownerId:'owner',entryId:'mc1'}));
  const ins=await db.prepare('INSERT INTO totp_seeds(owner_id,entry_id,envelope,created_at,updated_at,algorithm,digits,period,seed_bytes) VALUES(?,?,?,?,?,?,?,?,?)').bind('owner','mc1',env,NOW,NOW,'SHA-1',6,30,10).run();
  info.seedInsertChanges=ins.meta.changes;assert.ok(ins.meta.changes>=1,'insert changes');
  const upd=await db.prepare("UPDATE totp_seeds SET envelope=?2,updated_at=?3 WHERE entry_id=?1").bind('mc1',env+' ',NOW+1).run();info.seedUpdateChanges=upd.meta.changes;assert.ok(upd.meta.changes>=1,'update changes');
  const none=await db.prepare("UPDATE totp_seeds SET envelope=?2 WHERE entry_id=?1 AND owner_id='nobody'").bind('mc1',env).run();assert.equal(none.meta.changes,0,'zero-row update stays 0');
  const nodel=await db.prepare("DELETE FROM totp_seeds WHERE entry_id='mc1' AND owner_id='nobody'").run();assert.equal(nodel.meta.changes,0,'zero-row delete stays 0');
  const del=await db.prepare("DELETE FROM totp_seeds WHERE entry_id='mc1'").run();info.seedDeleteChanges=del.meta.changes;assert.ok(del.meta.changes>=1,'delete changes');
  info.triggerRowsCounted=ins.meta.changes>plain.meta.changes;
 });
 await check('putSeed and removeSeed: >=1 success, zero-row failure stays false (missing entry, other owner)',async()=>{
  await addEntry('mc2');await db.prepare("INSERT OR IGNORE INTO accounts(owner_id,created_at) VALUES('other',?)").bind(NOW).run();
  assert.equal(await store.putSeed('owner','mc2',{secret:sec(20),algorithm:'SHA-1',digits:6,period:30},NOW),true,'insert');
  assert.equal(await store.putSeed('owner','mc2',{secret:sec(20),algorithm:'SHA-1',digits:7,period:30},NOW+1),true,'rotate');
  assert.equal(await store.putSeed('owner','missing',{secret:sec(20),algorithm:'SHA-1',digits:6,period:30},NOW),false,'missing entry');
  assert.equal(await store.putSeed('other','mc2',{secret:sec(20),algorithm:'SHA-1',digits:6,period:30},NOW),false,'other owner cannot write');
  assert.equal(await store.removeSeed('other','mc2'),false,'other owner cannot remove');
  assert.equal(await store.removeSeed('owner','mc2'),true,'remove');assert.equal(await store.removeSeed('owner','mc2'),false,'second remove');
 });
 await check('entry delete cascades into a seed delete: >=1, tombstone written; account delete cascade writes no tombstone or owner revision',async()=>{
  await addEntry('mc3');await store.putSeed('owner','mc3',{secret:sec(16),algorithm:'SHA-1',digits:6,period:30},NOW);
  const r=await db.prepare("DELETE FROM entries WHERE entry_id='mc3' AND owner_id='owner'").run();assert.ok(r.meta.changes>=1,'entry delete');
  assert.equal((await db.prepare("SELECT count(*) n FROM totp_seeds WHERE entry_id='mc3'").first()).n,0,'seed cascaded');
  assert.equal((await db.prepare("SELECT count(*) n FROM seed_sync_tombstones WHERE entry_id='mc3'").first()).n,1,'tombstone');
  await db.prepare("INSERT INTO accounts(owner_id,created_at) VALUES('gone',?)").bind(NOW).run();await addEntry('mc4','gone');await store.putSeed('gone','mc4',{secret:sec(16),algorithm:'SHA-1',digits:6,period:30},NOW);
  await db.prepare("DELETE FROM accounts WHERE owner_id='gone'").run();
  assert.equal((await db.prepare("SELECT count(*) n FROM totp_seeds WHERE owner_id='gone'").first()).n,0,'account cascade removed seeds');
  assert.equal((await db.prepare("SELECT count(*) n FROM seed_sync_tombstones WHERE owner_id='gone'").first()).n,0,'no tombstone after account delete');
 });
 // ---- metadata writers ----
 await check('metadata: putSeed writes algorithm, digits, period and seed_bytes with the envelope, rotation updates them, version rises across delete and re-create',async()=>{
  await addEntry('md1');await store.putSeed('owner','md1',{secret:sec(32),algorithm:'SHA-256',digits:8,period:60},NOW);
  let r=await seedRow('md1');assert.deepEqual([r.algorithm,r.digits,r.period,r.seed_bytes],['SHA-256',8,60,32],'insert metadata');const v1=r.seed_version;
  await store.putSeed('owner','md1',{secret:sec(20),algorithm:'SHA-1',digits:6,period:30},NOW+1);r=await seedRow('md1');assert.deepEqual([r.algorithm,r.digits,r.period,r.seed_bytes],['SHA-1',6,30,20],'rotated metadata');
  assert.ok(r.seed_version>v1,'rotation raises version');const v2=r.seed_version;
  await store.removeSeed('owner','md1');await store.putSeed('owner','md1',{secret:sec(20),algorithm:'SHA-1',digits:6,period:30},NOW+2);assert.ok((await seedRow('md1')).seed_version>v2,'re-create version above any earlier');
 });
 await check('metadata backfill: legacy NULL rows are decrypted in memory and filled, an undecryptable row stays pending, nothing is defaulted',async()=>{
  const svc2=new SeedSync({db,cipher,clock:()=>NOW});
  await addEntry('lg1');await addEntry('lg2');
  const payload=JSON.stringify({secret:base64urlEncode(sec(24)),algorithm:'SHA-512',digits:7,period:45});
  const good=JSON.stringify(await cipher.encrypt(payload,{ownerId:'owner',entryId:'lg1'}));
  await db.prepare('INSERT INTO totp_seeds(owner_id,entry_id,envelope,created_at,updated_at) VALUES(?,?,?,?,?)').bind('owner','lg1',good,NOW,NOW).run();
  const bad=JSON.stringify(await cipher.encrypt(payload,{ownerId:'owner',entryId:'WRONG'}));
  await db.prepare('INSERT INTO totp_seeds(owner_id,entry_id,envelope,created_at,updated_at) VALUES(?,?,?,?,?)').bind('owner','lg2',bad,NOW,NOW).run();
  assert.equal(await svc2.metadataPending(),2,'two pending');
  assert.equal(await svc2.backfillMetadata({limit:50}),1,'one filled');
  const a=await seedRow('lg1'),b=await seedRow('lg2');assert.deepEqual([a.algorithm,a.digits,a.period,a.seed_bytes],['SHA-512',7,45,24],'filled from the envelope');
  assert.deepEqual([b.algorithm,b.digits,b.period,b.seed_bytes],[null,null,null,null],'undecryptable row stays NULL');
  assert.equal(await svc2.metadataPending(),1,'one still pending');assert.equal(await svc2.backfillMetadata({limit:50}),0,'idempotent');
 });

 // ---- real HTTP writers (synthetic ceremony seam only, as in qualification/transfer) ----
 const actor={ownerId:'owner',deviceId:'devweb',generation:0,clientKind:'web',expiresAt:NOW+1e9};
 const passkeys={begin:async()=>({token:'synthetic'}),finishAuthentication:async()=>({generation:0})};
 const sessions={authenticate:async()=>actor};
 let rc=0;const send=async(http,path,body)=>{const r=await http.fetch(new Request(API+path,{method:'POST',headers:{Origin:APP,Authorization:'Bearer synthetic','Content-Type':'application/json'},body:JSON.stringify(body)}),{clientAddress:'synthetic-md-'+(++rc)});return{status:r.status,body:await r.json()};};
 await db.prepare("INSERT OR IGNORE INTO device_sessions(device_id,owner_id,credential_id,provider_identity_id,generation,client_kind,created_at,last_used_at,expires_at) VALUES('devweb','owner','cred',NULL,0,'web',0,0,9999999999999)").run();
 await check('metadata: management create route writes metadata with the seed in the same insert (otpauth parameters)',async()=>{
  const http=createTotpManagementHttp({db,sessions,getSeedCipher:async()=>cipher,clock:()=>NOW,passkeys});
  const body={label:'Synthetic mgmt',account:'a@example.test',secret:'otpauth://totp/S:m?secret='+SECRET32+'&digits=7&period=60&algorithm=SHA256',response:{},token:'synthetic'};
  const r=await send(http,'/v1/manage/totp',body);assert.equal(r.status,201,'create status '+r.status+' '+JSON.stringify(r.body));
  const row=await seedRow(r.body.entryId);assert.deepEqual([row.algorithm,row.digits,row.period,row.seed_bytes],['SHA-256',7,60,20],'management metadata');
  const plain=JSON.parse(await cipher.decrypt(JSON.parse(row.envelope),{ownerId:'owner',entryId:r.body.entryId}));assert.equal(plain.digits,7,'envelope agrees with metadata');
 });
 await check('metadata: batch import writes metadata for every seed in the one atomic batch, nonce replay is stable, nothing is NULL',async()=>{
  const http=createTotpBatchImportHttp({db,sessions,getSeedCipher:async()=>cipher,clock:()=>NOW,passkeys});
  const items=[0,1,2].map(i=>({label:'Synthetic b'+i,account:'b@example.test',secret:'otpauth://totp/S:b'+i+'?secret='+SECRET32+'&digits='+(6+i%3)+'&period='+(30+30*(i%2))}));
  const body={batchNonce:'synthetic_seed_sync_batch_nonce_000001',items,token:'synthetic',response:{}};
  const r=await send(http,'/v1/manage/totp/batch-finish',body);assert.equal(r.status,201,'batch status '+r.status+' '+JSON.stringify(r.body));assert.equal(r.body.entryIds.length,3);
  for(const [i,id] of r.body.entryIds.entries()){const row=await seedRow(id);assert.deepEqual([row.algorithm,row.digits,row.period,row.seed_bytes],['SHA-1',6+i%3,30+30*(i%2),20],'batch metadata '+i);assert.ok(row.seed_version>0,'version set');}
  const again=await send(http,'/v1/manage/totp/batch-finish',body);assert.equal(again.status,200);assert.deepEqual(again.body.entryIds,r.body.entryIds);
  const n=(await db.prepare("SELECT count(*) n FROM totp_seeds WHERE entry_id IN (?1,?2,?3)").bind(...r.body.entryIds).first()).n;assert.equal(n,3,'replay wrote nothing new');
 });
 info.note='Counts reflect the D1 build that ran this check; local workerd and remote D1 may differ.';
 return{synthetic:true,group:group??'all',pass:checks.length>0&&checks.every(x=>x.pass),checks,info,totalQueries:c.n};
}
