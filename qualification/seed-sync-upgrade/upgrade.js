// Synthetic-only upgrade qualification: legacy totp_seeds rows that exist BEFORE migrations 0052/0053, then the migrations, then behaviour.
// Shared by the local test (test/seed-sync-upgrade.test.js, node:sqlite) and the remote scratch Worker (worker.js, real D1). Never mounted by production.
// Phase 1 seedLegacy(): runs on the pre-0052 schema (only the 0016 columns exist). Phase 2 verifyUpgrade(): runs after 0052 and 0053.
import {PER_REQUEST_CAP} from '../seed-sync/budget.mjs';
import {SeedCipher} from '../../src/seed-cipher.js';import {TotpSeedStore} from '../../src/totp-seeds.js';import {SeedSync} from '../../src/seed-sync.js';import {base64urlEncode} from '../../src/tokens.js';
export const NOW=1800000000000;
const sec=n=>new Uint8Array(n).map((_,i)=>(i*7+n)%251);
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const assert={ok:(v,m)=>{if(!v)throw Error(m||'assertion failed');},equal:(a,b,m)=>{if(a!==b)throw Error((m||'not equal')+': '+String(a)+' vs '+String(b));},deepEqual:(a,b,m)=>{if(!same(a,b))throw Error((m||'not deep equal')+': '+JSON.stringify(a)+' vs '+JSON.stringify(b));}};
// Legacy dataset. d=decryptable envelope (carries algorithm, digits, period inside), x=envelope bound to the wrong entry id (undecryptable: must stay metadata_pending).
export const LEGACY=[
 {owner:'u1',entry:'e1a',kind:'d',len:24,algorithm:'SHA-512',digits:7,period:45},
 {owner:'u1',entry:'e1b',kind:'d',len:20,algorithm:'SHA-1',digits:6,period:30},
 {owner:'u1',entry:'e1c',kind:'x',len:20,algorithm:'SHA-1',digits:6,period:30},
 {owner:'u2',entry:'e2a',kind:'d',len:16,algorithm:'SHA-256',digits:8,period:60},
 {owner:'u4',entry:'e4a',kind:'d',len:20,algorithm:'SHA-1',digits:6,period:30},
 {owner:'u4',entry:'e4b',kind:'d',len:32,algorithm:'SHA-256',digits:6,period:30},
];
export const ENTRY_ONLY={owner:'u3',entry:'e3a'};// owner with an entry but no seed at upgrade time
export const newCipher=async()=>new SeedCipher({keys:new Map([['t',await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt'])]]),activeKeyId:'t'});
// Counts rows_written/rows_read from D1 meta and enforces the per-request cap from the shared budget (a statement can still overshoot by its own rows).
export function counted(raw,cap=PER_REQUEST_CAP){const real=new WeakMap(),c={n:0,rw:0,rr:0};
 const guard=()=>{if(c.rw>cap.writes||c.rr>cap.reads)throw Error('per-request row cap reached');};
 const add=r=>{const m=r?.meta;if(m){c.rw+=m.rows_written??m.changes??0;c.rr+=m.rows_read??0;}return r;};
 const wrap=st=>{const p=new Proxy(st,{get(t,k){if(k==='bind')return(...a)=>wrap(t.bind(...a));if(['run','all','raw'].includes(k))return async(...a)=>{guard();c.n++;return add(await t[k](...a));};if(k==='first')return async(...a)=>{guard();c.n++;return t.first(...a);};return t[k];}});real.set(p,st);return p;};
 return{c,db:{prepare:sql=>wrap(raw.prepare(sql)),batch:async s=>{guard();c.n++;const r=await raw.batch(s.map(x=>real.get(x)??x));r.forEach(add);return r;}}};}
const q=(db,sql,...b)=>db.prepare(sql).bind(...b);
// Phase 1. Only legacy columns. Fails if the schema is already upgraded, so a wrong order cannot pass silently.
export async function seedLegacy(rawDb,cipher){
 const {c,db}=counted(rawDb);
 const cols=(await db.prepare("SELECT name FROM pragma_table_info('totp_seeds')").all()).results.map(r=>r.name);
 assert.deepEqual(cols,['owner_id','entry_id','envelope','created_at','updated_at'],'pre-upgrade totp_seeds columns');
 assert.equal((await db.prepare("SELECT count(*) n FROM sqlite_master WHERE name LIKE 'seed_sync%'").first()).n,0,'no seed_sync object exists before 0052');
 const st=[];for(const o of ['u1','u2','u3','u4']){st.push(q(db,'INSERT INTO accounts(owner_id,created_at) VALUES(?,?)',o,NOW));st.push(q(db,'INSERT INTO account_security(owner_id) VALUES(?)',o));}
 st.push(q(db,"INSERT OR IGNORE INTO services(service_id,name) VALUES('custom-totp','Authenticator')"));
 for(const r of [...LEGACY,ENTRY_ONLY])st.push(q(db,'INSERT INTO entries(entry_id,owner_id,service_id,label,created_at) VALUES(?,?,?,?,?)',r.entry,r.owner,'custom-totp','L '+r.entry,NOW));
 await db.batch(st);
 const rows=[];for(const r of LEGACY){
  const payload=JSON.stringify({secret:base64urlEncode(sec(r.len)),algorithm:r.algorithm,digits:r.digits,period:r.period});
  const env=JSON.stringify(await cipher.encrypt(payload,{ownerId:r.owner,entryId:r.kind==='d'?r.entry:'WRONG'}));
  rows.push(q(db,'INSERT INTO totp_seeds(owner_id,entry_id,envelope,created_at,updated_at) VALUES(?,?,?,?,?)',r.owner,r.entry,env,NOW,NOW));}
 await db.batch(rows);
 assert.equal((await db.prepare('SELECT count(*) n FROM totp_seeds').first()).n,LEGACY.length,'legacy rows present');
 return{synthetic:true,phase:'legacy',pass:true,legacyRows:LEGACY.length,totalQueries:c.n,totalRowsWritten:c.rw,totalRowsRead:c.rr};
}
// Phase 2. After 0052 and 0053. Each step records the rows it wrote (D1 meta.rows_written, trigger rows included) so the cost of upgrade and of each writer is measured.
export async function verifyUpgrade(rawDb,cipher){
 const {c,db}=counted(rawDb),steps=[];
 const step=async(name,fn)=>{const w0=c.rw,r0=c.rr,q0=c.n;try{const info=await fn();steps.push({name,pass:true,queries:c.n-q0,rowsWritten:c.rw-w0,rowsRead:c.rr-r0,...(info?{info}:{})});}catch(e){steps.push({name,pass:false,error:String(e?.message??e).slice(0,300)});throw e;}};
 const store=new TotpSeedStore(db,cipher),svc=new SeedSync({db,cipher,clock:()=>NOW});
 const rev=async o=>(await db.prepare('SELECT revision r FROM seed_sync_owner WHERE owner_id=?').bind(o).first())?.r??null;
 const row=e=>db.prepare('SELECT owner_id,algorithm,digits,period,seed_bytes,seed_version FROM totp_seeds WHERE entry_id=?').bind(e).first();
 const tomb=async o=>(await db.prepare('SELECT entry_id,revision FROM seed_sync_tombstones WHERE owner_id=? ORDER BY entry_id').bind(o).all()).results.map(r=>[r.entry_id,r.revision]);
 const n=async t=>(await db.prepare('SELECT count(*) n FROM '+t).first()).n;
 const plain=async e=>{const r=await db.prepare('SELECT owner_id,envelope FROM totp_seeds WHERE entry_id=?').bind(e).first();return JSON.parse(await cipher.decrypt(JSON.parse(r.envelope),{ownerId:r.owner_id,entryId:e}));};
 const put=(o,e,len,alg='SHA-1',d=6,p=30)=>store.putSeed(o,e,{secret:sec(len),algorithm:alg,digits:d,period:p},NOW);
 try{
 await step('upgraded shape: owner revisions start at 1 only for owners holding seeds, every legacy row is seed_version 1, metadata NULL (metadata_pending), nothing defaulted',async()=>{
  const cols=(await db.prepare("SELECT name FROM pragma_table_info('totp_seeds')").all()).results.map(r=>r.name);
  for(const x of ['seed_version','algorithm','digits','period','seed_bytes'])assert.ok(cols.includes(x),'column '+x);
  assert.deepEqual([await rev('u1'),await rev('u2'),await rev('u3'),await rev('u4')],[1,1,null,1],'owner revisions');
  for(const l of LEGACY){const r=await row(l.entry);assert.deepEqual([r.seed_version,r.algorithm,r.digits,r.period,r.seed_bytes],[1,null,null,null,null],'legacy '+l.entry);}
  assert.equal(await svc.metadataPending(),LEGACY.length,'all pending');
  assert.deepEqual([await n('seed_sync_tombstones'),await n('seed_sync_keys'),await n('seed_sync_notices'),await n('seed_sync_challenges')],[0,0,0,0],'no tombstones, keys, notices or challenges');
  for(const l of LEGACY){if(l.kind!=='d')continue;const p=await plain(l.entry);assert.equal(p.digits,l.digits,'envelope intact '+l.entry);assert.equal(p.secret,base64urlEncode(sec(l.len)),'secret intact '+l.entry);}
 });
 await step('insert for an owner that held seeds: >=1 changes, revision 1->2, only the new row takes version 2, legacy rows keep version 1',async()=>{
  await db.prepare("INSERT INTO entries(entry_id,owner_id,service_id,label,created_at) VALUES('e1d','u1','custom-totp','L e1d',?)").bind(NOW).run();
  assert.equal(await put('u1','e1d',20),true);assert.equal(await rev('u1'),2);
  const r=await row('e1d');assert.deepEqual([r.seed_version,r.algorithm,r.digits,r.period,r.seed_bytes],[2,'SHA-1',6,30,20],'new row');
  for(const e of ['e1a','e1b','e1c'])assert.equal((await row(e)).seed_version,1,'legacy untouched '+e);
 });
 await step('first-ever seed of an owner with no owner row (u3): owner row created at revision 1, row version 1',async()=>{
  assert.equal(await put('u3','e3a',20),true);assert.equal(await rev('u3'),1);assert.equal((await row('e3a')).seed_version,1);
 });
 await step('rotation of a legacy row: revision 2->3, that row version 3 with metadata now set, sibling legacy row unchanged and still pending',async()=>{
  assert.equal(await put('u1','e1b',24,'SHA-256',8,60),true);assert.equal(await rev('u1'),3);
  const r=await row('e1b');assert.deepEqual([r.seed_version,r.algorithm,r.digits,r.period,r.seed_bytes],[3,'SHA-256',8,60,24],'rotated');
  const a=await row('e1a');assert.deepEqual([a.seed_version,a.algorithm],[1,null],'sibling');
 });
 await step('metadata backfill: decryptable legacy rows filled from their envelopes, the undecryptable one stays NULL, revisions move once per filled row, seed_version does not',async()=>{
  assert.equal(await svc.metadataPending(),5,'pending before (e1a,e1c,e2a,e4a,e4b)');
  assert.equal(await svc.backfillMetadata({limit:50}),4,'filled');
  for(const l of LEGACY){if(['e1b'].includes(l.entry))continue;const r=await row(l.entry);
   if(l.kind==='d'){assert.deepEqual([r.algorithm,r.digits,r.period,r.seed_bytes],[l.algorithm,l.digits,l.period,l.len],'filled '+l.entry);assert.equal(r.seed_version,1,'version unchanged '+l.entry);}
   else assert.deepEqual([r.algorithm,r.digits,r.period,r.seed_bytes],[null,null,null,null],'stays pending '+l.entry);}
  assert.deepEqual([await rev('u1'),await rev('u2'),await rev('u4')],[4,2,3],'revision moved once per filled row');
  assert.equal(await svc.metadataPending(),1);assert.equal(await svc.backfillMetadata({limit:50}),0,'idempotent');
 });
 await step('delete then re-create: tombstone at the post-bump revision, then removed by the re-create, new version above every earlier one',async()=>{
  assert.equal(await store.removeSeed('u1','e1a'),true);assert.equal(await rev('u1'),5);assert.deepEqual(await tomb('u1'),[['e1a',5]]);
  assert.equal(await put('u1','e1a',24,'SHA-512',7,45),true);assert.equal(await rev('u1'),6);assert.deepEqual(await tomb('u1'),[]);assert.equal((await row('e1a')).seed_version,6);
  assert.equal(await store.removeSeed('u1','e1a'),true);assert.equal(await store.removeSeed('u1','e1a'),false,'zero-row delete stays false');
 });
 await step('entry delete cascades into a seed delete: >=1 changes, seed gone, tombstone written',async()=>{
  const r=await db.prepare("DELETE FROM entries WHERE entry_id='e1d' AND owner_id='u1'").run();assert.ok(r.meta.changes>=1);
  assert.equal(await n("totp_seeds WHERE entry_id='e1d'"),0);assert.deepEqual((await tomb('u1')).map(x=>x[0]),['e1a','e1d']);
 });
 await step('account delete cascade for u4 (legacy seeds): seeds, owner row and entries gone, no tombstones, no revision written',async()=>{
  const before=await n('seed_sync_tombstones');
  await db.prepare("DELETE FROM accounts WHERE owner_id='u4'").run();
  assert.equal(await n("totp_seeds WHERE owner_id='u4'"),0);assert.equal(await rev('u4'),null);assert.deepEqual(await tomb('u4'),[]);assert.equal(await n('seed_sync_tombstones'),before,'tombstone count unchanged');
 });
 await step('zero-row writes keep failing: missing entry and other-owner writes return false and change nothing',async()=>{
  const r1=await rev('u2');assert.equal(await put('u2','nope',20),false);assert.equal(await put('u2','e1b',20),false,'other owner entry');assert.equal(await rev('u2'),r1);
 });
 }catch(e){return{synthetic:true,phase:'verify',pass:false,fatal:String(e?.message??e).slice(0,300),steps,totalQueries:c.n,totalRowsWritten:c.rw,totalRowsRead:c.rr};}
 return{synthetic:true,phase:'verify',pass:steps.every(x=>x.pass),steps,totalQueries:c.n,totalRowsWritten:c.rw,totalRowsRead:c.rr};
}
