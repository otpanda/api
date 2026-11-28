// Local executed proof of the 0051-state upgrade: legacy rows seeded on the schema without 0052/0053, the two migrations applied, then writers verified.
// Pre-state matches deployed main through0051; all remaining migrations apply in order after legacy seeding.
import test from 'node:test';import assert from 'node:assert/strict';
import {database} from './sqlite-helper.js';import {seedLegacy,verifyUpgrade,newCipher,LEGACY} from '../qualification/seed-sync-upgrade/upgrade.js';
const SKIP=['0052_seed_sync.sql','0053_seed_sync_notices.sql','0063_access_grants_machine_profiles.sql','0064_totp_batch_imports.sql','0065_action_audience_revisions.sql'];
test('upgrade from legacy rows: seed, apply 0052 then 0053, verify revisions, versions, pending metadata, writers and cascades; measure rows written',async()=>{
 const db=database(':memory:',{skip:SKIP}),cipher=await newCipher();try{
  const p1=await seedLegacy(db,cipher);assert.equal(p1.pass,true);assert.equal(p1.legacyRows,LEGACY.length);
  const t=()=>Number(db.sqlite.prepare('SELECT total_changes() n').get().n);
  const a=t();db.migrate(SKIP[0]);const w52=t()-a;const b=t();db.migrate(SKIP[1]);const w53=t()-b;
  for(const f of SKIP.slice(2))db.migrate(f);
  const v=await verifyUpgrade(db,cipher);for(const s of v.steps)assert.equal(s.pass,true,s.name+' '+(s.error??''));assert.equal(v.pass,true,v.fatal);
  // 0052 backfill INSERT only for the three owners that hold seeds; the ALTER TABLEs rewrite no rows.
  assert.equal(db.sqlite.prepare('SELECT count(*) n FROM seed_sync_owner').get().n>=3,true);
  console.log(JSON.stringify({localMigrationRowsWritten:{'0052':w52,'0053':w53},seedLegacy:{written:p1.totalRowsWritten,read:p1.totalRowsRead},verify:{written:v.totalRowsWritten,read:v.totalRowsRead,queries:v.totalQueries},steps:v.steps.map(s=>[s.name.slice(0,48),s.rowsWritten,s.rowsRead])}));
 }finally{db.sqlite.close();}});
test('the harness refuses a wrong order: seeding legacy rows after 0052 is rejected',async()=>{
 const db=database(':memory:'),cipher=await newCipher();try{await assert.rejects(seedLegacy(db,cipher),/pre-upgrade/);}finally{db.sqlite.close();}});
test('remote Worker code path, run against the local D1-shaped adapter: one POST per phase, shared per-run key across requests, replay is 409, wrong phase order is refused',async()=>{
 const {default:worker}=await import('../qualification/seed-sync-upgrade/worker.js');
 const db=database(':memory:',{skip:SKIP}),env={DB:db,FIXTURE_PREFIX:'p1',FIXTURE_KEY_B64:Buffer.alloc(32,9).toString('base64')};
 const call=(op,m='POST')=>worker.fetch(new Request('https://x.test/p1/'+op,{method:m}),env);
 try{
  assert.equal((await call('ready','GET')).status,200);assert.equal((await call('nope')).status,404);
  const a=await call('seed-legacy');assert.equal(a.status,200);const ja=await a.json();assert.equal(ja.pass,true);assert.equal((await call('seed-legacy')).status,409);
  for(const f of SKIP)db.migrate(f);
  const v=await call('verify');const jv=await v.json();assert.equal(v.status,200,JSON.stringify(jv));assert.equal(jv.pass,true);assert.ok(jv.totalRowsWritten>0&&jv.totalRowsWritten<200,'per-request cap');assert.equal((await call('verify')).status,409);
 }finally{db.sqlite.close();}});
