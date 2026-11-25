import assert from 'node:assert/strict';import {database} from '../test/sqlite-helper.js';import {createRequire} from 'node:module';import {readdirSync,readFileSync} from 'node:fs';
const require=createRequire(import.meta.url);const {Miniflare,convertV4MiniflareOptions}=require('miniflare');
const options=await convertV4MiniflareOptions({modules:[{type:'ESModule',path:new URL('./realtime-hub-worker.mjs',import.meta.url).pathname},{type:'ESModule',path:new URL('../src/realtime-hub.js',import.meta.url).pathname}],modulesRoot:new URL('..',import.meta.url).pathname,compatibilityDate:'2026-11-23',d1Databases:['DB'],durableObjects:{HUB:{className:'RealtimeHub',useSQLite:true}}});
const mf=new Miniflare(options);
try{const db=await mf.getD1Database('DB');
for(const f of readdirSync('migrations').sort())for(const sql of readFileSync('migrations/'+f,'utf8').replace(/^--.*$/gm,'').split(/;(?=\s*(?:CREATE|ALTER|PRAGMA|$))/).map(s=>s.trim()).filter(Boolean))await db.prepare(sql).run();
const shim=database(),N=1700000000000,run=async(s,...a)=>{const r=await db.prepare(s).bind(...a).run(),m=await shim.prepare(s).bind(...a).run();assert.equal(r.meta.changes,m.meta.changes,'D1 vs test shim meta.changes differ for: '+s);console.log('changes',r.meta.changes,'shim',m.meta.changes,s.slice(0,60));return r;};
const rw=[];
const step=async(s,...a)=>{const r=await run(s,...a);rw.push([r.meta.changes,r.meta.rows_written,s.slice(0,48)]);return r;};
for(const q of [["INSERT INTO accounts(owner_id,created_at) VALUES ('o',?)",N],["INSERT INTO accounts(owner_id,created_at) VALUES ('v',?)",N],["INSERT INTO services(service_id,name) VALUES ('svc','svc')"]])await step(...q);
await step("INSERT INTO sources(source_id,owner_id,kind,label,created_at) VALUES ('s1','o','gmail','m',?)",N);
await step("INSERT INTO entries(entry_id,owner_id,service_id,label,created_at) VALUES ('e1','o','svc','l',?)",N);
await step("INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) VALUES ('c1','o','pk',0,'[]','singleDevice',0,?)",N);
await step("INSERT INTO account_security(owner_id,generation) VALUES ('o',1)");
await step("INSERT INTO device_sessions(device_id,owner_id,credential_id,generation,client_kind,created_at,last_used_at,expires_at) VALUES ('d1','o','c1',1,'web',?,?,?)",N,N,N+9e9);
// ticket insert (trigger writes realtime_activity)
await step("INSERT INTO realtime_tickets(ticket_id,secret_digest,owner_id,device_id,generation,created_at,expires_at,close_at) VALUES ('t1',?,'o','d1',1,?,?,?)",'a'.repeat(64),N,N+30000,N+300000);
// organization: insert, update with a pending hint (coalesces), update with none pending (trigger row added)
await step("INSERT INTO personal_organization(viewer_id,revision,document,updated_at) VALUES ('o',0,'{}',?)",N);
await step("UPDATE personal_organization SET revision=revision+1,document='{\"a\":1}',updated_at=? WHERE viewer_id='o' AND revision=0",N);
await run('DELETE FROM realtime_outbox');shim.sqlite.exec('DELETE FROM realtime_outbox');
const org=await step("UPDATE personal_organization SET revision=revision+1,document='{\"a\":2}',updated_at=? WHERE viewer_id='o' AND revision=1",N);
assert.equal(org.meta.changes,2,'org write with no pending hint counts the trigger row');
// entry shares insert + revoke
await step("INSERT INTO entry_shares(entry_id,recipient_id,created_at) VALUES ('e1','v',?)",N);
await step("UPDATE entry_shares SET revoked_at=? WHERE entry_id='e1' AND recipient_id='v'",N);
// incoming code insert, assign (entry_id update), delete
await step("INSERT INTO incoming_codes(owner_id,event_id,source_id,entry_id,envelope,received_at,expires_at,assignment) VALUES ('o','u','s1',NULL,'{}',?,?,'unassigned')",N,N+9e9);
await step("UPDATE incoming_codes SET entry_id='e1',assignment='confirmed' WHERE event_id='u' AND entry_id IS NULL");
// device revoke, generation bump, source revoke, entry update/delete
await step("UPDATE device_sessions SET revoked_at=? WHERE device_id='d1' AND revoked_at IS NULL",N);
await step("UPDATE account_security SET generation=generation+1 WHERE owner_id='o'");
await step("UPDATE sources SET revoked_at=? WHERE source_id='s1'",N);
await step("UPDATE entries SET label='z' WHERE entry_id='e1' AND owner_id='o'");
await step("UPDATE entries SET account_name='z' WHERE entry_id='e1' AND owner_id='o'");
await step("DELETE FROM entries WHERE entry_id='e1' AND owner_id='o'");
console.log('meta.changes / rows_written (LOCAL workerd D1 only, not Cloudflare billing):');for(const r of rw)console.log(' ',r.join(' | '));
console.log('PASS: test D1 shim meta.changes matches workerd D1 (trigger writes counted)');}finally{await mf.dispose();}
