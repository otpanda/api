import test from 'node:test';import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';import {readFileSync,readdirSync} from 'node:fs';
const dir=new URL('../migrations/',import.meta.url);
const apply=(db,files)=>{for(const f of files){db.exec('BEGIN');try{db.exec(readFileSync(new URL(f,dir),'utf8'));db.exec('COMMIT');}catch(e){db.exec('ROLLBACK');throw e;}}};
test('0060 dedupes pre-existing duplicate routes (oldest stays, NULL-safe) and then enforces uniqueness; 0054/0061 apply on top',()=>{
 const db=new DatabaseSync(':memory:'),files=readdirSync(dir).sort();
 apply(db,files.filter(f=>f<'0060'));
 db.exec('PRAGMA foreign_keys=OFF');
 const cols=db.prepare("PRAGMA table_info(service_routes)").all().map(c=>c.name);
 const ins=db.prepare('INSERT INTO service_routes(route_id,owner_id,service_id,source_id,origin_kind,origin_value,entry_id,account_hint) VALUES(?,?,?,?,?,?,?,?)');
 // identical (entry NULL, hint NULL) x3, identical with entry/hint x2, and one distinct row
 for(const id of ['a','b','c'])ins.run(id,'o','svc','src','email_address','x@y.test',null,null);
 for(const id of ['d','e'])ins.run(id,'o','svc','src','email_address','x@y.test','ent','h');
 ins.run('f','o','svc','src','email_address','other@y.test','ent','h');
 assert.ok(cols.includes('route_id'));
 apply(db,files.filter(f=>f>='0060'));
 assert.deepEqual(db.prepare('SELECT route_id FROM service_routes ORDER BY route_id').all().map(r=>r.route_id),['a','d','f']);
 assert.throws(()=>db.prepare("INSERT INTO service_routes(route_id,owner_id,service_id,source_id,origin_kind,origin_value,entry_id,account_hint) VALUES('z','o','svc','src','email_address','x@y.test',NULL,NULL)").run(),/UNIQUE/i);
 // same origin, different phrase or template is a different rule
 db.prepare("INSERT INTO service_routes(route_id,owner_id,service_id,source_id,origin_kind,origin_value,entry_id,account_hint,phrase) VALUES('p','o','svc','src','email_address','x@y.test',NULL,NULL,'abc')").run();
 for(const t of ['unassigned_context','rule_intents'])assert.ok(db.prepare("SELECT 1 FROM sqlite_master WHERE name=?").get(t),t);
 assert.ok(db.prepare("PRAGMA table_info(unassigned_context)").all().some(c=>c.name==='template_fp'));
});

test('0062 backfill: rules of an already revoked source are paused and its previews deleted; a live source is untouched; later reconnect keeps them paused',()=>{
 const db=new DatabaseSync(':memory:'),files=readdirSync(dir).sort();
 apply(db,files.filter(f=>f<'0062'));db.exec('PRAGMA foreign_keys=OFF');
 db.exec("INSERT INTO sources(source_id,owner_id,kind,label,created_at,revoked_at) VALUES('dead','o','gmail','d',0,5),('live','o','gmail','l',0,NULL)");
 const ins=db.prepare('INSERT INTO service_routes(route_id,owner_id,service_id,source_id,origin_kind,origin_value,entry_id,created_at) VALUES(?,?,?,?,?,?,?,0)');
 ins.run('r-dead','o','svc','dead','email_address','a@y.test','e1');ins.run('r-live','o','svc','live','email_address','a@y.test','e1');ins.run('fence-dead','o','svc','dead','email_address','f@y.test',null);ins.run('fence-live','o','svc','live','email_address','f@y.test',null);
 const cx=db.prepare("INSERT INTO unassigned_context(context_id,owner_id,source_id,sender_digest,kind,latest_event_id,received_at,arrived_at,retain_until,sender_envelope,size_bytes,key_fingerprint) VALUES(?,?,?,?,?,?,0,0,9e12,'{}',1,'kkkkkkkkkkkkkkkk')");
 try{cx.run('c-dead','o','dead','d1d1d1d1d1d1d1d1d1','email','ev1');cx.run('c-live','o','live','d2d2d2d2d2d2d2d2d2','email','ev2');}catch(e){assert.fail('fixture: '+e.message);}
 apply(db,files.filter(f=>f>='0062'));
 const paused=Object.fromEntries(db.prepare('SELECT route_id,paused_at FROM service_routes').all().map(r=>[r.route_id,r.paused_at]));
 assert.equal(paused['r-dead'],5);assert.equal(paused['r-live'],null);assert.equal(paused['fence-dead'],null);assert.equal(paused['fence-live'],null);
 assert.deepEqual(db.prepare('SELECT context_id FROM unassigned_context').all().map(r=>r.context_id),['c-live']);
 db.exec("UPDATE sources SET revoked_at=NULL WHERE source_id='dead'");
 assert.equal(db.prepare("SELECT paused_at FROM service_routes WHERE route_id='r-dead'").get().paused_at,5,'reconnect keeps it paused');
 db.exec("UPDATE sources SET revoked_at=7 WHERE source_id='live';UPDATE sources SET revoked_at=NULL WHERE source_id='live'");assert.equal(db.prepare("SELECT paused_at FROM service_routes WHERE route_id='r-live'").get().paused_at,7);assert.equal(db.prepare("SELECT paused_at FROM service_routes WHERE route_id='fence-live'").get().paused_at,null);assert.equal(db.prepare("SELECT paused_at FROM service_routes WHERE route_id='fence-dead'").get().paused_at,null);
});
