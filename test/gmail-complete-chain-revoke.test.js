import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {readFileSync,readdirSync} from 'node:fs';
test('complete migration chain Gmail revoke coexists with realtime, repeats and rolls back atomically',()=>{
 const db=new DatabaseSync(':memory:');
 try{
  db.exec('PRAGMA foreign_keys=ON');
  for(const n of readdirSync(new URL('../migrations/',import.meta.url)).filter(n=>n.endsWith('.sql')).sort())db.exec(readFileSync(new URL('../migrations/'+n,import.meta.url),'utf8'));
  db.exec(`INSERT INTO accounts(owner_id,created_at)VALUES('synthetic-owner',0);
   INSERT INTO sources(source_id,owner_id,kind,label,created_at)VALUES('synthetic-source','synthetic-owner','gmail','Synthetic',0);
   INSERT INTO gmail_connections(source_id,owner_id,mailbox,refresh_envelope,history_id,watch_expires_at,created_at,updated_at)VALUES('synthetic-source','synthetic-owner','test@example.test','synthetic-envelope','1',100,0,0);
   INSERT INTO gmail_deferred VALUES('synthetic-source','synthetic-message',0,10,1,'fetch_timeout');
   DELETE FROM realtime_outbox;`);
  const read=()=>db.prepare('SELECT status,refresh_envelope,gen FROM gmail_connections').get();
  db.exec("BEGIN;UPDATE sources SET revoked_at=20 WHERE source_id='synthetic-source';ROLLBACK;");
  assert.equal(read().status,'active');assert.equal(db.prepare('SELECT count(*) n FROM gmail_deferred').get().n,1);assert.equal(db.prepare('SELECT count(*) n FROM realtime_outbox').get().n,0);
  db.exec("UPDATE sources SET revoked_at=20 WHERE source_id='synthetic-source'");
  assert.deepEqual({...read()},{status:'disconnected',refresh_envelope:'',gen:1});
  assert.equal(db.prepare('SELECT count(*) n FROM gmail_deferred').get().n,0);
  assert.ok(db.prepare("SELECT count(*) n FROM realtime_outbox WHERE account_id='synthetic-owner'").get().n>0);
  db.exec("UPDATE sources SET revoked_at=20 WHERE source_id='synthetic-source'");
  assert.equal(read().status,'disconnected');assert.equal(read().refresh_envelope,'');assert.equal(read().gen,2);
  assert.equal(db.prepare('PRAGMA foreign_key_check').all().length,0);
 }finally{db.close();}
});
