import assert from 'node:assert/strict';import {database} from '../test/sqlite-helper.js';
const db=database(),s=db.sqlite;
s.prepare('INSERT INTO accounts VALUES (?,?)').run('owner',0);s.prepare('INSERT INTO accounts VALUES (?,?)').run('unrelated',0);
s.prepare("INSERT INTO entries(entry_id,owner_id,service_id,label,created_at)VALUES('owned','owner','test','Target',0)").run();
s.prepare("INSERT INTO machine_profiles(profile_id,creator_id,name,mode,created_at)VALUES('p','owner','Synthetic','all',0)").run();
const sql="UPDATE entries SET mutation_revision=mutation_revision+1 WHERE entry_id IN (SELECT entry_id FROM entries WHERE owner_id='owner' UNION SELECT r.entry_id FROM entry_readers r WHERE r.recipient_id='owner' AND r.allow_automation=1)";
const plan=s.prepare('EXPLAIN QUERY PLAN '+sql).all();console.log(JSON.stringify(plan));assert.ok(!plan.some(r=>/^SCAN (entries|e|s)$/.test(r.detail)), 'no unbounded entry/share scan');
function cost(){const start=performance.now();for(let i=0;i<300;i++)s.prepare("UPDATE machine_profiles SET name='Synthetic' WHERE profile_id='p'").run();return performance.now()-start;}
const before=cost();s.exec('BEGIN');const insert=s.prepare("INSERT INTO entries(entry_id,owner_id,service_id,label,created_at)VALUES(?,'unrelated','test','Other',0)");for(let i=0;i<20000;i++)insert.run('other-'+i);s.exec('COMMIT');const after=cost();assert.equal(s.prepare("SELECT count(*) n FROM entries WHERE owner_id='unrelated' AND mutation_revision<>0").get().n,0);console.log(JSON.stringify({runs:300,unrelatedEntries:20000,beforeMs:before,afterMs:after,ratio:after/before}));assert.ok(after<before*6+50,'unrelated-entry growth must not scale trigger writes');db.sqlite.close();
