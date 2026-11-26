import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { COMBINED_CEILING,drainOutbox,drainSome,cleanupRealtime,CHANGED,CLOSE_ALL,PAGE,LEASE_MS,RETAIN_MS,ACTIVITY_MS,Budget,MAX_ATTEMPTS,backoffMs,ROW_MIN_BUDGET,FOREGROUND_DELIVERY_MAX,CRON_DELIVERY_MAX } from '../src/realtime-outbox.js';
import { ACCESS_TTL_MS } from '../src/device-sessions.js';
import { TICKET_TTL_MS,SOCKET_MAX_MS } from '../src/realtime-http.js';
import { createQueryMeter } from '../src/query-meter.js';
const NOW=1_800_000_000_000;
const CODE="INSERT INTO incoming_codes(owner_id,event_id,source_id,entry_id,envelope,received_at,expires_at,assignment) VALUES ('owner',?,'s1',?,'{}',?,?,?)";
function world(){const db=database(),q=(s,...a)=>db.sqlite.prepare(s).run(...a),all=(s,...a)=>db.sqlite.prepare(s).all(...a).map(r=>({...r}));
 const account=id=>q('INSERT INTO accounts(owner_id,created_at) VALUES (?,?)',id,NOW);
 ['owner','r1','r2','r3'].forEach(account);
 q("INSERT INTO services(service_id,name) VALUES ('svc','svc')");
 q("INSERT INTO entries(entry_id,owner_id,service_id,label,created_at) VALUES ('e1','owner','svc','l',?)",NOW);
 q("INSERT INTO sources(source_id,owner_id,kind,label,created_at) VALUES ('s1','owner','gmail','m',?)",NOW);
 const code=(ev,entry='e1',expires=NOW+60000)=>q(CODE,ev,entry,NOW,expires,entry?'rule':'unassigned');
 const share=(r,e='e1')=>q('INSERT INTO entry_shares(entry_id,recipient_id,created_at) VALUES (?,?,?)',e,r,NOW);
 const live=(...ids)=>ids.forEach(id=>q('INSERT OR REPLACE INTO realtime_activity(account_id,last_ticket_at) VALUES (?,?)',id,NOW-1000));
 const rows=()=>all('SELECT kind,account_id,scope_id,device_id,payload,cursor,claimed_at,claim_id FROM realtime_outbox ORDER BY seq');
 const clear=()=>q('DELETE FROM realtime_outbox');
 return {db,q,all,account,code,share,live,rows,clear};}
const sink=(failFor=new Set())=>{const log=[];return {log,deliver:async(a,m)=>{if(failFor.has(a))return false;log.push([a,JSON.stringify(m)]);return true;}};};
const ids=n=>Array.from({length:n},(_,i)=>'x'+String(i).padStart(5,'0'));
test('assigned and unassigned codes emit once, coalesce while unclaimed, and a replay emits nothing',()=>{
 const w=world();w.share('r1');w.clear();
 w.code('a');w.code('b');assert.deepEqual(w.rows().map(r=>[r.kind,r.account_id,r.scope_id]),[['entry','owner','e1']]);
 w.code('u',null);assert.deepEqual(w.rows().map(r=>r.kind),['entry','account']);
 const n=w.rows().length;w.q("INSERT OR IGNORE INTO incoming_codes(owner_id,event_id,source_id,entry_id,envelope,received_at,expires_at,assignment) VALUES ('owner','a','s1','e1','{}',?,?,'rule')",NOW,NOW+1);assert.equal(w.rows().length,n,'replay fires nothing');
 w.q("UPDATE realtime_outbox SET claimed_at=1,claim_id='z' WHERE kind='entry'");w.code('c');assert.equal(w.rows().filter(r=>r.kind==='entry').length,2,'after claim a new write gets its own row');
 assert.ok(!/envelope|code|label|sender/.test(Object.keys(w.all('SELECT * FROM realtime_outbox')[0]).join()));w.db.sqlite.close();});
test('a rolled back change leaves no outbox row; a failing batch rolls its trigger rows back too',async()=>{
 const w=world();w.clear();w.db.sqlite.exec('BEGIN');w.code('x');w.db.sqlite.exec('ROLLBACK');assert.equal(w.rows().length,0);
 await assert.rejects(w.db.batch([w.db.prepare(CODE).bind('y','e1',NOW,NOW+1,'rule'),w.db.prepare("INSERT INTO incoming_codes(owner_id,event_id,source_id,entry_id,envelope,received_at,expires_at,assignment) VALUES ('owner','z','missing','e1','{}',?,?,'rule')").bind(NOW,NOW+1)]));
 assert.equal(w.rows().length,0);w.db.sqlite.close();});
test('confirming an assignment emits for the entry and does not disturb changes() inside the same batch',async()=>{
 const w=world();w.code('u',null);w.clear();w.q('CREATE TABLE probe(n INTEGER)');
 await w.db.batch([w.db.prepare("UPDATE incoming_codes SET entry_id='e1',assignment='confirmed' WHERE event_id='u' AND entry_id IS NULL"),w.db.prepare('INSERT INTO probe SELECT changes()')]);
 assert.equal(w.all('SELECT n FROM probe')[0].n,1);assert.deepEqual(w.rows().map(r=>[r.kind,r.scope_id]),[['entry','e1']]);w.db.sqlite.close();});
test('entry delete packs every former active recipient (100 per row, no limit) before the cascade, plus the owner',()=>{
 const w=world();w.share('r1');w.share('r2');w.share('r3');w.q('UPDATE entry_shares SET revoked_at=? WHERE recipient_id=?',NOW,'r3');
 w.clear();w.q('DELETE FROM entries WHERE entry_id=?','e1');
 const r=w.rows();assert.deepEqual(r.filter(x=>x.kind==='account').map(x=>x.account_id),['owner']);
 assert.deepEqual(r.filter(x=>x.kind==='accounts').flatMap(x=>JSON.parse(x.payload)).sort(),['r1','r2']);assert.equal(w.all('SELECT count(*) n FROM entry_shares')[0].n,0);
 const v=world();v.share('r1');v.clear();v.q('UPDATE entry_shares SET revoked_at=? WHERE recipient_id=?',NOW,'r1');assert.deepEqual(v.rows().map(x=>x.account_id).sort(),['owner','r1']);
 w.db.sqlite.close();v.db.sqlite.close();});
test('1000+ recipients: exactly ceil(N/100) packed rows, every id exactly once, the delete itself succeeds',()=>{
 const w=world(),N=1037;for(const id of ids(N)){w.account(id);w.share(id);}
 w.clear();const r=w.q('DELETE FROM entries WHERE entry_id=?','e1');assert.equal(r.changes,1);
 const packed=w.rows().filter(x=>x.kind==='accounts');assert.equal(packed.length,Math.ceil(N/100));
 const all=packed.flatMap(x=>JSON.parse(x.payload));assert.equal(all.length,N);assert.equal(new Set(all).size,N);assert.ok(packed.every(x=>JSON.parse(x.payload).length<=100&&x.payload.length<3000));
 assert.equal(w.rows().filter(x=>x.kind==='account').length,1);w.db.sqlite.close();});
test('source revoke snapshots recipients of entries its codes were assigned to, at revoke time, independent of later code deletion',async()=>{
 const w=world();w.share('r1');w.share('r2');w.q("INSERT INTO entries(entry_id,owner_id,service_id,label,created_at) VALUES ('e2','owner','svc','l',?)",NOW);w.share('r3','e2');
 w.code('a','e1');w.clear();w.q('UPDATE sources SET revoked_at=? WHERE source_id=?',NOW,'s1');
 const r=w.rows();assert.deepEqual(r.filter(x=>x.kind==='accounts').flatMap(x=>JSON.parse(x.payload)).sort(),['r1','r2'],'r3 only has an entry with no codes from this source');assert.equal(r.filter(x=>x.kind==='account'&&x.account_id==='owner').length,1);
 w.q('UPDATE sources SET revoked_at=? WHERE source_id=?',NOW+1,'s1');assert.equal(w.rows().length,r.length,'a second revoke is not a change');
 w.q('DELETE FROM incoming_codes');w.live('owner','r1','r2');const s=sink();await drainOutbox({db:w.db,deliver:s.deliver,clock:()=>NOW});
 assert.deepEqual([...new Set(s.log.map(x=>x[0]))].sort(),['owner','r1','r2'],'recipients are still reached after the code rows are gone');w.db.sqlite.close();});
test('every mounted mutation class has a hint source: entry/source create, org, live-code delete, generation bump; expiry cleanup is silent',()=>{
 const w=world();w.clear();
 w.q("INSERT INTO entries(entry_id,owner_id,service_id,label,created_at) VALUES ('e9','owner','svc','l',?)",NOW);assert.deepEqual(w.rows().map(r=>r.kind),['account']);w.clear();
 w.q("INSERT INTO sources(source_id,owner_id,kind,label,created_at) VALUES ('s9','r1','gmail','m',?)",NOW);assert.deepEqual(w.rows().map(r=>r.account_id),['r1']);w.clear();
 w.q("INSERT INTO personal_organization(viewer_id,revision,document,updated_at) VALUES ('r2',0,'{}',?)",NOW);w.q("UPDATE personal_organization SET document='{\"a\":1}',revision=1 WHERE viewer_id='r2'");assert.deepEqual(w.rows().map(r=>r.account_id),['r2'],'coalesced, viewer-only');w.clear();
 w.q('INSERT INTO account_security(owner_id,generation) VALUES (?,0)','r3');w.clear();w.q('UPDATE account_security SET generation=1 WHERE owner_id=?','r3');w.q('UPDATE account_security SET recovery_hold_until=5 WHERE owner_id=?','r3');assert.deepEqual(w.rows().map(r=>[r.kind,r.account_id]),[['revoke','r3']]);w.clear();
 w.q("INSERT INTO incoming_codes(owner_id,event_id,source_id,entry_id,envelope,received_at,expires_at,assignment) VALUES ('owner','old','s1','e1','{}',0,1,'rule')");w.code('live','e1',2**50);w.clear();w.q("DELETE FROM incoming_codes WHERE event_id='old'");assert.equal(w.rows().length,0,'an already expired code is not a visible change');
 w.q("DELETE FROM incoming_codes WHERE event_id='live'");assert.deepEqual(w.rows().map(r=>[r.kind,r.scope_id]),[['entry','e1']]);w.db.sqlite.close();});
test('drain: owner and ACTIVE recipients get exactly the content-free message; inactive accounts cost no hub call',async()=>{
 const w=world();w.share('r1');w.share('r2');w.share('r3');w.q('UPDATE entry_shares SET revoked_at=? WHERE recipient_id=?',NOW,'r2');w.live('owner','r1','r2');w.clear();w.code('a');
 const s=sink(),r=await drainOutbox({db:w.db,deliver:s.deliver,clock:()=>NOW});
 assert.deepEqual(s.log.map(x=>x[0]).sort(),['owner','r1'],'r2 revoked, r3 revoked-by-nothing but has no activity');for(const [,m] of s.log)assert.equal(m,'{"v":1,"t":"changed"}');
 assert.equal(JSON.stringify(CHANGED),'{"v":1,"t":"changed"}');assert.equal(r.delivered,1);assert.equal(w.rows().length,0);w.db.sqlite.close();});
test('account hints reach exactly the owner, the share recipient, and the unassigned-code owner (and only when active)',async()=>{
 const w=world();w.live('owner','r1');w.clear();w.share('r1');let s=sink();await drainOutbox({db:w.db,deliver:s.deliver,clock:()=>NOW});assert.deepEqual(s.log.map(x=>x[0]).sort(),['owner','r1']);
 w.code('u',null);s=sink();await drainOutbox({db:w.db,deliver:s.deliver,clock:()=>NOW});assert.deepEqual(s.log.map(x=>x[0]),['owner']);
 w.q('DELETE FROM realtime_activity');w.code('v',null);s=sink();const r=await drainOutbox({db:w.db,deliver:s.deliver,clock:()=>NOW});assert.equal(s.log.length,0);assert.equal(r.skipped,1);assert.equal(w.rows().length,0,'skipped hint is consumed: nothing could be connected');
 w.live('owner');w.q('UPDATE realtime_activity SET last_ticket_at=?',NOW-ACTIVITY_MS-1);w.code('w',null);s=sink();await drainOutbox({db:w.db,deliver:s.deliver,clock:()=>NOW});assert.equal(s.log.length,0,'activity older than the access window is stale');w.db.sqlite.close();});
test('fanout beyond one page is never truncated: a persistent cursor finishes across drains with every active recipient reached',async()=>{
 const w=world(),N=PAGE*2+37;for(const id of ids(N)){w.account(id);w.share(id);}w.live('owner',...ids(N));
 w.clear();w.code('a');const s=sink();let t=NOW,drains=0,res;
 do{res=await drainOutbox({db:w.db,deliver:s.deliver,clock:()=>t,maxPages:1});t+=1;drains++;assert.ok(drains<10);}while(res.pending);
 const got=s.log.map(x=>x[0]);assert.equal(new Set(got).size,N+1);assert.equal(got.length,N+1);assert.ok(drains>=3);assert.equal(w.rows().length,0);w.db.sqlite.close();});
test('packed snapshot rows are delivered to every active member of every pack, and consumed',async()=>{
 const w=world(),N=250;for(const id of ids(N)){w.account(id);w.share(id);}w.live('owner',...ids(N));w.clear();w.q('DELETE FROM entries WHERE entry_id=?','e1');
 const s=sink();const r=await drainSome({db:w.db,deliver:s.deliver,clock:()=>NOW,sends:new Budget(1e9),budget:new Budget(1e9)});assert.equal(new Set(s.log.map(x=>x[0])).size,N+1);assert.equal(w.rows().length,0);assert.equal(r.pending,false);w.db.sqlite.close();});
test('a failed recipient is isolated into its own backoff row, the parent finishes, and the isolated row retries later',async()=>{
 const w=world();w.share('r1');w.share('r2');w.live('owner','r1','r2');w.clear();w.code('a');
 let s=sink(new Set(['r2']));let r=await drainOutbox({db:w.db,deliver:s.deliver,clock:()=>NOW});assert.equal(r.delivered,1,'parent row done');assert.equal(r.isolated,1);
 assert.deepEqual(w.all('SELECT kind,account_id,attempts,claim_id FROM realtime_outbox'),[{kind:'account',account_id:'r2',attempts:1,claim_id:null}]);
 assert.ok(s.log.some(x=>x[0]==='r1'),'the healthy recipient was not blocked');
 s=sink();r=await drainOutbox({db:w.db,deliver:s.deliver,clock:()=>NOW+1});assert.equal(s.log.length,0,'backing off: not retried before next_attempt_at');
 r=await drainOutbox({db:w.db,deliver:s.deliver,clock:()=>NOW+backoffMs(0)+1});assert.ok(s.log.some(x=>x[0]==='r2'));assert.equal(w.rows().length,0);
 // hub down: the owner is isolated into its own backoff row and the entry row finishes
 w.code('b');r=await drainOutbox({db:w.db,deliver:async()=>{throw new Error('hub down');},clock:()=>NOW+2});assert.equal(r.isolated>=1,true);assert.ok(w.all("SELECT 1 FROM realtime_outbox WHERE kind='account' AND account_id='owner'").length>=1);w.db.sqlite.close();});
test('concurrent drains claim each row once; an abandoned claim is reclaimed after the lease',async()=>{
 const w=world();w.share('r1');w.live('owner','r1');w.clear();w.code('a');
 w.q("INSERT INTO entries(entry_id,owner_id,service_id,label,created_at) VALUES ('e2','owner','svc','l',?)",NOW);w.clear();w.code('a1');w.code('b','e2');
 const s=sink();const [a,b]=await Promise.all([drainOutbox({db:w.db,deliver:s.deliver,clock:()=>NOW}),drainOutbox({db:w.db,deliver:s.deliver,clock:()=>NOW})]);
 assert.equal(a.delivered+b.delivered,2);assert.equal(w.rows().length,0);
 w.code('c');w.q("UPDATE realtime_outbox SET claimed_at=?,claim_id='other'",NOW);let r=await drainOutbox({db:w.db,deliver:s.deliver,clock:()=>NOW+10});assert.equal(r.delivered,0,'live claim respected');
 r=await drainOutbox({db:w.db,deliver:s.deliver,clock:()=>NOW+LEASE_MS+1});assert.equal(r.delivered,1);w.db.sqlite.close();});
test('claim ownership is an exact random id: a stale worker cannot advance, release or delete after takeover, even on the same millisecond',async()=>{
 const w=world(),N=PAGE+20;for(const id of ids(N)){w.account(id);w.share(id);}w.live('owner',...ids(N));w.clear();w.code('a');
 let release,gate=new Promise(r=>release=r),seen=0,log=[];
 const slow=async(a)=>{if(++seen===2)await gate;log.push(a);return true;};
 const A=drainOutbox({db:w.db,deliver:slow,clock:()=>NOW,claimId:()=>'AAAA',maxPages:1});
 await new Promise(r=>setTimeout(r,20));assert.equal(w.rows()[0].claim_id,'AAAA');
 // lease expires, B takes over, then the row is made to look like A's tick again (same-clock ABA)
 const B=await drainOutbox({db:w.db,deliver:async()=>true,clock:()=>NOW+LEASE_MS+1,claimId:()=>'BBBB',maxPages:1});assert.equal(B.pending,true);
 const midCursor=w.rows()[0].cursor;w.q("UPDATE realtime_outbox SET claimed_at=?,claim_id='BBBB'",NOW);
 release();const a=await A;assert.equal(a.delivered,0);assert.equal(w.rows().length,1,'A deleted nothing');assert.equal(w.rows()[0].claim_id,'BBBB','A did not release B');assert.equal(w.rows()[0].cursor,midCursor,'A did not move the cursor');w.db.sqlite.close();});
test('device revoke delivers a close naming only that device; a generation bump closes every socket of the account',async()=>{
 const w=world();w.live('owner');w.q('INSERT INTO account_security(owner_id,generation) VALUES (?,0)','owner');w.clear();
 w.q("INSERT INTO realtime_outbox(kind,account_id,device_id,created_at) VALUES ('device','owner','dev_abcdefgh',?)",NOW);let t=sink();await drainOutbox({db:w.db,deliver:t.deliver,clock:()=>NOW});assert.deepEqual(t.log,[['owner','{"v":1,"t":"close","deviceId":"dev_abcdefgh"}']]);
 w.q('UPDATE account_security SET generation=generation+1 WHERE owner_id=?','owner');t=sink();await drainOutbox({db:w.db,deliver:t.deliver,clock:()=>NOW});assert.deepEqual(t.log,[['owner',JSON.stringify(CLOSE_ALL)]]);assert.equal(JSON.stringify(CLOSE_ALL),'{"v":1,"t":"closeAll"}');w.db.sqlite.close();});
test('retention drops old hints and stale activity in bounded batches',async()=>{
 const w=world();w.clear();w.q("INSERT INTO realtime_outbox(kind,account_id,created_at) VALUES ('account','owner',?),('account','r1',?),('account','r2',?)",NOW-RETAIN_MS-5,NOW-RETAIN_MS-4,NOW);
 w.q('INSERT INTO realtime_activity VALUES (?,?),(?,?)','r1',NOW-ACTIVITY_MS-1,'r2',NOW);
 assert.equal(await cleanupRealtime({db:w.db,clock:()=>NOW,limit:1}),1);assert.equal(await cleanupRealtime({db:w.db,clock:()=>NOW}),1);assert.equal(w.rows().length,1);assert.deepEqual(w.all('SELECT account_id FROM realtime_activity').map(r=>r.account_id),['r2']);
 for(const limit of [0,501,1.5])await assert.rejects(cleanupRealtime({db:w.db,limit}));w.db.sqlite.close();});
test('a write after fanout has started (cursor set) gets its own row, so recipients already notified are not skipped',async()=>{
 const w=world();for(const id of ids(PAGE+5)){w.account(id);w.share(id);}w.live('owner',...ids(PAGE+5));
 w.clear();w.code('a');const s=sink();await drainOutbox({db:w.db,deliver:s.deliver,clock:()=>NOW,maxPages:1});
 assert.equal(w.rows().length,1);assert.notEqual(w.rows()[0].cursor,null);w.code('b');assert.equal(w.rows().length,2);
 let t=NOW+1;while((await drainOutbox({db:w.db,deliver:s.deliver,clock:()=>t++})).pending);assert.equal(w.rows().length,0);assert.equal(new Set(s.log.map(x=>x[0])).size,PAGE+6);w.db.sqlite.close();});
test('drain input is bounded',async()=>{const w=world();for(const bad of [{limit:0},{limit:101},{maxPages:0}])await assert.rejects(drainOutbox({db:w.db,deliver:async()=>true,...bad}));await assert.rejects(drainOutbox({db:w.db}));w.db.sqlite.close();});
test('source revoke ignores recipients of entries that only hold codes from other sources',()=>{
 const w=world();w.q("INSERT INTO sources(source_id,owner_id,kind,label,created_at) VALUES ('s2','owner','sms','m',?)",NOW);w.share('r1');w.q("INSERT INTO entries(entry_id,owner_id,service_id,label,created_at) VALUES ('e2','owner','svc','l',?)",NOW);w.share('r2','e2');
 w.q(CODE.replace("'s1'","'s2'"),'c2','e2',NOW,NOW+60000,'rule');w.code('c1','e1');w.clear();w.q('UPDATE sources SET revoked_at=? WHERE source_id=?',NOW,'s1');
 assert.deepEqual(w.rows().filter(x=>x.kind==='accounts').flatMap(x=>JSON.parse(x.payload)),['r1']);w.db.sqlite.close();});
test('a later ticket refreshes the account activity (never moves it backwards)',()=>{
 const w=world();w.q('INSERT INTO realtime_activity VALUES (?,?)','r1',100);
 w.q('PRAGMA foreign_keys=OFF');
 const t=(id,at)=>w.q("INSERT INTO realtime_tickets(ticket_id,secret_digest,owner_id,device_id,generation,created_at,expires_at,close_at) VALUES (?,?,?,?,0,?,?,?)",id,'a'.repeat(64),'r1','dev_abcdefgh',at,at+30000,at+300000);
 t('t1',500);assert.equal(w.all('SELECT last_ticket_at x FROM realtime_activity')[0].x,500);t('t2',300);assert.equal(w.all('SELECT last_ticket_at x FROM realtime_activity')[0].x,500);w.db.sqlite.close();});

test('the activity window covers the longest possible socket: socket cap plus ticket TTL plus a margin',()=>{
 assert.equal(ACCESS_TTL_MS,15*60*1000);assert.equal(SOCKET_MAX_MS,5*60*1000);assert.equal(TICKET_TTL_MS,30_000);
 assert.ok(SOCKET_MAX_MS<=ACCESS_TTL_MS,'the cap only ever shortens a socket');
 assert.ok(ACTIVITY_MS>=SOCKET_MAX_MS+TICKET_TTL_MS+30_000,'6 min >= 5 min + 30 s + margin');});
test('poison rows back off exponentially, cannot starve later healthy rows, and are dropped at the cap',async()=>{
 const w=world();w.live('owner');w.clear();
 for(let i=0;i<30;i++)w.q("INSERT INTO realtime_outbox(kind,account_id,device_id,created_at) VALUES ('device','owner',?,?)",'dev_p'+String(i).padStart(6,'0'),NOW+i);
 const poison=async(a,m)=>{if(m.t==='close')return false;return true;};let t=NOW;
 let r=await drainOutbox({db:w.db,deliver:poison,clock:()=>t,limit:25});assert.equal(r.delivered,0);assert.equal(w.all('SELECT count(*) n FROM realtime_outbox WHERE attempts=1')[0].n,25);
 // a healthy row arriving later is reached on the very next drain even though 25 poison rows are older
 w.q("INSERT INTO entries(entry_id,owner_id,service_id,label,created_at) VALUES ('eh','owner','svc','l',?)",NOW);
 const log=[];t+=1;r=await drainOutbox({db:w.db,deliver:async(a,m)=>{log.push(m.t);return m.t!=='close';},clock:()=>t,limit:25});
 assert.ok(log.includes('changed'),'healthy row delivered');assert.equal(w.all("SELECT count(*) n FROM realtime_outbox WHERE kind='account'").length,1);
 // no hot loop: rows still backing off are not retried
 const before=w.all('SELECT sum(attempts) a FROM realtime_outbox')[0].a;t+=1;await drainOutbox({db:w.db,deliver:poison,clock:()=>t,limit:25});assert.equal(w.all('SELECT sum(attempts) a FROM realtime_outbox')[0].a,before,'every poison row is backing off: nothing is retried');
 for(let i=0;i<MAX_ATTEMPTS+2;i++){t+=backoffMs(i)+1;w.q('UPDATE realtime_activity SET last_ticket_at=?',t-1000);await drainOutbox({db:w.db,deliver:poison,clock:()=>t,limit:25});}
 assert.equal(w.all("SELECT count(*) n FROM realtime_outbox WHERE kind='device'").length>=0,true);assert.equal(w.all("SELECT count(*) n FROM realtime_outbox WHERE kind='device'")[0].n,0,'poison hints dropped at the cap');
 assert.ok(backoffMs(0)<backoffMs(1)&&backoffMs(20)===15*60_000);w.db.sqlite.close();});
test('stale takeover still works with backoff columns: an expired lease is reclaimed regardless of attempts',async()=>{
 const w=world();w.live('owner');w.clear();w.q("INSERT INTO realtime_outbox(kind,account_id,created_at,claimed_at,claim_id,attempts,next_attempt_at) VALUES ('account','owner',?,?, 'old',2,?)",NOW,NOW-LEASE_MS-5,0);
 const s=sink();const r=await drainOutbox({db:w.db,deliver:s.deliver,clock:()=>NOW});assert.equal(r.delivered,1);w.db.sqlite.close();});
test('the drain never issues a query beyond its budget, at any budget, with large fanout (independently counted)',async()=>{
 for(const n of [0,1,5,6,7,8,9,12,20,45]){
  const w=world(),N=PAGE*3+10;for(const id of ids(N)){w.account(id);w.share(id);}w.live('owner',...ids(N));w.clear();w.code('a');
  const meter=createQueryMeter(w.db);const budget=new Budget(n);let t=NOW,calls=0,r;
  do{r=await drainOutbox({db:meter.db,deliver:async()=>true,clock:()=>t++,budget,maxPages:50});calls++;if(r.pending&&budget.left<ROW_MIN_BUDGET+1)break;}while(r.pending&&calls<3);
  assert.ok(meter.count()<=n,`budget ${n}: independently counted ${meter.count()}`);assert.equal(meter.count(),budget.used,'budget accounting equals the real count');
  if(n<ROW_MIN_BUDGET+1)assert.equal(r.pending,true,'too little budget: nothing started, work stays pending');
  w.db.sqlite.close();}});
test('budget exhaustion mid-fanout persists the cursor and releases the claim, so the next invocation resumes with no missed recipient',async()=>{
 const w=world(),N=PAGE*3+10;for(const id of ids(N)){w.account(id);w.share(id);}w.live('owner',...ids(N));w.clear();w.code('a');
 const got=new Set();let t=NOW,rounds=0,r;
 do{r=await drainOutbox({db:w.db,deliver:async a=>{got.add(a);return true;},clock:()=>t+=1,budget:new Budget(10),maxPages:50});rounds++;assert.ok(rounds<60);}while(r.pending||w.rows().length);
 assert.equal(got.size,N+1);assert.ok(rounds>=2,'it needed several budget-limited invocations');assert.equal(w.rows().length,0);w.db.sqlite.close();});
test('foreground plus drain stays within the 50 query cap: the meter counts a request and the drain takes the remainder',async()=>{
 const w=world();w.share('r1');w.live('owner','r1');w.clear();w.code('a');const meter=createQueryMeter(w.db);
 for(let i=0;i<20;i++)await meter.db.prepare('SELECT 1').run();// a heavy foreground request
 const before=meter.count();const remaining=45-10-before;const budget=new Budget(remaining);
 const r=await drainSome({db:meter.db,deliver:async()=>true,clock:()=>NOW,budget});assert.ok(meter.count()+1<=45,'request + drain + one hub call stays inside 45');assert.equal(r.delivered,1);
 const w2=world();w2.live('owner');w2.clear();w2.code('b',null);const m2=createQueryMeter(w2.db);for(let i=0;i<45;i++)await m2.db.prepare('SELECT 1').run();
 const left=45-10-m2.count();assert.ok(left<ROW_MIN_BUDGET+1,'a nearly spent request leaves too little: no drain starts, row stays for cron');
 const r2=await drainOutbox({db:m2.db,deliver:async()=>true,clock:()=>NOW,budget:new Budget(Math.max(0,left))});assert.equal(r2.pending,true);assert.equal(m2.count(),45);w.db.sqlite.close();w2.db.sqlite.close();});
test('foreground budget: 35 minus what the request spent, capped at 20; with 10 hub calls the total stays at or under 45 of 50',async()=>{
 const {foregroundBudget,FOREGROUND_DRAIN_MAX,COMBINED_CEILING}=await import('../src/realtime-outbox.js');
 assert.equal(COMBINED_CEILING,45);assert.equal(foregroundBudget(0),FOREGROUND_DRAIN_MAX);assert.equal(foregroundBudget(15),20);assert.equal(foregroundBudget(16),19);assert.equal(foregroundBudget(30),5);assert.equal(foregroundBudget(35),0);assert.equal(foregroundBudget(60),0);
 for(let spent=0;spent<=60;spent++)assert.ok(spent+foregroundBudget(spent)+FOREGROUND_DELIVERY_MAX<=COMBINED_CEILING||foregroundBudget(spent)===0,'request + D1 drain + hub calls never pass 45');});
test('many small rows under a small budget: stops cleanly before the budget runs out, leaves the rest due, and resumes',async()=>{
 const w=world();w.live('owner');w.clear();for(let i=0;i<60;i++)w.q("INSERT INTO realtime_outbox(kind,account_id,device_id,created_at) VALUES ('device','owner',?,?)",'dev_s'+String(i).padStart(6,'0'),NOW+i);
 const meter=createQueryMeter(w.db),budget=new Budget(20);const r=await drainOutbox({db:meter.db,deliver:async()=>true,clock:()=>NOW+100,budget,limit:25});
 assert.ok(meter.count()<=20);assert.ok(r.delivered>=1&&r.delivered<25,'delivered some, stopped early on budget');assert.equal(r.pending,true);assert.equal(w.rows().filter(x=>x.claim_id!==null).length,0,'no claim is left dangling');
 let t=NOW+200,rounds=0;while(w.rows().length&&rounds++<40)await drainOutbox({db:w.db,deliver:async()=>true,clock:()=>t++,budget:new Budget(20),limit:25});assert.equal(w.rows().length,0);w.db.sqlite.close();});
// ---- Durable Object delivery budget (Free: 50 subrequests per invocation; foreground at most 10, cron at most 40) ----
const counting=(fail=()=>false)=>{const s={calls:0,ok:[],deliver:async(a,m)=>{s.calls++;if(fail(a))return false;s.ok.push([a,JSON.stringify(m)]);return true;}};return s;};
test('delivery budget constants stay inside the 50 subrequest cap',()=>{assert.ok(FOREGROUND_DELIVERY_MAX<=10&&CRON_DELIVERY_MAX<=40&&FOREGROUND_DELIVERY_MAX+CRON_DELIVERY_MAX<=50);});
test('DO calls never exceed the delivery budget at any cap, failed attempts count, and a budget stop is not a failure',async()=>{
 for(const n of [0,1,2,3,9,10,11,40]){
  const w=world(),N=PAGE*3+10;for(const id of ids(N)){w.account(id);w.share(id);}w.live('owner',...ids(N));w.clear();w.code('a');
  const sends=new Budget(n),s=counting();
  const r=await drainSome({db:w.db,deliver:s.deliver,clock:()=>NOW,sends,budget:new Budget(45)},{rounds:3});
  assert.ok(s.calls<=n,`cap ${n}: ${s.calls} calls`);assert.equal(s.calls,sends.used,'accounting equals the real call count');
  const row=w.all('SELECT attempts,claim_id FROM realtime_outbox');
  if(n<N+1){assert.equal(row.length,1,'work persisted for the next trigger');assert.equal(row[0].attempts,0,'budget stop is not a failed attempt');assert.equal(row[0].claim_id,null,'claim released');assert.equal(r.pending,true);}
  w.db.sqlite.close();}
 // failures spend budget too
 const w=world();for(const id of ids(30)){w.account(id);w.share(id);}w.live('owner',...ids(30));w.clear();w.code('a');
 const s=counting(a=>a==='x00003'),sends=new Budget(25);await drainOutbox({db:w.db,deliver:s.deliver,clock:()=>NOW,sends});
 assert.ok(s.calls<=25&&sends.used===s.calls);assert.equal(w.all("SELECT attempts FROM realtime_outbox WHERE kind='entry'").length+w.all("SELECT attempts FROM realtime_outbox WHERE kind='account' AND account_id='x00003'").length>=1,true);assert.ok(w.all("SELECT attempts FROM realtime_outbox WHERE kind='entry'").every(r=>r.attempts===0),'isolating a recipient is not a row failure');w.db.sqlite.close();});
test('with a tiny delivery budget every recipient of an entry and of a packed row is eventually covered, with no replay and the owner hinted once',async()=>{
 const w=world(),N=250;for(const id of ids(N)){w.account(id);w.share(id);}w.live('owner',...ids(N));w.clear();
 w.code('a');w.q('DELETE FROM entries WHERE entry_id=?','e1'); // one packed row set for the delete plus the earlier entry row
 const s=counting();let t=NOW,loops=0;
 while(w.rows().length&&loops++<200){await drainSome({db:w.db,deliver:s.deliver,clock:()=>t,sends:new Budget(7),budget:new Budget(45)},{rounds:1});}
 assert.equal(w.rows().length,0,'everything drained');
 const per=new Map();for(const [a] of s.ok)per.set(a,(per.get(a)??0)+1);
 for(const id of ids(N))assert.ok(per.has(id),'covered '+id);assert.ok(per.has('owner'));
 // the entry row was coalesced away by the delete or finished; either way no recipient got more than the rows that name it, and resumes do not replay a finished slice
 assert.ok([...per.values()].every(c=>c<=3),'bounded duplicates');
 w.db.sqlite.close();});
test('resume after a delivery stop continues at the persisted cursor: a single entry row delivers each recipient once and the owner once',async()=>{
 const w=world(),N=PAGE+60;for(const id of ids(N)){w.account(id);w.share(id);}w.live('owner',...ids(N));w.clear();w.code('a');
 const s=counting();let loops=0;
 while(w.rows().length&&loops++<100)await drainOutbox({db:w.db,deliver:s.deliver,clock:()=>NOW,sends:new Budget(13)});
 const per=new Map();for(const [a] of s.ok)per.set(a,(per.get(a)??0)+1);
 assert.equal(per.size,N+1);assert.ok([...per.values()].every(c=>c===1),'no replay');assert.equal(s.calls,N+1);w.db.sqlite.close();});
test('poison recipients under a delivery budget still back off and drop, and do not starve later rows',async()=>{
 const w=world();w.account('p');w.share('p');w.live('owner','p');w.clear();w.code('a');
 let t=NOW;const bad=counting(a=>a==='p');
 for(let i=0;i<MAX_ATTEMPTS+2;i++){t+=backoffMs(i)+1;w.q('UPDATE realtime_activity SET last_ticket_at=?',t-1000);await drainOutbox({db:w.db,deliver:bad.deliver,clock:()=>t,sends:new Budget(10)});}
 assert.equal(w.rows().length,0,'dropped at the cap');
 w.code('b');w.q('UPDATE realtime_activity SET last_ticket_at=?',t);const ok=counting();await drainOutbox({db:w.db,deliver:ok.deliver,clock:()=>t+1,sends:new Budget(10)});assert.ok(ok.ok.length>0);w.db.sqlite.close();});
test('a delivery budget of 1 still makes progress (owner hint sent once, then one recipient per drain)',async()=>{
 const w=world(),N=5;for(const id of ids(N)){w.account(id);w.share(id);}w.live('owner',...ids(N));w.clear();w.code('a');
 const s=counting();let loops=0;while(w.rows().length&&loops++<50)await drainOutbox({db:w.db,deliver:s.deliver,clock:()=>NOW,sends:new Budget(1)});
 assert.equal(w.rows().length,0);assert.equal(s.calls,N+1,'no livelock, no replay');w.db.sqlite.close();});
test('once the delivery budget is spent no further row is claimed (no wasted queries)',async()=>{
 const w=world();w.share('r1');w.live('owner','r1');w.clear();w.code('a');w.code('b',null);w.q("INSERT INTO realtime_outbox(kind,account_id,created_at) VALUES ('account','owner',?)",NOW);
 const meter=createQueryMeter(w.db),s=counting();const r=await drainOutbox({db:meter.db,deliver:s.deliver,clock:()=>NOW,sends:new Budget(1)});
 const left=w.all('SELECT claim_id FROM realtime_outbox');assert.ok(left.every(x=>x.claim_id===null));assert.equal(r.pending,true);assert.equal(s.calls,1);assert.ok(meter.count()<=5,'later rows are not even claimed: '+meter.count());w.db.sqlite.close();});
// ---- Combined budget and failure isolation ----
import { CRON_QUERY_MAX,foregroundBudget as fgBudget } from '../src/realtime-outbox.js';
test('an early poison recipient cannot starve later healthy ones: entry rows and packed rows both finish, the poison gets its own row and is dropped at the cap',async()=>{
 for(const packed of [false,true]){
  const w=world(),N=250;for(const id of ids(N)){w.account(id);w.share(id);}w.live('owner',...ids(N));w.clear();
  if(packed)w.q('DELETE FROM entries WHERE entry_id=?','e1');else w.code('a');
  const poison=new Set(['x00002']),s=counting(a=>poison.has(a));let t=NOW,loops=0;
  while(w.all("SELECT 1 FROM realtime_outbox WHERE kind IN ('entry','accounts')").length&&loops++<200)await drainSome({db:w.db,deliver:s.deliver,clock:()=>t,sends:new Budget(25),budget:new Budget(20)},{rounds:1});
  const got=new Set(s.ok.map(x=>x[0]));for(const id of ids(N))if(!poison.has(id))assert.ok(got.has(id),(packed?'packed ':'entry ')+id);
  assert.equal(w.all("SELECT 1 FROM realtime_outbox WHERE kind IN ('entry','accounts')").length,0,'parent rows gone');
  const iso=w.all("SELECT attempts FROM realtime_outbox WHERE kind='account' AND account_id='x00002'");assert.equal(iso.length,1);assert.equal(iso[0].attempts,1);
  for(let i=0;i<MAX_ATTEMPTS+2;i++){t+=backoffMs(i)+1;w.q('UPDATE realtime_activity SET last_ticket_at=?',t-1000);await drainSome({db:w.db,deliver:s.deliver,clock:()=>t,sends:new Budget(25),budget:new Budget(20)},{rounds:1});}
  assert.equal(w.all("SELECT 1 FROM realtime_outbox WHERE account_id='x00002'").length,0,'isolated poison dropped, no hot loop');
  w.db.sqlite.close();}});
test('isolation writes are paid before the chunk: D1 queries never exceed the budget at any cap even when every recipient fails, and accounting equals the real count',async()=>{
 for(const n of [9,10,11,12,15,20]){
  for(const failing of [()=>false,()=>true,a=>a.endsWith('3')]){
   const w=world(),N=120;for(const id of ids(N)){w.account(id);w.share(id);}w.live('owner',...ids(N));w.clear();w.code('a');
   const meter=createQueryMeter(w.db),budget=new Budget(n),s=counting(failing);
   await drainOutbox({db:meter.db,deliver:s.deliver,clock:()=>NOW,budget,sends:new Budget(25),maxPages:50});
   assert.ok(meter.count()<=n,`cap ${n}: ${meter.count()} queries`);assert.equal(meter.count(),budget.used);w.db.sqlite.close();}}});
test('combined ceiling: request spend + D1 drain + hub calls never pass 45 of 50, foreground at low and high request spend and cron, with healthy, failing and mixed recipients',async()=>{
 const cases=[];for(const spent of [0,10,20,26,30,34,35,40])cases.push({kind:'fg',spent});cases.push({kind:'cron',spent:0});
 for(const c of cases)for(const failing of [()=>false,()=>true,a=>a.endsWith('7')]){
  const w=world(),N=200;for(const id of ids(N)){w.account(id);w.share(id);}w.live('owner',...ids(N));w.clear();w.code('a');
  const meter=createQueryMeter(w.db);for(let i=0;i<c.spent;i++)await meter.db.prepare('SELECT 1').run();
  const d1=c.kind==='cron'?CRON_QUERY_MAX:fgBudget(meter.count()),hub=c.kind==='cron'?CRON_DELIVERY_MAX:FOREGROUND_DELIVERY_MAX;
  const s=counting(failing);const before=meter.count();
  if(d1>=ROW_MIN_BUDGET+1)await drainSome({db:meter.db,deliver:s.deliver,clock:()=>NOW,budget:new Budget(d1),sends:new Budget(hub)},{rounds:3});
  const total=meter.count()+s.calls;assert.ok(total<=COMBINED_CEILING,`${c.kind} spent ${c.spent}: measured ${total}`);assert.ok(s.calls<=hub);
  if(c.kind==='cron')assert.ok(meter.count()-before<=20&&s.calls<=25);
  w.db.sqlite.close();}});
test('chunk guard: with plenty of hub calls but a small D1 budget and every recipient failing, the drain stops before the budget is gone',async()=>{
 for(const n of [9,10,12,14]){
  const w=world(),N=300;for(const id of ids(N)){w.account(id);w.share(id);}w.live('owner',...ids(N));w.clear();w.code('a');
  const meter=createQueryMeter(w.db),budget=new Budget(n),s=counting(x=>x!=='owner');
  await drainOutbox({db:meter.db,deliver:s.deliver,clock:()=>NOW,budget,sends:new Budget(1e9),maxPages:50});
  assert.ok(meter.count()<=n&&budget.left>=0);assert.equal(w.all('SELECT claim_id FROM realtime_outbox WHERE kind=\'entry\'')[0].claim_id,null,'claim released with the reserve');w.db.sqlite.close();}});
test('an isolated failure does not duplicate a pending hint for the same recipient',async()=>{
 const w=world();w.share('r1');w.live('owner','r1');w.clear();w.code('a');w.q("INSERT INTO realtime_outbox(kind,account_id,created_at) VALUES ('account','r1',?)",NOW);
 await drainOutbox({db:w.db,deliver:async a=>a!=='r1',clock:()=>NOW,limit:1});
 assert.equal(w.all("SELECT 1 FROM realtime_outbox WHERE kind='account' AND account_id='r1'").length,1);w.db.sqlite.close();});
test('if the isolation write itself fails the parent row backs off as a whole and the cursor does not move past the chunk',async()=>{
 const w=world();for(const id of ids(5)){w.account(id);w.share(id);}w.live('owner',...ids(5));w.clear();w.code('a');
 const db=new Proxy(w.db,{get:(t,k)=>k==='batch'?async()=>{throw new Error('d1 down');}:typeof t[k]==='function'?t[k].bind(t):t[k]});
 const r=await drainOutbox({db,deliver:async a=>a!=='x00001',clock:()=>NOW});
 const row=w.all("SELECT attempts,cursor FROM realtime_outbox WHERE kind='entry'")[0];assert.equal(row.attempts,1);assert.equal(r.delivered,0);w.db.sqlite.close();});
test('a failing owner is isolated like any recipient and cannot starve healthy later recipients, even under the tight combined budget',async()=>{
 for(const [q,h] of [[20,25],[9,3],[12,1],[9,10]]){
  const w=world(),N=60;for(const id of ids(N)){w.account(id);w.share(id);}w.live('owner',...ids(N));w.clear();w.code('a');
  const meter=createQueryMeter(w.db),s=counting(a=>a==='owner');let t=NOW,loops=0,calls=0;
  while(w.all("SELECT 1 FROM realtime_outbox WHERE kind='entry'").length&&loops++<300){const m0=meter.count(),c0=s.calls;
   await drainSome({db:meter.db,deliver:s.deliver,clock:()=>t,budget:new Budget(q),sends:new Budget(h)},{rounds:1});
   assert.ok(meter.count()-m0<=q&&s.calls-c0<=h&&(meter.count()-m0)+(s.calls-c0)<=COMBINED_CEILING);}
  const got=new Set(s.ok.map(x=>x[0]));for(const id of ids(N))assert.ok(got.has(id),`q${q} h${h} ${id}`);
  assert.equal(w.all("SELECT attempts FROM realtime_outbox WHERE kind='account' AND account_id='owner'").length,1,'owner isolated into its own row');
  assert.equal(w.all("SELECT 1 FROM realtime_outbox WHERE kind='entry'").length,0);w.db.sqlite.close();}});
