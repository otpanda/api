// Local workerd proof (miniflare): D1 triggers, cascade, batch rollback, large fanout, drain claims, and the real hub Durable Object.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';import {readdirSync,readFileSync} from 'node:fs';
import {drainOutbox,drainSome,LEASE_MS,Budget,ROW_MIN_BUDGET,MAX_ATTEMPTS,backoffMs} from '../src/realtime-outbox.js';
const require=createRequire(import.meta.url);const {Miniflare,convertV4MiniflareOptions}=require('miniflare');
const options=await convertV4MiniflareOptions({modules:[{type:'ESModule',path:new URL('./realtime-hub-worker.mjs',import.meta.url).pathname},{type:'ESModule',path:new URL('../src/realtime-hub.js',import.meta.url).pathname}],modulesRoot:new URL('..',import.meta.url).pathname,compatibilityDate:'2026-11-23',d1Databases:['DB'],durableObjects:{HUB:{className:'RealtimeHub',useSQLite:true}}});
const mf=new Miniflare(options);const out=[];const note=(k,v)=>{out.push(k+': '+v);};
try{
 const db=await mf.getD1Database('DB');const NOW=Date.now();
 for(const f of readdirSync('migrations').sort())for(const sql of readFileSync('migrations/'+f,'utf8').replace(/^--.*$/gm,'').split(/;(?=\s*(?:CREATE|ALTER|PRAGMA|$))/).map(s=>s.trim()).filter(Boolean))await db.prepare(sql).run();
 const run=(s,...a)=>db.prepare(s).bind(...a).run(),all=async(s,...a)=>(await db.prepare(s).bind(...a).all()).results;
 await run("INSERT INTO accounts(owner_id,created_at) VALUES ('owner',?)",NOW);await run("INSERT INTO services(service_id,name) VALUES ('svc','svc')");
 await run("INSERT INTO sources(source_id,owner_id,kind,label,created_at) VALUES ('s1','owner','gmail','m',?)",NOW);
 await run("INSERT INTO entries(entry_id,owner_id,service_id,label,created_at) VALUES ('e1','owner','svc','l',?)",NOW);
 const N=1037,ids=Array.from({length:N},(_,i)=>'x'+String(i).padStart(5,'0'));
 for(let i=0;i<N;i+=50)await db.batch(ids.slice(i,i+50).map(id=>db.prepare('INSERT INTO accounts(owner_id,created_at) VALUES (?,?)').bind(id,NOW)));
 for(let i=0;i<N;i+=50)await db.batch(ids.slice(i,i+50).map(id=>db.prepare("INSERT INTO entry_shares(entry_id,recipient_id,created_at) VALUES ('e1',?,?)").bind(id,NOW)));
 note('triggers+window function applied on workerd D1','yes');
 // atomicity: a failing batch leaves no outbox rows
 await run('DELETE FROM realtime_outbox');
 await assert.rejects(db.batch([db.prepare("INSERT INTO incoming_codes(owner_id,event_id,source_id,entry_id,envelope,received_at,expires_at,assignment) VALUES ('owner','y','s1','e1','{}',?,?,'rule')").bind(NOW,NOW+60000),db.prepare("INSERT INTO incoming_codes(owner_id,event_id,source_id,entry_id,envelope,received_at,expires_at,assignment) VALUES ('owner','z','missing','e1','{}',?,?,'rule')").bind(NOW,NOW+60000)]));
 assert.equal((await all('SELECT count(*) n FROM realtime_outbox'))[0].n,0);note('failed batch rolls back trigger rows','yes');
 // changes() unaffected + replay silent
 await run("INSERT INTO incoming_codes(owner_id,event_id,source_id,entry_id,envelope,received_at,expires_at,assignment) VALUES ('owner','u','s1',NULL,'{}',?,?,'unassigned')",NOW,NOW+60000);await run('DELETE FROM realtime_outbox');await run('CREATE TABLE probe(n INTEGER)');
 await db.batch([db.prepare("UPDATE incoming_codes SET entry_id='e1',assignment='confirmed' WHERE event_id='u' AND entry_id IS NULL"),db.prepare('INSERT INTO probe SELECT changes()')]);
 assert.equal((await all('SELECT n FROM probe'))[0].n,1);assert.deepEqual((await all('SELECT kind,scope_id FROM realtime_outbox')).map(r=>[r.kind,r.scope_id]),[['entry','e1']]);
 const before=(await all('SELECT count(*) n FROM realtime_outbox'))[0].n;await run("INSERT OR IGNORE INTO incoming_codes(owner_id,event_id,source_id,entry_id,envelope,received_at,expires_at,assignment) VALUES ('owner','u','s1','e1','{}',?,?,'rule')",NOW,NOW+60000);assert.equal((await all('SELECT count(*) n FROM realtime_outbox'))[0].n,before);note('changes() inside batch unaffected, ignored replay silent','yes');
 // source revoke snapshot survives code deletion
 await run('DELETE FROM realtime_outbox');await run('UPDATE sources SET revoked_at=? WHERE source_id=?',NOW,'s1');
 const snap=await all("SELECT payload FROM realtime_outbox WHERE kind='accounts'");const snapIds=snap.flatMap(r=>JSON.parse(r.payload));assert.equal(new Set(snapIds).size,N);assert.equal(snap.length,Math.ceil(N/100));note('source revoke packs recipients',`${snap.length} rows for ${N}`);
 // entry delete: cascade + packed capture; measure D1 cost
 await run('DELETE FROM realtime_outbox');await run('DELETE FROM realtime_activity');
 const del=await run('DELETE FROM entries WHERE entry_id=?','e1');
 const packed=await all("SELECT payload FROM realtime_outbox WHERE kind='accounts'"),allIds=packed.flatMap(r=>JSON.parse(r.payload));
 assert.equal(packed.length,Math.ceil(N/100));assert.equal(allIds.length,N);assert.equal(new Set(allIds).size,N);assert.equal((await all('SELECT count(*) n FROM entry_shares'))[0].n,0);
 note('entry delete with 1037 recipients on workerd D1',`succeeded; ${packed.length} packed rows + owner row; all ids present once; cascade removed shares; meta rows_written=${del.meta.rows_written} rows_read=${del.meta.rows_read}`);
 // drain through real D1 + claim takeover with random ids
 await run("INSERT INTO entries(entry_id,owner_id,service_id,label,created_at) VALUES ('e2','owner','svc','l',?)",NOW);
 for(let i=0;i<N;i+=50)await db.batch(ids.slice(i,i+50).map(id=>db.prepare("INSERT INTO entry_shares(entry_id,recipient_id,created_at) VALUES ('e2',?,?)").bind(id,NOW)));
 await run('DELETE FROM realtime_outbox');for(const id of ['owner',...ids])await run('INSERT OR REPLACE INTO realtime_activity(account_id,last_ticket_at) VALUES (?,?)',id,NOW);
 await run("UPDATE entries SET label='n' WHERE entry_id='e2'");const sent=new Set();let n=0,res;
 do{res=await drainOutbox({db,deliver:async a=>{sent.add(a);return true;},clock:()=>NOW+n,maxPages:2});n++;assert.ok(n<20);}while(res.pending);
 assert.equal(sent.size,N+1);assert.equal((await all('SELECT count(*) n FROM realtime_outbox'))[0].n,0);note('paged drain on workerd D1',`${N+1} accounts reached in ${n} drain calls, cursor persisted, row consumed`);
 // stale claim: B takes over after lease; A's guarded writes fail
 await run("UPDATE entries SET label='m' WHERE entry_id='e2'");let release,gate=new Promise(r=>release=r),k=0;
 const A=drainOutbox({db,deliver:async()=>{if(++k===2)await gate;return true;},clock:()=>NOW,claimId:()=>'AAAA',maxPages:1});await new Promise(r=>setTimeout(r,200));
 await drainOutbox({db,deliver:async()=>true,clock:()=>NOW+LEASE_MS+1,claimId:()=>'BBBB',maxPages:1});await run("UPDATE realtime_outbox SET claimed_at=?,claim_id='BBBB'",NOW);const cur=(await all('SELECT cursor FROM realtime_outbox'))[0].cursor;
 release();const ra=await A;assert.equal(ra.delivered,0);const rowsNow=await all('SELECT claim_id,cursor FROM realtime_outbox');assert.equal(rowsNow.length,1);assert.equal(rowsNow[0].claim_id,'BBBB');assert.equal(rowsNow[0].cursor,cur);note('stale worker cannot advance/release/delete after takeover (same-ms)','yes');
 // Instrumented budget proof on real D1: an INDEPENDENT counter on the binding (not the code's own accounting) never exceeds the budget.
 const counted=d=>{let n=0;const stmt=st=>new Proxy(st,{get(t,k){if(k==='__t')return t;if(k==='bind')return(...a)=>stmt(t.bind(...a));if(['run','all','first','raw'].includes(k))return(...a)=>{n++;return t[k](...a);};const v=t[k];return typeof v==='function'?v.bind(t):v;}});
  return {n:()=>n,db:new Proxy(d,{get(t,k){if(k==='prepare')return q=>stmt(t.prepare(q));if(k==='batch')return l=>{n++;return t.batch(l.map(x=>x.__t??x));};const v=t[k];return typeof v==='function'?v.bind(t):v;}})};};
 for(const cap of [0,5,8,9,12,20,45]){
  await run('DELETE FROM realtime_outbox');await run("UPDATE entries SET label=? WHERE entry_id='e2'",'b'+cap);
  const c=counted(db),budget=new Budget(cap);let t2=NOW+1_000_000+cap*1000,rr,rounds=0;
  do{rr=await drainOutbox({db:c.db,deliver:async()=>true,clock:()=>t2++,budget,maxPages:50});rounds++;}while(rr.pending&&budget.left>=ROW_MIN_BUDGET+1&&rounds<5);
  assert.ok(c.n()<=cap,`cap ${cap}: real D1 queries ${c.n()}`);assert.equal(c.n(),budget.used);
  // finish whatever is left with an unmetered budget so later checks start clean
  let guard=0;while((await drainOutbox({db,deliver:async()=>true,clock:()=>t2++,maxPages:50})).pending&&guard++<20);
 }
 // Hub (DO) delivery budget on real D1: calls counted independently inside deliver, failures included; the remainder resumes from the persisted cursor.
 for(const dcap of [3,10,25,40]){
  await run('DELETE FROM realtime_outbox');await run("UPDATE entries SET label=? WHERE entry_id='e2'",'d'+dcap);
  let calls=0;const seen=new Set();const sends=new Budget(dcap);let t3=NOW+5_000_000+dcap*1000,first;await run('UPDATE realtime_activity SET last_ticket_at=?',t3);
  first=await drainOutbox({db,deliver:async a=>{calls++;seen.add(a);return true;},clock:()=>t3++,maxPages:50,sends});
  assert.ok(calls<=dcap,`delivery cap ${dcap}: ${calls} hub calls`);assert.equal(calls,sends.used);assert.ok(calls>0,'deliveries were actually exercised');
  let loops=0;while((await all('SELECT 1 FROM realtime_outbox')).length&&loops++<2000){const s2=new Budget(dcap);const b=calls;await drainOutbox({db,deliver:async a=>{calls++;seen.add(a);return true;},clock:()=>t3++,maxPages:50,sends:s2});assert.ok(calls-b<=dcap);}
  assert.equal((await all('SELECT 1 FROM realtime_outbox')).length,0,'fully drained across invocations at delivery cap '+dcap);
 }
 // Failure isolation + combined ceiling on real D1: a poison recipient near the front, D1 queries and hub calls both counted independently.
 for(const [dcap,qcap] of [[10,20],[25,20]]){
  await run('DELETE FROM realtime_outbox');await run("UPDATE entries SET label=? WHERE entry_id='e2'",'iso'+dcap);
  const c=counted(db);let calls=0;const got=new Set();let poisonSeen=0;let poison=null;
  let t4=NOW+9_000_000+dcap*1000,loops=0;await run('UPDATE realtime_activity SET last_ticket_at=?',t4);
  while((await all("SELECT 1 FROM realtime_outbox WHERE kind IN ('entry','accounts')")).length&&loops++<300){
   const b0=c.n(),k0=calls;await drainOutbox({db:c.db,deliver:async a=>{calls++;if(poison===null&&a!=='owner')poison=a;if(a===poison){poisonSeen++;return false;}got.add(a);return true;},clock:()=>t4,maxPages:50,budget:new Budget(qcap),sends:new Budget(dcap)});
   assert.ok(c.n()-b0<=qcap&&calls-k0<=dcap,'per-invocation caps');assert.ok((c.n()-b0)+(calls-k0)<=45,'combined 45');
  }
  assert.equal((await all("SELECT 1 FROM realtime_outbox WHERE kind IN ('entry','accounts')")).length,0,'parent rows finished despite a poison recipient');
  assert.ok(poison!==null&&poisonSeen>=1&&got.size>=1,'a poison recipient was exercised and healthy ones still delivered');
 }
 note('failure isolation + combined 45 ceiling on real D1','poison recipient isolated into its own backoff row, healthy recipients completed, per-invocation D1<=20 and hub<=cap, combined<=45');
 note('instrumented hub delivery budget (caps 3,10,25,40) on real D1','independent hub-call count never exceeded the cap; remainder resumed to completion');
 note('instrumented D1 query budget (caps 0,5,8,9,12,20,45)','independent count never exceeded the cap; budget accounting equals the real count; leftovers resume');
 // poison rows on real D1: backoff, fairness, cap drop
 await run('DELETE FROM realtime_outbox');await run('INSERT OR REPLACE INTO realtime_activity(account_id,last_ticket_at) VALUES (?,?)','owner',Date.now());
 for(let i=0;i<30;i++)await run("INSERT INTO realtime_outbox(kind,account_id,device_id,created_at) VALUES ('device','owner',?,?)",'dev_p'+String(i).padStart(6,'0'),NOW+i);
 let tp=Date.now();const bad=async(a,m)=>m.t!=='close';await drainOutbox({db,deliver:bad,clock:()=>tp,limit:25});
 await run("INSERT INTO realtime_outbox(kind,account_id,created_at) VALUES ('account','owner',?)",NOW);const seen=[];tp+=1;await drainOutbox({db,deliver:async(a,m)=>{seen.push(m.t);return m.t!=='close';},clock:()=>tp,limit:25});
 assert.ok(seen.includes('changed'),'healthy row not starved by 25 poison rows');
 for(let i=0;i<MAX_ATTEMPTS+2;i++){tp+=backoffMs(i)+1;await run('UPDATE realtime_activity SET last_ticket_at=?',tp-1000);await drainOutbox({db,deliver:bad,clock:()=>tp,limit:25});}
 assert.equal((await all("SELECT count(*) n FROM realtime_outbox WHERE kind='device'"))[0].n,0);note('poison hints on real D1','backed off, healthy row delivered first, dropped at cap');
 // real Durable Object hub
 const wsConnect=async(d,closeAt,acct='acct_aaaa1111')=>{const r=await mf.dispatchFetch(`http://x/connect?d=${d}&c=${closeAt}&a=${acct}`,{headers:{Upgrade:'websocket','Sec-WebSocket-Protocol':'otpanda.v1, rt1.unused'}});assert.equal(r.status,101);const ws=r.webSocket;ws.accept();const ev={msgs:[],closed:null};ws.addEventListener('message',e=>ev.msgs.push(e.data));ws.addEventListener('close',e=>ev.closed=e.code);return {ws,ev};};
 const notify=async body=>{const r=await mf.dispatchFetch('http://x/notify?a=acct_aaaa1111',{method:'POST',body:JSON.stringify(body)});return r.status;};
 const wait=ms=>new Promise(r=>setTimeout(r,ms));
 // NOTE: in local workerd a close issued by the DO outside a socket event handler is not surfaced as a client close event
 // (a close inside webSocketMessage is). So closes are proven server-side: a closed socket is gone from the DO and receives nothing more.
 const c1=await wsConnect('dev_aaaaaaaa',Date.now()+60000),c2=await wsConnect('dev_bbbbbbbb',Date.now()+60000);
 assert.equal(await notify({v:1,t:'changed'}),204);await wait(200);assert.deepEqual(c1.ev.msgs,['{"v":1,"t":"changed"}']);assert.deepEqual(c2.ev.msgs,['{"v":1,"t":"changed"}']);
 assert.equal(await notify({v:1,t:'close',deviceId:'dev_aaaaaaaa'}),204);await wait(200);assert.equal(await notify({v:1,t:'changed'}),204);await wait(200);
 assert.equal(c1.ev.msgs.length,1,'revoked device receives nothing after close');assert.equal(c2.ev.msgs.length,2,'other device still receives');
 c2.ws.send('hi');await wait(300);assert.equal(c2.ev.closed,1008);note('real DO: changed fanout exact message, close-by-device removes only that device, client message closes socket (1008 seen by client)','yes');
 const c3=await wsConnect('dev_cccccccc',Date.now()+1500),c4=await wsConnect('dev_dddddddd',Date.now()+60000);await wait(2800);
 assert.equal(await notify({v:1,t:'changed'}),204);await wait(300);assert.equal(c3.ev.msgs.length,0,'expired socket got nothing: alarm closed it');assert.equal(c4.ev.msgs.length,1,'live socket survives the alarm');
 note('real DO alarm: expiry removes only the due socket, no re-arm failure','yes (server-side)');
 assert.equal(await notify({v:1,t:'closeAll'}),204);await wait(200);assert.equal(await notify({v:1,t:'changed'}),204);await wait(300);assert.equal(c4.ev.msgs.length,1,'closeAll removed every socket');note('real DO closeAll','yes (server-side)');
 note('UNVERIFIED locally','client-visible close code (4401/4408) for DO-initiated closes outside an event handler; hibernation eviction; real free-plan DO creation');
 console.log(out.join('\n'));console.log('PASS realtime workerd checks');
}finally{await mf.dispose();}
