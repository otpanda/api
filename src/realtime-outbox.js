// Delivery of content-free invalidation hints. Inactive: nothing mounts or calls this yet.
// At-least-once and idempotent: a duplicate hint only makes a client refetch. Hints never carry
// data; every read still goes through the authorized GET.
export const REALTIME_CRON='*/5 * * * *';
export const PAGE=100,LEASE_MS=60_000,RETAIN_MS=24*60*60*1000;
// A socket exists only if a ticket was minted within the socket cap (5 min, SOCKET_MAX_MS in realtime-http.js; access itself lives 15 min) plus margin.
export const ACTIVITY_MS=6*60*1000;
export const CHANGED=Object.freeze({v:1,t:'changed'});
export const CLOSE_ALL=Object.freeze({v:1,t:'closeAll'});

// Recipients of an entry are resolved at delivery time, after the row is claimed, and only those that could have an open socket.
// A recipient revoked by the change itself, or by a delete, got its own direct row or packed snapshot at write time.
const ENTRY_RECIPIENTS='SELECT m.recipient_id AS r FROM entry_shares m JOIN realtime_activity a ON a.account_id=m.recipient_id AND a.last_ticket_at>?4 WHERE m.entry_id=?1 AND m.revoked_at IS NULL AND m.recipient_id>?2 ORDER BY m.recipient_id LIMIT ?3';
const SNAPSHOT_RECIPIENTS='SELECT j.value AS r FROM json_each(?1) j JOIN realtime_activity a ON a.account_id=j.value AND a.last_ticket_at>?2 WHERE j.value>?3 ORDER BY j.value';
// A recipient whose hub call failed gets its own backing-off row (attempts 1), so the parent row's cursor can move on and later recipients are not starved.
const ISOLATE="INSERT INTO realtime_outbox(kind,account_id,created_at,attempts,next_attempt_at) SELECT 'account',?1,?2,1,?3 WHERE NOT EXISTS (SELECT 1 FROM realtime_outbox WHERE claimed_at IS NULL AND cursor IS NULL AND kind='account' AND account_id=?1)";
const randomClaim=()=>{const b=crypto.getRandomValues(new Uint8Array(16));return Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');};

export const MAX_ATTEMPTS=8,BACKOFF_BASE_MS=30_000,BACKOFF_MAX_MS=15*60_000;
// Free plan: 50 D1 queries per invocation, one per run/all/first, one per batch. The drain spends from an explicit budget
// and never issues a query it cannot pay for, always keeping one for the release/delete that ends a claim.
// A row needs claim, read, owner check, one page query, one isolation write, one cursor advance and one release (and PAGE_MIN is the same minus the first three).
export const ROW_MIN_BUDGET=8,PAGE_MIN_BUDGET=5,CHUNK_MIN_BUDGET=3;
// Conservative realtime-only accounting: D1 queries plus hub calls never exceed COMBINED_CEILING (45).
// This is an application budget, not one shared platform bucket. Official Workers history (2021-07-16) raised DO calls to 1000;
// current Workers limits retain 1000 internal-service calls, while D1 Free limits queries to 50 per invocation.
// Post-write drain: at most 10 hub calls and D1 min(20, 35 - what the request used). Realtime cron: 20 D1 + 25 hub = 45.
export const INVOCATION_QUERY_LIMIT=50,COMBINED_CEILING=45,FOREGROUND_DRAIN_MAX=20,CRON_QUERY_MAX=20;
export const foregroundBudget=spent=>Math.max(0,Math.min(FOREGROUND_DRAIN_MAX,COMBINED_CEILING-FOREGROUND_DELIVERY_MAX-spent));
// Every hub (Durable Object) call is spent from its own application budget, whether it succeeds or fails.
// The conservative realtime-only combined ceiling remains unchanged. Foreground gets at most 10 hub calls, cron 25.
// Budget stops are not failures: the recipient cursor is persisted and the remainder is delivered by the next drain. CPU: Free is 10 ms per invocation, so
// work is staged in chunks of `concurrency` deliveries and nothing else is done per recipient.
export const FOREGROUND_DELIVERY_MAX=10,CRON_DELIVERY_MAX=25;
export const backoffMs=attempts=>Math.min(BACKOFF_MAX_MS,BACKOFF_BASE_MS*2**attempts);
export class Budget{
 constructor(n){this.left=n;this.used=0;}
 take(){if(this.left<=0)throw new RangeError('query budget exhausted');this.left--;this.used++;}
 refund(){this.left++;this.used--;}
}
// deliver(accountId, message) resolves true once the account's hub accepted it; false or a throw
// leaves the row for the next drain with exponential backoff, and a row that keeps failing is dropped after MAX_ATTEMPTS
// (a hint carries no data: a reconnect refetches, and the 5 min socket cap backs up revocation closes).
// Returns {delivered, skipped, lost, dropped, pending, budgetLeft}.
export async function drainOutbox({db,deliver,clock=Date.now,limit=25,maxPages=20,concurrency=10,claimId=randomClaim,budget=new Budget(Number.MAX_SAFE_INTEGER),sends=new Budget(Number.MAX_SAFE_INTEGER)}={}){
 if(!db||typeof deliver!=='function'||!Number.isSafeInteger(limit)||limit<1||limit>100||!Number.isSafeInteger(maxPages)||maxPages<1||!(budget instanceof Budget)||!(sends instanceof Budget))throw new TypeError('Bounded drain required');
 const Q=(sql,...args)=>{budget.take();return db.prepare(sql).bind(...args);};
 const start=clock();let delivered=0,skipped=0,lost=0,dropped=0,pending=false,isolatedCount=0;
 if(budget.left<ROW_MIN_BUDGET+1||sends.left<1)return {delivered,skipped,lost,dropped,pending:true,budgetLeft:budget.left};
 const rows=(await Q('SELECT seq FROM realtime_outbox WHERE (claimed_at IS NULL OR claimed_at<?1) AND next_attempt_at<=?2 ORDER BY next_attempt_at,seq LIMIT ?3',start-LEASE_MS,start,limit).all()).results;
 pending=rows.length===limit;
 for(const {seq} of rows){
  if(budget.left<ROW_MIN_BUDGET||sends.left<1){pending=true;break;}
  // Claim with a random per-claim id (compare-and-set). Every later write is guarded by that exact id, so a worker whose
  // lease was taken over can no longer read, advance, release or delete the row, even on the same clock tick.
  const mine=claimId(),now=clock();
  const claim=await Q('UPDATE realtime_outbox SET claimed_at=?1,claim_id=?2 WHERE seq=?3 AND (claimed_at IS NULL OR claimed_at<?4) AND next_attempt_at<=?1',now,mine,seq,now-LEASE_MS).run();
  if(claim.meta.changes!==1)continue;
  const row=await Q('SELECT kind,account_id,device_id,scope_id,payload,cursor,attempts FROM realtime_outbox WHERE seq=?1 AND claim_id=?2',seq,mine).first();
  if(!row){lost++;continue;}
  const live=now-ACTIVITY_MS;
  let cursor=row.cursor,ok=true,done=false,owned=true,failed=false,stopped=false;
  const ownerLive=async()=>(await Q('SELECT 1 AS x FROM realtime_activity WHERE account_id=?1 AND last_ticket_at>?2',row.account_id,live).first())!==null;
  const fail=()=>{ok=false;failed=true;};
  // Returns true when every recipient was attempted and accepted; a failure backs the row off, a spent delivery budget only stops it.
  // Fan-out of CHANGED to many recipients. Each chunk first PAYS (one D1 query) for the batch that would isolate its failures, and refunds it if nothing failed.
  // A failed recipient becomes its own backoff row and the parent cursor moves past it. Returns how many recipients were passed.
  const fan=async ids=>{
   let passed=0;
   while(passed<ids.length){
    if(sends.left<1||budget.left<CHUNK_MIN_BUDGET){stopped=true;return passed;}
    const n=Math.min(concurrency,sends.left,ids.length-passed),chunk=ids.slice(passed,passed+n);
    budget.take();for(let k=0;k<n;k++)sends.take();
    const res=await Promise.all(chunk.map(a=>Promise.resolve().then(()=>deliver(a,CHANGED)).then(v=>v===true,()=>false)));
    const bad=chunk.filter((_,i)=>!res[i]);
    if(bad.length){
     try{const at=clock();await db.batch(bad.map(a=>db.prepare(ISOLATE).bind(a,at,at+backoffMs(0))));isolatedCount+=bad.length;}
     catch{fail();return passed;}
    }else budget.refund();
    passed+=n;
   }
   return passed;
  };
  const push=async(ids,message)=>{const r=await send(deliver,ids,message,concurrency,sends);if(!r.ok){fail();return {done:r.done,all:false};}if(r.stopped)stopped=true;return {done:r.done,all:!r.stopped};};
  if(row.kind==='account'||row.kind==='device'||row.kind==='revoke'){
   const message=row.kind==='account'?CHANGED:row.kind==='revoke'?CLOSE_ALL:{v:1,t:'close',deviceId:row.device_id};
   if(await ownerLive()){done=(await push([row.account_id],message)).all;}else{skipped++;done=true;}
  }else if(row.kind==='accounts'){
   const ids=(await Q(SNAPSHOT_RECIPIENTS,row.payload,live,cursor??'').all()).results.map(x=>x.r);
   const passed=await fan(ids);done=!stopped&&!failed;if(stopped&&passed>0)cursor=ids[passed-1];
  }else{
   // The owner hint is sent once, through the same prepaid failure isolation as any recipient; an empty cursor records that it was accepted or durably isolated, so a resume never repeats it.
   if(cursor===null&&await ownerLive()){const passed=await fan([row.account_id]);if(passed===1&&!failed)cursor='';else ok=false;}
   for(let page=0;ok&&page<maxPages&&!done;page++){
    // Keep enough budget for this page, its cursor advance and the release that ends the claim.
    if(budget.left<PAGE_MIN_BUDGET||sends.left<1){stopped=true;break;}
    const found=(await Q(ENTRY_RECIPIENTS,row.scope_id,cursor??'',PAGE+1,live).all()).results.map(x=>x.r);
    const batch=found.slice(0,PAGE);
    const passed=await fan(batch);
    if(failed)break;
    if(stopped){if(passed>0)cursor=batch[passed-1];break;}
    if(found.length>PAGE){
     cursor=batch[batch.length-1];
     // Persistent cursor, advanced only while this claim still owns the row; the lease is refreshed.
     const advanced=await Q('UPDATE realtime_outbox SET cursor=?1,claimed_at=?2 WHERE seq=?3 AND claim_id=?4',cursor,clock(),seq,mine).run();
     if(advanced.meta.changes!==1){owned=false;ok=false;break;}
    }else done=true;
   }
  }
  if(!owned){lost++;continue;}
  if(done){const r=await Q('DELETE FROM realtime_outbox WHERE seq=?1 AND claim_id=?2',seq,mine).run();if(r.meta.changes===1)delivered++;else lost++;}
  else if(failed){
   // Delivery failed: back off exponentially; past the cap drop the content-free hint instead of retrying forever.
   if(row.attempts+1>=MAX_ATTEMPTS){const r=await Q('DELETE FROM realtime_outbox WHERE seq=?1 AND claim_id=?2',seq,mine).run();if(r.meta.changes===1)dropped++;}
   else{pending=true;await Q('UPDATE realtime_outbox SET claimed_at=NULL,claim_id=NULL,attempts=attempts+1,next_attempt_at=?3 WHERE seq=?1 AND claim_id=?2',seq,mine,clock()+backoffMs(row.attempts)).run();}
  }
  else{pending=true;await Q('UPDATE realtime_outbox SET claimed_at=NULL,claim_id=NULL,cursor=COALESCE(?3,cursor) WHERE seq=?1 AND claim_id=?2',seq,mine,cursor).run();}
 }
 return {delivered,skipped,lost,dropped,isolated:isolatedCount,pending,budgetLeft:budget.left};
}
// Spends one delivery per attempted recipient, in chunks. `done` counts recipients attempted and accepted before any failure or budget stop.
async function send(deliver,accounts,message,concurrency,sends){
 let done=0;
 while(done<accounts.length){
  if(sends.left<1)return {ok:true,done,stopped:true};
  const n=Math.min(concurrency,sends.left,accounts.length-done);
  for(let k=0;k<n;k++)sends.take();
  const results=await Promise.all(accounts.slice(done,done+n).map(a=>Promise.resolve().then(()=>deliver(a,message)).then(v=>v===true,()=>false)));
  if(results.includes(false))return {ok:false,done,stopped:false};
  done+=n;
 }
 return {ok:true,done,stopped:false};
}
// Bounded post-write / cron drain: rounds share ONE query budget, then the rest is left to the next trigger.
export async function drainSome({budget=new Budget(CRON_QUERY_MAX),sends=new Budget(CRON_DELIVERY_MAX),...options}={},{rounds=3}={}){
 const total={delivered:0,skipped:0,lost:0,dropped:0,isolated:0,pending:false,budgetLeft:budget.left};
 for(let i=0;i<rounds;i++){const r=await drainOutbox({...options,budget,sends});for(const k of ['delivered','skipped','lost','dropped','isolated'])total[k]+=r[k];total.pending=r.pending;total.budgetLeft=r.budgetLeft;total.sendsLeft=sends.left;if(!r.pending||budget.left<ROW_MIN_BUDGET+1||sends.left<1)break;}
 return total;
}
// Dropping an old hint is not data loss: every reconnect starts with a fresh snapshot.
export async function cleanupRealtime({db,clock=Date.now,limit=100}={}){
 if(!db||!Number.isSafeInteger(limit)||limit<1||limit>500)throw new TypeError('Bounded cleanup required');
 const now=clock();
 const r=await db.prepare('DELETE FROM realtime_outbox WHERE seq IN (SELECT seq FROM realtime_outbox WHERE created_at<?1 ORDER BY created_at LIMIT ?2)').bind(now-RETAIN_MS,limit).run();
 await db.prepare('DELETE FROM realtime_activity WHERE account_id IN (SELECT account_id FROM realtime_activity WHERE last_ticket_at<?1 ORDER BY last_ticket_at LIMIT ?2)').bind(now-ACTIVITY_MS,limit).run();
 return r.meta.changes;
}
