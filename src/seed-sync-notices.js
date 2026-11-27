// Delivers seed_sync_notices rows. Same contract as recovery-notifier: claim with a 60 s lease, mark delivered only after the transport accepts,
// at most 5 attempts with backoff, terminal failed_at (never silent). The recipient is always the account's stored mailbox; the body is a fixed
// server template that carries no key id, install id or account detail. At-least-once: a repeat after a crash is acceptable for a security notice.
// Recipient rule = the existing notifier's rule: account_emails.email for the owner. That table has no unverified rows (verified_at is NOT NULL by schema, a test pins
// that constraint); the extra `verified_at IS NOT NULL` here is defense in depth that costs nothing and keeps the intent visible.
// Never silent: a failure-path write that itself fails leaves attempts=5 with no failed_at; the next run marks such rows failed (healed), and
// seedSyncNoticeHealth() is the monitoring read. Delivered rows are pruned after RETAIN_DELIVERED_MS; failed rows are kept for operators.
const LEASE=60_000,MAX_ATTEMPTS=5,RETAIN_DELIVERED_MS=30*24*60*60*1000,OVERDUE_MS=15*60*1000;
export async function seedSyncNoticeHealth({db,clock=Date.now}={}){
 const now=clock();
 const r=await db.prepare('SELECT COALESCE(SUM(failed_at IS NOT NULL),0) failed,COALESCE(SUM(failed_at IS NULL AND delivered_at IS NULL AND attempts>=?1),0) exhausted_unmarked,COALESCE(SUM(failed_at IS NULL AND delivered_at IS NULL AND attempts<?1 AND max(next_attempt_at,created_at)<=?2-?3 AND claimed_until<=?2-?3),0) overdue,MIN(CASE WHEN failed_at IS NULL AND delivered_at IS NULL THEN created_at END) oldest_pending FROM seed_sync_notices').bind(MAX_ATTEMPTS,now,OVERDUE_MS).first();
 const out={failed:r.failed,exhaustedUnmarked:r.exhausted_unmarked,overdue:r.overdue,oldestPendingAgeMs:r.oldest_pending===null?0:now-r.oldest_pending};
 out.alert=out.failed>0||out.exhaustedUnmarked>0||out.overdue>0;return out;
}
export async function deliverSeedSyncNotices({db,deliver,clock=Date.now,limit=10}={}){
 if(!db||typeof deliver!=='function'||!Number.isSafeInteger(limit)||limit<1||limit>25)throw new TypeError('Bounded notifier required');
 const now=clock(),out={delivered:0,failed:0,healed:0,pruned:0};
 try{out.healed=(await db.prepare('UPDATE seed_sync_notices SET failed_at=?1,claimed_until=0 WHERE delivered_at IS NULL AND failed_at IS NULL AND attempts>=?2 AND claimed_until<=?1').bind(now,MAX_ATTEMPTS).run()).meta.changes;}catch{}
 const due=await db.prepare('SELECT notice_id FROM seed_sync_notices WHERE delivered_at IS NULL AND failed_at IS NULL AND attempts<?1 AND next_attempt_at<=?2 AND claimed_until<=?2 ORDER BY created_at LIMIT ?3').bind(MAX_ATTEMPTS,now,limit).all();
 for(const {notice_id:id} of due.results){
  const row=await db.prepare('UPDATE seed_sync_notices SET attempts=attempts+1,claimed_until=?2 WHERE notice_id=?1 AND delivered_at IS NULL AND failed_at IS NULL AND attempts<?3 AND next_attempt_at<=?4 AND claimed_until<=?4 RETURNING owner_id,kind,attempts').bind(id,now+LEASE,MAX_ATTEMPTS,now).first();
  if(!row)continue;
  try{
   const a=await db.prepare('SELECT email FROM account_emails WHERE owner_id=?1 AND verified_at IS NOT NULL').bind(row.owner_id).first();if(!a)throw new Error('no mailbox');
   await deliver({kind:'seed-sync-'+row.kind,to:a.email});
   await db.prepare('UPDATE seed_sync_notices SET delivered_at=?2,claimed_until=0 WHERE notice_id=?1 AND delivered_at IS NULL').bind(id,clock()).run();out.delivered++;
  }catch{
   await db.prepare('UPDATE seed_sync_notices SET claimed_until=0,next_attempt_at=?2,failed_at=CASE WHEN attempts>=?3 THEN ?4 END WHERE notice_id=?1 AND delivered_at IS NULL').bind(id,clock()+60_000*2**row.attempts,MAX_ATTEMPTS,clock()).run().catch(()=>{out.unmarked=(out.unmarked??0)+1;});out.failed++;
  }
 }
 try{out.pruned=(await db.prepare('DELETE FROM seed_sync_notices WHERE notice_id IN (SELECT notice_id FROM seed_sync_notices WHERE delivered_at IS NOT NULL AND delivered_at<?1 LIMIT 50)').bind(now-RETAIN_DELIVERED_MS).run()).meta.changes;}catch{}
 return out;
}
