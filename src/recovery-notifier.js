// Delivers recovery_notifications rows. At-least-once with a bounded lease:
// a row is claimed (attempts+1, 60 s lease) before sending and marked delivered
// only after the transport accepts it. At most 5 attempts, exponential backoff.
// A crash or an uncertain transport result can repeat a notice after the lease;
// these are security notices to the account owner, so a repeat is acceptable and
// a silent drop is not. The recipient is always the account's stored mailbox.
const LEASE=60_000,MAX_ATTEMPTS=5;
export async function deliverRecoveryNotifications({db,deliver,clock=Date.now,limit=10}={}){
 if(!db||typeof deliver!=='function'||!Number.isSafeInteger(limit)||limit<1||limit>25)throw new TypeError('Bounded notifier required');
 const now=clock(),out={delivered:0,failed:0};
 const due=await db.prepare('SELECT notification_id FROM recovery_notifications WHERE delivered_at IS NULL AND attempts<?1 AND next_attempt_at<=?2 AND claimed_until<=?2 ORDER BY created_at LIMIT ?3').bind(MAX_ATTEMPTS,now,limit).all();
 for(const {notification_id:id} of due.results){
  const row=await db.prepare('UPDATE recovery_notifications SET attempts=attempts+1,claimed_until=?2 WHERE notification_id=?1 AND delivered_at IS NULL AND attempts<?3 AND next_attempt_at<=?4 AND claimed_until<=?4 RETURNING owner_id,kind,attempts').bind(id,now+LEASE,MAX_ATTEMPTS,now).first();
  if(!row)continue;
  try{
   const a=await db.prepare('SELECT email FROM account_emails WHERE owner_id=?1').bind(row.owner_id).first();if(!a)throw new Error('no mailbox');
   await deliver({kind:row.kind,to:a.email});
   await db.prepare('UPDATE recovery_notifications SET delivered_at=?2,claimed_until=0,failed_at=NULL WHERE notification_id=?1 AND delivered_at IS NULL').bind(id,clock()).run();out.delivered++;
  }catch{
   // Terminal on the last attempt: failed_at makes it visible, never silent.
   await db.prepare('UPDATE recovery_notifications SET claimed_until=0,next_attempt_at=?2,failed_at=CASE WHEN attempts>=?3 THEN ?4 END WHERE notification_id=?1 AND delivered_at IS NULL').bind(id,clock()+60_000*2**row.attempts,MAX_ATTEMPTS,clock()).run().catch(()=>{});out.failed++;
  }
 }
 return out;
}
// ---- mailbox-code jobs (durable, encrypted, bounded retry) ----
// Claim -> decrypt -> send -> mark delivered and wipe the envelope. Retries
// until the code expires or 6 attempts; backoff 30 s * 2^n. A repeat after a
// crash resends the same code, which is harmless. Nothing here logs a code.
const CODE_MAX_ATTEMPTS=6;
export async function deliverRecoveryCodeJob({db,cipher,deliver,clock=Date.now,jobId}){
 const now=clock();
 const row=await db.prepare("UPDATE recovery_code_jobs SET attempts=attempts+1,claimed_until=?2 WHERE job_id=?1 AND kind<>'decoy' AND delivered_at IS NULL AND failed_at IS NULL AND superseded_at IS NULL AND attempts<?3 AND expires_at>?4 AND next_attempt_at<=?4 AND claimed_until<=?4 AND EXISTS(SELECT 1 FROM human_email_codes h WHERE h.code_id=recovery_code_jobs.code_id AND h.expires_at>?4) RETURNING owner_id,kind,envelope,created_at,expires_at,attempts,generation").bind(jobId,now+LEASE,CODE_MAX_ATTEMPTS,now).first();
 if(!row)return false;
 const wipe=failure=>db.prepare("UPDATE recovery_code_jobs SET failed_at=?2,failure=?3,envelope='',claimed_until=0 WHERE job_id=?1 AND delivered_at IS NULL AND failed_at IS NULL AND superseded_at IS NULL").bind(jobId,clock(),failure).run();
 try{
  const {code,to}=JSON.parse(await cipher.decrypt(JSON.parse(row.envelope),{ownerId:row.owner_id,recordId:jobId,serviceId:'recovery-code',receivedAt:row.created_at,expiresAt:row.expires_at}));
  // Revalidate the snapshot at send time: the canonical mailbox, the security
  // generation and the opt-in must still be what the code was issued for.
  const live=await db.prepare('SELECT 1 x FROM account_emails e JOIN account_security s ON s.owner_id=e.owner_id JOIN email_recovery_optin o ON o.owner_id=e.owner_id WHERE e.owner_id=?1 AND e.email=?2 AND s.generation=?3').bind(row.owner_id,to,row.generation).first();
  if(!live){await wipe('stale');return false;}
  // Last check before the network: a newer request may have superseded this job.
  // The ACTUAL predicate: this job's code_id must still be the current, unexpired,
  // unclaimed human code row for its binding. Anything else means a newer issue or a claim.
  if(!await db.prepare('SELECT 1 x FROM recovery_code_jobs j WHERE j.job_id=?1 AND j.superseded_at IS NULL AND j.delivered_at IS NULL AND j.failed_at IS NULL AND EXISTS(SELECT 1 FROM human_email_codes h WHERE h.code_id=j.code_id AND h.expires_at>?2)').bind(jobId,clock()).first())return false;
  await deliver({kind:row.kind,to,code,expiresAt:row.expires_at});
  await db.prepare("UPDATE recovery_code_jobs SET delivered_at=?2,claimed_until=0,envelope='' WHERE job_id=?1 AND delivered_at IS NULL AND failed_at IS NULL").bind(jobId,clock()).run();
  return true;
 }catch{
  // The last attempt is terminal: visible as failed, with the code wiped.
  await db.prepare("UPDATE recovery_code_jobs SET claimed_until=0,next_attempt_at=?2,failed_at=CASE WHEN attempts>=?3 THEN ?4 END,failure=CASE WHEN attempts>=?3 THEN 'attempts' END,envelope=CASE WHEN attempts>=?3 THEN '' ELSE envelope END WHERE job_id=?1 AND delivered_at IS NULL AND failed_at IS NULL AND superseded_at IS NULL").bind(jobId,clock()+30_000*2**row.attempts,CODE_MAX_ATTEMPTS,clock()).run().catch(()=>{});
  return false;
 }
}
// Jobs whose code lapsed before delivery become explicit expired failures (and
// their envelope is wiped) instead of silently leaving the pending set.
export async function expireRecoveryCodeJobs({db,clock=Date.now}={}){
 const now=clock(),r=await db.prepare("UPDATE recovery_code_jobs SET failed_at=?1,failure='expired',envelope='',claimed_until=0 WHERE kind<>'decoy' AND delivered_at IS NULL AND failed_at IS NULL AND superseded_at IS NULL AND expires_at<=?1").bind(now).run();
 return r.meta.changes;
}
export async function drainRecoveryCodeJobs({db,cipher,deliver,clock=Date.now,limit=10}={}){
 if(!db||!cipher||typeof deliver!=='function'||!Number.isSafeInteger(limit)||limit<1||limit>25)throw new TypeError('Bounded drain required');
 const expired=await expireRecoveryCodeJobs({db,clock});
 const now=clock(),due=await db.prepare("SELECT job_id FROM recovery_code_jobs WHERE kind<>'decoy' AND delivered_at IS NULL AND failed_at IS NULL AND superseded_at IS NULL AND attempts<?1 AND expires_at>?2 AND next_attempt_at<=?2 AND claimed_until<=?2 AND EXISTS(SELECT 1 FROM human_email_codes h WHERE h.code_id=recovery_code_jobs.code_id AND h.expires_at>?2) ORDER BY created_at LIMIT ?3").bind(CODE_MAX_ATTEMPTS,now,limit).all(),out={delivered:0,failed:0,expired};
 for(const {job_id:jobId} of due.results)(await deliverRecoveryCodeJob({db,cipher,deliver,clock,jobId}))?out.delivered++:out.failed++;
 return out;
}

// ---- operational visibility and deliberate retry ----
// Health counts only: no addresses, codes or ids. dead* are terminal failures
// that need attention; pending* are waiting or in retry.
export async function recoveryDeliveryHealth({db,clock=Date.now}={}){
 const now=clock(),n=await db.prepare('SELECT sum(delivered_at IS NULL AND failed_at IS NULL) p,sum(failed_at IS NOT NULL) d,min(CASE WHEN delivered_at IS NULL AND failed_at IS NULL THEN created_at END) o FROM recovery_notifications').first();
 await expireRecoveryCodeJobs({db,clock});
 const c=await db.prepare("SELECT sum(delivered_at IS NULL AND failed_at IS NULL AND superseded_at IS NULL) p,sum(failed_at IS NOT NULL) d,sum(failure='expired') e,sum(failure='stale') st FROM recovery_code_jobs WHERE kind<>'decoy'").first();
 return{pendingNotifications:n.p??0,deadNotifications:n.d??0,oldestPendingNotificationAgeMs:n.o==null?null:now-n.o,pendingCodeJobs:c.p??0,deadCodeJobs:c.d??0,expiredCodeJobs:c.e??0,staleCodeJobs:c.st??0};
}
// Deliberate operator retry for terminally failed notices: attempts reset, once
// per call, bounded. Never automatic, so a permanent fault cannot loop forever.
export async function retryFailedRecoveryNotifications({db,clock=Date.now,limit=25}={}){
 if(!Number.isSafeInteger(limit)||limit<1||limit>100)throw new TypeError('Bounded retry required');
 const r=await db.prepare('UPDATE recovery_notifications SET attempts=0,failed_at=NULL,next_attempt_at=?1,claimed_until=0 WHERE notification_id IN(SELECT notification_id FROM recovery_notifications WHERE failed_at IS NOT NULL AND delivered_at IS NULL ORDER BY failed_at LIMIT ?2)').bind(clock(),limit).run();
 return r.meta.changes;
}
