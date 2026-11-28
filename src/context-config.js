// One place that turns deployment variables into unassigned-context store options, so every runtime that builds a SourceEntryStore
// (identity runtime reads and housekeeping, Gmail collection ingest) gets the same configuration.
// CONTEXT_RETENTION_DAYS: plain variable, integer 1 to 30. Unset, empty or invalid means off (invalid also alerts).
// CONTEXT_DIGEST_SECRET: Worker secret, 32+ random bytes as hex or base64url. Never log it.
const DAY=86400000;
export function contextStoreOptions(env,alert=message=>console.warn(message)){
  const raw=env?.CONTEXT_RETENTION_DAYS;
  if(raw===undefined||raw===null||raw==='')return {};
  const text=String(raw).trim();
  if(!/^\d{1,2}$/.test(text)||Number(text)<1||Number(text)>30){try{alert('context-retention-disabled: invalid CONTEXT_RETENTION_DAYS');}catch{}return {};}
  return {contextRetentionMs:Number(text)*DAY,contextDigestSecret:env?.CONTEXT_DIGEST_SECRET,contextAlert:alert};
}
import {createSourceEntryStore,contextOutstandingSelect} from './source-entries.js';
// Scheduled housekeeping for unassigned context. Needs no code keys. Isolated from other cron work: a failure is logged (counts only, no data) and never rejects the caller.
// Missing table (before migration 0054) is a quiet no-op. Returns {removed} or {failed:true}.
export async function runContextCleanup({db,env,clock=Date.now,maxPasses=5,warn=(...a)=>console.warn(...a)}){
  try{
    const store=createSourceEntryStore(db,null,contextStoreOptions(env));
    return {removed:await store.cleanupContext(clock(),{maxPasses})};
  }catch{
    try{warn('context-cleanup-failed');}catch{}
    return {failed:true};
  }
}
// Durable, derived health signal for context cleanup. PULL ONLY: it is read from /ready by whoever or whatever polls it. It is not an alert,
// pushes nothing, and is not a monitor. The cron failure log is best-effort (Workers logs may be off), but a failing or starved cleanup always
// leaves rows that cleanup would have removed, so this reads that state. Returns 'ok' | 'attention', never counts, ids or content.
// It uses the SAME effective configuration as the cron cleanup (createSourceEntryStore): an invalid days value or a missing or short digest secret
// makes retention effectively off, and then every remaining row is outstanding because the real cleanup purges them all.
// Retention on: a row is outstanding when it is CONTEXT_OVERDUE_MS past retain_until (a reporting grace of 8 cron windows, NOT a retention
// policy: retention itself is exactly the configured days), or when it carries a key fingerprint other than the current secret's (a rotation
// purge the cron has not completed; it reads 'attention' for at most about one cron window after a rotation, which is the point of the signal).
// One LIMIT 1 read on the readiness request, never in the cron budget, using index probes only (see contextOutstandingSelect): a healthy table reads no rows.
export const CONTEXT_OVERDUE_MS=2*60*60*1000,CONTEXT_STATUS_TTL_MS=60*1000,CONTEXT_STATUS_FAILURE_TTL_MS=10*1000;
export const CONTEXT_STATUS_SQL=contextOutstandingSelect('1 x',1);
// Public /ready must not become an unbounded public query path: the probe is index-only (see contextOutstandingSelect), the answer is cached per
// database object and effective configuration (retention window plus the secret's one-way fingerprint, never the secret), concurrent probes share one
// in-flight read, and a missing table (ok) is cached like any answer. A failed read ('attention') is cached for a shorter time so recovery shows quickly.
const cache=new WeakMap();
export async function contextCleanupStatus({db,env,clock=Date.now}){
  try{
    const store=createSourceEntryStore(db,null,contextStoreOptions(env,()=>{}),()=>{});
    const fingerprint=store.contextRetentionMs===null?null:await store.contextKeyFingerprint();
    const key=store.contextRetentionMs===null?'off':store.contextRetentionMs+':'+fingerprint,now=clock(),hit=cache.get(db);
    if(hit&&hit.key===key){
      if(hit.pending)return hit.pending;
      if(now>=hit.at&&now-hit.at<hit.ttl)return hit.value;
    }
    const read=(async()=>{
      try{
        const row=fingerprint===null
          ?await db.prepare('SELECT 1 x FROM unassigned_context LIMIT 1').first()
          :await db.prepare(CONTEXT_STATUS_SQL).bind(now-CONTEXT_OVERDUE_MS,fingerprint).first();
        return {value:row?'attention':'ok',ttl:CONTEXT_STATUS_TTL_MS};
      }catch(error){return /no such table/i.test(String(error?.message))?{value:'ok',ttl:CONTEXT_STATUS_TTL_MS}:{value:'attention',ttl:CONTEXT_STATUS_FAILURE_TTL_MS};}
    })();
    const pending=read.then(r=>{cache.set(db,{key,at:now,value:r.value,ttl:r.ttl});return r.value;});
    cache.set(db,{key,pending});
    return await pending;
  }catch{return 'attention';}
}
