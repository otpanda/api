// Fixed-table bounded housekeeping for the new identity runtime only.
// No legacy session/OIDC path is mounted by this module.
import {cleanupRealtime} from './realtime-outbox.js';
export const RETAIN_FAILED=7*24*60*60*1000;
const TABLES=Object.freeze([
 ['human_email_codes','expires_at'],['pending_logins','expires_at'],['setting_changes','expires_at'],
 ['google_continuations','expires_at'],['google_link_tickets','expires_at'],['google_enrollment_grants','expires_at'],['passkey_add_authorizations','expires_at'],['enrolled_approvals','expires_at'],['device_key_receipts','expires_at'],['email_recovery_grants','expires_at'],['recovery_changes','expires_at'],['oauth_transactions','expires_at'],
 ['assignment_intents','result_expires_at'],
 ['browser_logout_bindings','expires_at'],['auth_challenges','expires_at'],['passkey_ceremonies','expires_at'],
 ['passkey_signups','expires_at'],['web_signup_starts','expires_at'],['signup_mail_bindings','expires_at'],['web_login_starts','expires_at'],
 ['web_login_handoffs','expires_at'],['browser_exchanges','expires_at'],
 ['native_exchanges','expires_at'],['native_challenges','expires_at'],['native_google_nonces','expires_at'],['device_access_handles','expires_at'],['incoming_codes','expires_at'],
 ['entry_tokens','expires_at'],['realtime_tickets','expires_at'],['rate_buckets','resets_at'],
]);
export async function cleanupIdentity({db,clock=Date.now,limit=100}={}) {
 if(!db||!Number.isSafeInteger(limit)||limit<1||limit>500)throw new TypeError('Bounded cleanup required');
 const now=clock();if(!Number.isSafeInteger(now)||now<0)throw new TypeError('Valid instant required');
 const removed={};
 for(const [table,column] of TABLES) {
  const r=await db.prepare(`DELETE FROM ${table} WHERE rowid IN (SELECT rowid FROM ${table} WHERE ${column}<=?1 ORDER BY ${column} LIMIT ?2)`).bind(now,limit).run();removed[table]=r.meta.changes;
 }
 // Code jobs: unclassified lapsed jobs are expired-failed by the scheduled handler first. Terminal
 // failures keep a 7-day metric record (no code: the envelope is already wiped); everything else goes at expiry.
 const jobs=await db.prepare('DELETE FROM recovery_code_jobs WHERE rowid IN (SELECT rowid FROM recovery_code_jobs WHERE (failed_at IS NULL AND expires_at<=?1) OR failed_at<=?3 ORDER BY expires_at LIMIT ?2)').bind(now,limit,now-RETAIN_FAILED).run();removed.recovery_code_jobs=jobs.meta.changes;
 // A lineage with no live handle stays renewable by its key until 30 days after its last renewal (device idle window).
 const lineages=await db.prepare('DELETE FROM access_lineages WHERE lineage_id IN (SELECT l.lineage_id FROM access_lineages l WHERE COALESCE(l.last_renewed_at,l.created_at)<=?3 AND NOT EXISTS(SELECT 1 FROM device_access_handles a WHERE a.lineage_id=l.lineage_id AND a.expires_at>?1) ORDER BY l.created_at LIMIT ?2)').bind(now,limit,now-30*24*60*60*1000).run();removed.access_lineages=lineages.meta.changes;
 const spent=await db.prepare('DELETE FROM device_refresh_handles WHERE handle_id IN (SELECT handle_id FROM device_refresh_handles WHERE used_at IS NOT NULL AND used_at<=?1 ORDER BY used_at LIMIT ?2)').bind(now-30*24*60*60*1000,limit).run();removed.device_refresh_handles=spent.meta.changes;
 const devices=await db.prepare('DELETE FROM device_sessions WHERE device_id IN (SELECT device_id FROM device_sessions WHERE expires_at<=?1 OR revoked_at IS NOT NULL ORDER BY expires_at LIMIT ?2)').bind(now,limit).run();removed.device_sessions=devices.meta.changes;
 const receipts=await db.prepare('DELETE FROM personal_copy_receipts WHERE rowid IN (SELECT rowid FROM personal_copy_receipts WHERE accepted_at<?1 ORDER BY accepted_at LIMIT ?2)').bind(now-600000,limit).run();removed.personal_copy_receipts=receipts.meta.changes;
 const days=await db.prepare('DELETE FROM personal_copy_days WHERE rowid IN (SELECT rowid FROM personal_copy_days WHERE day<?1 ORDER BY day LIMIT ?2)').bind(Math.floor(now/86400000)-89,limit).run();removed.personal_copy_days=days.meta.changes;
 const recognition=await db.prepare('DELETE FROM recognized_browsers WHERE recognition_id IN(SELECT r.recognition_id FROM recognized_browsers r LEFT JOIN account_security s ON s.owner_id=r.owner_id LEFT JOIN provider_identities g ON g.identity_id=r.provider_identity_id WHERE r.revoked_at IS NOT NULL OR s.generation<>r.generation OR g.revoked_at IS NOT NULL ORDER BY r.created_at LIMIT ?2)').bind(now,limit).run();removed.recognized_browsers=recognition.meta.changes;
 removed.realtime_outbox=await cleanupRealtime({db,clock:()=>now,limit});
 return removed;
}
