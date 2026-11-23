// Fixed-table bounded housekeeping for the new identity runtime only.
// No legacy session/OIDC path is mounted by this module.
const TABLES=Object.freeze([
 ['browser_logout_bindings','expires_at'],['auth_challenges','expires_at'],['passkey_ceremonies','expires_at'],
 ['passkey_signups','expires_at'],['web_login_starts','expires_at'],
 ['web_login_handoffs','expires_at'],['browser_exchanges','expires_at'],
 ['device_access_handles','expires_at'],['incoming_codes','expires_at'],
 ['entry_tokens','expires_at'],['rate_buckets','resets_at'],
]);
export async function cleanupIdentity({db,clock=Date.now,limit=100}={}) {
 if(!db||!Number.isSafeInteger(limit)||limit<1||limit>500)throw new TypeError('Bounded cleanup required');
 const now=clock();if(!Number.isSafeInteger(now)||now<0)throw new TypeError('Valid instant required');
 const removed={};
 for(const [table,column] of TABLES) {
  const r=await db.prepare(`DELETE FROM ${table} WHERE rowid IN (SELECT rowid FROM ${table} WHERE ${column}<=?1 ORDER BY ${column} LIMIT ?2)`).bind(now,limit).run();removed[table]=r.meta.changes;
 }
 const spent=await db.prepare('DELETE FROM device_refresh_handles WHERE handle_id IN (SELECT handle_id FROM device_refresh_handles WHERE used_at IS NOT NULL AND used_at<=?1 ORDER BY used_at LIMIT ?2)').bind(now-30*24*60*60*1000,limit).run();removed.device_refresh_handles=spent.meta.changes;
 const devices=await db.prepare('DELETE FROM device_sessions WHERE device_id IN (SELECT device_id FROM device_sessions WHERE expires_at<=?1 OR revoked_at IS NOT NULL ORDER BY expires_at LIMIT ?2)').bind(now,limit).run();removed.device_sessions=devices.meta.changes;
 const receipts=await db.prepare('DELETE FROM personal_copy_receipts WHERE rowid IN (SELECT rowid FROM personal_copy_receipts WHERE accepted_at<?1 ORDER BY accepted_at LIMIT ?2)').bind(now-600000,limit).run();removed.personal_copy_receipts=receipts.meta.changes;
 const days=await db.prepare('DELETE FROM personal_copy_days WHERE rowid IN (SELECT rowid FROM personal_copy_days WHERE day<?1 ORDER BY day LIMIT ?2)').bind(Math.floor(now/86400000)-89,limit).run();removed.personal_copy_days=days.meta.changes;
 return removed;
}
