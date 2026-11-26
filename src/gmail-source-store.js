// Durable Gmail connection state. The mailbox to owner mapping comes only from
// a completed OAuth exchange (the mailbox Google's API reports for the granted
// token), never from a callback or push parameter.
import { hashText } from './sessions.js';
import { normalizeEmail } from './service-metadata.js';
const STATE_TTL = 10 * 60 * 1000;
const rand = n => { const b = crypto.getRandomValues(new Uint8Array(n)); let s = ''; for (const x of b) s += x.toString(16).padStart(2, '0'); return s; };
export const canonicalMailbox = v => { if (typeof v !== 'string' || v.length > 254 || !/^[^\s@]+@[^\s@]+$/.test(v)) throw new TypeError('Mailbox required'); return v.trim().toLowerCase(); };
export const DEFERRED_CAP = 1000; // pending message fetches per source; when full the history cursor is held, nothing is evicted
export class GmailSourceStore {
  constructor(db, cipher) { this.db = db; this.cipher = cipher; }
  async createState(ownerId, { deviceId, generation }, now) {
    if (typeof ownerId !== 'string' || !ownerId || typeof deviceId !== 'string' || !deviceId || typeof generation !== 'string' || !generation) throw new TypeError('Owner, device and generation required');
    const state = rand(32), verifier = rand(48);
    await this.db.prepare('INSERT INTO gmail_oauth_states (state_hash,owner_id,verifier,device_id,generation,created_at,expires_at) VALUES (?1,?2,?3,?4,?5,?6,?7)').bind(await hashText(state), ownerId, verifier, deviceId, generation, now, now + STATE_TTL).run();
    return { state, verifier };
  }
  // Single use. The row is claimed atomically before any token exchange.
  async consumeState(state, now) {
    if (typeof state !== 'string' || !/^[0-9a-f]{64}$/.test(state)) return;
    const row = await this.db.prepare('UPDATE gmail_oauth_states SET used_at=?2 WHERE state_hash=?1 AND used_at IS NULL AND expires_at>?2 RETURNING owner_id,verifier,device_id,generation').bind(await hashText(state), now).first();
    return row ? { ownerId: row.owner_id, verifier: row.verifier, deviceId: row.device_id, generation: row.generation } : undefined;
  }
  // source_revoked_at comes from the same row read, so a revoked source is seen without a second query.
  async byMailbox(mailbox) { return await this.db.prepare('SELECT c.*, s.revoked_at AS source_revoked_at FROM gmail_connections c JOIN sources s ON s.source_id=c.source_id AND s.owner_id=c.owner_id WHERE c.mailbox=?1').bind(canonicalMailbox(mailbox)).first() ?? undefined; }
  async bySource(ownerId, sourceId) { return await this.db.prepare('SELECT * FROM gmail_connections WHERE owner_id=?1 AND source_id=?2').bind(ownerId, sourceId).first() ?? undefined; }
  async refreshToken(conn) { return this.cipher.decrypt(JSON.parse(conn.refresh_envelope), { ownerId: conn.owner_id, sourceId: conn.source_id }); }
  // Returns {sourceId}, {conflict:true} when another owner holds the mailbox, or
  // {revoked:true} when the session guard no longer matches. guard = {sql, params}
  // from the session layer: a SELECT with anonymous ? placeholders that returns a
  // row only while the exact device session and security generation are still
  // active. Every write below is conditional on it inside one atomic batch, so a
  // revocation between the preflight and the write cannot leave a connection.
  async connect(ownerId, { mailbox, refreshToken, historyId, watchExpiresAt, labelId = null, filterId = null, guard }, now) {
    if (!guard || typeof guard.sql !== 'string' || !Array.isArray(guard.params) || !/^\s*SELECT\b/i.test(guard.sql) || /;/.test(guard.sql)) throw new TypeError('Session guard required');
    mailbox = canonicalMailbox(mailbox);
    // The entry matcher compares sources.receiver with the delivered-to address after both
    // go through normalizeEmail. The mailbox is already fully lowercased, so this is the
    // canonical form the ingest path produces. Without it every code is unassigned.
    const receiver = normalizeEmail(mailbox);
    const existing = await this.byMailbox(mailbox);
    if (existing && existing.owner_id !== ownerId) return { conflict: true };
    const sourceId = existing?.source_id ?? crypto.randomUUID();
    const envelope = JSON.stringify(await this.cipher.encrypt(refreshToken, { ownerId, sourceId }));
    const g = `EXISTS (${guard.sql})`;
    let results;
    if (existing) {
      results = await this.db.batch([
        this.db.prepare(`UPDATE gmail_connections SET refresh_envelope=?,history_id=?,watch_expires_at=?,label_id=?,filter_id=?,status='active',gen=gen+1,recovery_hid=NULL,recovery_page=NULL,recovery_count=0,updated_at=? WHERE source_id=? AND owner_id=? AND gen=? AND ${g}`).bind(envelope, historyId, watchExpiresAt, labelId, filterId, now, sourceId, ownerId, existing.gen, ...guard.params),
        this.db.prepare(`UPDATE sources SET revoked_at=NULL, receiver=? WHERE source_id=? AND owner_id=? AND ${g} AND EXISTS (SELECT 1 FROM gmail_connections WHERE source_id=? AND refresh_envelope=?)`).bind(receiver, sourceId, ownerId, ...guard.params, sourceId, envelope),
      ]);
    } else {
      results = await this.db.batch([
        this.db.prepare(`INSERT INTO sources (source_id,owner_id,kind,label,created_at,receiver) SELECT ?,?,'gmail',?,?,? WHERE ${g}`).bind(sourceId, ownerId, mailbox.slice(0, 120), now, receiver, ...guard.params),
        this.db.prepare(`INSERT INTO gmail_connections (source_id,owner_id,mailbox,refresh_envelope,history_id,watch_expires_at,created_at,updated_at,label_id,filter_id) SELECT ?,?,?,?,?,?,?,?,?,? WHERE ${g}`).bind(sourceId, ownerId, mailbox, envelope, historyId, watchExpiresAt, now, now, labelId, filterId, ...guard.params),
      ]);
    }
    if (!(results[0].meta.changes >= 1)) {
      // The row's generation moved after it was read (a revoke by any path, or another connect): nothing was written.
      if (existing && (await this.bySource(ownerId, sourceId))?.gen !== existing.gen) return { changed: true };
      return { revoked: true };
    }
    return { sourceId };
  }
  // Forward-only in SQL (numeric compare on digit strings), so concurrent workers
  // each advance independently and nothing can move the cursor backwards.
  async advance(conn, historyId, now) {
    if (!/^[1-9]\d{0,19}$/.test(String(historyId))) return false;
    const r = await this.db.prepare('UPDATE gmail_connections SET history_id=?2,updated_at=?3 WHERE source_id=?1 AND (length(history_id)<length(?2) OR (length(history_id)=length(?2) AND history_id<?2))').bind(conn.source_id, String(historyId), now).run();
    return r.meta.changes >= 1;
  }
  // Owner-initiated disconnect. One atomic batch revokes the source and wipes the stored
  // refresh token. Idempotent. Returns false when the source is not this owner's Gmail source.
  async disconnect(ownerId, sourceId, now) {
    const r = await this.db.batch([
      this.db.prepare("UPDATE sources SET revoked_at=COALESCE(revoked_at,?1) WHERE owner_id=?2 AND source_id=?3 AND kind='gmail'").bind(now, ownerId, sourceId),
      this.db.prepare("UPDATE gmail_connections SET status='disconnected', refresh_envelope='', recovery_hid=NULL, recovery_page=NULL, recovery_count=0, updated_at=?1 WHERE owner_id=?2 AND source_id=?3").bind(now, ownerId, sourceId),
    ]);
    return r[0].meta.changes >= 1;
  }
  // Single-flight lifecycle operation per mailbox (see gmail_op in migration 0051). acquire returns true for exactly one caller
  // while no row exists; a held or indeterminate row blocks. release deletes only the caller's own running row.
  async acquireOp(mailbox, kind, opId, now, ownerId) {
    const r = await this.db.prepare("INSERT INTO gmail_op (mailbox,owner_id,op_id,kind,state,started_at) VALUES (?1,?5,?2,?3,'running',?4) ON CONFLICT(mailbox) DO NOTHING").bind(canonicalMailbox(mailbox), opId, kind, now, ownerId).run();
    return r.meta.changes >= 1;
  }
  async releaseOp(mailbox, opId) { await this.db.prepare("DELETE FROM gmail_op WHERE mailbox=?1 AND op_id=?2 AND state='running'").bind(canonicalMailbox(mailbox), opId).run(); }
  async markOpIndeterminate(mailbox, opId) { await this.db.prepare("UPDATE gmail_op SET state='indeterminate' WHERE mailbox=?1 AND op_id=?2").bind(canonicalMailbox(mailbox), opId).run(); }
  async opFor(mailbox) { return await this.db.prepare('SELECT mailbox,owner_id,op_id,kind,state,started_at FROM gmail_op WHERE mailbox=?1').bind(canonicalMailbox(mailbox)).first() ?? undefined; }
  // Label mode: forget artifact ids once they are confirmed gone from the mailbox. Ids that could not be removed stay
  // on the row, so the owner can be told something was left behind.
  // Compare-and-set: an id is cleared only when the row is still disconnected AND still holds exactly the id that was removed,
  // so a reconnect that stored new ids in the meantime is never touched.
  async clearArtifacts(sourceId, { filter = false, label = false } = {}, { filterId = null, labelId = null } = {}) {
    if ((!filter || !filterId) && (!label || !labelId)) return;
    await this.db.prepare("UPDATE gmail_connections SET filter_id=CASE WHEN ?2 AND filter_id=?4 THEN NULL ELSE filter_id END, label_id=CASE WHEN ?3 AND label_id=?5 THEN NULL ELSE label_id END WHERE source_id=?1 AND status='disconnected'").bind(sourceId, filter ? 1 : 0, label ? 1 : 0, filterId, labelId).run();
  }
  // A failed reconnect that already removed the old label and filter: the connection is not usable until reconnected.
  // Only if the row still holds those old ids (a concurrent reconnect that succeeded has stored new ones).
  async markReauthIfArtifacts(sourceId, labelId, now) {
    await this.db.prepare("UPDATE gmail_connections SET status='reauth_required',updated_at=?3 WHERE source_id=?1 AND label_id=?2 AND status='active'").bind(sourceId, labelId, now).run();
  }
  // Owner-scoped, counts only: label/filter this app created that are still in a mailbox whose connection is gone.
  async ownerArtifactStatus(ownerId) {
    const r = await this.db.prepare("SELECT count(label_id) AS labels, count(filter_id) AS filters FROM gmail_connections WHERE owner_id=?1 AND status='disconnected'").bind(ownerId).first();
    const o = await this.db.prepare('SELECT count(*) AS n FROM gmail_op WHERE owner_id=?1').bind(ownerId).first();
    return { leftoverLabels: r?.labels ?? 0, leftoverFilters: r?.filters ?? 0, lifecycleBlocked: (o?.n ?? 0) > 0 };
  }
  // Bounded cleanup for expired or used OAuth states. Safe to run from a scheduled handler.
  async pruneStates(now, limit = 100) {
    const r = await this.db.prepare('DELETE FROM gmail_oauth_states WHERE state_hash IN (SELECT state_hash FROM gmail_oauth_states WHERE expires_at<?1 LIMIT ?2)').bind(now, limit).run();
    return r.meta.changes;
  }
  async markReauth(sourceId, now) { await this.db.prepare("UPDATE gmail_connections SET status='reauth_required',updated_at=?2 WHERE source_id=?1").bind(sourceId, now).run(); }
  async setWatch(sourceId, watchExpiresAt, now) { await this.db.prepare('UPDATE gmail_connections SET watch_expires_at=?2,updated_at=?3 WHERE source_id=?1').bind(sourceId, watchExpiresAt, now).run(); }
  // `mailbox` (optional) restricts the rows to that one canonical mailbox, in SQL, for the dev-only scheduled maintenance.
  async dueForRenewal(beforeMs, limit = 50, mailbox) { return (await this.db.prepare("SELECT * FROM gmail_connections WHERE status='active' AND watch_expires_at<?1 AND (?3 IS NULL OR mailbox=?3) ORDER BY watch_expires_at LIMIT ?2").bind(beforeMs, limit, mailbox === undefined ? null : canonicalMailbox(mailbox)).all()).results; }
  async handledSet(sourceId, ids) {
    const out = new Set();
    for (let i = 0; i < ids.length; i += 90) {
      const chunk = ids.slice(i, i + 90);
      const rows = (await this.db.prepare(`SELECT message_id FROM gmail_handled WHERE source_id=? AND message_id IN (${chunk.map(() => '?').join(',')})`).bind(sourceId, ...chunk).all()).results;
      for (const r of rows) out.add(r.message_id);
    }
    return out;
  }
  // Deferred message fetches (see migration 0051). Ids and counters only, never content.
  async deferredFor(sourceId, ids) {
    const out = new Map();
    for (let i = 0; i < ids.length; i += 90) {
      const chunk = ids.slice(i, i + 90);
      const rows = (await this.db.prepare(`SELECT message_id, next_attempt_at FROM gmail_deferred WHERE source_id=? AND message_id IN (${chunk.map(() => '?').join(',')})`).bind(sourceId, ...chunk).all()).results;
      for (const r of rows) out.set(r.message_id, r.next_attempt_at);
    }
    return out;
  }
  // One statement. New row: first try now, next attempt in 1 min. Existing row: attempts+1 and the
  // delay doubles (1,2,4,... capped at 1 h). A new row is refused (returns 'full') when the source
  // already has DEFERRED_CAP rows; an existing row always updates. Nothing is ever evicted.
  async deferFetch(sourceId, id, reason, now) {
    if (reason !== 'fetch_timeout' && reason !== 'fetch_error') throw new TypeError('bad defer reason');
    const r = await this.db.prepare(`INSERT INTO gmail_deferred (source_id,message_id,first_seen_at,next_attempt_at,attempts,last_reason)
      SELECT ?1,?2,?3,?3+60000,1,?4 WHERE EXISTS (SELECT 1 FROM gmail_deferred WHERE source_id=?1 AND message_id=?2) OR (SELECT count(*) FROM gmail_deferred WHERE source_id=?1) < ?5
      ON CONFLICT(source_id,message_id) DO UPDATE SET attempts=attempts+1, last_reason=excluded.last_reason,
        next_attempt_at=?3 + MIN(3600000, 60000 * (1 << MIN(attempts, 6)))`).bind(sourceId, id, now, reason, DEFERRED_CAP).run();
    return r.meta.changes >= 1 ? 'queued' : 'full';
  }
  // Message reached a verdict (ingested, skipped, or gone): handled and no longer deferred, atomically.
  async finishMessage(sourceId, id, now, skipReason = null) {
    if(skipReason !== null && !['too_large','invalid_message'].includes(skipReason)) throw new TypeError('bad skip reason');
    await this.db.batch([
      this.db.prepare('INSERT OR IGNORE INTO gmail_handled (source_id,message_id,handled_at,skip_reason) VALUES (?1,?2,?3,?4)').bind(sourceId, id, now, skipReason),
      this.db.prepare('DELETE FROM gmail_deferred WHERE source_id=?1 AND message_id=?2').bind(sourceId, id),
    ]);
  }
  async dueDeferred(sourceId, now, limit = 5) { return (await this.db.prepare('SELECT message_id FROM gmail_deferred WHERE source_id=?1 AND next_attempt_at<=?2 ORDER BY next_attempt_at LIMIT ?3').bind(sourceId, now, limit).all()).results.map(r => r.message_id); }
  async connectionsWithDue(now, limit = 5, mailbox) { return (await this.db.prepare("SELECT c.* FROM gmail_connections c WHERE c.status='active' AND (?3 IS NULL OR c.mailbox=?3) AND EXISTS (SELECT 1 FROM gmail_deferred d WHERE d.source_id=c.source_id AND d.next_attempt_at<=?1) ORDER BY c.source_id LIMIT ?2").bind(now, limit, mailbox === undefined ? null : canonicalMailbox(mailbox)).all()).results; }
  // Owner-scoped, for the status API: counts and timestamps only. No ids, senders or content.
  async ownerDeferredStatus(ownerId, now = Date.now()) {
    const rows=(await this.db.prepare(`SELECT d.source_id,count(*) AS n,min(d.first_seen_at) AS oldest FROM gmail_deferred d JOIN gmail_connections c ON c.source_id=d.source_id WHERE c.owner_id=?1 GROUP BY d.source_id`).bind(ownerId).all()).results;
    const skipped=(await this.db.prepare(`SELECT h.skip_reason AS reason,count(*) AS n FROM gmail_handled h JOIN gmail_connections c ON c.source_id=h.source_id WHERE c.owner_id=?1 AND h.handled_at>=?2 AND h.skip_reason IS NOT NULL GROUP BY h.skip_reason`).bind(ownerId,now-8*86400000).all()).results;
    return {skipped:Object.fromEntries(skipped.map(r=>[r.reason,r.n])),pending:rows.reduce((a,r)=>a+r.n,0),oldestFirstSeenAt:rows.length?Math.min(...rows.map(r=>r.oldest)):null,full:rows.some(r=>r.n>=DEFERRED_CAP)};
  }
  async deferredStatus(ownerId, sourceId) {
    const rows = (await this.db.prepare(`SELECT d.last_reason AS reason, count(*) AS n, min(d.first_seen_at) AS oldest, min(d.next_attempt_at) AS next
      FROM gmail_deferred d JOIN gmail_connections c ON c.source_id=d.source_id WHERE c.owner_id=?1 AND d.source_id=?2 GROUP BY d.last_reason`).bind(ownerId, sourceId).all()).results;
    const pending = rows.reduce((a, r) => a + r.n, 0);
    return { pending, oldestFirstSeenAt: pending ? Math.min(...rows.map(r => r.oldest)) : null, nextAttemptAt: pending ? Math.min(...rows.map(r => r.next)) : null,
      reasons: Object.fromEntries(rows.map(r => [r.reason, r.n])), full: pending >= DEFERRED_CAP };
  }
  async markHandled(sourceId, id, now) { await this.db.prepare('INSERT OR IGNORE INTO gmail_handled (source_id,message_id,handled_at) VALUES (?1,?2,?3)').bind(sourceId, id, now).run(); }
  async pruneHandled(sourceId, before) { await this.db.prepare('DELETE FROM gmail_handled WHERE source_id=?1 AND handled_at<?2').bind(sourceId, before).run(); }
  async startRecovery(sourceId, hid) { await this.db.prepare('UPDATE gmail_connections SET recovery_hid=?2,recovery_page=NULL,recovery_count=0 WHERE source_id=?1 AND recovery_hid IS NULL').bind(sourceId, hid).run(); }
  async recoveryProgress(sourceId, page, count) { await this.db.prepare('UPDATE gmail_connections SET recovery_page=?2,recovery_count=?3 WHERE source_id=?1').bind(sourceId, page, count).run(); }
  async finishRecovery(sourceId, now) { await this.db.prepare('UPDATE gmail_connections SET recovery_hid=NULL,recovery_page=NULL,recovery_count=0,updated_at=?2 WHERE source_id=?1').bind(sourceId, now).run(); }
}
