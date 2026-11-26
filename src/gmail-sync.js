// Pulls new messages (INBOX, or the connection's label in label mode) for one connected mailbox after a push hint, and
// feeds them to the existing ingest path. The push body is only a hint: the
// mailbox maps to its owner through the stored connection, and message content
// always comes from Google's API using that owner's own refresh token.
import { parseGmailRaw, readBoundedText, rawResponseCap, GMAIL_POLICY } from './gmail-message.js';
import { ingestEmail } from './email-ingest.js';
import { BudgetExceeded } from './request-budget.js';
const API = 'https://gmail.googleapis.com/gmail/v1/users/me';
const PAGE_RECORDS = 25;
const RECOVERY_PAGE = 25;
const DRAIN_BATCH = 3;
const HANDLED_KEEP_MS = 8 * 86400000;
export const MESSAGE_COST = 8; // worst case Google fetch + D1 requests to handle one message; asserted by test
import { canonicalMailbox } from './gmail-source-store.js';
const idOk = v => typeof v === 'string' && /^[0-9a-zA-Z_-]{1,64}$/.test(v);
// Every Google call has a wall-clock timeout so a hung request ends and is recorded as indeterminate; the timeout does NOT
// prove Google stopped working on a mutating request, which is why an indeterminate operation blocks instead of expiring.
const FETCH_TIMEOUT_MS = 10000;
// One lifecycle operation that may write to a mailbox. Every mutating Google call goes through f(): a thrown error (timeout,
// transport, parse) or a 408/429/5xx answer means the write may still land later, so the operation is indeterminate.
class LifecycleOp {
  constructor(sync, mailbox, kind) { this.sync = sync; this.mailbox = mailbox; this.kind = kind; this.id = crypto.randomUUID(); this.unknown = false; }
  // A 2xx whose body cannot be used: the write happened, we cannot tell what it did, so the operation is indeterminate.
  async json(r) { try { return await r.json(); } catch { this.unknown = true; return undefined; } }
  async f(url, init) {
    try { const r = await this.sync.f(url, init); if (r.status === 408 || r.status === 429 || r.status >= 500) this.unknown = true; return r; }
    catch (e) { this.unknown = true; throw e; }
  }
}
export class GmailSync {
  constructor({ store, sources, fetchImpl = fetch, clientId, clientSecret, topicName, clock = Date.now, budget, policy = GMAIL_POLICY, maxMessageUnits = Infinity, labelFilter } = {}) {
    if (!store || !sources || !clientId || !clientSecret || !topicName || typeof budget?.remaining !== 'function') throw new TypeError('Gmail sync dependencies required');
    Object.assign(this, { store, sources, f: (u, i) => fetchImpl(u, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS), ...i, redirect: 'error' }), clientId, clientSecret, topicName, clock, budget, policy });
    if (labelFilter !== undefined && !(typeof labelFilter?.query === 'string' && labelFilter.query.length > 0 && labelFilter.query.length <= 1500 && typeof labelFilter.labelName === 'string' && /^[\w .-]{1,100}$/.test(labelFilter.labelName))) throw new TypeError('labelFilter needs a query and a simple labelName');
    this.labelFilter = labelFilter; // undefined: INBOX mode, no mailbox settings are touched
    this.messageCost = MESSAGE_COST;
    this.units = 0; this.maxMessageUnits = maxMessageUnits;
    this.counts = {}; // outcomes since construction, for logs; never message content
  }
  async accessToken(conn) {
    const body = new URLSearchParams({ client_id: this.clientId, client_secret: this.clientSecret, grant_type: 'refresh_token', refresh_token: await this.store.refreshToken(conn) });
    const r = await this.f('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body });
    if (r.status === 400 || r.status === 401) { await this.store.markReauth(conn.source_id, this.clock()); return; }
    if (!r.ok) throw new Error('token refresh unavailable');
    const j = await r.json(); return typeof j.access_token === 'string' ? j.access_token : undefined;
  }
  async get(path, token, signal) { return this.f(API + path, { headers: { authorization: 'Bearer ' + token }, ...(signal ? { signal } : {}) }); }
  mf(op, url, init) { return op ? op.f(url, init) : this.f(url, init); }
  async startWatch(token, labelId = 'INBOX', op) {
    const r = await this.mf(op, API + '/watch', { method: 'POST', headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json' }, body: JSON.stringify({ topicName: this.topicName, labelIds: [labelId], labelFilterBehavior: 'INCLUDE' }) });
    if (!r.ok) throw new Error('watch failed');
    const j = op ? await op.json(r) : await r.json(); const exp = Number(j?.expiration);
    if (!/^\d+$/.test(String(j?.historyId)) || !Number.isSafeInteger(exp)) { if (op) op.unknown = true; throw new Error('watch invalid'); }
    return { historyId: String(j.historyId), watchExpiresAt: exp };
  }
  // ---- Label mode (only when `labelFilter` is configured) ----
  // Creates ONE label and ONE add-label-only filter in the owner's mailbox and returns their ids. Nothing is
  // adopted: a label that already has this name is a conflict ('label_exists'), never reused or deleted, so
  // cleanup can only ever touch what this app created. Any failure removes what this call created.
  async createArtifacts(token, op) {
    const auth = { authorization: 'Bearer ' + token, 'content-type': 'application/json' };
    const lr = await this.mf(op, API + '/labels', { method: 'POST', headers: auth, body: JSON.stringify({ name: this.labelFilter.labelName }) });
    if (lr.status === 409) return { ok: false, reason: 'label_exists' };
    if (!lr.ok) return { ok: false, reason: 'label_failed' };
    const labelId = (op ? await op.json(lr) : await lr.json().catch(() => undefined))?.id;
    if (!idOk(labelId)) { if (op) op.unknown = true; return { ok: false, reason: 'label_failed' }; } // created, but we cannot name it
    let filterId, lastFilterOk = false;
    try {
      // add-label-only: no archive, no mark-read, no forward, no delete
      const fr = await this.mf(op, API + '/settings/filters', { method: 'POST', headers: auth, body: JSON.stringify({ criteria: { query: this.labelFilter.query }, action: { addLabelIds: [labelId] } }) });
      lastFilterOk = fr.ok;
      if (fr.ok) filterId = (op ? await op.json(fr) : await fr.json().catch(() => undefined))?.id;
    } catch (e) { await this.deleteArtifacts(token, { labelId }, op).catch(() => {}); throw e; }
    if (!idOk(filterId)) { if (op && lastFilterOk) op.unknown = true; await this.deleteArtifacts(token, { labelId }, op).catch(() => {}); return { ok: false, reason: 'filter_failed' }; }
    return { ok: true, labelId, filterId };
  }
  // Deletes only the ids given (the ones this app stored). A 404 counts as gone. Best effort: never throws.
  async deleteArtifacts(token, { labelId, filterId }, op) {
    const out = { filter: !filterId, label: !labelId };
    const del = async (path) => { try { this.need(1); const r = await this.mf(op, API + path, { method: 'DELETE', headers: { authorization: 'Bearer ' + token } }); return r.ok || r.status === 404; } catch { return false; } };
    if (filterId && idOk(filterId)) out.filter = await del('/settings/filters/' + filterId);
    if (labelId && idOk(labelId)) out.label = await del('/labels/' + labelId);
    return out;
  }
  // Runs body(op) as the single lifecycle operation for the mailbox. {blocked:true} when another one is running or an earlier one
  // is indeterminate (nothing was done). The row is deleted only when no mutating call is indeterminate; otherwise it stays and
  // blocks every later operation on that mailbox. A crash also leaves it. Exceptions from body are rethrown after that decision.
  async withOp(mailbox, kind, ownerId, body) {
    const op = new LifecycleOp(this, canonicalMailbox(mailbox), kind);
    let got; try { got = await this.store.acquireOp(op.mailbox, kind, op.id, this.clock(), ownerId); } catch { return { blocked: true }; }
    if (!got) return { blocked: true };
    let value, err, failed = false;
    try { value = await body(op); } catch (e) { failed = true; err = e; }
    try { if (op.unknown) await this.store.markOpIndeterminate(op.mailbox, op.id); else await this.store.releaseOp(op.mailbox, op.id); } catch { /* the row stays: later operations fail closed */ }
    if (failed) throw err;
    return { blocked: false, value };
  }
  // Renews watches that expire within the horizon. Each connection is isolated: one failing
  // mailbox (token revoked, Google error) never blocks the others. Every renewal needs about
  // 3 requests (token, watch, write), so work stops when the budget cannot finish another.
  // Returns the number renewed; details are on lastRenewal.
  async renewWatches(horizonMs = 2 * 86400000, { mailbox } = {}) {
    const stats = { renewed: 0, failed: 0, partial: false };
    this.lastRenewal = stats;
    try {
      this.need(2);
      for (const conn of await this.store.dueForRenewal(this.clock() + horizonMs, 50, mailbox)) {
        if (this.budget.remaining() < 3) { stats.partial = true; break; }
        try {
          const r = await this.withOp(conn.mailbox, 'renew', conn.owner_id, async (op) => {
            const token = await this.accessToken(conn); if (!token) return false;
            const w = await this.startWatch(token, conn.label_id ?? 'INBOX', op); await this.store.setWatch(conn.source_id, w.watchExpiresAt, this.clock()); return true;
          });
          if (r.blocked) { stats.blocked = (stats.blocked ?? 0) + 1; continue; }
          if (r.value) stats.renewed++; else stats.failed++;
        } catch (e) { if (e instanceof BudgetExceeded) { stats.partial = true; break; } stats.failed++; }
      }
    } catch (e) { if (!(e instanceof BudgetExceeded)) throw e; stats.partial = true; }
    return stats.renewed;
  }
  // Owner-initiated disconnect. Local state is the authority (token wiped, source revoked, atomically). This does NOT revoke the
  // Google grant: the app stays listed under the user's Google account permissions until they remove it there. Label mode first
  // removes this app's own label and filter (only the stored ids), as the single lifecycle operation for the mailbox.
  // `revoke` (optional) is the caller's own atomic local revoke, for example the session-guarded one on the mounted route; it
  // must return true only when it revoked. If it returns false nothing is written at Google.
  // An in-flight operation makes this return {disconnected:false, lifecycleBlocked:true} (retry). An INDETERMINATE earlier
  // operation still allows the local revoke (collection stops) but touches nothing at Google: ids stay and are reported as left.
  async disconnect(ownerId, sourceId, { revoke } = {}) {
    const first = await this.store.bySource(ownerId, sourceId);
    if (!first) return { disconnected: false };
    const local = async () => revoke ? await revoke() === true : await this.store.disconnect(ownerId, sourceId, this.clock());
    const base = { remoteRevoked: false, googlePermissionRemains: true };
    if (!this.labelFilter) return { disconnected: await local(), ...base };
    const r = await this.withOp(first.mailbox, 'disconnect', ownerId, async (op) => {
      const conn = await this.store.bySource(ownerId, sourceId); // re-read inside the single-flight
      if (!conn) return { disconnected: false };
      let access; if (conn.status !== 'disconnected' && conn.refresh_envelope && (conn.label_id || conn.filter_id)) { try { this.need(1); access = await this.accessToken(conn); } catch { /* cleanup is skipped, reported below */ } }
      const done = await local();
      if (!done) return { disconnected: false };
      const ids = { labelId: conn.label_id, filterId: conn.filter_id };
      let artifacts;
      if (ids.labelId || ids.filterId) {
        artifacts = access ? await this.deleteArtifacts(access, ids, op) : { filter: !ids.filterId, label: !ids.labelId };
        try { await this.store.clearArtifacts(sourceId, artifacts, ids); } catch { /* ids stay: reported as left behind */ }
      }
      return { disconnected: true, ...(artifacts ? { artifactsRemoved: artifacts.filter && artifacts.label } : {}) };
    });
    if (!r.blocked) return { ...base, ...r.value };
    const held = await this.store.opFor(first.mailbox).catch(() => undefined);
    if (held?.state === 'indeterminate') return { disconnected: await local(), lifecycleBlocked: true, ...base };
    return { disconnected: false, lifecycleBlocked: true, ...base };
  }
  // Bounded work per invocation. Every fetch and D1 query spends from the request
  // budget (see request-budget.js). Before each unit of work we check there is
  // enough left to finish it; otherwise the call stops with 'partial' and the push
  // handler answers 503 so Pub/Sub redelivers. Progress is durable at every step:
  // handled messages are recorded, the cursor moves only over fully handled
  // history records, and recovery keeps its own resumable page state.
  async syncMailbox(mailbox, pushedHistoryId) {
    if (!/^\d{1,20}$/.test(String(pushedHistoryId))) return 'invalid';
    const conn = await this.store.byMailbox(mailbox);
    if (!conn || conn.status !== 'active' || conn.source_revoked_at) return 'ignored'; // revoked: acknowledge, never refresh a token
    if (!conn.recovery_hid && BigInt(pushedHistoryId) <= BigInt(conn.history_id)) return 'stale';
    try {
      this.need(3);
      const token = await this.accessToken(conn); if (!token) return 'reauth';
      if (conn.recovery_hid) return await this.recover(conn, token);
      let cursor = conn.history_id, page;
      for (;;) {
        this.need(3);
        const label = conn.label_id ?? 'INBOX';
        const q = new URLSearchParams({ startHistoryId: cursor, labelId: label, maxResults: String(PAGE_RECORDS) }); q.append('historyTypes', 'messageAdded'); if (conn.label_id) q.append('historyTypes', 'labelAdded'); if (page) q.set('pageToken', page);
        const r = await this.get('/history?' + q, token);
        if (r.status === 404) return await this.recover(conn, token);
        if (!r.ok) throw new Error('history unavailable');
        const j = await r.json();
        const records = j.history ?? [];
        for (const h of records) if (!/^\d{1,20}$/.test(String(h?.id))) throw new Error('history record invalid');
        for (const h of records) {
          // Label mode: a message can show up as added with the label, or as the label being added later (the filter
          // applies it). Both lead to the same message id, and handled-dedupe makes the second sighting free.
          const added = (h.messagesAdded ?? []).map(m => m?.message?.id);
          const labeled = conn.label_id ? (h.labelsAdded ?? []).filter(l => Array.isArray(l?.labelIds) && l.labelIds.includes(conn.label_id)).map(l => l?.message?.id) : [];
          const ids = [...new Set([...added, ...labeled].filter(idOk))];
          await this.handleAll(conn, ids, token);
          // Only now is the whole record done, so the cursor may stand on it.
          if (BigInt(h.id) > BigInt(cursor)) { this.need(1); await this.store.advance(conn, String(h.id), this.clock()); cursor = String(h.id); }
        }
        page = j.nextPageToken;
        if (!page) {
          if (/^\d{1,20}$/.test(String(j.historyId)) && BigInt(j.historyId) > BigInt(cursor)) { this.need(2); await this.store.advance(conn, String(j.historyId), this.clock()); }
          if (this.budget.remaining() >= 1) await this.store.pruneHandled(conn.source_id, this.clock() - HANDLED_KEEP_MS);
          try { await this.drainDue(conn, token); } catch (e) { if (!(e instanceof BudgetExceeded)) this.counts.drain_error = (this.counts.drain_error ?? 0) + 1; } // the forward sync is durable; a failed retry must not undo the 204
          return 'ok';
        }
      }
    } catch (e) {
      if (e instanceof BudgetExceeded) return 'partial';
      throw e;
    }
  }
  need(n) { if (this.budget.remaining() < n) throw new BudgetExceeded(); }
  // Skips ids already handled (one query for the whole record) and ids whose fetch is deferred and not
  // yet due (a second query), then fetches, parses and ingests the rest. A message that reaches an outcome
  // (collected, skipped, or gone) is marked handled and un-deferred in one batch, so a resume continues after it.
  // A fetch timeout, 5xx or 429 never drops the message and never blocks the history behind it: it is queued
  // for retry with backoff (see gmail_deferred) and the cursor may move on. `force` (the due-queue drain)
  // ignores the not-yet-due skip.
  async handleAll(conn, ids, token, { force = false } = {}) {
    if (!ids.length) return;
    this.need(2);
    const done = await this.store.handledSet(conn.source_id, ids);
    const queued = force ? new Map() : await this.store.deferredFor(conn.source_id, ids.filter(id => !done.has(id)));
    const count = k => { this.counts[k] = (this.counts[k] ?? 0) + 1; };
    for (const id of ids) {
      if (done.has(id)) continue;
      if (queued.has(id) && queued.get(id) > this.clock()) continue; // waiting for its backoff
      this.need(this.messageCost);
      if (this.units >= this.maxMessageUnits) throw new BudgetExceeded();
      this.units += 1;
      const limit = this.policy.fetchTimeoutMs ?? 5000;
      const ac = new AbortController(); const fto = setTimeout(() => ac.abort(), limit);
      let text, transient;
      try {
        const r = await this.get('/messages/' + id + '?format=raw', token, ac.signal);
        if (r.status === 404) { await this.store.finishMessage(conn.source_id, id, this.clock()); continue; } // deleted: nothing to collect
        if (r.status >= 500 || r.status === 429) { try { await r.body?.cancel(); } catch { /* ignore */ } transient = 'fetch_error'; }
        else if (!r.ok) throw new Error('message unavailable');
        else text = await readBoundedText(r, rawResponseCap(this.policy), { deadlineMs: limit });
      } catch (e) {
        if (e instanceof BudgetExceeded) throw e;
        if (e?.name === 'AbortError' || e?.name === 'TimeoutError' || e?.message === 'message body timeout') transient = 'fetch_timeout'; else throw e;
      } finally { clearTimeout(fto); }
      if (transient) {
        const q = await this.store.deferFetch(conn.source_id, id, transient, this.clock());
        if (q === 'full') throw new Error('deferred queue full'); // hold the cursor; never evict a pending fetch
        count('deferred'); continue;
      }
      let verdict;
      if (text === undefined) verdict = { ok: false, reason: 'too_large' };
      else { let j; try { j = JSON.parse(text); } catch { j = undefined; } verdict = parseGmailRaw(j, { id, mailbox: conn.mailbox, policy: this.policy }); }
      count(verdict.ok ? 'parsed' : verdict.reason);
      if (verdict.ok) await ingestEmail(this.sources, conn.owner_id, conn.source_id, verdict.message);
      await this.store.finishMessage(conn.source_id, id, this.clock(), verdict.ok ? null : verdict.reason === 'too_large' ? 'too_large' : 'invalid_message');
    }
  }
  // Retries deferred fetches that are due, a few per call, with whatever budget is left (BudgetExceeded
  // just stops). Called after forward progress on a push and from the scheduled drain.
  async drainDue(conn, token) {
    this.need(this.messageCost + 3);
    const ids = await this.store.dueDeferred(conn.source_id, this.clock(), DRAIN_BATCH);
    await this.handleAll(conn, ids, token, { force: true });
  }
  // Scheduled entry point (the 5 minute cron): mailboxes with a due retry, bounded by the budget.
  async drainDueAll(limit = 5, { mailbox } = {}) {
    const stats = { mailboxes: 0, failed: 0, partial: false };
    try {
      this.need(2);
      for (const conn of await this.store.connectionsWithDue(this.clock(), limit, mailbox)) {
        if (this.budget.remaining() < this.messageCost + 6) { stats.partial = true; break; }
        try {
          const token = await this.accessToken(conn); if (!token) { stats.failed++; continue; }
          await this.drainDue(conn, token); stats.mailboxes++;
        } catch (e) { if (e instanceof BudgetExceeded) { stats.partial = true; break; } stats.failed++; }
      }
    } catch (e) { if (!(e instanceof BudgetExceeded)) throw e; stats.partial = true; }
    return stats;
  }
  // Google dropped the history window (404). Resumable, bounded recovery: read the
  // mailbox history id FIRST, then page through inbox mail from the last day
  // (newest first), then restart the cursor from that earlier history id so later
  // mail is covered by normal history reads. Work per call is bounded by the
  // request budget; the whole window completes across redeliveries. The window is
  // one day because collected codes never live longer than 24h.
  async recover(conn, token) {
    let hid = conn.recovery_hid, page = conn.recovery_page ?? undefined, count = conn.recovery_count ?? 0;
    if (!hid) {
      this.need(4);
      const pr = await this.get('/profile', token); if (!pr.ok) throw new Error('profile unavailable');
      hid = String((await pr.json()).historyId ?? '');
      if (!/^[1-9]\d{0,19}$/.test(hid)) throw new Error('profile invalid');
      await this.store.startRecovery(conn.source_id, hid);
    }
    for (;;) {
      this.need(3);
      const q = new URLSearchParams({ labelIds: conn.label_id ?? 'INBOX', maxResults: String(RECOVERY_PAGE), q: 'newer_than:1d' }); if (page) q.set('pageToken', page);
      const lr = await this.get('/messages?' + q, token);
      if (lr.status === 400 && page) { await this.store.recoveryProgress(conn.source_id, null, count); page = undefined; continue; } // stale page token: restart the (idempotent) listing
      if (!lr.ok) throw new Error('list unavailable');
      const j = await lr.json();
      await this.handleAll(conn, [...new Set((j.messages ?? []).map(m => m?.id).filter(idOk))], token);
      count += (j.messages ?? []).length;
      const next = j.nextPageToken;
      if (!next) {
        this.need(3);
        await this.store.advance(conn, hid, this.clock());
        await this.store.finishRecovery(conn.source_id, this.clock());
        return 'resynced';
      }
      this.need(1); await this.store.recoveryProgress(conn.source_id, next, count); page = next;
    }
  }
}
