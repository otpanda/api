// Owner-bound Gmail connection flow. start() needs an already authenticated
// owner (the caller authenticates). The callback has no session: the owner comes
// only from the single-use state created at start, and the mailbox identity from
// Google's own profile endpoint for the token it just issued.
import { canonicalMailbox } from './gmail-source-store.js';
import { GMAIL_SCOPES_READ, GMAIL_SCOPES_LABEL_FILTER } from './gmail-label-filter.js';
async function s256(v) { const d = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(v))); return btoa(String.fromCharCode(...d)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
export const normGeneration = v => typeof v === 'string' && v ? v : Number.isSafeInteger(v) && v >= 0 ? String(v) : undefined;
export class GmailSourceOauth {
  constructor({ store, sync, fetchImpl = fetch, clientId, clientSecret, redirectUri, devMailbox, clock = Date.now, verifyStepUp, isCurrent, sessionGuard } = {}) {
    if (!store || !sync || !clientId || !clientSecret || !redirectUri || typeof verifyStepUp !== 'function' || typeof isCurrent !== 'function' || typeof sessionGuard !== 'function') throw new TypeError('OAuth dependencies required');
    Object.assign(this, { store, sync, f: (u, i) => fetchImpl(u, { ...i, redirect: 'error' }), clientId, clientSecret, redirectUri, clock, verifyStepUp, isCurrent, sessionGuard, devMailbox: devMailbox === undefined ? undefined : canonicalMailbox(devMailbox) });
  }
  scopes() { return this.sync.labelFilter ? GMAIL_SCOPES_LABEL_FILTER : GMAIL_SCOPES_READ; }
  // ctx = { ownerId, deviceId, generation } of the authenticated session, plus the
  // caller's step-up proof. verifyStepUp must atomically consume a proof made for
  // exactly this owner, device, generation and action 'gmail-source-connect'.
  async start({ ownerId, deviceId, generation, stepUp } = {}) {
    generation = normGeneration(generation);
    if (typeof ownerId !== 'string' || !ownerId || typeof deviceId !== 'string' || !deviceId || generation === undefined) return { ok: false, reason: 'session_required' };
    if (await this.verifyStepUp({ ownerId, deviceId, generation, action: 'gmail-source-connect', proof: stepUp }) !== true) return { ok: false, reason: 'step_up_required' };
    const { state, verifier } = await this.store.createState(ownerId, { deviceId, generation }, this.clock());
    const q = new URLSearchParams({ client_id: this.clientId, redirect_uri: this.redirectUri, response_type: 'code', scope: this.scopes().join(' '), access_type: 'offline', prompt: 'consent', include_granted_scopes: 'false', state, code_challenge: await s256(verifier), code_challenge_method: 'S256' });
    return { ok: true, authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth?' + q };
  }
    // session = { ownerId, deviceId, generation } from a read-only inspection of the
  // browser's own first-party cookie (no rotation). All three must equal what the
  // state recorded. The final write is additionally guarded atomically in the store.
  async callback({ code, state, error, session } = {}) {
    const claimed = await this.store.consumeState(state, this.clock());
    if (!claimed) return { ok: false, reason: 'invalid_state' };
    if (session?.ownerId !== claimed.ownerId || session?.deviceId !== claimed.deviceId || normGeneration(session?.generation) !== claimed.generation) return { ok: false, reason: 'session_mismatch' };
    if (error || typeof code !== 'string' || !code || code.length > 2048) return { ok: false, reason: 'denied' };
    // Dev-only lifecycle: the one allowed mailbox is known up front, so the single-flight is taken BEFORE the code exchange and
    // held through every Google write. Label mode refuses to run without it. See gmail_op in migration 0051.
    if (!this.devMailbox) return this.sync.labelFilter ? { ok: false, reason: 'dev_mailbox_required' } : this.finish(claimed, code, undefined);
    const r = await this.sync.withOp(this.devMailbox, 'connect', claimed.ownerId, op => this.finish(claimed, code, op));
    return r.blocked ? { ok: false, reason: 'lifecycle_blocked' } : r.value;
  }
  // Wraps the exchange so a failure AFTER Google issued tokens never leaves a live grant that no stored connection owns.
  // The new refresh token is revoked at Google only when ALL hold: this call holds the single-flight (which belongs to the
  // configured DEV mailbox, not to the profile mailbox Google returned), the profile mailbox was read for this very token,
  // and no stored connection for that profile mailbox holds an envelope. Revoking a refresh token revokes the grant, so any stored token for the same Google account could die with
  // it; if a row with an envelope exists, or it cannot be read, the grant is left alone. Without the op (no dev mailbox) or
  // without a known mailbox (profile or scope failure) ownership cannot be established, so nothing is revoked.
  async finish(claimed, code, op) {
    const ctx = {};
    let res;
    try { res = await this.finishExchange(claimed, code, op, ctx); }
    catch (e) { await this.revokeUnowned(ctx, op); throw e; }
    if (res?.ok === false) res = { ...res, grantRevoked: await this.revokeUnowned(ctx, op) };
    return res;
  }
  async revokeUnowned(ctx, op) {
    if (!op || !ctx.refresh || !ctx.mailbox) return false;
    try {
      const row = await this.store.byMailbox(ctx.mailbox);
      if (row && row.refresh_envelope) return false;
      // Plain fetch, not op.f: a cleanup outage must never mark the DEV mailbox lifecycle indeterminate. Result is reported only.
      const r = await this.f('https://oauth2.googleapis.com/revoke', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ token: ctx.refresh }) });
      return r.ok === true;
    } catch { return false; } // best effort: any failure just reports false and leaves the grant
  }
  async finishExchange(claimed, code, op, ctx) {
    const tr = await this.f('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_id: this.clientId, client_secret: this.clientSecret, code, code_verifier: claimed.verifier, grant_type: 'authorization_code', redirect_uri: this.redirectUri }) });
    if (!tr.ok) return { ok: false, reason: 'exchange_failed' };
    const t = await tr.json();
    if (typeof t.access_token !== 'string' || typeof t.refresh_token !== 'string' || !this.scopes().every(x => String(t.scope ?? '').split(' ').includes(x))) return { ok: false, reason: 'scope_missing' };
    ctx.refresh = t.refresh_token;
    const pr = await this.sync.get('/profile', t.access_token);
    if (!pr.ok) return { ok: false, reason: 'profile_failed' };
    let mailbox; try { mailbox = canonicalMailbox((await pr.json()).emailAddress); } catch { return { ok: false, reason: 'profile_failed' }; }
    ctx.mailbox = mailbox;
    if (this.devMailbox && mailbox !== this.devMailbox) return { ok: false, reason: 'mailbox_not_allowed' }; // no Gmail write of any kind
    if (await this.isCurrent({ ownerId: claimed.ownerId, deviceId: claimed.deviceId, generation: claimed.generation }) !== true) return { ok: false, reason: 'session_revoked' };
    const existing = this.sync.labelFilter ? await this.store.byMailbox(mailbox) : undefined;
    if (existing && existing.owner_id !== claimed.ownerId) return { ok: false, reason: 'mailbox_in_use' }; // before any write to that mailbox
    let ids = { labelId: null, filterId: null }, created = false;
    const old = { labelId: existing?.label_id ?? null, filterId: existing?.filter_id ?? null };
    if (this.sync.labelFilter) {
      // Never reuse: a concurrent disconnect may be deleting exactly those ids. Reconnect removes this app's earlier label and
      // filter (by stored id, a 404 is fine) and creates new ones, so each connection owns ids no other flow is acting on.
      if (old.labelId || old.filterId) await this.sync.deleteArtifacts(t.access_token, old, op);
      const a = await this.sync.createArtifacts(t.access_token, op);
      if (!a.ok) {
        // The old label is gone, so a still-active connection would watch a deleted label: mark it as needing a reconnect.
        if (old.labelId) await this.store.markReauthIfArtifacts(existing.source_id, old.labelId, this.clock());
        return { ok: false, reason: a.reason };
      }
      ids = { labelId: a.labelId, filterId: a.filterId }; created = true;
    }
    // After the old label is removed a failure leaves nothing usable: delete what this call created and, if the old ids are still
    // what the active row holds, mark it as needing a reconnect.
    const undo = async () => { if (created) await this.sync.deleteArtifacts(t.access_token, { labelId: ids.labelId, filterId: ids.filterId }, op); if (created && old.labelId) await this.store.markReauthIfArtifacts(existing.source_id, old.labelId, this.clock()); };
    let w, r;
    try {
      w = await this.sync.startWatch(t.access_token, ids.labelId ?? 'INBOX', op);
      r = await this.store.connect(claimed.ownerId, { mailbox, refreshToken: t.refresh_token, historyId: w.historyId, watchExpiresAt: w.watchExpiresAt, ...ids, guard: await this.sessionGuard({ ownerId: claimed.ownerId, deviceId: claimed.deviceId, generation: claimed.generation }) }, this.clock());
    } catch (e) { await undo(); throw e; } // a partial setup leaves nothing behind that this call created
    if (r.changed) { await undo(); return { ok: false, reason: 'source_changed' }; } // revoked or replaced while this connect was preparing: nothing written, retry
    if (r.revoked) { await undo(); return { ok: false, reason: 'session_revoked' }; }
    if (r.conflict) { await undo(); return { ok: false, reason: 'mailbox_in_use' }; }
    return { ok: true, sourceId: r.sourceId, mailbox };
  }
}
