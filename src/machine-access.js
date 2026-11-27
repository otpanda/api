import { generateAccessToken, digestSecret, timingSafeEqual } from './tokens.js';
import { opaqueDigest, json, hashText, takeRateLimit } from './sessions.js';
import { bearerToken, unauthorized } from './http.js';
import { EntryTotpGenerator } from './totp-seeds.js';
import { SESSION_METHOD_JOIN as MJ, SESSION_METHOD_ACTIVE as MA } from './session-method.js';

// Account sharing grants and machine profiles. Every decision is a live query;
// nothing about entries, grants or lists is cached in a token.
const MODES = ['all', 'allow', 'deny'];
const KINDS = { totp: ['totp'], email: ['email'], sms: ['sms'], all: ['totp', 'email', 'sms'] };
const SOURCE_KINDS = { email: ['gmail', 'outlook'], sms: ['sms'] };
function id(v) { if (typeof v !== 'string' || !v || v.length > 256) throw new TypeError('Bounded identifier required'); return v; }
function selector(mode, entryIds) {
  if (!MODES.includes(mode)) throw new TypeError('Unsupported mode');
  if (!Array.isArray(entryIds) || entryIds.length > 500) throw new TypeError('Bounded entry list required');
  const list = [...new Set(entryIds.map(id))];
  if (mode === 'all' && list.length) throw new TypeError('Full access takes no entry list');
  if (mode === 'allow' && !list.length) throw new TypeError('Allow list needs at least one entry');
  return list;
}
// SQL fragment: does selector row X (alias with .mode and link table T) cover entry ?E.
const covers = (x, link, key, entry) => `(${x}.mode='all' OR (${x}.mode='allow' AND EXISTS (SELECT 1 FROM ${link} l WHERE l.${key}=${x}.${key} AND l.entry_id=${entry})) OR (${x}.mode='deny' AND NOT EXISTS (SELECT 1 FROM ${link} l WHERE l.${key}=${x}.${key} AND l.entry_id=${entry})))`;

// Management writes are conditioned, inside each SQL statement, on a live device session of the acting
// owner (same predicate as entry-manage-http) and on owner/creator scope. Callers pass a viewer taken from
// the authenticated session: { ownerId, deviceId, generation, kind: 'web' | 'android' }.
function viewerOf(v) {
  if (!v || typeof v !== 'object' || !['web', 'android'].includes(v.kind) || !Number.isSafeInteger(v.generation)) throw new TypeError('Authenticated viewer required');
  return { ownerId: id(v.ownerId), deviceId: id(v.deviceId), generation: v.generation, kind: v.kind };
}
// Appends the session guard as the last four numbered parameters after `n` existing ones.
function guarded(n, kind) {
  const [o, d, g, t] = [n + 1, n + 2, n + 3, n + 4].map(i => '?' + i);
  return `EXISTS (SELECT 1 FROM device_sessions d ${MJ} JOIN account_security s ON s.owner_id=d.owner_id WHERE d.device_id=${d} AND d.owner_id=${o} AND d.generation=${g} AND s.generation=${g} AND d.client_kind='${kind}' AND d.revoked_at IS NULL AND ${MA} AND d.created_at<=${t} AND d.expires_at>${t})`;
}
// Machine token lifetime: owner-chosen. User decision (latest): "never expires" is allowed (ttlMs === null);
// client default is one year. A finite value is only bounded to keep arithmetic safe.
export const MAX_TOKEN_TTL_MS = 3650 * 86400000;
const guardArgs = (v, now) => [v.ownerId, v.deviceId, v.generation, now];

import { googlePictureUrl, googleDisplayName } from './account-identity.js';
export class MachineAccess {
  constructor(db) { this.db = db; }
  // Runs a batch as one transaction. A failed tx_assert row rolls everything back; returns undefined then.
  async #atomic(statements) {
    try { return await this.db.batch(statements); }
    catch (error) { if (/CHECK constraint failed/i.test(String(error?.message ?? error))) return undefined; throw error; }
  }
  async #live(v, now) { return Boolean(await this.db.prepare('SELECT 1 AS ok WHERE ' + guarded(0, v.kind)).bind(...guardArgs(v, now)).first()); }

  // ---- owner-managed grants to other OTPanda accounts (already-resolved ids) ----
  // Returns false when the session or owner scope does not hold at write time.
  async grant(viewer, granteeId, terms, now = Date.now()) { return this.#grant(viewer, granteeId, terms, now, 0); }
  // Edit terms of an existing live grant only; never creates or revives one.
  async updateGrant(viewer, granteeId, terms, now = Date.now()) { return this.#grant(viewer, granteeId, terms, now, 1); }
  // Share again with someone this owner already shared with through an accepted invite. Never reaches an
  // account that is not in the owner's own contact list, so account ids cannot be probed or guessed.
  // All owner-facing sharing calls name a recipient by the opaque contact_ref from listContacts, resolved only within
  // the caller's own contacts. Unknown, foreign or malformed refs behave exactly like absent ones.
  async #resolve(v, ref, includeRemoved) {
    if (typeof ref !== 'string' || !/^[0-9a-f]{32}$/.test(ref)) return undefined;
    const r = await this.db.prepare('SELECT contact_id FROM sharing_contacts WHERE owner_id=?1 AND contact_ref=?2' + (includeRemoved ? '' : ' AND removed_at IS NULL')).bind(v.ownerId, ref).first();
    return r?.contact_id;
  }
  // Share again with a remembered recipient, no new link. The SQL batch re-checks the contact is still present.
  async grantToContact(viewer, ref, terms, now = Date.now()) {
    const v = viewerOf(viewer), c = await this.#resolve(v, ref, false);
    return c ? this.#grant(viewer, c, terms, now, 2) : false;
  }
  // Update or revoke stay possible for a hidden contact while its grant is live.
  async updateGrantForContact(viewer, ref, terms, now = Date.now()) {
    const v = viewerOf(viewer), c = await this.#resolve(v, ref, true);
    return c ? this.#grant(viewer, c, terms, now, 1) : false;
  }
  async revokeGrantForContact(viewer, ref, now = Date.now()) {
    const v = viewerOf(viewer), c = await this.#resolve(v, ref, true);
    return c ? this.revokeGrant(viewer, c, now) : false;
  }
  async listContacts(viewer, now = Date.now()) {
    const v = viewerOf(viewer), g = guardArgs(v, now);
    // Only the initiating owner's own contacts: name, email and picture, as the user approved. A hidden contact
    // is listed only while a grant to it is live, so it can still be managed.
    const r = await this.db.prepare("SELECT c.contact_ref,c.created_at,c.removed_at,(SELECT i.display_name FROM provider_identities i WHERE i.owner_id=c.contact_id AND i.issuer='https://accounts.google.com' AND i.revoked_at IS NULL LIMIT 1) AS name,(SELECT e.email FROM account_emails e WHERE e.owner_id=c.contact_id LIMIT 1) AS email,(SELECT i.picture FROM provider_identities i WHERE i.owner_id=c.contact_id AND i.issuer='https://accounts.google.com' AND i.revoked_at IS NULL LIMIT 1) AS picture,gr.mode AS gmode,gr.can_delegate AS gdel FROM sharing_contacts c LEFT JOIN access_grants gr ON gr.owner_id=c.owner_id AND gr.grantee_id=c.contact_id AND gr.revoked_at IS NULL WHERE c.owner_id=?1 AND " + guarded(0, v.kind) + ' AND (c.removed_at IS NULL OR gr.grant_id IS NOT NULL) ORDER BY c.created_at,c.contact_ref LIMIT 200').bind(...g).all();
    return (r.results ?? []).map(x => ({ contactRef: x.contact_ref, since: x.created_at, hidden: x.removed_at !== null, name: googleDisplayName(x.name) ?? null, email: x.email ?? null, ...(googlePictureUrl(x.picture) ? { picture: x.picture } : {}), grant: x.gmode ? { mode: x.gmode, canDelegate: x.gdel === 1 } : null }));
  }
  async removeContact(viewer, ref, now = Date.now()) {
    const v = viewerOf(viewer), g = guardArgs(v, now);
    if (typeof ref !== 'string' || !/^[0-9a-f]{32}$/.test(ref)) return false;
    const r = await this.db.prepare('UPDATE sharing_contacts SET removed_at=COALESCE(removed_at,?6) WHERE owner_id=?1 AND contact_ref=?5 AND ' + guarded(0, v.kind)).bind(...g, ref, now).run();
    return r.meta.changes >= 1;
  }
  async #grant(viewer, granteeId, { mode, entryIds = [], canDelegate = false }, now, existingOnly) {
    const v = viewerOf(viewer); id(granteeId);
    if (v.ownerId === granteeId || typeof canDelegate !== 'boolean' || !Number.isSafeInteger(now)) throw new TypeError('Distinct grantee, explicit delegation flag and clock required');
    const list = selector(mode, entryIds), g = guardArgs(v, now), nonce = crypto.randomUUID();
    // One transaction: grant row, list, then an assertion that the session still holds and that every listed
    // entry was inserted. An entry that is not the owner's, or vanished meanwhile, rolls back all of it
    // The final assert also requires that this batch wrote the grant row (a per-call random write_nonce, not a timestamp), so a refused
    // upsert can never leave an existing grant with a wiped list. (an existing grant, its list, outbox hints and revision bumps are left exactly as they were).
    const results = await this.#atomic([
      this.db.prepare(`INSERT INTO access_grants (grant_id,owner_id,grantee_id,mode,can_delegate,created_at,granted_at,write_nonce) SELECT ?1,?2,?3,?4,?5,?9,?9,?1 WHERE ${guarded(5, v.kind)} AND EXISTS (SELECT 1 FROM accounts WHERE owner_id=?3) AND (?10=0 OR (?10=1 AND EXISTS (SELECT 1 FROM access_grants WHERE owner_id=?2 AND grantee_id=?3 AND revoked_at IS NULL)) OR (?10=2 AND EXISTS (SELECT 1 FROM sharing_contacts WHERE owner_id=?2 AND contact_id=?3 AND removed_at IS NULL))) ON CONFLICT(owner_id,grantee_id) DO UPDATE SET mode=excluded.mode,can_delegate=excluded.can_delegate,created_at=excluded.created_at,write_nonce=excluded.write_nonce,granted_at=CASE WHEN access_grants.revoked_at IS NOT NULL OR (access_grants.can_delegate=0 AND excluded.can_delegate=1) THEN excluded.granted_at ELSE access_grants.granted_at END,revoked_at=NULL`)
        .bind(nonce, v.ownerId, granteeId, mode, canDelegate ? 1 : 0, ...g, existingOnly),
      this.db.prepare('DELETE FROM access_grant_entries WHERE grant_id=(SELECT grant_id FROM access_grants WHERE owner_id=?1 AND grantee_id=?2 AND write_nonce=?7) AND ' + guarded(2, v.kind)).bind(v.ownerId, granteeId, ...g, nonce),
      ...list.map(e => this.db.prepare('INSERT INTO access_grant_entries (grant_id,entry_id) SELECT g.grant_id,e.entry_id FROM access_grants g JOIN entries e ON e.owner_id=g.owner_id AND e.entry_id=?3 WHERE g.owner_id=?1 AND g.grantee_id=?2 AND g.write_nonce=?8 AND ' + guarded(3, v.kind)).bind(v.ownerId, granteeId, e, ...g, nonce)),
      this.db.prepare('INSERT INTO tx_assert SELECT CASE WHEN ' + guarded(3, v.kind) + ' AND (SELECT count(*) FROM access_grant_entries WHERE grant_id=(SELECT grant_id FROM access_grants WHERE owner_id=?1 AND grantee_id=?2 AND revoked_at IS NULL))=?3 AND (SELECT write_nonce FROM access_grants WHERE owner_id=?1 AND grantee_id=?2 AND revoked_at IS NULL)=?8 THEN 1 ELSE 0 END').bind(v.ownerId, granteeId, list.length, ...g, nonce)]);
    if (results) return true;
    if (!await this.#live(v, now)) return false;
    if (existingOnly === 2 && !await this.db.prepare('SELECT 1 AS x FROM sharing_contacts WHERE owner_id=?1 AND contact_id=?2 AND removed_at IS NULL').bind(v.ownerId, granteeId).first()) return false;
    if (existingOnly === 1 && !await this.db.prepare('SELECT 1 AS x FROM access_grants WHERE owner_id=?1 AND grantee_id=?2 AND revoked_at IS NULL').bind(v.ownerId, granteeId).first()) return false;
    throw new TypeError('Entries must belong to the owner');
  }
  async revokeGrant(viewer, granteeId, now = Date.now()) {
    const v = viewerOf(viewer);
    const r = await this.db.prepare('UPDATE access_grants SET revoked_at=COALESCE(revoked_at,?3) WHERE owner_id=?1 AND grantee_id=?2 AND revoked_at IS NULL AND ' + guarded(3, v.kind)).bind(v.ownerId, id(granteeId), now, ...guardArgs(v, now)).run();
    return r.meta.changes >= 1;
  }

  // ---- invitation links ----
  // Owner creates; nothing is granted until a signed-in different account accepts. Returns the raw token once.
  async createInvite(viewer, { mode, entryIds = [], canDelegate = false }, ttlMs, now = Date.now()) {
    const v = viewerOf(viewer);
    if (typeof canDelegate !== 'boolean' || !Number.isSafeInteger(ttlMs) || ttlMs < 60000 || ttlMs > 7 * 86400000 || !Number.isSafeInteger(now)) throw new TypeError('Explicit delegation flag, bounded lifetime and clock required');
    const list = selector(mode, entryIds), t = generateAccessToken(), g = guardArgs(v, now);
    const results = await this.#atomic([
      // At most 20 open invites per owner.
      this.db.prepare('INSERT INTO access_invites (invite_id,token_digest,owner_id,mode,can_delegate,created_at,expires_at) SELECT ?1,?2,?3,?4,?5,?6,?7 WHERE (SELECT count(*) FROM access_invites WHERE owner_id=?3 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>?6)<20 AND ' + guarded(7, v.kind)).bind(t.tokenId, Array.from(await digestSecret(t.secret)), v.ownerId, mode, canDelegate ? 1 : 0, now, now + ttlMs, ...g),
      ...list.map(e => this.db.prepare('INSERT INTO access_invite_entries (invite_id,entry_id) SELECT i.invite_id,e.entry_id FROM access_invites i JOIN entries e ON e.owner_id=i.owner_id AND e.entry_id=?3 WHERE i.invite_id=?1 AND i.owner_id=?2 AND ' + guarded(3, v.kind)).bind(t.tokenId, v.ownerId, e, ...g)),
      this.db.prepare('INSERT INTO tx_assert SELECT CASE WHEN ' + guarded(3, v.kind) + ' AND EXISTS (SELECT 1 FROM access_invites WHERE invite_id=?1 AND owner_id=?2) AND (SELECT count(*) FROM access_invite_entries WHERE invite_id=?1)=?3 THEN 1 ELSE 0 END').bind(t.tokenId, v.ownerId, list.length, ...g)]);
    if (results) return { token: t.token, inviteId: t.tokenId, expiresAt: now + ttlMs };
    if (!await this.#live(v, now)) return undefined;
    const open = await this.db.prepare('SELECT count(*) AS n FROM access_invites WHERE owner_id=?1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>?2').bind(v.ownerId, now).first();
    if (open.n >= 20) return undefined;
    throw new TypeError('Entries must belong to the owner');
  }
  async revokeInvite(viewer, inviteId, now = Date.now()) {
    const v = viewerOf(viewer);
    const r = await this.db.prepare('UPDATE access_invites SET revoked_at=COALESCE(revoked_at,?3) WHERE invite_id=?1 AND owner_id=?2 AND accepted_at IS NULL AND ' + guarded(3, v.kind)).bind(id(inviteId), v.ownerId, now, ...guardArgs(v, now)).run();
    return r.meta.changes >= 1;
  }
  // The recipient session must be live; the invite is consumed and the grant written in one batch.
  async acceptInvite(viewer, token, now = Date.now()) {
    const v = viewerOf(viewer);
    const parsed = await opaqueDigest(token); if (!parsed || !Number.isSafeInteger(now)) return undefined;
    const row = await this.db.prepare('SELECT invite_id,token_digest,owner_id,mode,can_delegate FROM access_invites WHERE invite_id=?1').bind(parsed.id).first();
    if (!row || !timingSafeEqual(parsed.digest, new Uint8Array(row.token_digest)) || row.owner_id === v.ownerId) return undefined;
    const g = guardArgs(v, now), digest = Array.from(parsed.digest), nonce = crypto.randomUUID();
    // Every dependent statement is bound to this attempt's unpredictable nonce, written by the consuming UPDATE only.
    // A replay of an already-consumed invite never matches, whatever the clock says.
    const mine = 'i.invite_id=?1 AND i.accepted_by=?2 AND i.accept_nonce=?5 AND i.revoked_at IS NULL';
    const results = await this.#atomic([
      this.db.prepare('UPDATE access_invites SET accepted_by=?2,accepted_at=?3,accept_nonce=?5 WHERE invite_id=?1 AND token_digest=?4 AND accepted_at IS NULL AND accept_nonce IS NULL AND revoked_at IS NULL AND expires_at>?3 AND owner_id<>?2 AND ' + guarded(5, v.kind)).bind(row.invite_id, v.ownerId, now, digest, nonce, ...g),
      this.db.prepare(`INSERT INTO access_grants (grant_id,owner_id,grantee_id,mode,can_delegate,created_at,granted_at,write_nonce) SELECT ?4,i.owner_id,?2,i.mode,i.can_delegate,?3,?3,?5 FROM access_invites i WHERE ${mine} ON CONFLICT(owner_id,grantee_id) DO UPDATE SET mode=excluded.mode,can_delegate=excluded.can_delegate,created_at=excluded.created_at,write_nonce=excluded.write_nonce,granted_at=CASE WHEN access_grants.revoked_at IS NOT NULL OR (access_grants.can_delegate=0 AND excluded.can_delegate=1) THEN excluded.granted_at ELSE access_grants.granted_at END,revoked_at=NULL`).bind(row.invite_id, v.ownerId, now, crypto.randomUUID(), nonce),
      this.db.prepare(`DELETE FROM access_grant_entries WHERE grant_id=(SELECT g.grant_id FROM access_grants g JOIN access_invites i ON i.owner_id=g.owner_id AND g.grantee_id=i.accepted_by WHERE ${mine} AND g.write_nonce=?5)`).bind(row.invite_id, v.ownerId, now, null, nonce),
      this.db.prepare(`INSERT INTO access_grant_entries (grant_id,entry_id) SELECT g.grant_id,n.entry_id FROM access_invites i JOIN access_invite_entries n ON n.invite_id=i.invite_id JOIN entries e ON e.entry_id=n.entry_id AND e.owner_id=i.owner_id JOIN access_grants g ON g.owner_id=i.owner_id AND g.grantee_id=i.accepted_by WHERE ${mine} AND g.write_nonce=?5`).bind(row.invite_id, v.ownerId, now, null, nonce),
      this.db.prepare(`INSERT INTO sharing_contacts (owner_id,contact_id,contact_ref,created_at) SELECT i.owner_id,i.accepted_by,lower(hex(randomblob(16))),?3 FROM access_invites i WHERE ${mine} ON CONFLICT(owner_id,contact_id) DO UPDATE SET removed_at=NULL`).bind(row.invite_id, v.ownerId, now, null, nonce),
      // Consumed by this attempt, session still live, grant carries this attempt's nonce, list copied in full.
      this.db.prepare(`INSERT INTO tx_assert SELECT CASE WHEN ${guarded(5, v.kind)} AND EXISTS (SELECT 1 FROM access_invites i WHERE ${mine}) AND (SELECT write_nonce FROM access_grants WHERE owner_id=?4 AND grantee_id=?2)=?5 AND (SELECT count(*) FROM access_grant_entries WHERE grant_id=(SELECT grant_id FROM access_grants WHERE owner_id=?4 AND grantee_id=?2))=(SELECT count(*) FROM access_invite_entries WHERE invite_id=?1) THEN 1 ELSE 0 END`).bind(row.invite_id, v.ownerId, now, row.owner_id, nonce, ...g)]);
    return results ? { ownerId: row.owner_id, mode: row.mode, canDelegate: row.can_delegate === 1 } : undefined;
  }

  // ---- human recipient read check (shared entries are read-only) ----
  async canHumanRead(actorId, entryId) {
    id(actorId); id(entryId);
    return Boolean(await this.db.prepare('SELECT 1 AS ok FROM entries e WHERE e.entry_id=?2 AND (e.owner_id=?1 OR EXISTS (SELECT 1 FROM entry_readers r WHERE r.entry_id=e.entry_id AND r.recipient_id=?1))').bind(actorId, entryId).first());
  }

  // ---- machine profiles ----
  // A profile is not tied to one owner. Entry lists may name any entry the creator can currently reach
  // (own, or delegated by anyone); reach is re-resolved on every read, so the list never grants anything itself.
  async createProfile(viewer, { name, mode, entryIds = [] }, now = Date.now()) {
    const v = viewerOf(viewer);
    if (typeof name !== 'string' || !name.trim() || name.length > 120 || !Number.isSafeInteger(now)) throw new TypeError('Bounded name and clock required');
    const list = selector(mode, entryIds), profileId = crypto.randomUUID(), g = guardArgs(v, now);
    const results = await this.#atomic([
      this.db.prepare('INSERT INTO machine_profiles (profile_id,creator_id,name,mode,created_at) SELECT ?1,?2,?3,?4,?5 WHERE ' + guarded(5, v.kind)).bind(profileId, v.ownerId, name.trim(), mode, now, ...g),
      ...list.map(e => this.db.prepare('INSERT INTO machine_profile_entries (profile_id,entry_id) SELECT p.profile_id,e.entry_id FROM machine_profiles p JOIN entries e ON e.entry_id=?3 WHERE p.profile_id=?1 AND p.creator_id=?2 AND (e.owner_id=?2 OR EXISTS (SELECT 1 FROM entry_readers r WHERE r.entry_id=e.entry_id AND r.recipient_id=?2 AND r.allow_automation=1)) AND ' + guarded(3, v.kind)).bind(profileId, v.ownerId, e, ...g)),
      this.db.prepare('INSERT INTO tx_assert SELECT CASE WHEN ' + guarded(3, v.kind) + ' AND EXISTS (SELECT 1 FROM machine_profiles WHERE profile_id=?1 AND creator_id=?2) AND (SELECT count(*) FROM machine_profile_entries WHERE profile_id=?1)=?3 THEN 1 ELSE 0 END').bind(profileId, v.ownerId, list.length, ...g)]);
    if (results) return profileId;
    if (!await this.#live(v, now)) return undefined;
    throw new TypeError('Entries must be reachable by the creator');
  }
  async revokeProfile(viewer, profileId, now = Date.now()) {
    const v = viewerOf(viewer), g = guardArgs(v, now);
    const r = await this.db.batch([
      this.db.prepare('UPDATE machine_profiles SET revoked_at=COALESCE(revoked_at,?3) WHERE profile_id=?1 AND creator_id=?2 AND ' + guarded(3, v.kind)).bind(id(profileId), v.ownerId, now, ...g),
      this.db.prepare('UPDATE machine_tokens SET revoked_at=COALESCE(revoked_at,?3) WHERE profile_id=?1 AND EXISTS (SELECT 1 FROM machine_profiles WHERE profile_id=?1 AND creator_id=?2) AND ' + guarded(3, v.kind)).bind(profileId, v.ownerId, now, ...g)]);
    return r[0].meta.changes >= 1;
  }
  // Owner-only management view of the caller's OWN profiles and token metadata. Never returns a secret or digest, and
  // nothing here reads a code. Requires the live session.
  async listProfiles(viewer, now = Date.now()) {
    const v = viewerOf(viewer), g = guardArgs(v, now);
    const [ps, ts, es] = await Promise.all([
      this.db.prepare('SELECT p.profile_id,p.name,p.mode,p.created_at,p.revoked_at FROM machine_profiles p WHERE p.creator_id=?1 AND ' + guarded(0, v.kind) + ' ORDER BY p.created_at DESC,p.profile_id LIMIT 100').bind(...g).all(),
      this.db.prepare('SELECT t.token_id,t.profile_id,t.created_at,t.expires_at,t.revoked_at FROM machine_tokens t JOIN machine_profiles p ON p.profile_id=t.profile_id WHERE p.creator_id=?1 AND ' + guarded(0, v.kind) + ' ORDER BY t.created_at DESC,t.token_id LIMIT 1000').bind(...g).all(),
      this.db.prepare('SELECT n.profile_id,n.entry_id FROM machine_profile_entries n JOIN machine_profiles p ON p.profile_id=n.profile_id WHERE p.creator_id=?1 AND ' + guarded(0, v.kind) + ' ORDER BY n.profile_id,n.entry_id LIMIT 5000').bind(...g).all()]);
    const by = (rows, key) => { const m = new Map(); for (const r of rows.results ?? []) { if (!m.has(r[key])) m.set(r[key], []); m.get(r[key]).push(r); } return m; };
    const tokens = by(ts, 'profile_id'), entries = by(es, 'profile_id');
    return (ps.results ?? []).map(p => ({
      profileId: p.profile_id, name: p.name, mode: p.mode, createdAt: p.created_at, revokedAt: p.revoked_at,
      entryIds: (entries.get(p.profile_id) ?? []).map(r => r.entry_id),
      tokens: (tokens.get(p.profile_id) ?? []).map(t => ({ tokenId: t.token_id, createdAt: t.created_at, expiresAt: t.expires_at, revokedAt: t.revoked_at }))
    }));
  }
  // Revokes one token. The profile and its other tokens are untouched.
  async revokeToken(viewer, profileId, tokenId, now = Date.now()) {
    const v = viewerOf(viewer), g = guardArgs(v, now);
    const r = await this.db.prepare('UPDATE machine_tokens SET revoked_at=COALESCE(revoked_at,?7) WHERE token_id=?5 AND profile_id=?6 AND EXISTS (SELECT 1 FROM machine_profiles p WHERE p.profile_id=?6 AND p.creator_id=?1) AND ' + guarded(0, v.kind)).bind(...g, id(tokenId), id(profileId), now).run();
    return r.meta.changes >= 1;
  }
  // Entries a machine profile of this viewer may name: their own, plus entries delegated to them with machine
  // permission. Names only, no codes and no other owner's identity.
  async listMachineEntries(viewer, now = Date.now()) {
    const v = viewerOf(viewer), g = guardArgs(v, now);
    const r = await this.db.prepare('SELECT e.entry_id,e.label,e.account_name,e.service_id,CASE WHEN e.owner_id=?1 THEN 1 ELSE 0 END AS owned FROM entries e WHERE (e.owner_id=?1 OR EXISTS (SELECT 1 FROM entry_readers r WHERE r.entry_id=e.entry_id AND r.recipient_id=?1 AND r.allow_automation=1)) AND ' + guarded(0, v.kind) + ' ORDER BY owned DESC,e.label,e.entry_id LIMIT 500').bind(...g).all();
    return (r.results ?? []).map(x => ({ entryId: x.entry_id, label: x.label, account: x.account_name ?? '', serviceId: x.service_id, owned: x.owned === 1 }));
  }
  async mintToken(viewer, profileId, ttlMs, now = Date.now()) {
    const v = viewerOf(viewer);
    if (ttlMs !== null && (!Number.isSafeInteger(ttlMs) || ttlMs < 1 || ttlMs > MAX_TOKEN_TTL_MS) || !Number.isSafeInteger(now)) throw new TypeError('Explicit expiry required: a lifetime or null for never');
    const t = generateAccessToken();
    const r = await this.db.prepare('INSERT INTO machine_tokens (token_id,token_digest,profile_id,created_at,expires_at) SELECT ?1,?2,p.profile_id,?3,?4 FROM machine_profiles p WHERE p.profile_id=?5 AND p.creator_id=?6 AND p.revoked_at IS NULL AND ' + guarded(6, v.kind)).bind(t.tokenId, Array.from(await digestSecret(t.secret)), now, ttlMs === null ? null : now + ttlMs, id(profileId), v.ownerId, ...guardArgs(v, now)).run();
    return r.meta.changes >= 1 ? { token: t.token, tokenId: t.tokenId, profileId, expiresAt: ttlMs === null ? null : now + ttlMs } : undefined;
  }
  async verifyToken(token, now = Date.now()) {
    const parsed = await opaqueDigest(token); if (!parsed) return undefined;
    const row = await this.db.prepare('SELECT t.token_digest,t.profile_id,t.created_at,t.expires_at,t.revoked_at,p.revoked_at AS profile_revoked FROM machine_tokens t JOIN machine_profiles p ON p.profile_id=t.profile_id WHERE t.token_id=?1').bind(parsed.id).first();
    if (!row || row.revoked_at !== null || row.profile_revoked !== null || (row.expires_at !== null && row.expires_at <= now) || !timingSafeEqual(parsed.digest, new Uint8Array(row.token_digest))) return undefined;
    return { profileId: row.profile_id, issuedAt: row.created_at };
  }
  // Effective access = entry reachable by the creator through own ownership or a live delegating path that
  // predates the token, AND the profile selector. Returns the entry owner, or undefined.
  async canMachineRead(profileId, entryId, issuedAt) {
    id(profileId); id(entryId);
    if (!Number.isSafeInteger(issuedAt)) throw new TypeError('Token issue time required');
    const row = await this.db.prepare(`SELECT e.owner_id FROM machine_profiles p JOIN entries e ON e.entry_id=?2 WHERE p.profile_id=?1 AND p.revoked_at IS NULL AND (e.owner_id=p.creator_id OR EXISTS (SELECT 1 FROM entry_readers r WHERE r.entry_id=e.entry_id AND r.recipient_id=p.creator_id AND r.allow_automation=1 AND r.created_at<=?3)) AND ${covers('p', 'machine_profile_entries', 'profile_id', '?2')}`).bind(profileId, entryId, issuedAt).first();
    return row?.owner_id;
  }
}

// One entry, requested source kinds, newest unexpired code per kind. Always
// authorized live before and after decryption.
export class MachineReader {
  constructor({ access, sources, seeds, clock = Date.now }) { this.clock = clock; this.access = access; this.sources = sources; this.seeds = seeds; this.db = access.db; }
  async read(profileId, issuedAt, entryId, kind, nowMs) {
    if (!Object.hasOwn(KINDS, kind) || !Number.isSafeInteger(nowMs) || nowMs < 0) throw new TypeError('Valid source kind and clock required');
    const owner = await this.access.canMachineRead(profileId, entryId, issuedAt);
    if (!owner) return undefined;
    const out = {};
    for (const k of KINDS[kind]) {
      const r = k === 'totp' ? await this.#totp(profileId, issuedAt, owner, entryId, nowMs) : await this.#delivered(profileId, issuedAt, owner, entryId, k, nowMs);
      if (r) out[k] = r;
    }
    if (!await this.access.canMachineRead(profileId, entryId, issuedAt)) return undefined;
    for (const v of Object.values(out)) if (!(this.clock() < (v.expiresAt ?? v.validUntil * 1000))) return undefined;
    return Object.keys(out).length ? { entryId, codes: out } : undefined;
  }
  async #totp(profileId, issuedAt, owner, entryId, nowMs) {
    const adapter = { canRead: async (_a, e) => (await this.access.canMachineRead(profileId, e, issuedAt)) === owner };
    const r = await new EntryTotpGenerator(this.db, this.seeds, adapter).generateForActor(owner, entryId, Math.floor(nowMs / 1000));
    return r && this.clock() < r.validUntil * 1000 ? { code: r.code, validFrom: r.validFrom, validUntil: r.validUntil } : undefined;
  }
  async #delivered(profileId, issuedAt, owner, entryId, kind, nowMs) {
    const marks = SOURCE_KINDS[kind].map((_, i) => `?${i + 4}`).join(',');
    const row = await this.db.prepare(`SELECT c.event_id,c.source_id,c.envelope,c.received_at,c.expires_at FROM incoming_codes c JOIN sources s ON s.source_id=c.source_id AND s.owner_id=c.owner_id WHERE c.owner_id=?1 AND c.entry_id=?2 AND c.received_at<=?3 AND c.expires_at>?3 AND s.revoked_at IS NULL AND s.kind IN (${marks}) ORDER BY c.received_at DESC,c.event_id DESC LIMIT 1`).bind(owner, entryId, nowMs, ...SOURCE_KINDS[kind]).first();
    if (!row) return undefined;
    const code = await this.sources.cipher.decrypt(JSON.parse(row.envelope), { ownerId: owner, recordId: await hashText(JSON.stringify([row.source_id, row.event_id])), serviceId: entryId, receivedAt: row.received_at, expiresAt: row.expires_at });
    const current = await this.db.prepare('SELECT 1 AS x FROM incoming_codes c JOIN sources s ON s.source_id=c.source_id AND s.owner_id=c.owner_id WHERE c.owner_id=?1 AND c.source_id=?2 AND c.event_id=?3 AND c.entry_id=?4 AND c.envelope=?5 AND s.revoked_at IS NULL').bind(owner, row.source_id, row.event_id, entryId, row.envelope).first();
    return current && this.clock() < row.expires_at ? { code, receivedAt: row.received_at, expiresAt: row.expires_at } : undefined;
  }
}

// GET /v1/machine/code?entry=<id>&source=totp|email|sms|all  (exactly those two params).
// No listing, no multi-entry, no history. Unknown and unauthorized entries look identical.
export function createMachineHandler({ access, reader, clock = Date.now, limit = 60 }) {
  return { async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname !== '/v1/machine/code' || request.method !== 'GET') return json({ error: 'not_found' }, 404);
    const grant = await access.verifyToken(bearerToken(request.headers.get('authorization')), clock());
    if (!grant) return unauthorized();
    const p = url.searchParams, keys = [...p.keys()].sort().join(',');
    const entry = p.getAll('entry'), source = p.getAll('source');
    if (keys !== 'entry,source' || entry.length !== 1 || source.length !== 1 || !entry[0] || entry[0].length > 256 || !Object.hasOwn(KINDS, source[0])) return json({ error: 'bad_request' }, 400);
    const rate = await takeRateLimit(access.db, 'machine:' + grant.profileId, { now: clock(), limit });
    if (!rate.allowed) return json({ error: 'rate_limited' }, 429, { 'Retry-After': String(rate.retryAfter), 'Cache-Control': 'no-store' });
    const now = clock();
    const result = await reader.read(grant.profileId, grant.issuedAt, entry[0], source[0], now);
    if (!result || !await access.verifyToken(bearerToken(request.headers.get('authorization')), clock())) return result ? unauthorized() : json({ error: 'not_found' }, 404);
    return new Response(JSON.stringify(result), { status: 200, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
  } };
}
