// Authorization always consults current ownership and membership. A token
// must never cache a sharing decision, including allow_automation.
export class EntryAccess {
  constructor(db, sourceEntries) { this.db=db; this.store=sourceEntries; }
  async owner(entryId) {
    return (await this.db.prepare('SELECT owner_id FROM entries WHERE entry_id = ?1').bind(entryId).first())?.owner_id;
  }
  async share(actorId, entryId, recipientId, {allowAutomation=false}={}, now=Date.now()) {
    if(typeof allowAutomation!=='boolean' || actorId===recipientId)throw new TypeError('Explicit recipient and automation permission required');
    const statements=[this.db.prepare('INSERT INTO entry_shares (entry_id,recipient_id,allow_automation,created_at,revoked_at) SELECT ?1,?2,?3,?4,NULL WHERE EXISTS (SELECT 1 FROM entries WHERE entry_id = ?1 AND owner_id = ?5) ON CONFLICT(entry_id,recipient_id) DO UPDATE SET allow_automation=excluded.allow_automation, created_at=excluded.created_at, revoked_at=NULL').bind(entryId,recipientId,allowAutomation?1:0,now,actorId)];
    if(!allowAutomation)statements.push(this.db.prepare('UPDATE entry_tokens SET revoked_at = COALESCE(revoked_at,?1) WHERE entry_id = ?2 AND actor_id = ?3 AND EXISTS (SELECT 1 FROM entries WHERE entry_id = ?2 AND owner_id = ?4)').bind(now,entryId,recipientId,actorId));
    const results=await this.db.batch(statements);
    return results[0].meta.changes>=1;
  }
  async revoke(actorId,entryId,recipientId,now=Date.now()) {
    const results=await this.db.batch([
      this.db.prepare('UPDATE entry_shares SET revoked_at = COALESCE(revoked_at,?1) WHERE entry_id = ?2 AND recipient_id = ?3 AND EXISTS (SELECT 1 FROM entries WHERE entry_id = ?2 AND owner_id = ?4)').bind(now,entryId,recipientId,actorId),
      this.db.prepare('UPDATE entry_tokens SET revoked_at = COALESCE(revoked_at,?1) WHERE entry_id = ?2 AND actor_id = ?3 AND EXISTS (SELECT 1 FROM entries WHERE entry_id = ?2 AND owner_id = ?4)').bind(now,entryId,recipientId,actorId),
    ]);
    return results[0].meta.changes>=1;
  }
  async canRead(actorId,entryId,{automation=false}={}) {
    const owner=await this.owner(entryId);
    if(!owner)return false;
    if(owner===actorId)return true;
    // Canonical policy: legacy per-entry shares and account grants are both rows of entry_readers.
    const row=await this.db.prepare('SELECT 1 AS ok FROM entry_readers WHERE entry_id = ?1 AND recipient_id = ?2 AND (?3 = 0 OR allow_automation = 1) LIMIT 1').bind(entryId,actorId,automation?1:0).first();
    return Boolean(row);
  }
  async latest(actorId,entryId,now,{automation=false}={}) {
    if(!await this.canRead(actorId,entryId,{automation}))return undefined;
    const owner=await this.owner(entryId);
    const result=await this.store.latestOwned(owner,entryId,now);
    // Re-check after async decrypt so a concurrent revocation during the
    // read cannot return a code based solely on stale membership state.
    if(!await this.canRead(actorId,entryId,{automation}))return undefined;
    return result;
  }
  async activeRecent(actorId,now){return this.store.activeForActor(actorId,now);}
  async updateEntry(actorId,entryId,label) {
    if(typeof label!=='string'||!label.trim()||label.length>120)throw new TypeError('Bounded label required');
    const r=await this.db.prepare('UPDATE entries SET label = ?1 WHERE entry_id = ?2 AND owner_id = ?3').bind(label,entryId,actorId).run();return r.meta.changes>=1;
  }
  async deleteEntry(actorId,entryId) {
    const r=await this.db.prepare('DELETE FROM entries WHERE entry_id = ?1 AND owner_id = ?2').bind(entryId,actorId).run();return r.meta.changes>=1;
  }
}
