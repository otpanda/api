import { hashText } from './sessions.js';
// Multi-source ownership and explicit assignment. This module does not fetch
// messages, authenticate provider senders, expose source details or share codes.
function id(value) {
  if (typeof value !== 'string' || !value || value.length > 256) throw new TypeError('Bounded identifier required');
  return value;
}
function label(value) {
  if (typeof value !== 'string' || !value.trim() || value.length > 120) throw new TypeError('Bounded label required');
  return value;
}
export class SourceEntryStore {
  constructor(db, cipher, { matcher } = {}) { this.db=db; this.cipher=cipher; this.matcher=matcher; }
  async createSource(ownerId, kind, name, now) {
    if(!['gmail','outlook','sms'].includes(kind))throw new TypeError('Unsupported source kind');
    const sourceId=crypto.randomUUID();
    await this.db.prepare('INSERT INTO sources (source_id, owner_id, kind, label, created_at) VALUES (?1,?2,?3,?4,?5)').bind(sourceId,id(ownerId),kind,label(name),now).run();
    return sourceId;
  }
  async createEntry(ownerId, serviceId, name, now, {accountName=null}={}) {
    const entryId=crypto.randomUUID();
    // Unknown services work immediately. The generic display name is the
    // service identifier, never a caller-controlled overwrite of a catalog.
    [ownerId,serviceId].forEach(id); label(name);
    if(accountName!==null)label(accountName);
    await this.db.batch([
      this.db.prepare('INSERT INTO services (service_id,name) VALUES (?1,?1) ON CONFLICT(service_id) DO NOTHING').bind(serviceId),
      this.db.prepare('INSERT INTO entries (entry_id, owner_id, service_id, label, created_at, account_name) VALUES (?1,?2,?3,?4,?5,?6)').bind(entryId,ownerId,serviceId,name,now,accountName),
    ]);
    return entryId;
  }
  async sourcesForOwner(ownerId) {
    return (await this.db.prepare('SELECT source_id, kind, label, created_at, revoked_at FROM sources WHERE owner_id = ?1 ORDER BY source_id LIMIT 100').bind(id(ownerId)).all()).results;
  }
  async entriesForOwner(ownerId) {
    return (await this.db.prepare('SELECT entry_id, service_id, label, created_at FROM entries WHERE owner_id = ?1 ORDER BY entry_id LIMIT 100').bind(id(ownerId)).all()).results;
  }
  async addRule(ownerId, {sourceId,entryId,sender,accountHint}, now) {
    // Internal exact-match adapter only. A public rule editor/matching syntax
    // has not been selected. Empty discriminators never match every message.
    const ruleId=crypto.randomUUID();
    await this.db.prepare('INSERT INTO assignment_rules (rule_id, owner_id, source_id, entry_id, sender, account_hint, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7)').bind(ruleId,id(ownerId),id(sourceId),id(entryId),id(sender),id(accountHint),now).run();
    return ruleId;
  }
  async receive(ownerId, {sourceId,eventId,code,receivedAt,expiresAt,sender,receiver,accountHint}) {
    [ownerId,sourceId,eventId].forEach(id);
    if(typeof code!=='string' || !/^[A-Za-z0-9-]{4,32}$/.test(code) || !Number.isSafeInteger(receivedAt) || receivedAt<0 || !Number.isSafeInteger(expiresAt) || expiresAt<=receivedAt || expiresAt-receivedAt>86400000)throw new TypeError('Bounded code lifetime required');
    const source=await this.db.prepare('SELECT source_id FROM sources WHERE owner_id = ?1 AND source_id = ?2 AND revoked_at IS NULL').bind(ownerId,sourceId).first();
    if(!source)throw new Error('Source unavailable');
    let matches=[];
    if(this.matcher) {
      const matched=await this.matcher.match(ownerId,{sourceId,receiver,sender,accountHint});
      if(matched.entryId)matches=[{entry_id:matched.entryId}];
    } else if(typeof sender==='string' && sender.length>0 && sender.length<=256 && typeof accountHint==='string' && accountHint.length>0 && accountHint.length<=256) {
      matches=(await this.db.prepare('SELECT DISTINCT entry_id FROM assignment_rules WHERE owner_id = ?1 AND source_id = ?2 AND sender = ?3 AND account_hint = ?4 LIMIT 2').bind(ownerId,sourceId,sender,accountHint).all()).results;
    }
    // A tie between entries is not a ranking problem. Keep it private and
    // unassigned. Duplicate rules for the same entry do not create ambiguity.
    const entryId=matches.length===1?matches[0].entry_id:null;
    const context={ownerId,recordId:await hashText(JSON.stringify([sourceId,eventId])),serviceId:entryId ?? 'unassigned',receivedAt,expiresAt};
    const envelope=await this.cipher.encrypt(code,context);
    const r=await this.db.prepare('INSERT INTO incoming_codes (owner_id,event_id,source_id,entry_id,envelope,received_at,expires_at,assignment) SELECT ?1,?2,?3,?4,?5,?6,?7,?8 WHERE EXISTS (SELECT 1 FROM sources WHERE owner_id = ?1 AND source_id = ?3 AND revoked_at IS NULL) ON CONFLICT(owner_id,source_id,event_id) DO NOTHING').bind(ownerId,eventId,sourceId,entryId,JSON.stringify(envelope),receivedAt,expiresAt,entryId?'rule':'unassigned').run();
    return {inserted:r.meta.changes===1,entryId};
  }
  async confirm(ownerId, sourceId, eventId, entryId) {
    // Explicit owner confirmation only, no source/entry ownership inferred.
    [ownerId,sourceId,eventId,entryId].forEach(id);
    const row=await this.db.prepare('SELECT envelope,received_at,expires_at FROM incoming_codes WHERE owner_id = ?1 AND source_id = ?2 AND event_id = ?3 AND entry_id IS NULL').bind(ownerId,sourceId,eventId).first();
    const entry=await this.db.prepare('SELECT entry_id FROM entries WHERE owner_id = ?1 AND entry_id = ?2').bind(ownerId,entryId).first();
    if(!row||!entry)return false;
    const context={ownerId,recordId:await hashText(JSON.stringify([sourceId,eventId])),serviceId:'unassigned',receivedAt:row.received_at,expiresAt:row.expires_at};
    const code=await this.cipher.decrypt(JSON.parse(row.envelope),context);
    const envelope=await this.cipher.encrypt(code,{...context,serviceId:entryId});
    const r=await this.db.prepare("UPDATE incoming_codes SET entry_id = ?1, assignment = 'confirmed', envelope = ?2 WHERE owner_id = ?3 AND source_id = ?4 AND event_id = ?5 AND entry_id IS NULL AND envelope = ?6 AND EXISTS (SELECT 1 FROM entries WHERE owner_id = ?3 AND entry_id = ?1)").bind(entryId,JSON.stringify(envelope),ownerId,sourceId,eventId,row.envelope).run();
    return r.meta.changes===1;
  }

  // Owner-private review surface. Never return source labels, sender metadata,
  // raw envelopes or messages. A bounded active-only page limits decrypt work.
  async unassignedForOwner(ownerId, now) {
    id(ownerId);if(!Number.isSafeInteger(now)||now<0)throw new TypeError('Valid clock required');
    const rows=(await this.db.prepare('SELECT c.source_id,c.event_id,c.envelope,c.received_at,c.expires_at FROM incoming_codes c JOIN sources s ON s.source_id=c.source_id AND s.owner_id=c.owner_id WHERE c.owner_id=?1 AND c.entry_id IS NULL AND c.received_at<=?2 AND c.expires_at>?2 AND s.revoked_at IS NULL ORDER BY c.received_at DESC,c.event_id DESC LIMIT 20').bind(ownerId,now).all()).results;
    const result=[];
    for(const row of rows){
      const code=await this.cipher.decrypt(JSON.parse(row.envelope),{ownerId,recordId:await hashText(JSON.stringify([row.source_id,row.event_id])),serviceId:'unassigned',receivedAt:row.received_at,expiresAt:row.expires_at});
      // A concurrent assignment or source revocation must remove it from this
      // private review response rather than return stale assignment context.
      const current=await this.db.prepare('SELECT c.event_id FROM incoming_codes c JOIN sources s ON s.source_id=c.source_id AND s.owner_id=c.owner_id WHERE c.owner_id=?1 AND c.source_id=?2 AND c.event_id=?3 AND c.entry_id IS NULL AND c.envelope=?4 AND s.revoked_at IS NULL').bind(ownerId,row.source_id,row.event_id,row.envelope).first();
      if(current)result.push({sourceId:row.source_id,eventId:row.event_id,code,receivedAt:row.received_at,expiresAt:row.expires_at});
    }
    return result;
  }

  async latestOwned(ownerId, entryId, now) {
    if(!Number.isSafeInteger(now)||now<0)throw new TypeError('Valid clock required');
    const row=await this.db.prepare('SELECT c.event_id,c.source_id,c.envelope,c.received_at,c.expires_at FROM incoming_codes c JOIN entries e ON e.owner_id = c.owner_id AND e.entry_id = c.entry_id WHERE c.owner_id = ?1 AND c.entry_id = ?2 AND c.received_at <= ?3 AND c.expires_at > ?3 ORDER BY c.received_at DESC, c.event_id DESC LIMIT 1').bind(id(ownerId),id(entryId),now).first();
    if(!row)return undefined;
    const code=await this.cipher.decrypt(JSON.parse(row.envelope),{ownerId,recordId:await hashText(JSON.stringify([row.source_id,row.event_id])),serviceId:entryId,receivedAt:row.received_at,expiresAt:row.expires_at});
    return {code,entryId,receivedAt:row.received_at,expiresAt:row.expires_at};
  }
}
