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
  async revokeSource(ownerId,sourceId,now){
    [ownerId,sourceId].forEach(id);if(!Number.isSafeInteger(now)||now<0)throw new TypeError('Valid clock required');
    const result=await this.db.prepare('UPDATE sources SET revoked_at=COALESCE(revoked_at,?1) WHERE owner_id=?2 AND source_id=?3').bind(now,ownerId,sourceId).run();
    return result.meta.changes>=1;
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
    return {inserted:r.meta.changes>=1,entryId};
  }
  async confirm(ownerId, sourceId, eventId, entryId, now=Date.now()) {
    if(!Number.isSafeInteger(now)||now<0)throw new TypeError('Valid clock required');
    // Explicit owner confirmation only, no source/entry ownership inferred.
    [ownerId,sourceId,eventId,entryId].forEach(id);
    const row=await this.db.prepare('SELECT c.envelope,c.received_at,c.expires_at FROM incoming_codes c JOIN sources s ON s.source_id=c.source_id AND s.owner_id=c.owner_id WHERE c.owner_id = ?1 AND c.source_id = ?2 AND c.event_id = ?3 AND c.entry_id IS NULL AND c.received_at<=?4 AND c.expires_at>?4 AND s.revoked_at IS NULL').bind(ownerId,sourceId,eventId,now).first();
    const entry=await this.db.prepare('SELECT entry_id FROM entries WHERE owner_id = ?1 AND entry_id = ?2').bind(ownerId,entryId).first();
    if(!row||!entry)return false;
    const context={ownerId,recordId:await hashText(JSON.stringify([sourceId,eventId])),serviceId:'unassigned',receivedAt:row.received_at,expiresAt:row.expires_at};
    const code=await this.cipher.decrypt(JSON.parse(row.envelope),context);
    const envelope=await this.cipher.encrypt(code,{...context,serviceId:entryId});
    const r=await this.db.prepare("UPDATE incoming_codes SET entry_id = ?1, assignment = 'confirmed', envelope = ?2 WHERE owner_id = ?3 AND source_id = ?4 AND event_id = ?5 AND entry_id IS NULL AND envelope = ?6 AND received_at<=?7 AND expires_at>?7 AND EXISTS (SELECT 1 FROM sources WHERE owner_id=?3 AND source_id=?4 AND revoked_at IS NULL) AND EXISTS (SELECT 1 FROM entries WHERE owner_id = ?3 AND entry_id = ?1)").bind(entryId,JSON.stringify(envelope),ownerId,sourceId,eventId,row.envelope,now).run();
    return r.meta.changes>=1;
  }

  // Owner-private review surface. Never return source labels, sender metadata,
  // raw envelopes or messages. A bounded active-only page limits decrypt work.
  async unassignedForOwner(ownerId, now) {
    id(ownerId);if(!Number.isSafeInteger(now)||now<0)throw new TypeError('Valid clock required');
    const rows=(await this.db.prepare('SELECT c.source_id,c.event_id,c.envelope,c.received_at,c.expires_at FROM incoming_codes c JOIN sources s ON s.source_id=c.source_id AND s.owner_id=c.owner_id WHERE c.owner_id=?1 AND c.entry_id IS NULL AND c.received_at<=?2 AND c.expires_at>?2 AND s.revoked_at IS NULL ORDER BY c.received_at DESC,c.event_id DESC LIMIT 20').bind(ownerId,now).all()).results;
    const decoded=[];
    for(const row of rows){
      const code=await this.cipher.decrypt(JSON.parse(row.envelope),{ownerId,recordId:await hashText(JSON.stringify([row.source_id,row.event_id])),serviceId:'unassigned',receivedAt:row.received_at,expiresAt:row.expires_at});
      decoded.push({row,code});
    }
    const result=[];
    for(const {row,code} of decoded){
      // Validate after every decrypt is complete: later decrypt work can race
      // revocation/assignment of an earlier record in this response too.
      const current=await this.db.prepare('SELECT c.event_id FROM incoming_codes c JOIN sources s ON s.source_id=c.source_id AND s.owner_id=c.owner_id WHERE c.owner_id=?1 AND c.source_id=?2 AND c.event_id=?3 AND c.entry_id IS NULL AND c.envelope=?4 AND s.revoked_at IS NULL').bind(ownerId,row.source_id,row.event_id,row.envelope).first();
      if(current)result.push({sourceId:row.source_id,eventId:row.event_id,code,receivedAt:row.received_at,expiresAt:row.expires_at});
    }
    return result;
  }

  // Bounded session feed. Decrypt first, then validate each exact envelope,
  // source and current entry permission. At most 21 DB queries for 20 codes.
  async activeForActor(actorId,now){
    id(actorId);if(!Number.isSafeInteger(now)||now<0)throw new TypeError('Valid clock required');
    const permitted='(e.owner_id=?1 OR EXISTS (SELECT 1 FROM entry_readers m WHERE m.entry_id=e.entry_id AND m.recipient_id=?1 AND m.revoked_at IS NULL))';
    const rows=(await this.db.prepare(`SELECT * FROM (SELECT c.owner_id,c.entry_id,c.source_id,c.event_id,c.envelope,c.received_at,c.expires_at,ROW_NUMBER() OVER (PARTITION BY c.entry_id ORDER BY c.received_at DESC,c.event_id DESC) AS position FROM incoming_codes c JOIN entries e ON e.entry_id=c.entry_id AND e.owner_id=c.owner_id JOIN sources s ON s.source_id=c.source_id AND s.owner_id=c.owner_id WHERE c.received_at<=?2 AND c.expires_at>?2 AND s.revoked_at IS NULL AND ${permitted}) WHERE position=1 ORDER BY received_at DESC,entry_id LIMIT 20`).bind(actorId,now).all()).results;
    const decoded=[];
    for(const row of rows){const code=await this.cipher.decrypt(JSON.parse(row.envelope),{ownerId:row.owner_id,recordId:await hashText(JSON.stringify([row.source_id,row.event_id])),serviceId:row.entry_id,receivedAt:row.received_at,expiresAt:row.expires_at});decoded.push({row,code});}
    const records=[];
    for(const {row,code} of decoded){const current=await this.db.prepare(`SELECT c.event_id FROM incoming_codes c JOIN entries e ON e.entry_id=c.entry_id AND e.owner_id=c.owner_id JOIN sources s ON s.source_id=c.source_id AND s.owner_id=c.owner_id WHERE c.owner_id=?2 AND c.source_id=?3 AND c.event_id=?4 AND c.entry_id=?5 AND c.envelope=?6 AND s.revoked_at IS NULL AND ${permitted}`).bind(actorId,row.owner_id,row.source_id,row.event_id,row.entry_id,row.envelope).first();if(current)records.push({entryId:row.entry_id,code,receivedAt:row.received_at,expiresAt:row.expires_at});}
    return records;
  }

  async latestOwned(ownerId, entryId, now) {
    if(!Number.isSafeInteger(now)||now<0)throw new TypeError('Valid clock required');
    const row=await this.db.prepare('SELECT c.event_id,c.source_id,c.envelope,c.received_at,c.expires_at FROM incoming_codes c JOIN entries e ON e.owner_id = c.owner_id AND e.entry_id = c.entry_id JOIN sources s ON s.source_id=c.source_id AND s.owner_id=c.owner_id WHERE c.owner_id = ?1 AND c.entry_id = ?2 AND c.received_at <= ?3 AND c.expires_at > ?3 AND s.revoked_at IS NULL ORDER BY c.received_at DESC, c.event_id DESC LIMIT 1').bind(id(ownerId),id(entryId),now).first();
    if(!row)return undefined;
    const code=await this.cipher.decrypt(JSON.parse(row.envelope),{ownerId,recordId:await hashText(JSON.stringify([row.source_id,row.event_id])),serviceId:entryId,receivedAt:row.received_at,expiresAt:row.expires_at});
    const current=await this.db.prepare('SELECT c.event_id FROM incoming_codes c JOIN sources s ON s.source_id=c.source_id AND s.owner_id=c.owner_id WHERE c.owner_id=?1 AND c.source_id=?2 AND c.event_id=?3 AND c.entry_id=?4 AND c.envelope=?5 AND s.revoked_at IS NULL').bind(ownerId,row.source_id,row.event_id,entryId,row.envelope).first();
    return current?{code,entryId,receivedAt:row.received_at,expiresAt:row.expires_at}:undefined;
  }
}
