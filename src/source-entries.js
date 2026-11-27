import { hashText } from './sessions.js';
import {parseDigestSecret,parseDigestKeys,normalizeTemplate,templateDigest} from './template-fingerprint.js';
import { redactContext } from './context-redaction.js';
export {parseDigestSecret};
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
const DAY=86400000,CONTEXT_MAX={sms:4096,email:1024};
// Victims are found with three index probes combined with UNION ALL, never a table scan and no sort (a single OR, or `<>`, is planned as a full SCAN).
// The arms are DISJOINT, so LIMIT n counts distinct rows: arm 1 is the expired rows, arms 2 and 3 are the other-fingerprint rows that are NOT expired
// (the residual `retain_until > ?1` is checked inside the fingerprint index, which is (key_fingerprint, retain_until), so no table row is read for a non-victim; INDEXED BY pins it because the planner otherwise picks the expiry index and walks every live row). Row reads stay bounded: arms 2 and 3 only run when arm 1 returned fewer
// than n rows, i.e. fewer than n rows are expired, so each arm skips at most n expired rows. Any victims will do, there is no ordering requirement.
export const contextOutstandingSelect=(columns,limit)=>`SELECT ${columns} FROM unassigned_context WHERE retain_until <= ?1 UNION ALL SELECT ${columns} FROM unassigned_context INDEXED BY unassigned_context_fingerprint WHERE key_fingerprint < ?2 AND retain_until > ?1 UNION ALL SELECT ${columns} FROM unassigned_context INDEXED BY unassigned_context_fingerprint WHERE key_fingerprint > ?2 AND retain_until > ?1 LIMIT ${limit}`;
export const CONTEXT_CLEANUP_SQL=`DELETE FROM unassigned_context WHERE rowid IN (${contextOutstandingSelect('rowid',100)})`;
export function createSourceEntryStore(db,cipher,options={},alert=options.contextAlert??(()=>{})){
  options={...options};delete options.contextAlert;
  try{return new SourceEntryStore(db,cipher,options);}
  catch(error){
    if(options.contextRetentionMs==null)throw error;
    try{alert('context-retention-disabled: invalid configuration');}catch{}
    return new SourceEntryStore(db,cipher,{...options,contextRetentionMs:null,contextDigestSecret:null});
  }
}
// Multi-source ownership and explicit assignment. This module does not fetch
// messages, authenticate provider senders, expose source details or share codes.
export class SourceEntryStore {
  #hmacKey;
  constructor(db, cipher, { matcher, templateSecret = null, templateKeyring = null, contextRetentionMs = null, maxContextIdentities = 200, maxContextBytes = 2097152, contextDigestSecret = null, clock = Date.now } = {}) {
    this.db=db; this.cipher=cipher; this.matcher=matcher; this.templateKeys=null; if(templateSecret!==null||templateKeyring!==null){this.templateKeys=parseDigestKeys(templateSecret,templateKeyring);if(!this.templateKeys)throw new TypeError('Template digest secret/keyring must be 32+ random bytes (hex or base64url), keyring ids 4 hex chars');}
    if(contextRetentionMs!==null&&(!Number.isSafeInteger(contextRetentionMs)||contextRetentionMs<DAY||contextRetentionMs>30*DAY))throw new TypeError('Retention must be 1 to 30 days (the approved maximum) or null');
    if(!Number.isSafeInteger(maxContextIdentities)||maxContextIdentities<1||!Number.isSafeInteger(maxContextBytes)||maxContextBytes<8192)throw new TypeError('Valid context caps required');
    if(contextRetentionMs!==null&&!parseDigestSecret(contextDigestSecret))throw new TypeError('A server digest secret of at least 32 random bytes (hex or base64url) is required when context retention is on');
    if(typeof clock!=='function')throw new TypeError('Clock function required');
    this.contextDigestSecret=contextDigestSecret; this.clock=clock; this.#hmacKey=null;
    this.contextRetentionMs=contextRetentionMs; this.maxContextIdentities=maxContextIdentities; this.maxContextBytes=maxContextBytes;
  }
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
  async receive(ownerId, {sourceId,eventId,code,receivedAt,expiresAt,sender,receiver,accountHint,text,subject,context:reviewContext}) {
    [ownerId,sourceId,eventId].forEach(id);
    if(typeof code!=='string' || !/^[A-Za-z0-9-]{4,32}$/.test(code) || !Number.isSafeInteger(receivedAt) || receivedAt<0 || !Number.isSafeInteger(expiresAt) || expiresAt<=receivedAt || expiresAt-receivedAt>86400000)throw new TypeError('Bounded code lifetime required');
    const source=await this.db.prepare('SELECT source_id,kind FROM sources WHERE owner_id = ?1 AND source_id = ?2 AND revoked_at IS NULL').bind(ownerId,sourceId).first();
    if(!source)throw new Error('Source unavailable');
    // Keyed template digest of the code-redacted, digit-free SMS text or email SUBJECT. Computed once here; the text itself is never stored. Off (null) without a secret.
    let templateFp=null,templateFps=null;
    if(this.templateKeys){const kind=source.kind==='sms'?'sms':'email',norm=normalizeTemplate(kind==='sms'?text:subject,{code,kind});if(norm){templateFps=await Promise.all(this.templateKeys.map(k=>templateDigest(k,ownerId,sourceId,norm)));templateFp=templateFps[0];}}
    let matches=[];
    if(this.matcher) {
      const matched=await this.matcher.match(ownerId,{sourceId,receiver,sender,accountHint,text,templateFp,templateFps});
      if(matched.entryId)matches=[{entry_id:matched.entryId}];
    } else if(typeof sender==='string' && sender.length>0 && sender.length<=256 && typeof accountHint==='string' && accountHint.length>0 && accountHint.length<=256) {
      matches=(await this.db.prepare('SELECT DISTINCT entry_id FROM assignment_rules WHERE owner_id = ?1 AND source_id = ?2 AND sender = ?3 AND account_hint = ?4 LIMIT 2').bind(ownerId,sourceId,sender,accountHint).all()).results;
    }
    // A tie between entries is not a ranking problem. Keep it private and
    // unassigned. Duplicate rules for the same entry do not create ambiguity.
    const entryId=matches.length===1?matches[0].entry_id:null;
    const context={ownerId,recordId:await hashText(JSON.stringify([sourceId,eventId])),serviceId:entryId ?? 'unassigned',receivedAt,expiresAt};
    const envelope=await this.cipher.encrypt(code,context);
    // Exact sender (and mailbox hint) kept encrypted with the code row only, so a later Assign can write an exact-sender rule. Never returned by any read.
    let senderEnvelope=null;
    if(typeof sender==='string'&&sender&&sender.length<=256){const hint=typeof accountHint==='string'&&accountHint&&accountHint.length<=256?accountHint:null;senderEnvelope=JSON.stringify(await this.cipher.encrypt(JSON.stringify({sender,accountHint:hint}),{...context,recordId:await hashText(JSON.stringify([sourceId,eventId,'sender'])),serviceId:'sender'}));}
    const r=await this.db.prepare('INSERT INTO incoming_codes (owner_id,event_id,source_id,entry_id,envelope,received_at,expires_at,assignment,sender_envelope,template_fp) SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10 WHERE EXISTS (SELECT 1 FROM sources WHERE owner_id = ?1 AND source_id = ?3 AND revoked_at IS NULL) ON CONFLICT(owner_id,source_id,event_id) DO NOTHING').bind(ownerId,eventId,sourceId,entryId,JSON.stringify(envelope),receivedAt,expiresAt,entryId?'rule':'unassigned',senderEnvelope,templateFp).run();
    const inserted=r.meta.changes>=1,arrivedAt=this.clock();
    // Review context is best effort and never blocks or alters code ingest. A failure means "context unavailable", never a raw fallback.
    if(inserted&&this.contextRetentionMs!==null&&typeof sender==='string'&&sender.length>0&&sender.length<=256){
      try{ if(entryId)await this.#dropContextFor(ownerId,sourceId,sender,templateFp); else if(reviewContext)await this.#saveContext(ownerId,{sourceId,eventId,code,receivedAt,arrivedAt,sender,accountHint,context:reviewContext,templateFp}); }catch{}
    }
    return {inserted,entryId};
  }
  // HMAC-SHA-256 keyed by a server secret and scoped to owner+source, so equal senders never share a digest across owners or sources and a DB reader cannot test guesses.
  async #senderDigest(ownerId,sourceId,sender){
    this.#hmacKey??=await crypto.subtle.importKey('raw',parseDigestSecret(this.contextDigestSecret),{name:'HMAC',hash:'SHA-256'},false,['sign']);
    const mac=new Uint8Array(await crypto.subtle.sign('HMAC',this.#hmacKey,new TextEncoder().encode(JSON.stringify(['otpanda-context-sender-v2',ownerId,sourceId,sender]))));
    return [...mac].map(b=>b.toString(16).padStart(2,'0')).join('');
  }
  async #dropContextFor(ownerId,sourceId,sender,templateFp){await this.db.prepare('DELETE FROM unassigned_context WHERE owner_id=?1 AND source_id=?2 AND sender_digest=?3 AND template_fp IS ?4').bind(ownerId,sourceId,await this.#senderDigest(ownerId,sourceId,sender),templateFp??null).run();}
  async #saveContext(ownerId,{sourceId,eventId,code,receivedAt,arrivedAt,sender,accountHint,context,templateFp}){
    if(!['sms','email'].includes(context.kind))return;
    if(!Number.isSafeInteger(arrivedAt)||arrivedAt<0)return;
    // Retention and 'latest' use the server arrival clock. The provider date is display metadata only, clamped to [0, arrival], so a forged date cannot extend retention or win ordering.
    const shown=Math.min(receivedAt,arrivedAt),retainUntil=arrivedAt+this.contextRetentionMs,digest=await this.#senderDigest(ownerId,sourceId,sender),recordId=await hashText(JSON.stringify(['otpanda-context',sourceId,digest]));
    const red=redactContext(context.text,{code,maxBytes:CONTEXT_MAX[context.kind]});
    const ctx=part=>({ownerId,recordId,serviceId:'unassigned-context-'+part,receivedAt:arrivedAt,expiresAt:retainUntil});
    const senderEnv=JSON.stringify(await this.cipher.encrypt(sender,ctx('sender')));
    const hintEnv=typeof accountHint==='string'&&accountHint&&accountHint.length<=256?JSON.stringify(await this.cipher.encrypt(accountHint,ctx('hint'))):null;
    const textEnv=red?JSON.stringify(await this.cipher.encrypt(red.text,ctx('text'))):null;
    const size=senderEnv.length+(textEnv?textEnv.length:0)+(hintEnv?hintEnv.length:0)+96;
    // Latest arrival wins; an older or equal-time lower event id never overwrites. Identity (source+sender) is never merged with another sender.
    // One statement: the row exists only while the incoming event is still live and unassigned, the source is not revoked, and no rule already covers this sender.
    // A confirm, revoke or rule creation that lands between the code insert and this write therefore wins, and nothing is resurrected.
    await this.db.prepare(`INSERT INTO unassigned_context (context_id,owner_id,source_id,sender_digest,kind,latest_event_id,received_at,arrived_at,retain_until,sender_envelope,text_envelope,truncated,size_bytes,key_fingerprint,template_fp,hint_envelope)
      SELECT ?1,?2,?3,?4,?5,?6,?7,?13,?8,?9,?10,?11,?12,?16,?17,?18 WHERE EXISTS (SELECT 1 FROM sources WHERE owner_id=?2 AND source_id=?3 AND revoked_at IS NULL)
      AND EXISTS (SELECT 1 FROM incoming_codes WHERE owner_id=?2 AND source_id=?3 AND event_id=?6 AND entry_id IS NULL AND expires_at>?13)
      AND NOT EXISTS (SELECT 1 FROM service_routes WHERE paused_at IS NULL AND owner_id=?2 AND source_id=?3 AND origin_value=?14 AND COALESCE(account_hint,'')=COALESCE(?15,'') AND template_fp IS ?17)
      ON CONFLICT(owner_id,source_id,sender_digest) DO UPDATE SET kind=excluded.kind,latest_event_id=excluded.latest_event_id,received_at=excluded.received_at,arrived_at=excluded.arrived_at,retain_until=excluded.retain_until,sender_envelope=excluded.sender_envelope,text_envelope=excluded.text_envelope,truncated=excluded.truncated,size_bytes=excluded.size_bytes,key_fingerprint=excluded.key_fingerprint,template_fp=excluded.template_fp,hint_envelope=excluded.hint_envelope
      WHERE excluded.arrived_at>unassigned_context.arrived_at OR (excluded.arrived_at=unassigned_context.arrived_at AND excluded.latest_event_id>unassigned_context.latest_event_id)`)
      .bind(crypto.randomUUID(),ownerId,sourceId,digest,context.kind,eventId,shown,retainUntil,senderEnv,textEnv,red?.truncated?1:0,size,arrivedAt,sender,typeof accountHint==='string'&&accountHint?accountHint:null,await this.contextKeyFingerprint(),templateFp??null,hintEnv).run();
    await this.#enforceContextCaps(ownerId);
  }
  // Oldest first, bounded. A fixed small loop: one row is at most about 12 KB, so the byte cap needs few deletions.
  async #enforceContextCaps(ownerId){
    await this.db.prepare('DELETE FROM unassigned_context WHERE owner_id=?1 AND context_id IN (SELECT context_id FROM unassigned_context WHERE owner_id=?1 ORDER BY arrived_at DESC,context_id DESC LIMIT -1 OFFSET ?2)').bind(ownerId,this.maxContextIdentities).run();
    // One statement: keep the newest rows whose running size fits the byte cap (window function), so the trim is a single query, not a loop.
    await this.db.prepare('DELETE FROM unassigned_context WHERE context_id IN (SELECT context_id FROM (SELECT context_id,SUM(size_bytes) OVER (ORDER BY arrived_at DESC,context_id DESC) AS run FROM unassigned_context WHERE owner_id=?1) WHERE run>?2)').bind(ownerId,this.maxContextBytes).run();
  }
  // Server-keyed fingerprint of the current digest secret. Rows written under another secret (rotation) are purged by housekeeping.
  async contextKeyFingerprint(){
    if(this.contextRetentionMs===null)return null;
    this.#hmacKey??=await crypto.subtle.importKey('raw',parseDigestSecret(this.contextDigestSecret),{name:'HMAC',hash:'SHA-256'},false,['sign']);
    const mac=new Uint8Array(await crypto.subtle.sign('HMAC',this.#hmacKey,new TextEncoder().encode('otpanda-context-key-fingerprint-v1')));
    return [...mac.slice(0,8)].map(b=>b.toString(16).padStart(2,'0')).join('');
  }
  // Housekeeping, bounded to 100 rows per pass, whenever the table exists. Retention off: every row is deleted (disabled means purged). Retention on: expired rows and rows written under a different digest secret.
  // Missing table (before 0054) is a no-op. Any other failure is counted and rethrown, never silent.
  // Returns the number of rows removed. maxPasses repeats (100 rows each) while a pass was full, so a disable purge drains faster than one batch per cron run.
  async cleanupContext(now,{maxPasses=1}={}){
    if(!Number.isSafeInteger(now)||now<0)throw new TypeError('Valid clock required');
    let total=0;
    try{
     for(let pass=0;pass<maxPasses;pass++){
      const r=this.contextRetentionMs===null?await this.db.prepare('DELETE FROM unassigned_context WHERE rowid IN (SELECT rowid FROM unassigned_context LIMIT 100)').run():await this.db.prepare(CONTEXT_CLEANUP_SQL).bind(now,await this.contextKeyFingerprint()).run();
      total+=r.meta.changes;if(r.meta.changes<100)break;
     }
     return total;
    }
    catch(error){if(/no such table/i.test(String(error?.message)))return 0;this.contextCleanupFailures=(this.contextCleanupFailures??0)+1;throw error;}
  }
  // Must be called when retention is disabled or the digest secret is rotated: removes every stored context row. No-op before 0054.
  async purgeAllContext(){
    try{await this.db.prepare('DELETE FROM unassigned_context').run();}
    catch(error){if(/no such table/i.test(String(error?.message)))return;this.contextCleanupFailures=(this.contextCleanupFailures??0)+1;throw error;}
  }
  async dismissContext(ownerId,contextId){
    [ownerId,contextId].forEach(id);
    if(this.contextRetentionMs===null)return false;
    return (await this.db.prepare('DELETE FROM unassigned_context WHERE owner_id=?1 AND context_id=?2').bind(ownerId,contextId).run()).meta.changes>=1;
  }
  // Owner-only, code-free review model. There is NO code field, never an envelope and never the raw message. Inactive (empty) unless retention is enabled.
  async contextsForOwner(ownerId,now){
    id(ownerId);if(!Number.isSafeInteger(now)||now<0)throw new TypeError('Valid clock required');
    if(this.contextRetentionMs===null)return [];
    try{return await this.#contexts(ownerId,now);}catch{return [];} // schema not migrated yet: fail safe, empty
  }
  async #contexts(ownerId,now){
    const rows=(await this.db.prepare('SELECT x.context_id,x.source_id,x.sender_digest,x.kind,x.latest_event_id,x.received_at,x.arrived_at,x.retain_until,x.sender_envelope,x.text_envelope,x.truncated,s.label FROM unassigned_context x JOIN sources s ON s.source_id=x.source_id AND s.owner_id=x.owner_id WHERE x.owner_id=?1 AND x.key_fingerprint=?3 AND x.arrived_at<=?2 AND x.retain_until>?2 AND s.revoked_at IS NULL ORDER BY x.arrived_at DESC,x.context_id DESC LIMIT 50').bind(ownerId,now,await this.contextKeyFingerprint()).all()).results;
    const decoded=[];
    for(const r of rows){
      try{
        const recordId=await hashText(JSON.stringify(['otpanda-context',r.source_id,r.sender_digest])),ctx=part=>({ownerId,recordId,serviceId:'unassigned-context-'+part,receivedAt:r.arrived_at,expiresAt:r.retain_until});
        const sender=await this.cipher.decrypt(JSON.parse(r.sender_envelope),ctx('sender'));
        const text=r.text_envelope?await this.cipher.decrypt(JSON.parse(r.text_envelope),ctx('text')):null;
        decoded.push({r,sender,text});
      }catch{}
    }
    // One re-validation query for the whole page (not one per row, D1 Free allows 50 queries per invocation): dismissal, assignment, revocation or an update during the decrypt work wins.
    const out=[];
    if(!decoded.length)return out;
    const ids=decoded.map(d=>d.r.context_id),live=new Map((await this.db.prepare(`SELECT x.context_id,x.sender_envelope FROM unassigned_context x JOIN sources s ON s.source_id=x.source_id AND s.owner_id=x.owner_id WHERE x.owner_id=?1 AND x.retain_until>?2 AND s.revoked_at IS NULL AND x.context_id IN (${ids.map((_,i)=>'?'+(i+3)).join(',')})`).bind(ownerId,now,...ids).all()).results.map(x=>[x.context_id,x.sender_envelope]));
    for(const {r,sender,text} of decoded){
      if(live.get(r.context_id)!==r.sender_envelope)continue;
      out.push({contextId:r.context_id,sourceId:r.source_id,eventId:r.latest_event_id,kind:r.kind,sender,sourceLabel:r.label,receivedAt:r.received_at,arrivedAt:r.arrived_at,retainedUntil:r.retain_until,contextUnavailable:text===null,truncated:text!==null&&r.truncated===1,...(text===null?{}:{redactedText:text})});
    }
    return out;
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
    if(r.meta.changes>=1&&this.contextRetentionMs!==null){try{await this.db.prepare('DELETE FROM unassigned_context WHERE owner_id=?1 AND source_id=?2 AND latest_event_id=?3').bind(ownerId,sourceId,eventId).run();}catch{}}
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
    const permitted='(e.owner_id=?1 OR EXISTS (SELECT 1 FROM entry_shares m WHERE m.entry_id=e.entry_id AND m.recipient_id=?1 AND m.revoked_at IS NULL))';
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
