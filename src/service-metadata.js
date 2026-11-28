function bounded(value,max=256){if(typeof value!=='string'||!value||value.length>max)throw new TypeError('Bounded text required');return value;}
export function normalizeEmail(value){
 bounded(value,320);if(value!==value.trim()||/[\s<>(),;:]/.test(value))throw new TypeError('Plain email address required');
 const at=value.lastIndexOf('@');if(at<1||at!==value.indexOf('@'))throw new TypeError('Email required');
 // Preserve local-part case. Do not remove dots or plus tags, which are
 // provider-specific and can combine distinct receiving identities.
 return value.slice(0,at)+'@'+normalizeDomain(value.slice(at+1));
}
export function normalizeDomain(value){
 bounded(value,253);if(!/^[A-Za-z0-9.-]+$/.test(value)||value.startsWith('.')||value.endsWith('.')||value.includes('..')||value.split('.').some(p=>!p||p.startsWith('-')||p.endsWith('-')||p.length>63))throw new TypeError('ASCII hostname required');
 return value.toLowerCase();
}
export function normalizePhone(value){if(typeof value!=='string'||!/^\+[1-9][0-9]{7,14}$/.test(value))throw new TypeError('E.164 phone required');return value;}
export function normalizePhrase(value){
 if(value===null||value===undefined)return null;
 if(typeof value!=='string')throw new TypeError('Phrase must be text');
 const p=value.trim().toLowerCase();if(!p)return null;
 if(p.length>120||/[\u0000-\u001f\u007f]/.test(p))throw new TypeError('Bounded phrase required');return p;
}
export class ServiceMetadata {
 constructor(db){this.db=db;}
 async putService(serviceId,{name,websiteHost=null,iconKey=null}){
  bounded(serviceId,128);bounded(name,120);
  if(websiteHost!==null)websiteHost=normalizeDomain(websiteHost);
  // icon_key is a local asset identifier, never an arbitrary remote URL.
  if(iconKey!==null&&!/^[a-z0-9_-]{1,64}$/.test(iconKey))throw new TypeError('Local icon key required');
  await this.db.prepare('INSERT INTO services (service_id,name,website_host,icon_key) VALUES (?1,?2,?3,?4) ON CONFLICT(service_id) DO UPDATE SET name=excluded.name,website_host=excluded.website_host,icon_key=excluded.icon_key').bind(serviceId,name,websiteHost,iconKey).run();
 }
 async setEntryAccount(ownerId,entryId,accountName){
  if(accountName!==null)bounded(accountName,120);
  const r=await this.db.prepare('UPDATE entries SET account_name = ?1 WHERE owner_id = ?2 AND entry_id = ?3').bind(accountName,ownerId,entryId).run();return r.meta.changes>=1;
 }
 async setReceiver(ownerId,sourceId,receiver){
  const source=await this.db.prepare('SELECT kind FROM sources WHERE owner_id = ?1 AND source_id = ?2').bind(ownerId,sourceId).first();if(!source)return false;
  receiver=source.kind==='sms'?normalizePhone(receiver):normalizeEmail(receiver);
  // A connected Gmail source's receiver is its canonical mailbox, written only by the Gmail connect batch: never rebound here.
  const r=await this.db.prepare('UPDATE sources SET receiver = ?1 WHERE owner_id = ?2 AND source_id = ?3 AND NOT EXISTS (SELECT 1 FROM gmail_connections g WHERE g.source_id = sources.source_id)').bind(receiver,ownerId,sourceId).run();return r.meta.changes>=1;
 }
 async addRoute(ownerId,{serviceId,sourceId,originKind,originValue,entryId=null,accountHint=null,phrase=null,now=Date.now()}){
  const source=await this.db.prepare('SELECT kind,receiver FROM sources WHERE owner_id = ?1 AND source_id = ?2 AND revoked_at IS NULL').bind(ownerId,sourceId).first();
  if(!source?.receiver)throw new TypeError('Receiving source must be identified');
  if(originKind==='sms_number'){if(source.kind!=='sms')throw new TypeError('SMS source required');originValue=normalizePhone(originValue);}
  else if(['email_address','email_domain'].includes(originKind)){if(source.kind==='sms')throw new TypeError('Mailbox source required');originValue=originKind==='email_address'?normalizeEmail(originValue):normalizeDomain(originValue);}
  else throw new TypeError('Known origin filter required');
  if(entryId!==null){const entry=await this.db.prepare('SELECT service_id FROM entries WHERE owner_id = ?1 AND entry_id = ?2').bind(ownerId,entryId).first();if(entry?.service_id!==serviceId)throw new TypeError('Entry must belong to owner and service');}
  if(accountHint!==null)bounded(accountHint);
  phrase=normalizePhrase(phrase);
  // An identical PAUSED rule is never silently reactivated or reported as existing: the caller gets its id and must use the signed resume.
  const paused=await this.db.prepare('SELECT route_id FROM service_routes WHERE owner_id=?1 AND source_id=?2 AND origin_kind=?3 AND origin_value=?4 AND entry_id IS ?5 AND account_hint IS ?6 AND phrase IS ?7 AND template_fp IS NULL AND paused_at IS NOT NULL').bind(ownerId,sourceId,originKind,originValue,entryId,accountHint,phrase).first();
  if(paused)return{paused:true,ruleId:paused.route_id};
  const routeId=crypto.randomUUID();
  const r=await this.db.prepare('INSERT INTO service_routes (route_id,owner_id,service_id,source_id,origin_kind,origin_value,entry_id,account_hint,phrase,created_at) SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10 WHERE NOT EXISTS (SELECT 1 FROM service_routes WHERE owner_id=?2 AND source_id=?4 AND origin_kind=?5 AND origin_value=?6 AND entry_id IS ?7 AND account_hint IS ?8 AND phrase IS ?9)').bind(routeId,ownerId,serviceId,sourceId,originKind,originValue,entryId,accountHint,phrase,now).run();
  return r.meta.changes>=1?routeId:undefined;
 }
 async match(ownerId,{sourceId,receiver,sender,accountHint=null,text,templateFp=null,templateFps=null}){
  const source=await this.db.prepare('SELECT kind,receiver FROM sources WHERE owner_id = ?1 AND source_id = ?2 AND revoked_at IS NULL').bind(ownerId,sourceId).first();
  if(!source?.receiver)return {entryId:null,reason:'unassigned'};
  let normalizedReceiver,normalizedSender;
  try{normalizedReceiver=source.kind==='sms'?normalizePhone(receiver):normalizeEmail(receiver);normalizedSender=source.kind==='sms'?normalizePhone(sender):normalizeEmail(sender);}catch{return {entryId:null,reason:'unassigned'};}
  if(source.receiver!==normalizedReceiver)return {entryId:null,reason:'unassigned'};
  const routes=(await this.db.prepare('SELECT service_id,origin_kind,origin_value,entry_id,account_hint,phrase,template_fp FROM service_routes WHERE owner_id = ?1 AND source_id = ?2 AND paused_at IS NULL').bind(ownerId,sourceId).all()).results;
  const matches=routes.filter(r=>{
   if(r.account_hint!==null&&r.account_hint!==accountHint)return false;
   // A phrase only narrows. It needs the message text, and a missing text never matches a phrase rule.
   // A template rule needs the arriving message's keyed digest to be equal. No digest (off, unsupported text) never matches.
   if(r.template_fp!==null&&r.template_fp!==undefined&&r.template_fp!==templateFp&&!(templateFps&&templateFps.includes(r.template_fp)))return false;
   if(r.phrase!==null&&r.phrase!==undefined&&!(typeof text==='string'&&text.toLowerCase().includes(r.phrase)))return false;
   if(r.origin_kind==='email_domain')return normalizedSender.slice(normalizedSender.lastIndexOf('@')+1)===r.origin_value;
   return normalizedSender===r.origin_value;
  });
  if(!matches.length)return {entryId:null,reason:'unassigned'};
  const services=new Set(matches.map(r=>r.service_id)),entries=new Set(matches.map(r=>r.entry_id));
  if(services.size!==1||entries.size!==1||entries.has(null))return {entryId:null,reason:'ambiguous'};
  return {entryId:[...entries][0],serviceId:[...services][0],reason:'rule'};
 }
 // Owner-only rule read (paged by route_id). Writes live in entry-rules-http with the live-session predicate inside the statement. Never joined to entry_shares.
 async routesForOwner(ownerId,{after='',limit=100,entryId=null}={}){
  return (await this.db.prepare('SELECT r.route_id,r.entry_id,r.source_id,s.kind,s.label,r.origin_kind,r.origin_value,r.phrase,r.template_fp,r.created_at,r.paused_at FROM service_routes r JOIN sources s ON s.owner_id=r.owner_id AND s.source_id=r.source_id JOIN entries e ON e.owner_id=r.owner_id AND e.entry_id=r.entry_id WHERE r.owner_id=?1 AND r.entry_id IS NOT NULL AND r.route_id>?2 AND (?4 IS NULL OR r.entry_id=?4) ORDER BY r.route_id LIMIT ?3').bind(ownerId,after,limit+1,entryId).all()).results;
 }
}
