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
  const r=await this.db.prepare('UPDATE entries SET account_name = ?1 WHERE owner_id = ?2 AND entry_id = ?3').bind(accountName,ownerId,entryId).run();return r.meta.changes===1;
 }
 async setReceiver(ownerId,sourceId,receiver){
  const source=await this.db.prepare('SELECT kind FROM sources WHERE owner_id = ?1 AND source_id = ?2').bind(ownerId,sourceId).first();if(!source)return false;
  receiver=source.kind==='sms'?normalizePhone(receiver):normalizeEmail(receiver);
  await this.db.prepare('UPDATE sources SET receiver = ?1 WHERE owner_id = ?2 AND source_id = ?3').bind(receiver,ownerId,sourceId).run();return true;
 }
 async addRoute(ownerId,{serviceId,sourceId,originKind,originValue,entryId=null,accountHint=null}){
  const source=await this.db.prepare('SELECT kind,receiver FROM sources WHERE owner_id = ?1 AND source_id = ?2 AND revoked_at IS NULL').bind(ownerId,sourceId).first();
  if(!source?.receiver)throw new TypeError('Receiving source must be identified');
  if(originKind==='sms_number'){if(source.kind!=='sms')throw new TypeError('SMS source required');originValue=normalizePhone(originValue);}
  else if(['email_address','email_domain'].includes(originKind)){if(source.kind==='sms')throw new TypeError('Mailbox source required');originValue=originKind==='email_address'?normalizeEmail(originValue):normalizeDomain(originValue);}
  else throw new TypeError('Known origin filter required');
  if(entryId!==null){const entry=await this.db.prepare('SELECT service_id FROM entries WHERE owner_id = ?1 AND entry_id = ?2').bind(ownerId,entryId).first();if(entry?.service_id!==serviceId)throw new TypeError('Entry must belong to owner and service');}
  if(accountHint!==null)bounded(accountHint);
  const routeId=crypto.randomUUID();
  await this.db.prepare('INSERT INTO service_routes (route_id,owner_id,service_id,source_id,origin_kind,origin_value,entry_id,account_hint) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)').bind(routeId,ownerId,serviceId,sourceId,originKind,originValue,entryId,accountHint).run();return routeId;
 }
 async match(ownerId,{sourceId,receiver,sender,accountHint=null}){
  const source=await this.db.prepare('SELECT kind,receiver FROM sources WHERE owner_id = ?1 AND source_id = ?2 AND revoked_at IS NULL').bind(ownerId,sourceId).first();
  if(!source?.receiver)return {entryId:null,reason:'unassigned'};
  let normalizedReceiver,normalizedSender;
  try{normalizedReceiver=source.kind==='sms'?normalizePhone(receiver):normalizeEmail(receiver);normalizedSender=source.kind==='sms'?normalizePhone(sender):normalizeEmail(sender);}catch{return {entryId:null,reason:'unassigned'};}
  if(source.receiver!==normalizedReceiver)return {entryId:null,reason:'unassigned'};
  const routes=(await this.db.prepare('SELECT service_id,origin_kind,origin_value,entry_id,account_hint FROM service_routes WHERE owner_id = ?1 AND source_id = ?2').bind(ownerId,sourceId).all()).results;
  const matches=routes.filter(r=>{
   if(r.account_hint!==null&&r.account_hint!==accountHint)return false;
   if(r.origin_kind==='email_domain')return normalizedSender.slice(normalizedSender.lastIndexOf('@')+1)===r.origin_value;
   return normalizedSender===r.origin_value;
  });
  if(!matches.length)return {entryId:null,reason:'unassigned'};
  const services=new Set(matches.map(r=>r.service_id)),entries=new Set(matches.map(r=>r.entry_id));
  if(services.size!==1||entries.size!==1||entries.has(null))return {entryId:null,reason:'ambiguous'};
  return {entryId:[...entries][0],serviceId:[...services][0],reason:'rule'};
 }
}
