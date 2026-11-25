// Internal assignment-only orchestration, unmounted. Auth comes from the HTTP
// adapter, never owner/device fields taken from an untrusted request body.
import {hashText} from './sessions.js';
import {SESSION_METHOD_JOIN as MJ,SESSION_METHOD_ACTIVE as MA} from './session-method.js';
const TTL=120000,RECEIPT=600000,MAX_PENDING=5;
const active=`EXISTS(SELECT 1 FROM device_sessions d ${MJ} JOIN account_security s ON s.owner_id=d.owner_id WHERE d.device_id=i.device_id AND d.owner_id=i.owner_id AND d.generation=i.generation AND s.generation=i.generation AND d.client_kind='web' AND d.revoked_at IS NULL AND ${MA} AND d.created_at<=?2 AND d.expires_at>?2)`;
function id(v){return typeof v==='string'&&v.length>0&&v.length<=256;}
export class AssignmentIntents {
 constructor({db,passkeys,cipher,prepare=async()=>{},clock=Date.now}={}){if(!db||!passkeys||!cipher)throw new TypeError('Assignment dependencies required');Object.assign(this,{db,passkeys,cipher,prepare,clock});}
 now(){const n=this.clock();if(!Number.isSafeInteger(n)||n<0)throw new TypeError('Valid instant required');return n;}
 async context(auth,sourceId,eventId,entryId){
  const now=this.now();
  if(!auth||![auth.ownerId,auth.deviceId,sourceId,eventId,entryId].every(id)||!Number.isSafeInteger(auth.generation))return;
  return await this.db.prepare(`SELECT c.envelope,c.received_at,c.expires_at,e.label,e.account_name,e.service_id,e.mutation_revision,(SELECT count(*) FROM entry_shares m WHERE m.entry_id=e.entry_id AND m.revoked_at IS NULL) AS recipients,(SELECT count(*) FROM entry_shares m WHERE m.entry_id=e.entry_id AND m.revoked_at IS NULL AND m.allow_automation=1) AS automation_recipients FROM incoming_codes c JOIN sources s ON s.owner_id=c.owner_id AND s.source_id=c.source_id JOIN entries e ON e.owner_id=c.owner_id AND e.entry_id=?4 WHERE c.owner_id=?1 AND c.source_id=?2 AND c.event_id=?3 AND c.entry_id IS NULL AND s.revoked_at IS NULL AND c.received_at<=?5 AND c.expires_at>?5`).bind(auth.ownerId,sourceId,eventId,entryId,now).first();
 }
 async begin(auth,{sourceId,eventId,entryId}={}){
  const row=await this.context(auth,sourceId,eventId,entryId);if(!row)return;
  // Dependency readiness after owner authorization, before intent/gesture.
  await this.prepare();
  const now=this.now(),intentId=crypto.randomUUID(),expiresAt=Math.min(now+TTL,row.expires_at);
  const action=JSON.stringify(['otpanda-assignment',1,intentId,auth.ownerId,auth.deviceId,auth.generation,sourceId,eventId,entryId,row.mutation_revision,await hashText(row.envelope),row.received_at,row.expires_at,row.recipients,row.automation_recipients,true]);
  const inserted=await this.db.prepare(`INSERT INTO assignment_intents(intent_id,owner_id,device_id,generation,source_id,event_id,entry_id,entry_revision,envelope,received_at,code_expires_at,action_digest,created_at,expires_at,result_expires_at) SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15 WHERE (SELECT count(*) FROM assignment_intents WHERE owner_id=?2 AND consumed_at IS NULL AND retired_at IS NULL AND expires_at>?13)<${MAX_PENDING} AND EXISTS(SELECT 1 FROM device_sessions d ${MJ} JOIN account_security s ON s.owner_id=d.owner_id WHERE d.device_id=?3 AND d.owner_id=?2 AND d.generation=?4 AND s.generation=?4 AND d.client_kind='web' AND d.revoked_at IS NULL AND ${MA} AND d.created_at<=?13 AND d.expires_at>?13)`).bind(intentId,auth.ownerId,auth.deviceId,auth.generation,sourceId,eventId,entryId,row.mutation_revision,row.envelope,row.received_at,row.expires_at,await hashText(action),now,expiresAt,now+RECEIPT).run();
  if(inserted.meta.changes!==1)return;
  try {
  const ceremony=await this.passkeys.begin({purpose:'step-up',ownerId:auth.ownerId,binding:intentId,action:await hashText(action)});
  if(!ceremony){await this.discard(intentId,{unissued:true});return;}
  return{intentId,token:ceremony.token,options:ceremony.options,expiresAt,summary:{operation:'assign-code',entryId,label:row.label,accountName:row.account_name,serviceId:row.service_id,activeRecipients:row.recipients,automationRecipients:row.automation_recipients,irreversible:true},action};
  }catch(error){await this.discard(intentId,{unissued:true});throw error;}
 }
 async discard(intentId,{unissued=false}={}){
  if(unissued){await this.db.prepare('DELETE FROM assignment_intents WHERE intent_id=?1 AND consumed_at IS NULL').bind(intentId).run();return;}
  await this.db.prepare('UPDATE assignment_intents SET retired_at=?2 WHERE intent_id=?1 AND consumed_at IS NULL AND retired_at IS NULL').bind(intentId,this.now()).run();
 }
 async status(auth,intentId){
  if(!auth||!id(intentId))return;
  const now=this.now();
  // Linearize expiry against the final assignment guard. A stale in-flight
  // finish cannot commit after this transition, regardless of its clock read.
  await this.db.prepare(`UPDATE assignment_intents AS i SET retired_at=?2 WHERE i.intent_id=?1 AND i.owner_id=?3 AND i.device_id=?4 AND i.generation=?5 AND i.result_expires_at>?2 AND i.expires_at<=?2 AND i.consumed_at IS NULL AND i.retired_at IS NULL AND ${active}`).bind(intentId,now,auth.ownerId,auth.deviceId,auth.generation).run();
  const row=await this.db.prepare(`SELECT i.consumed_at,i.retired_at,i.expires_at FROM assignment_intents i WHERE i.intent_id=?1 AND i.owner_id=?3 AND i.device_id=?4 AND i.generation=?5 AND i.result_expires_at>?2 AND ${active}`).bind(intentId,this.now(),auth.ownerId,auth.deviceId,auth.generation).first();
  return row?{status:row.consumed_at!==null?'assigned':row.retired_at!==null?'not-assigned':'pending'}:undefined;
 }
 async finish(auth,{intentId,token,action,response}={}){
  if(!auth||!id(intentId)||typeof action!=='string'||action.length>4096)return;
  const prior=await this.status(auth,intentId);if(['assigned','not-assigned'].includes(prior?.status))return prior;
  const now=this.now(),row=await this.db.prepare(`SELECT i.* FROM assignment_intents i WHERE i.intent_id=?1 AND i.owner_id=?3 AND i.device_id=?4 AND i.generation=?5 AND i.consumed_at IS NULL AND i.retired_at IS NULL AND i.created_at<=?2 AND i.expires_at>?2 AND ${active}`).bind(intentId,now,auth.ownerId,auth.deviceId,auth.generation).first();
  if(!row||await hashText(action)!==row.action_digest)return;
  let committed=false,claimed=false;
  try {
  const proof=await this.passkeys.finishAuthentication({token,binding:intentId,ownerId:auth.ownerId,action:row.action_digest,response,onCeremonyClaimed:()=>{claimed=true;}});
  if(!proof||proof.purpose!=='step-up'||proof.ownerId!==auth.ownerId||proof.generation!==auth.generation||proof.actionDigest!==await hashText(row.action_digest))return;
  const context={ownerId:row.owner_id,recordId:await hashText(JSON.stringify([row.source_id,row.event_id])),serviceId:'unassigned',receivedAt:row.received_at,expiresAt:row.code_expires_at};
  const code=await this.cipher.decrypt(JSON.parse(row.envelope),context),envelope=JSON.stringify(await this.cipher.encrypt(code,{...context,serviceId:row.entry_id}));
  const finished=this.now();if(finished<proof.verifiedAt||finished-proof.verifiedAt>=TTL)return;
  // First mark the intent only if every mutable predicate still holds. The
  // second statement writes only when that exact first statement changed1.
  // Both statements execute in one D1 batch. No intervening writer can run.
  const guard=`i.intent_id=?1 AND i.consumed_at IS NULL AND i.retired_at IS NULL AND i.created_at<=?2 AND i.expires_at>?2 AND i.owner_id=?3 AND i.device_id=?4 AND i.generation=?5 AND ${active} AND EXISTS(SELECT 1 FROM passkey_credentials p WHERE p.credential_id=?6 AND p.owner_id=i.owner_id AND p.revoked_at IS NULL) AND EXISTS(SELECT 1 FROM incoming_codes c JOIN sources s ON s.owner_id=c.owner_id AND s.source_id=c.source_id WHERE c.owner_id=i.owner_id AND c.source_id=i.source_id AND c.event_id=i.event_id AND c.entry_id IS NULL AND c.envelope=i.envelope AND c.received_at=i.received_at AND c.expires_at=i.code_expires_at AND c.received_at<=?2 AND c.expires_at>?2 AND s.revoked_at IS NULL) AND EXISTS(SELECT 1 FROM entries e WHERE e.owner_id=i.owner_id AND e.entry_id=i.entry_id AND e.mutation_revision=i.entry_revision)`;
  const results=await this.db.batch([
   this.db.prepare(`UPDATE assignment_intents AS i SET consumed_at=?2 WHERE ${guard}`).bind(intentId,finished,auth.ownerId,auth.deviceId,auth.generation,proof.credentialId),
   this.db.prepare(`UPDATE incoming_codes SET entry_id=?1,assignment='confirmed',envelope=?2 WHERE owner_id=?3 AND source_id=?4 AND event_id=?5 AND entry_id IS NULL AND envelope=?6 AND changes()=1 AND EXISTS(SELECT 1 FROM assignment_intents WHERE intent_id=?7 AND consumed_at=?8)`).bind(row.entry_id,envelope,row.owner_id,row.source_id,row.event_id,row.envelope,intentId,finished),
   this.db.prepare('INSERT INTO assignment_receipts(intent_id,assignment_changes) SELECT ?1,changes() WHERE EXISTS(SELECT 1 FROM assignment_intents WHERE intent_id=?1 AND consumed_at=?2)').bind(intentId,finished),
  ]);
  if(results[0]/*exact-count-ok*/.meta.changes!==1||results[1].meta.changes<1)return;
  committed=true;
  return{status:'assigned'};
  }finally{if(claimed&&!committed)await this.discard(intentId);}
 }
 async cleanup({limit=100}={}){if(!Number.isSafeInteger(limit)||limit<1||limit>500)throw new TypeError('Bounded cleanup required');return(await this.db.prepare('DELETE FROM assignment_intents WHERE intent_id IN(SELECT intent_id FROM assignment_intents WHERE result_expires_at<=?1 ORDER BY result_expires_at LIMIT ?2)').bind(this.now(),limit).run()).meta.changes;}
}
