// Internal assignment-only orchestration, unmounted. Auth comes from the HTTP
// adapter, never owner/device fields taken from an untrusted request body.
import {hashText} from './sessions.js';
import {SESSION_METHOD_JOIN as MJ,SESSION_METHOD_ACTIVE as MA} from './session-method.js';
import {DurableDeviceKeys} from './durable-device-keys.js';
import {parseAccessToken} from './tokens.js';
import {describeRule} from './assignment-rule.js';
import {normalizePhrase} from './service-metadata.js';
export const ACTION_MAX_BYTES=3072,LABEL_MAX=64,ACCOUNT_MAX=128,SERVICE_MAX=128;
export const deviceBinding=(deviceId,intentId)=>hashText(JSON.stringify(['otpanda-device-bind-v1',deviceId,intentId]));
const TTL=120000,RECEIPT=600000,MAX_PENDING=5;
const active=`EXISTS(SELECT 1 FROM device_sessions d ${MJ} JOIN account_security s ON s.owner_id=d.owner_id WHERE d.device_id=i.device_id AND d.owner_id=i.owner_id AND d.generation=i.generation AND s.generation=i.generation AND d.client_kind IN ('web','android') AND d.revoked_at IS NULL AND ${MA} AND d.created_at<=?2 AND d.expires_at>?2)`;
// Rule outcome as persisted by the committing batch. 'unavailable' carries a reason: the signed 'none' reason, or 'not_saved' when a signed save did not land.
function ruleReport(row){let reason;try{const j=JSON.parse(row.rule_json);reason=j[0]==='none'?j[1]:'not_saved';}catch{reason='not_saved';}if(row.rule_result==='paused'){let id=null;try{id=JSON.parse(row.rule_json)[1]??null;}catch{}return{status:'paused',ruleId:id,resumeRequiresSignedAction:true};}
  return row.rule_result==='unavailable'?{status:'unavailable',reason}:{status:row.rule_result};}
function id(v){return typeof v==='string'&&v.length>0&&v.length<=256;}
export class AssignmentIntents {
 constructor({db,passkeys,cipher,prepare=async()=>{},rules=false,clock=Date.now,deviceKeys=new DurableDeviceKeys(db,{clock})}={}){if(!db||!passkeys||!cipher)throw new TypeError('Assignment dependencies required');Object.assign(this,{db,passkeys,cipher,prepare,rules:!!rules,clock,deviceKeys});}
 now(){const n=this.clock();if(!Number.isSafeInteger(n)||n<0)throw new TypeError('Valid instant required');return n;}
 async context(auth,sourceId,eventId,entryId){
  const now=this.now();
  if(!auth||![auth.ownerId,auth.deviceId,sourceId,eventId,entryId].every(id)||!Number.isSafeInteger(auth.generation))return;
  return await this.db.prepare(`SELECT c.envelope,c.received_at,c.expires_at,c.sender_envelope,c.template_fp,s.kind AS source_kind,s.receiver AS source_receiver,s.label AS source_label,e.label,e.account_name,e.service_id,e.mutation_revision,(SELECT count(*) FROM entry_shares m WHERE m.entry_id=e.entry_id AND m.revoked_at IS NULL) AS recipients,((SELECT count(*) FROM entry_shares m WHERE m.entry_id=e.entry_id AND m.revoked_at IS NULL AND m.allow_automation=1)+(SELECT count(*) FROM entry_tokens t WHERE t.entry_id=e.entry_id AND t.revoked_at IS NULL AND t.created_at<=?5 AND t.expires_at>?5)) AS automation_recipients FROM incoming_codes c JOIN sources s ON s.owner_id=c.owner_id AND s.source_id=c.source_id JOIN entries e ON e.owner_id=c.owner_id AND e.entry_id=?4 WHERE c.owner_id=?1 AND c.source_id=?2 AND c.event_id=?3 AND c.entry_id IS NULL AND s.revoked_at IS NULL AND c.received_at<=?5 AND c.expires_at>?5`).bind(auth.ownerId,sourceId,eventId,entryId,now).first();
 }
 async begin(auth,{sourceId,eventId,entryId,keyId,phrase}={}){
  const android=auth?.clientKind==='android';
  const row=await this.context(auth,sourceId,eventId,entryId);if(!row)return;
  // Owner-private (zero recipients, zero automation incl. live entry tokens): no proof, v1 action, no keyId on any client.
  const isPrivate=Number(row.recipients)===0&&Number(row.automation_recipients)===0;
  // Android cannot know privacy in advance, so keyId is optional on begin: required for shared (key proof), ignored for private. Web never sends it.
  if(keyId!==undefined&&(!android||typeof keyId!=='string'||!keyId||keyId.length>128))return;
  if(android&&!isPrivate&&keyId===undefined)return;
  const v2=android&&!isPrivate;
  // A phrase is chosen BEFORE commit and signed. Only meaningful when rules are enabled.
  if(phrase!==undefined&&phrase!==null&&(!this.rules||typeof phrase!=='string'))return;
  let ruleDesc;if(this.rules){try{ruleDesc=await describeRule({db:this.db,cipher:this.cipher,row,ownerId:auth.ownerId,sourceId,eventId,phrase:phrase??null});}catch{return;}}
  // Dependency readiness after owner authorization, before intent/gesture.
  await this.prepare();
  const now=this.now(),intentId=crypto.randomUUID(),expiresAt=Math.min(now+TTL,row.expires_at);
  const base=['otpanda-assignment',this.rules?(v2?4:3):(v2?2:1),intentId,auth.ownerId,auth.deviceId,auth.generation,sourceId,eventId,entryId,row.mutation_revision,await hashText(row.envelope),row.received_at,row.expires_at,row.recipients,row.automation_recipients,true];
  const label=row.label??'',account=row.account_name??'',service=row.service_id??'';
  if(v2&&(typeof label!=='string'||typeof account!=='string'||typeof service!=='string'||label.length>LABEL_MAX||account.length>ACCOUNT_MAX||service.length>SERVICE_MAX))return;
  const ruleStr=ruleDesc?JSON.stringify(ruleDesc):undefined,action=JSON.stringify([...base,...(v2?[label,account,service]:[]),...(ruleStr?[ruleStr]:[])]);
  if((v2||ruleStr)&&new TextEncoder().encode(action).length>ACTION_MAX_BYTES)return;
  const inserted=await this.db.prepare(`INSERT INTO assignment_intents(intent_id,owner_id,device_id,generation,source_id,event_id,entry_id,entry_revision,envelope,received_at,code_expires_at,action_digest,created_at,expires_at,result_expires_at) SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15 WHERE (SELECT count(*) FROM assignment_intents WHERE owner_id=?2 AND consumed_at IS NULL AND retired_at IS NULL AND expires_at>?13)<${MAX_PENDING} AND EXISTS(SELECT 1 FROM device_sessions d ${MJ} JOIN account_security s ON s.owner_id=d.owner_id WHERE d.device_id=?3 AND d.owner_id=?2 AND d.generation=?4 AND s.generation=?4 AND d.client_kind IN ('web','android') AND d.revoked_at IS NULL AND ${MA} AND d.created_at<=?13 AND d.expires_at>?13)`).bind(intentId,auth.ownerId,auth.deviceId,auth.generation,sourceId,eventId,entryId,row.mutation_revision,row.envelope,row.received_at,row.expires_at,await hashText(action),now,expiresAt,now+RECEIPT).run();
  if(inserted.meta.changes!==1)return;
  try {
  let rule;if(ruleDesc){rule=ruleDesc[0]==='save'?{status:'will_save',senderKind:ruleDesc[1],sender:ruleDesc[2],basis:ruleDesc[6]!==null?'phrase':'template',phrase:ruleDesc[6],futureRecipients:Number(row.recipients),futureAutomations:Number(row.automation_recipients),sourceLabel:row.source_label,scope:ruleDesc[6]!==null?'sender+phrase':'sender+template',otherAccountRules:Number((await this.db.prepare('SELECT count(DISTINCT entry_id) AS n FROM service_routes WHERE owner_id=?1 AND source_id=?2 AND paused_at IS NULL AND origin_kind=?3 AND origin_value=?4 AND entry_id IS NOT ?5 AND (?6 IS NOT NULL OR template_fp IS NULL OR template_fp IS ?7)').bind(auth.ownerId,sourceId,ruleDesc[1],ruleDesc[2],entryId,ruleDesc[6],ruleDesc[7]).first())?.n??0)}:{status:'unavailable',reason:ruleDesc[1]};
   if(rule.status==='will_save'){const pz=await this.db.prepare('SELECT route_id FROM service_routes WHERE owner_id=?1 AND source_id=?2 AND origin_kind=?3 AND origin_value=?4 AND entry_id IS ?5 AND account_hint IS ?6 AND phrase IS ?7 AND template_fp IS ?8 AND paused_at IS NOT NULL').bind(auth.ownerId,ruleDesc[4],ruleDesc[1],ruleDesc[2],entryId,ruleDesc[3],ruleDesc[6],ruleDesc[7]).first();if(pz){rule.status='already_saved_paused';rule.ruleId=pz.route_id;rule.resumeRequiresSignedAction=true;}}}
  const summary={...(rule?{rule}:{}),operation:'assign-code',entryId,label:row.label,accountName:row.account_name,serviceId:row.service_id,activeRecipients:row.recipients,automationRecipients:row.automation_recipients,irreversible:true};
  // Owner-private target: no recipient or automation disclosure exists, so the approved owner-confirm rule applies and no strong proof is
  // issued. The zero counts are inside the hashed action; finish re-derives this only from the verified action and re-checks it in SQL.
  if(Number(row.recipients)===0&&Number(row.automation_recipients)===0)return{intentId,expiresAt,summary,action,proofRequired:false};
  if(v2){
   const c=await this.deviceKeys.beginProof({owner:auth.ownerId,keyId,purpose:'step-up',actionDigest:await hashText(action),browserBinding:await deviceBinding(auth.deviceId,intentId)});
   if(!c||c.challenge.ownerId!==auth.ownerId||c.challenge.generation!==auth.generation){await this.discard(intentId,{unissued:true});return;}
   return{intentId,token:c.token,challenge:c.challenge,expiresAt,summary,action,proofRequired:true};
  }
  const ceremony=await this.passkeys.begin({purpose:'step-up',ownerId:auth.ownerId,binding:intentId,action:await hashText(action)});
  if(!ceremony){await this.discard(intentId,{unissued:true});return;}
  return{intentId,token:ceremony.token,options:ceremony.options,expiresAt,summary,action,proofRequired:true};
  }catch(error){await this.discard(intentId,{unissued:true});throw error;}
 }
  // Same batch as the assignment. The route insert is guarded by the consumed intent, the just-confirmed code, a live receiving source and the entry; the outcome row is derived from changes().
 ruleStatements({intentId,finished,row,ruleDesc,ruleJson}){
  const save=ruleDesc[0]==='save',[,kind,value,hint,sourceId,serviceId,phrase,fp]=save?ruleDesc:[],out=[];
  if(save)out.push(this.db.prepare(`INSERT INTO service_routes(route_id,owner_id,service_id,source_id,origin_kind,origin_value,entry_id,account_hint,phrase,created_at,template_fp) SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?13 WHERE EXISTS(SELECT 1 FROM assignment_intents WHERE intent_id=?11 AND consumed_at=?10) AND EXISTS(SELECT 1 FROM incoming_codes WHERE owner_id=?2 AND source_id=?4 AND event_id=?12 AND entry_id=?7 AND assignment='confirmed') AND EXISTS(SELECT 1 FROM sources WHERE owner_id=?2 AND source_id=?4 AND revoked_at IS NULL AND receiver IS NOT NULL) AND EXISTS(SELECT 1 FROM entries WHERE owner_id=?2 AND entry_id=?7 AND service_id=?3) ON CONFLICT DO NOTHING`).bind(crypto.randomUUID(),row.owner_id,serviceId,sourceId,kind,value,row.entry_id,hint,phrase,finished,intentId,row.event_id,fp));
  out.push(this.db.prepare("UPDATE assignment_intents SET rule_json=CASE WHEN ?3<>0 AND changes()<1 AND EXISTS(SELECT 1 FROM service_routes WHERE owner_id=?4 AND source_id=?5 AND origin_kind=?6 AND origin_value=?7 AND entry_id IS ?8 AND account_hint IS ?9 AND phrase IS ?10 AND template_fp IS ?12 AND paused_at IS NOT NULL) THEN json_array('paused',(SELECT route_id FROM service_routes WHERE owner_id=?4 AND source_id=?5 AND origin_kind=?6 AND origin_value=?7 AND entry_id IS ?8 AND account_hint IS ?9 AND phrase IS ?10 AND template_fp IS ?12 AND paused_at IS NOT NULL LIMIT 1)) ELSE ?1 END,rule_result=CASE WHEN ?3=0 THEN 'unavailable' WHEN changes()>=1 THEN 'saved' WHEN EXISTS(SELECT 1 FROM service_routes WHERE owner_id=?4 AND source_id=?5 AND origin_kind=?6 AND origin_value=?7 AND entry_id IS ?8 AND account_hint IS ?9 AND phrase IS ?10 AND template_fp IS ?12 AND paused_at IS NULL) THEN 'exists' WHEN EXISTS(SELECT 1 FROM service_routes WHERE owner_id=?4 AND source_id=?5 AND origin_kind=?6 AND origin_value=?7 AND entry_id IS ?8 AND account_hint IS ?9 AND phrase IS ?10 AND template_fp IS ?12 AND paused_at IS NOT NULL) THEN 'paused' ELSE 'unavailable' END WHERE intent_id=?2 AND consumed_at=?11").bind(ruleJson,intentId,save?1:0,row.owner_id,sourceId??'',kind??'',value??'',row.entry_id,hint??null,phrase??null,finished,fp??null));
  return out;
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
  const row=await this.db.prepare(`SELECT i.consumed_at,i.retired_at,i.expires_at,i.rule_json,i.rule_result FROM assignment_intents i WHERE i.intent_id=?1 AND i.owner_id=?3 AND i.device_id=?4 AND i.generation=?5 AND i.result_expires_at>?2 AND ${active}`).bind(intentId,this.now(),auth.ownerId,auth.deviceId,auth.generation).first();
  return row?{status:row.consumed_at!==null?'assigned':row.retired_at!==null?'not-assigned':'pending',...(row.consumed_at!==null&&row.rule_result?{rule:ruleReport(row)}:{})}:undefined;
 }
 async finish(auth,{intentId,token,action,response,signature}={}){
  const android=auth?.clientKind==='android';
  if(!auth||!id(intentId)||typeof action!=='string'||action.length>4096)return;
  const prior=await this.status(auth,intentId);if(['assigned','not-assigned'].includes(prior?.status))return prior;
  const now=this.now(),row=await this.db.prepare(`SELECT i.* FROM assignment_intents i WHERE i.intent_id=?1 AND i.owner_id=?3 AND i.device_id=?4 AND i.generation=?5 AND i.consumed_at IS NULL AND i.retired_at IS NULL AND i.created_at<=?2 AND i.expires_at>?2 AND ${active}`).bind(intentId,now,auth.ownerId,auth.deviceId,auth.generation).first();
  if(!row||await hashText(action)!==row.action_digest)return;
  let committed=false,claimed=false;
  // Private only when the server-issued, hash-verified action says zero recipients and zero automation. A client cannot choose this.
  let parsed;try{parsed=JSON.parse(action);}catch{return;}
  // Versions: 1 private/web and 2 android-shared are the legacy shapes (no rule). 3 and 4 are the same shapes plus one trailing signed rule descriptor. A rule version is refused unless rules are enabled.
  const ver=Array.isArray(parsed)?parsed[1]:undefined,ruleAct=ver===3||ver===4;
  if(ruleAct&&!this.rules)return;
  const baseLen=ruleAct?17:16,sharedLen=ruleAct?20:19;
  const priv=Array.isArray(parsed)&&parsed[0]==='otpanda-assignment'&&parsed.length===baseLen&&(ruleAct?ver===3:ver===1)&&parsed[2]===intentId&&parsed[13]===0&&parsed[14]===0&&parsed[15]===true;
  // Branch by session kind AND the verified action shape: private (16, no proof), android shared (19, device key), web shared (16 with proof).
  const deviceShared=android&&!priv;
  if(!Array.isArray(parsed)||parsed[0]!=='otpanda-assignment'||parsed[2]!==intentId||parsed[3]!==auth.ownerId||parsed[4]!==auth.deviceId)return;
  if(priv?(token!==undefined||response!==undefined||signature!==undefined):deviceShared?(parsed.length!==sharedLen||parsed[1]!==(ruleAct?4:2)||typeof signature!=='string'||response!==undefined||!parseAccessToken(token)):(parsed.length!==baseLen||parsed[1]!==(ruleAct?3:1)||signature!==undefined))return;
  try {
  let proof;
  if(deviceShared){
   claimed=true;// a presented device challenge is consumed by verification: a failed attempt retires the intent like the passkey path
   proof=await this.deviceKeys.finish({token,browserBinding:await deviceBinding(auth.deviceId,intentId),signature});
   if(!proof||proof.purpose!=='step-up'||proof.ownerId!==auth.ownerId||proof.generation!==auth.generation||proof.actionDigest!==row.action_digest)return;
  }else if(!priv){
  proof=await this.passkeys.finishAuthentication({token,binding:intentId,ownerId:auth.ownerId,action:row.action_digest,response,onCeremonyClaimed:()=>{claimed=true;}});
  if(!proof||proof.purpose!=='step-up'||proof.ownerId!==auth.ownerId||proof.generation!==auth.generation||proof.actionDigest!==await hashText(row.action_digest))return;
  }
  const context={ownerId:row.owner_id,recordId:await hashText(JSON.stringify([row.source_id,row.event_id])),serviceId:'unassigned',receivedAt:row.received_at,expiresAt:row.code_expires_at};
  const code=await this.cipher.decrypt(JSON.parse(row.envelope),context),envelope=JSON.stringify(await this.cipher.encrypt(code,{...context,serviceId:row.entry_id}));
  // The signed descriptor is the only source of the rule. It must still equal what the server derives from its own row now (sender, source, service, phrase): otherwise nothing is assigned.
  let ruleDesc=['none','not_in_signed_action'];
  if(ruleAct){
   try{ruleDesc=JSON.parse(parsed[parsed.length-1]);}catch{return;}
   const cur=await this.context(auth,row.source_id,row.event_id,row.entry_id);if(!cur)return;
   let again;try{again=await describeRule({db:this.db,cipher:this.cipher,row:cur,ownerId:row.owner_id,sourceId:row.source_id,eventId:row.event_id,phrase:Array.isArray(ruleDesc)&&ruleDesc[0]==='save'?ruleDesc[6]:null});}catch{return;}
   if(JSON.stringify(again)!==parsed[parsed.length-1])return;
  }
  const finished=this.now();if(proof&&(finished<proof.verifiedAt||finished-proof.verifiedAt>=TTL))return;
  // First mark the intent only if every mutable predicate still holds. The
  // second statement writes only when that exact first statement changed1.
  // Both statements execute in one D1 batch. No intervening writer can run.
  const guard=`i.intent_id=?1 AND i.consumed_at IS NULL AND i.retired_at IS NULL AND i.created_at<=?2 AND i.expires_at>?2 AND i.owner_id=?3 AND i.device_id=?4 AND i.generation=?5 AND ${active} AND ${priv?`NOT EXISTS(SELECT 1 FROM entry_shares m WHERE m.entry_id=i.entry_id AND m.revoked_at IS NULL) AND NOT EXISTS(SELECT 1 FROM entry_tokens t WHERE t.entry_id=i.entry_id AND t.revoked_at IS NULL AND t.created_at<=?2 AND t.expires_at>?2)`:(deviceShared?`EXISTS(SELECT 1 FROM device_sessions dk WHERE dk.device_id=i.device_id AND dk.client_kind='android') AND EXISTS(SELECT 1 FROM durable_device_keys k WHERE k.key_id=?6 AND k.owner_id=i.owner_id AND k.revoked_at IS NULL AND k.generation=i.generation)`:`EXISTS(SELECT 1 FROM device_sessions dk WHERE dk.device_id=i.device_id AND dk.client_kind='web') AND EXISTS(SELECT 1 FROM passkey_credentials p WHERE p.credential_id=?6 AND p.owner_id=i.owner_id AND p.revoked_at IS NULL)`)} AND EXISTS(SELECT 1 FROM incoming_codes c JOIN sources s ON s.owner_id=c.owner_id AND s.source_id=c.source_id WHERE c.owner_id=i.owner_id AND c.source_id=i.source_id AND c.event_id=i.event_id AND c.entry_id IS NULL AND c.envelope=i.envelope AND c.received_at=i.received_at AND c.expires_at=i.code_expires_at AND c.received_at<=?2 AND c.expires_at>?2 AND s.revoked_at IS NULL) AND EXISTS(SELECT 1 FROM entries e WHERE e.owner_id=i.owner_id AND e.entry_id=i.entry_id AND e.mutation_revision=i.entry_revision)`;
  // Private path has no ceremony to claim: a failed guarded batch retires the intent (definite not-assigned), never leaves it replayable.
  if(priv)claimed=true;
  let results;
  try{results=await this.db.batch([
   this.db.prepare(`UPDATE assignment_intents AS i SET consumed_at=?2 WHERE ${guard}`).bind(...[intentId,finished,auth.ownerId,auth.deviceId,auth.generation,...(priv?[]:[deviceShared?proof.keyId:proof.credentialId])]),
   this.db.prepare(`UPDATE incoming_codes SET entry_id=?1,assignment='confirmed',envelope=?2 WHERE owner_id=?3 AND source_id=?4 AND event_id=?5 AND entry_id IS NULL AND envelope=?6 AND changes()=1 AND EXISTS(SELECT 1 FROM assignment_intents WHERE intent_id=?7 AND consumed_at=?8)`).bind(row.entry_id,envelope,row.owner_id,row.source_id,row.event_id,row.envelope,intentId,finished),
   this.db.prepare('INSERT INTO assignment_receipts(intent_id,assignment_changes) SELECT ?1,changes() WHERE EXISTS(SELECT 1 FROM assignment_intents WHERE intent_id=?1 AND consumed_at=?2)').bind(intentId,finished),
   ...(this.rules?this.ruleStatements({intentId,finished,row,ruleDesc,ruleJson:JSON.stringify(ruleDesc)}):[]),
  ]);}catch(error){
   // Same-instant duplicate private finish: the loser's receipt CHECK rolls back only its own batch. Report the winner's committed outcome.
   if(priv){const again=await this.status(auth,intentId);if(again?.status==='assigned')return again;}
   throw error;
  }
  if(results[0]/*exact-count-ok*/.meta.changes!==1||results[1].meta.changes<1)return;
  committed=true;
  if(!this.rules)return{status:'assigned'};
  const done=await this.db.prepare('SELECT rule_json,rule_result FROM assignment_intents WHERE intent_id=?1').bind(intentId).first();
  return{status:'assigned',...(done?.rule_result?{rule:ruleReport(done)}:{})};
  }finally{if(claimed&&!committed)await this.discard(intentId);}
 }
 async cleanup({limit=100}={}){if(!Number.isSafeInteger(limit)||limit<1||limit>500)throw new TypeError('Bounded cleanup required');return(await this.db.prepare('DELETE FROM assignment_intents WHERE intent_id IN(SELECT intent_id FROM assignment_intents WHERE result_expires_at<=?1 ORDER BY result_expires_at LIMIT ?2)').bind(this.now(),limit).run()).meta.changes;}
}
