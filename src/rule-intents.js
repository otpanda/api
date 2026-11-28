import {readers,automations,pinnedAudience} from './action-audience.js';
// Signed rule actions with no live code. 'review': create a rule from an unassigned review row (preview kept up to 30 days). 'edit': change a rule's basis (phrase, or back to its saved template).
// Same guards as signed Assign: owner-private target (no recipients and no automation tokens) needs no extra proof, anything shared needs a step-up (passkey on web, device key on Android),
// and the signed action carries the future recipient/automation counts. The row version the owner was shown is held server-side (subject_json) and pinned inside the guarded write batch.
// Never creates a rule from sender alone, never touches a code, never back-fills history.
import {hashText} from './sessions.js';
import {SESSION_METHOD_JOIN as MJ,SESSION_METHOD_ACTIVE as MA} from './session-method.js';
import {DurableDeviceKeys} from './durable-device-keys.js';
import {parseAccessToken} from './tokens.js';
import {normalizeEmail,normalizePhone,normalizePhrase} from './service-metadata.js';
import {digestKeyId} from './template-fingerprint.js';
import {deviceBinding} from './assignment-intents.js';
const TTL=120000,RECEIPT=600000,MAX_PENDING=5,VERSION=5,ID=/^[A-Za-z0-9_-]{1,128}$/;
const active=`EXISTS(SELECT 1 FROM device_sessions d ${MJ} JOIN account_security s ON s.owner_id=d.owner_id WHERE d.device_id=i.device_id AND d.owner_id=i.owner_id AND d.generation=i.generation AND s.generation=i.generation AND d.client_kind IN ('web','android') AND d.revoked_at IS NULL AND ${MA} AND d.created_at<=?2 AND d.expires_at>?2)`;
const entryInfo=`SELECT e.label,e.account_name,e.service_id,e.mutation_revision,${readers('e.entry_id')} AS recipients,${automations('e.entry_id','e.owner_id','?3')} AS automation FROM entries e WHERE e.owner_id=?1 AND e.entry_id=?2`;
const idOk=v=>typeof v==='string'&&v.length>0&&v.length<=256;
export class RuleIntents {
 // keyIds: the digest key ids currently configured (see template-fingerprint). A digest under any other id can never match, so such a rule is refused instead of saved. Default [] refuses every template-based rule.
 constructor({db,passkeys,cipher,clock=Date.now,deviceKeys=new DurableDeviceKeys(db,{clock}),prepare=async()=>{},keyIds=[]}={}){if(!db||!passkeys||!cipher)throw new TypeError('Rule intent dependencies required');Object.assign(this,{db,passkeys,cipher,clock,deviceKeys,prepare,keyIds:Array.isArray(keyIds)?keyIds:[]});}
 // Possible ties (a lower bound is never claimed: a phrase rule on either side can match the other's template, so any phrase rule counts): other entries on the same source and sender whose rule would also match what this rule matches (same digest, same phrase, or a legacy sender-wide rule), within a compatible address hint.
 async overlap(ownerId,{sourceId,kind,value,entryId,hint,fp,phrase}){return Number((await this.db.prepare('SELECT count(DISTINCT entry_id) AS n FROM service_routes WHERE owner_id=?1 AND source_id=?2 AND origin_kind=?3 AND origin_value=?4 AND paused_at IS NULL AND entry_id IS NOT NULL AND entry_id<>?5 AND (account_hint IS NULL OR ?6 IS NULL OR account_hint=?6) AND (?8 IS NOT NULL OR phrase IS NOT NULL OR (?7 IS NOT NULL AND template_fp=?7) OR (template_fp IS NULL AND phrase IS NULL))').bind(ownerId,sourceId,kind,value,entryId,hint??null,fp??null,phrase??null).first())?.n??0);}
 now(){const n=this.clock();if(!Number.isSafeInteger(n)||n<0)throw new TypeError('Valid instant required');return n;}
 // Derive the descriptor and the server-held version from the CURRENT rows. Used by begin and again by finish; the two must agree byte for byte with the signed action.
 async derive(auth,op,{contextId,ruleId,entryId,phrase},now){
  if(!auth||![auth.ownerId,auth.deviceId].every(idOk)||!Number.isSafeInteger(auth.generation)||!ID.test(entryId??''))return;
  let norm=null;try{norm=normalizePhrase(phrase??null);}catch{return;}
  const e=await this.db.prepare(entryInfo).bind(auth.ownerId,entryId,now).first();if(!e)return;
  if(op==='review'){
   if(!ID.test(contextId??''))return;
   const x=await this.db.prepare('SELECT x.*,s.kind AS source_kind,s.receiver AS source_receiver,s.label AS source_label FROM unassigned_context x JOIN sources s ON s.owner_id=x.owner_id AND s.source_id=x.source_id WHERE x.owner_id=?1 AND x.context_id=?2 AND x.arrived_at<=?3 AND x.retain_until>?3 AND s.revoked_at IS NULL').bind(auth.ownerId,contextId,now).first();
   if(!x||!x.source_receiver)return;
   if(!(await this.db.prepare('SELECT 1 AS x FROM services WHERE service_id=?1').bind(e.service_id).first()))return;
   let sender;try{sender=await this.cipher.decrypt(JSON.parse(x.sender_envelope),{ownerId:auth.ownerId,recordId:await hashText(JSON.stringify(['otpanda-context',x.source_id,x.sender_digest])),serviceId:'unassigned-context-sender',receivedAt:x.arrived_at,expiresAt:x.retain_until});}catch{return;}
   let value;try{value=x.source_kind==='sms'?normalizePhone(sender):normalizeEmail(sender);}catch{return;}
   const fp=norm===null?(x.template_fp??null):null;if(norm===null&&fp===null)return; // never a bare sender rule
   if(fp!==null&&!this.keyIds.includes(digestKeyId(fp)))return; // key_retired: this digest can no longer match
   let hint=null;if(x.hint_envelope){try{hint=await this.cipher.decrypt(JSON.parse(x.hint_envelope),{ownerId:auth.ownerId,recordId:await hashText(JSON.stringify(['otpanda-context',x.source_id,x.sender_digest])),serviceId:'unassigned-context-hint',receivedAt:x.arrived_at,expiresAt:x.retain_until});}catch{return;}}
   const kind=x.source_kind==='sms'?'sms_number':'email_address',overlap=await this.overlap(auth.ownerId,{sourceId:x.source_id,kind,value,entryId,hint,fp,phrase:norm});
   const desc=['save',kind,value,hint,x.source_id,e.service_id,norm,fp!==null,overlap];
   return {e,desc,fp,hint,overlap,phrase:norm,sourceId:x.source_id,sourceLabel:x.source_label,serviceId:e.service_id,subject:[x.latest_event_id,x.arrived_at,x.template_fp??null,x.sender_digest],subjectId:contextId,entryId,retainUntil:x.retain_until,value,originKind:kind};
  }
  if(op==='resume'){
   // Explicit resume of ONE paused rule whose source is live again. Per rule, so each resume is attributable, shows its own overlap and (for shared entries) needs its own step-up.
   if(!ID.test(ruleId??'')||norm!==null)return;
   const q=await this.db.prepare('SELECT r.*,s.label AS source_label,s.revoked_at AS src_revoked,s.receiver AS src_receiver FROM service_routes r JOIN sources s ON s.owner_id=r.owner_id AND s.source_id=r.source_id WHERE r.owner_id=?1 AND r.route_id=?2 AND r.entry_id=?3').bind(auth.ownerId,ruleId,entryId).first();
   if(!q||q.service_id!==e.service_id)return;
   // Explicit, content-free refusal reasons. The rule stays paused in every refusal; nothing is overwritten or deleted.
   if(q.paused_at===null)return{refused:'not_paused'};
   if(q.src_revoked!==null||!q.src_receiver)return{refused:'source_revoked'};
   if(q.template_fp&&!this.keyIds.includes(digestKeyId(q.template_fp)))return{refused:'key_retired'}; // it could never match again
   if(await this.db.prepare('SELECT 1 AS x FROM service_routes WHERE owner_id=?1 AND source_id=?2 AND origin_kind=?3 AND origin_value=?4 AND entry_id IS NOT NULL AND entry_id<>?5 AND paused_at IS NULL AND (account_hint IS NULL OR ?6 IS NULL OR account_hint=?6) AND ((?7 IS NOT NULL AND template_fp=?7) OR (?8 IS NOT NULL AND phrase=?8) OR (template_fp IS NULL AND phrase IS NULL)) LIMIT 1').bind(auth.ownerId,q.source_id,q.origin_kind,q.origin_value,entryId,q.account_hint??null,q.template_fp??null,q.phrase??null).first())return{refused:'live_collision'}; // an active rule of another entry would tie with it
   const overlap=await this.overlap(auth.ownerId,{sourceId:q.source_id,kind:q.origin_kind,value:q.origin_value,entryId,hint:q.account_hint,fp:q.template_fp,phrase:q.phrase??null});
   const basis=q.template_fp?'template':'phrase';
   return {e,desc:['resume',q.origin_kind,q.origin_value,q.account_hint??null,q.source_id,q.service_id,basis,q.phrase??null,overlap],phrase:q.phrase??null,hint:q.account_hint??null,overlap,sourceId:q.source_id,sourceLabel:q.source_label,serviceId:q.service_id,subject:[q.phrase??null,q.template_fp??null,q.saved_template_fp??null,q.paused_at],subjectId:ruleId,entryId,originKind:q.origin_kind,value:q.origin_value,retainUntil:null,resumeBasis:basis};
  }
  if(!ID.test(ruleId??''))return;
  const r=await this.db.prepare('SELECT r.* FROM service_routes r WHERE r.owner_id=?1 AND r.route_id=?2 AND r.entry_id=?3 AND r.paused_at IS NULL').bind(auth.ownerId,ruleId,entryId).first();
  if(!r||r.service_id!==e.service_id||(r.phrase??null)===norm)return;
  if(norm===null&&!r.saved_template_fp)return; // nothing to restore
  const newFp=norm===null?r.saved_template_fp:null,newSaved=norm===null?null:(r.template_fp??r.saved_template_fp??null);
  if(newFp!==null&&!this.keyIds.includes(digestKeyId(newFp)))return; // key_retired: restoring this digest could never match
  const overlap=await this.overlap(auth.ownerId,{sourceId:r.source_id,kind:r.origin_kind,value:r.origin_value,entryId,hint:r.account_hint,fp:newFp,phrase:norm});
  const desc=['edit',r.origin_kind,r.origin_value,r.source_id,r.service_id,r.template_fp?'template':'phrase',r.phrase??null,norm===null?'template':'phrase',norm,overlap];
  return {e,desc,phrase:norm,newFp,newSaved,overlap,before:{basis:r.template_fp?'template':'phrase',phrase:r.phrase??null},sourceId:r.source_id,serviceId:r.service_id,subject:[r.phrase??null,r.template_fp??null,r.saved_template_fp??null],subjectId:ruleId,entryId,originKind:r.origin_kind,value:r.origin_value,retainUntil:null};
 }
 async begin(auth,{operation,contextId,ruleId,entryId,phrase,keyId}={}){
  if(!['review','edit','resume'].includes(operation))return;
  const android=auth?.clientKind==='android',now=this.now(),d=await this.derive(auth,operation,{contextId,ruleId,entryId,phrase},now);if(!d)return;if(d.refused)return{refused:d.refused};
  const e=d.e,priv=Number(e.recipients)===0&&Number(e.automation)===0;
  if(keyId!==undefined&&(!android||typeof keyId!=='string'||!keyId||keyId.length>128))return;
  if(android&&!priv&&keyId===undefined)return;
  const v2=android&&!priv,label=e.label??'',account=e.account_name??'',service=e.service_id??'';
  if(v2&&(label.length>64||account.length>128||service.length>128))return;
  await this.prepare();
  const intentId=crypto.randomUUID(),expiresAt=Math.min(now+TTL,d.retainUntil??Infinity),version=await hashText(JSON.stringify(d.subject));
  if(expiresAt<=now)return;
  const action=JSON.stringify(['otpanda-rule',v2?VERSION+1:VERSION,intentId,auth.ownerId,auth.deviceId,auth.generation,operation,d.subjectId,entryId,e.mutation_revision,version,d.retainUntil,Number(e.recipients),Number(e.automation),priv,JSON.stringify(d.desc),...(v2?[label,account,service]:[])]);
  if(new TextEncoder().encode(action).length>3072)return;
  const ins=await this.db.prepare(`INSERT INTO rule_intents(intent_id,owner_id,device_id,generation,operation,subject_id,source_id,entry_id,entry_revision,subject_json,action_digest,created_at,expires_at,result_expires_at) SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14 WHERE (SELECT count(*) FROM rule_intents WHERE owner_id=?2 AND consumed_at IS NULL AND retired_at IS NULL AND expires_at>?12)<${MAX_PENDING} AND EXISTS(SELECT 1 FROM device_sessions d ${MJ} JOIN account_security s ON s.owner_id=d.owner_id WHERE d.device_id=?3 AND d.owner_id=?2 AND d.generation=?4 AND s.generation=?4 AND d.client_kind IN ('web','android') AND d.revoked_at IS NULL AND ${MA} AND d.created_at<=?12 AND d.expires_at>?12)`).bind(intentId,auth.ownerId,auth.deviceId,auth.generation,operation,d.subjectId,d.sourceId,entryId,e.mutation_revision,JSON.stringify(d.subject),await hashText(action),now,expiresAt,now+RECEIPT).run();
  if(ins.meta.changes!==1)return;
  try{
   const summary={operation:operation==='review'?'rule-from-review':operation==='resume'?'rule-resume':'rule-edit',entryId,label:e.label,accountName:e.account_name,serviceId:e.service_id,sender:d.value,senderKind:d.originKind,sourceLabel:d.sourceLabel??null,basis:operation==='resume'?d.resumeBasis:d.phrase!==null?'phrase':'template',phrase:d.phrase,futureRecipients:Number(e.recipients),futureAutomations:Number(e.automation),otherAccountRules:d.overlap,
    ...(operation==='review'?{addressScope:d.hint?'receiving-address':'any-address-on-connector',previewRemoved:true}:operation==='resume'?{addressScope:d.hint?'receiving-address':'any-address-on-connector',resumesPausedRule:true}:{basisBefore:d.before.basis,phraseBefore:d.before.phrase,mayMatchOtherTemplates:true}),irreversible:false};
   if(priv)return{intentId,expiresAt,summary,action,proofRequired:false};
   if(v2){const c=await this.deviceKeys.beginProof({owner:auth.ownerId,keyId,purpose:'step-up',actionDigest:await hashText(action),browserBinding:await deviceBinding(auth.deviceId,intentId)});if(!c||c.challenge.ownerId!==auth.ownerId||c.challenge.generation!==auth.generation){await this.discard(intentId,{unissued:true});return;}return{intentId,token:c.token,challenge:c.challenge,expiresAt,summary,action,proofRequired:true};}
   const ceremony=await this.passkeys.begin({purpose:'step-up',ownerId:auth.ownerId,binding:intentId,action:await hashText(action)});
   if(!ceremony){await this.discard(intentId,{unissued:true});return;}
   return{intentId,token:ceremony.token,options:ceremony.options,expiresAt,summary,action,proofRequired:true};
  }catch(error){await this.discard(intentId,{unissued:true});throw error;}
 }
 async discard(intentId,{unissued=false}={}){
  if(unissued){await this.db.prepare('DELETE FROM rule_intents WHERE intent_id=?1 AND consumed_at IS NULL').bind(intentId).run();return;}
  await this.db.prepare('UPDATE rule_intents SET retired_at=?2 WHERE intent_id=?1 AND consumed_at IS NULL AND retired_at IS NULL').bind(intentId,this.now()).run();
 }
 async status(auth,intentId){
  if(!auth||!idOk(intentId))return;const now=this.now();
  await this.db.prepare(`UPDATE rule_intents AS i SET retired_at=?2 WHERE i.intent_id=?1 AND i.owner_id=?3 AND i.device_id=?4 AND i.generation=?5 AND i.result_expires_at>?2 AND i.expires_at<=?2 AND i.consumed_at IS NULL AND i.retired_at IS NULL AND ${active}`).bind(intentId,now,auth.ownerId,auth.deviceId,auth.generation).run();
  const row=await this.db.prepare(`SELECT i.consumed_at,i.retired_at,i.rule_result,i.rule_json FROM rule_intents i WHERE i.intent_id=?1 AND i.owner_id=?3 AND i.device_id=?4 AND i.generation=?5 AND i.result_expires_at>?2 AND ${active}`).bind(intentId,this.now(),auth.ownerId,auth.deviceId,auth.generation).first();
  return row?{status:row.consumed_at!==null?'applied':row.retired_at!==null?'not-applied':'pending',...(row.consumed_at!==null&&row.rule_result?{rule:row.rule_result==='paused'?{status:'paused',ruleId:(()=>{try{return JSON.parse(row.rule_json)[1]??null;}catch{return null;}})(),resumeRequiresSignedAction:true}:{status:row.rule_result}}:{})}:undefined;
 }
 async finish(auth,{intentId,token,action,response,signature}={}){
  const android=auth?.clientKind==='android';
  if(!auth||!idOk(intentId)||typeof action!=='string'||action.length>4096)return;
  const prior=await this.status(auth,intentId);if(['applied','not-applied'].includes(prior?.status))return prior;
  const now=this.now(),row=await this.db.prepare(`SELECT i.* FROM rule_intents i WHERE i.intent_id=?1 AND i.owner_id=?3 AND i.device_id=?4 AND i.generation=?5 AND i.consumed_at IS NULL AND i.retired_at IS NULL AND i.created_at<=?2 AND i.expires_at>?2 AND ${active}`).bind(intentId,now,auth.ownerId,auth.deviceId,auth.generation).first();
  if(!row||await hashText(action)!==row.action_digest)return;
  let parsed;try{parsed=JSON.parse(action);}catch{return;}
  if(!Array.isArray(parsed)||parsed[0]!=='otpanda-rule'||parsed[2]!==intentId||parsed[3]!==auth.ownerId||parsed[4]!==auth.deviceId||parsed[5]!==auth.generation||parsed[6]!==row.operation)return;
  const priv=parsed[1]===VERSION&&parsed[12]===0&&parsed[13]===0&&parsed[14]===true,deviceShared=android&&!priv;
  if(priv?(token!==undefined||response!==undefined||signature!==undefined):deviceShared?(parsed.length!==18||parsed[1]!==VERSION+1||typeof signature!=='string'||response!==undefined||!parseAccessToken(token)):(parsed.length!==16||parsed[1]!==VERSION||signature!==undefined))return;
  let claimed=false,committed=false;
  try{
   let proof;
   if(deviceShared){claimed=true;proof=await this.deviceKeys.finish({token,browserBinding:await deviceBinding(auth.deviceId,intentId),signature});if(!proof||proof.purpose!=='step-up'||proof.ownerId!==auth.ownerId||proof.generation!==auth.generation||proof.actionDigest!==row.action_digest)return;}
   else if(!priv){proof=await this.passkeys.finishAuthentication({token,binding:intentId,ownerId:auth.ownerId,action:row.action_digest,response,onCeremonyClaimed:()=>{claimed=true;}});if(!proof||proof.purpose!=='step-up'||proof.ownerId!==auth.ownerId||proof.generation!==auth.generation||proof.actionDigest!==await hashText(row.action_digest))return;}
   if(priv)claimed=true;
   // Re-derive from the current rows using the signed phrase. Any drift (row replaced, edited, entry changed) means nothing is written.
   let signedDesc;try{signedDesc=JSON.parse(parsed[15]);}catch{return;}
   const phrase=row.operation==='review'?signedDesc[6]:row.operation==='resume'?undefined:signedDesc[8];
   const d=await this.derive(auth,row.operation,{contextId:row.operation==='review'?row.subject_id:undefined,ruleId:row.operation!=='review'?row.subject_id:undefined,entryId:row.entry_id,phrase},this.now());
   if(!d||JSON.stringify(d.desc)!==parsed[15]||JSON.stringify(d.subject)!==row.subject_json||Number(d.e.mutation_revision)!==row.entry_revision||Number(d.e.recipients)!==parsed[12]||Number(d.e.automation)!==parsed[13])return;
   if(parsed[10]!==await hashText(row.subject_json))return;
   const finished=this.now();if(proof&&(finished<proof.verifiedAt||finished-proof.verifiedAt>=300000))return;
   const privPred=`NOT EXISTS(SELECT 1 FROM entry_readers m WHERE m.entry_id=i.entry_id AND m.revoked_at IS NULL) AND NOT EXISTS(SELECT 1 FROM entry_tokens t WHERE t.entry_id=i.entry_id AND t.revoked_at IS NULL AND t.created_at<=?2 AND t.expires_at>?2)`;
   const sharedPred=deviceShared?`EXISTS(SELECT 1 FROM device_sessions dk WHERE dk.device_id=i.device_id AND dk.client_kind='android') AND EXISTS(SELECT 1 FROM durable_device_keys k WHERE k.key_id=?6 AND k.owner_id=i.owner_id AND k.revoked_at IS NULL AND k.generation=i.generation)`:`EXISTS(SELECT 1 FROM device_sessions dk WHERE dk.device_id=i.device_id AND dk.client_kind='web') AND EXISTS(SELECT 1 FROM passkey_credentials p WHERE p.credential_id=?6 AND p.owner_id=i.owner_id AND p.revoked_at IS NULL)`;
   const subjectPred=row.operation==='review'
    ?`EXISTS(SELECT 1 FROM unassigned_context x JOIN sources s ON s.owner_id=x.owner_id AND s.source_id=x.source_id WHERE x.owner_id=i.owner_id AND x.context_id=i.subject_id AND x.latest_event_id=json_extract(i.subject_json,'$[0]') AND x.arrived_at=json_extract(i.subject_json,'$[1]') AND x.template_fp IS json_extract(i.subject_json,'$[2]') AND x.sender_digest=json_extract(i.subject_json,'$[3]') AND x.retain_until>?2 AND s.revoked_at IS NULL AND s.receiver IS NOT NULL)`
    :row.operation==='resume'?`EXISTS(SELECT 1 FROM service_routes r JOIN sources s ON s.owner_id=r.owner_id AND s.source_id=r.source_id WHERE r.owner_id=i.owner_id AND r.route_id=i.subject_id AND r.entry_id=i.entry_id AND r.paused_at IS json_extract(i.subject_json,'$[3]') AND s.revoked_at IS NULL AND r.phrase IS json_extract(i.subject_json,'$[0]') AND r.template_fp IS json_extract(i.subject_json,'$[1]') AND r.saved_template_fp IS json_extract(i.subject_json,'$[2]'))`
    :`EXISTS(SELECT 1 FROM service_routes r WHERE r.owner_id=i.owner_id AND r.route_id=i.subject_id AND r.entry_id=i.entry_id AND r.paused_at IS NULL AND r.phrase IS json_extract(i.subject_json,'$[0]') AND r.template_fp IS json_extract(i.subject_json,'$[1]') AND r.saved_template_fp IS json_extract(i.subject_json,'$[2]'))`;
   const guard=`i.intent_id=?1 AND i.consumed_at IS NULL AND i.retired_at IS NULL AND i.created_at<=?2 AND i.expires_at>?2 AND i.owner_id=?3 AND i.device_id=?4 AND i.generation=?5 AND ${active} AND ${pinnedAudience('i.entry_id','i.owner_id','?2',parsed[12],parsed[13])} AND ${priv?privPred:sharedPred} AND ${subjectPred} AND EXISTS(SELECT 1 FROM entries e WHERE e.owner_id=i.owner_id AND e.entry_id=i.entry_id AND e.mutation_revision=i.entry_revision)`;
   const ruleId='rr-'+intentId,consumed='EXISTS(SELECT 1 FROM rule_intents WHERE intent_id=?1 AND consumed_at=?2)';
   const stmts=[this.db.prepare(`UPDATE rule_intents AS i SET consumed_at=?2 WHERE ${guard}`).bind(...[intentId,finished,auth.ownerId,auth.deviceId,auth.generation,...(priv?[]:[deviceShared?proof.keyId:proof.credentialId])])];
   const desc=d.desc;
   if(row.operation==='review'){
    const [,kind,value,hint,sourceId,serviceId,ph,usesFp]=desc;
    stmts.push(this.db.prepare(`INSERT INTO service_routes(route_id,owner_id,service_id,source_id,origin_kind,origin_value,entry_id,account_hint,phrase,created_at,template_fp) SELECT ?3,?4,?5,?6,?7,?8,?9,?12,?10,?2,?11 WHERE changes()=1 AND ${consumed} ON CONFLICT DO NOTHING`).bind(intentId,finished,ruleId,auth.ownerId,serviceId,sourceId,kind,value,row.entry_id,ph,usesFp?d.fp:null,hint));
    const match=`EXISTS(SELECT 1 FROM service_routes WHERE owner_id=?3 AND source_id=?4 AND origin_kind=?5 AND origin_value=?6 AND entry_id=?7 AND account_hint IS ?8 AND phrase IS ?9 AND template_fp IS ?10)`;
    const mw=match.slice('EXISTS(SELECT 1 FROM service_routes WHERE '.length,-1);
    const mb=[auth.ownerId,sourceId,kind,value,row.entry_id,hint,ph,usesFp?d.fp:null];
    stmts.push(this.db.prepare(`DELETE FROM unassigned_context WHERE owner_id=?3 AND context_id=?11 AND latest_event_id=?12 AND arrived_at=?13 AND template_fp IS ?14 AND sender_digest=?15 AND ${consumed} AND ${match.slice(0,-1)+' AND paused_at IS NULL)'}`).bind(intentId,finished,...mb,row.subject_id,...d.subject));
    stmts.push(this.db.prepare(`UPDATE rule_intents SET rule_json=CASE WHEN NOT EXISTS(SELECT 1 FROM service_routes WHERE route_id=?4) AND ${shift(match.slice(0,-1)+' AND paused_at IS NOT NULL)')} THEN json_array('paused',(SELECT route_id FROM service_routes WHERE ${shift(mw)} AND paused_at IS NOT NULL LIMIT 1)) ELSE ?3 END,rule_result=CASE WHEN EXISTS(SELECT 1 FROM service_routes WHERE route_id=?4) THEN 'saved' WHEN ${shift(match.slice(0,-1)+' AND paused_at IS NULL)')} THEN 'exists' WHEN ${shift(match.slice(0,-1)+' AND paused_at IS NOT NULL)')} THEN 'paused' ELSE 'unavailable' END WHERE intent_id=?1 AND consumed_at=?2`).bind(intentId,finished,JSON.stringify(desc),ruleId,...mb));
   }else if(row.operation==='resume'){
    stmts.push(this.db.prepare(`UPDATE service_routes SET paused_at=NULL WHERE owner_id=?3 AND route_id=?4 AND entry_id=?5 AND paused_at IS ?6 AND phrase IS ?7 AND template_fp IS ?8 AND saved_template_fp IS ?9 AND EXISTS(SELECT 1 FROM sources s WHERE s.owner_id=service_routes.owner_id AND s.source_id=service_routes.source_id AND s.revoked_at IS NULL) AND NOT EXISTS(SELECT 1 FROM service_routes o WHERE o.owner_id=service_routes.owner_id AND o.source_id=service_routes.source_id AND o.origin_kind=service_routes.origin_kind AND o.origin_value=service_routes.origin_value AND o.entry_id IS NOT NULL AND o.entry_id<>service_routes.entry_id AND o.paused_at IS NULL AND (o.account_hint IS NULL OR service_routes.account_hint IS NULL OR o.account_hint=service_routes.account_hint) AND ((service_routes.template_fp IS NOT NULL AND o.template_fp=service_routes.template_fp) OR (service_routes.phrase IS NOT NULL AND o.phrase=service_routes.phrase) OR (o.template_fp IS NULL AND o.phrase IS NULL))) AND changes()=1 AND ${consumed}`).bind(intentId,finished,auth.ownerId,row.subject_id,row.entry_id,d.subject[3],d.subject[0],d.subject[1],d.subject[2]));
    stmts.push(this.db.prepare(`UPDATE rule_intents SET rule_json=?3,rule_result=CASE WHEN EXISTS(SELECT 1 FROM service_routes WHERE owner_id=?4 AND route_id=?5 AND paused_at IS NULL) THEN 'resumed' ELSE 'unavailable' END WHERE intent_id=?1 AND consumed_at=?2`).bind(intentId,finished,JSON.stringify(desc),auth.ownerId,row.subject_id));
   }else{
    stmts.push(this.db.prepare(`UPDATE service_routes SET phrase=?3,template_fp=?4,saved_template_fp=?5 WHERE owner_id=?6 AND route_id=?7 AND entry_id=?8 AND paused_at IS NULL AND phrase IS ?9 AND template_fp IS ?10 AND saved_template_fp IS ?11 AND changes()=1 AND ${consumed}`).bind(intentId,finished,d.phrase,d.newFp,d.newSaved,auth.ownerId,row.subject_id,row.entry_id,...d.subject));
    stmts.push(this.db.prepare(`UPDATE rule_intents SET rule_json=?3,rule_result=CASE WHEN EXISTS(SELECT 1 FROM service_routes WHERE owner_id=?4 AND route_id=?5 AND phrase IS ?6 AND template_fp IS ?7 AND saved_template_fp IS ?8) THEN 'updated' ELSE 'unavailable' END WHERE intent_id=?1 AND consumed_at=?2`).bind(intentId,finished,JSON.stringify(desc),auth.ownerId,row.subject_id,d.phrase,d.newFp,d.newSaved));
   }
   let results;
   try{results=await this.db.batch(stmts);}catch(error){if(/UNIQUE/i.test(String(error?.message)))return;throw error;}
   if(results[0]/*exact-count-ok: rule_intents has no triggers*/.meta.changes!==1)return;
   committed=true;
   const done=await this.db.prepare('SELECT rule_result,rule_json FROM rule_intents WHERE intent_id=?1').bind(intentId).first();
   if(done?.rule_result==='paused'){let id=null;try{id=JSON.parse(done.rule_json)[1]??null;}catch{}return{status:'applied',rule:{status:'paused',ruleId:id,resumeRequiresSignedAction:true}};}
   return{status:'applied',rule:{status:done?.rule_result??'unavailable'}};
  }finally{if(claimed&&!committed)await this.discard(intentId);}
 }
 async cleanup({limit=100}={}){if(!Number.isSafeInteger(limit)||limit<1||limit>500)throw new TypeError('Bounded cleanup required');return(await this.db.prepare('DELETE FROM rule_intents WHERE intent_id IN(SELECT intent_id FROM rule_intents WHERE result_expires_at<=?1 ORDER BY result_expires_at LIMIT ?2)').bind(this.now(),limit).run()).meta.changes;}
}
const shift=s=>s.replace(/\?(\d+)/g,(x,n)=>'?'+(Number(n)+2));
const ownerParam=a=>a.ownerId;
