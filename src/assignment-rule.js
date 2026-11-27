import {hashText} from './sessions.js';
import {normalizeEmail,normalizePhone,normalizePhrase} from './service-metadata.js';
// The rule that a signed Assign would save, derived ONLY from the code row, its source and the entry. Never a whole connector: the exact sender is mandatory.
// Result is the exact array that is placed into the signed action: ['save',senderKind,sender,hint|null,sourceId,serviceId,phrase|null] or ['none',reason].
// reasons: template_unavailable (no phrase chosen and the message has no template digest: digest off, or the code could not be located in an SMS), receiver_unset (source has no receiving address), sender_unknown (legacy code without a stored sender), sender_invalid, service_unsupported (no services row for the entry's service).
export async function describeRule({db,cipher,row,ownerId,sourceId,eventId,phrase=null}){
 phrase=normalizePhrase(phrase);
 if(!row.source_receiver)return ['none','receiver_unset'];
 if(!row.sender_envelope)return ['none','sender_unknown'];
 let sender,hint;
 try{const v=JSON.parse(await cipher.decrypt(JSON.parse(row.sender_envelope),{ownerId,recordId:await hashText(JSON.stringify([sourceId,eventId,'sender'])),serviceId:'sender',receivedAt:row.received_at,expiresAt:row.expires_at}));sender=v.sender;hint=v.accountHint??null;}catch{return ['none','sender_unknown'];}
 const sms=row.source_kind==='sms';let value;
 try{value=sms?normalizePhone(sender):normalizeEmail(sender);}catch{return ['none','sender_invalid'];}
 if(!(await db.prepare('SELECT 1 AS x FROM services WHERE service_id=?1').bind(row.service_id).first()))return ['none','service_unsupported'];
 // Default basis is the keyed template digest held on the code row (never text). An explicit phrase replaces it. No digest and no phrase: no rule (never a bare sender rule).
 const fp=phrase===null?(row.template_fp??null):null;
 if(phrase===null&&fp===null)return ['none','template_unavailable'];
 return ['save',sms?'sms_number':'email_address',value,hint,sourceId,row.service_id,phrase,fp];
}
