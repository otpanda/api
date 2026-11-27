import { extractEmailCode, extractExpiry } from './email-code-extractor.js';
// Turns a normalized provider message into one SourceEntryStore event. The message arrived through the
// owner's authorized mailbox, so it is theirs to collect. The sender is NOT authenticated: it is only
// a match key for assignment rules (sender and receiving address) and is never shown as verified.
// Only the extracted code, sender address and receiving address are kept.
// Outlook stays disabled until it is designed and approved on its own.
const addr=v=>typeof v==='string'&&v.length>0&&v.length<=256?v.trim().toLowerCase():undefined;
export async function ingestEmail(store,ownerId,sourceId,message){
  if(!message||typeof message.id!=='string'||!Number.isSafeInteger(message.receivedAt))return {ingested:false,reason:'invalid'};
  if(message.provider!=='gmail')return {ingested:false,reason:'provider_disabled'};
  const text=`${message.subject??''}\n${message.text??''}`;
  const code=extractEmailCode(text);
  if(!code)return {ingested:false,reason:'no-code'};
  const r=await store.receive(ownerId,{sourceId,eventId:message.id,code,receivedAt:message.receivedAt,expiresAt:extractExpiry(text,message.receivedAt),text,subject:typeof message.subject==='string'?message.subject:undefined,sender:addr(message.from),receiver:addr(message.to),accountHint:addr(message.to),context:{kind:'email',text:message.subject}});
  return {ingested:r.inserted,reason:r.inserted?'stored':'duplicate',entryId:r.entryId};
}
