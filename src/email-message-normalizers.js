// Pure provider JSON to normalized message. No network, no body persistence.
// Gmail has no normalizer here: its raw mail is parsed in gmail-message.js.
const stripHtml=h=>h.replace(/<(style|script)[\s\S]*?<\/\1>/gi,' ').replace(/<[^>]+>/g,' ').replace(/&nbsp;/g,' ').replace(/&amp;/g,'&').replace(/\s+/g,' ');
// Outlook is not enabled: ingestEmail rejects provider 'outlook' until it is designed and approved.
export function normalizeOutlookMessage(m){
  const body=m?.body?.contentType==='html'?stripHtml(m.body.content||''):(m?.body?.content||'');
  return {id:m?.id,from:m?.from?.emailAddress?.address,to:m?.toRecipients?.[0]?.emailAddress?.address,subject:m?.subject||'',text:body,receivedAt:Date.parse(m?.receivedDateTime),provider:'outlook'};
}
