// Keyed, versioned fingerprint of a message TEMPLATE. The text is never stored: only an HMAC-SHA-256 digest scoped to owner+source.
// Canonical form (v1), applied identically at ingest and at rule creation:
//  1. NFC (canonical equivalence only; NFKC would fold distinct characters together and could widen a match);
//  2. the known code is located (digits/letters, up to two separators between characters) and removed. An SMS whose code cannot be located has NO fingerprint;
//  3. EVERY Unicode decimal digit (\p{Nd}) is removed, so amounts, dates and times do not change the template (user instruction, Nov 27 10:17);
//  4. locale-independent lowercase, all Unicode whitespace collapsed to one space, trim.
// An empty result, or one that still contains the code, has no fingerprint (fail closed). The digest never appears in listings, logs or recipient views.
export const TEMPLATE_VERSION='v1';
const MIN=32;
export function parseDigestSecret(value){
  if(typeof value!=='string')return null;
  let bytes=null;
  if(/^[0-9a-fA-F]+$/.test(value)&&value.length%2===0)bytes=Uint8Array.from(value.match(/../g),h=>parseInt(h,16));
  else if(/^[A-Za-z0-9_-]+$/.test(value)){try{const b=atob(value.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-value.length%4)%4));bytes=Uint8Array.from(b,c=>c.charCodeAt(0));}catch{return null;}}
  if(!bytes||bytes.length<MIN||new Set(bytes).size<8)return null;
  return bytes;
}
const esc=c=>c.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
const SEP='[\\s\\-._\\u00a0\\u2010-\\u2015\\u2212]{0,2}';
// kind 'sms': the text must contain the code. kind 'email': text is the SUBJECT only; a code that lives only in the body leaves the subject unchanged and is valid.
export function normalizeTemplate(text,{code,kind}){
  if(typeof text!=='string'||!text||text.length>20000||typeof code!=='string'||!/^[A-Za-z0-9-]{4,32}$/.test(code)||!['sms','email'].includes(kind))return null;
  const chars=[...code.replace(/-/g,'')];
  let t=text.normalize('NFC');
  // A code with letters is matched only at word boundaries, so it cannot eat part of a longer word. A numeric code needs no anchor: every digit is removed below anyway.
  const alnum=/[^\d]/.test(code),body=chars.map(esc).join(SEP),src=alnum?'(?<![\\p{L}\\p{N}])'+body+'(?![\\p{L}\\p{N}])':body;
  const found=new RegExp(src,'iu').test(t);
  if(!found&&kind==='sms'&&alnum)return null;
  t=t.replace(new RegExp(src,'giu'),' ');
  t=t.replace(/\p{Nd}/gu,'').toLowerCase().replace(/[\s\u00a0]+/gu,' ').trim().normalize('NFC');
  // Empty, or no letter at all ("<#> 123456", "(123456)"), would match every bare-code message from the sender: no fingerprint.
  if(!t||!/\p{L}/u.test(t))return null;
  if(/[a-z]/i.test(code)&&t.replace(/[^\p{L}\p{N}]/gu,'').includes(chars.join('').toLowerCase()))return null;
  return t;
}
// Key ring. CONTEXT_DIGEST_SECRET alone is the single legacy key with id 0000 and keeps working unchanged. CONTEXT_DIGEST_KEYRING ('id:secret,id:secret', at most 4, ids are 4 hex chars, the FIRST is
// active) adds replacement keys; when both are set the ring wins and the legacy secret only joins the ring as 0000 if not listed. A stored digest is 'v1:'+4-hex key id+60 hex of the MAC (same 67 characters as before, so the
// column check is unchanged). Ingest matches under every configured key; a rule whose key id is not configured is reported as needs_reassign and never matches (it is not dropped).
export function parseDigestKeys(secret,keyring){
  const keys=[];
  if(typeof keyring==='string'&&keyring.trim()){
    for(const part of keyring.split(',')){const i=part.indexOf(':'),id=part.slice(0,i).trim().toLowerCase(),bytes=i>0?parseDigestSecret(part.slice(i+1).trim()):null;if(!/^[0-9a-f]{4}$/.test(id)||!bytes||keys.some(k=>k.id===id))return null;keys.push({id,bytes});}
    if(keys.length>4)return null;
  }
  if(secret!==null&&secret!==undefined&&secret!==''){const bytes=parseDigestSecret(secret);if(!bytes)return null;if(!keys.some(k=>k.id==='0000'))keys.push({id:'0000',bytes});}
  return keys.length?keys:null;
}
export const digestKeyId=fp=>typeof fp==='string'&&/^v1:[0-9a-f]{64}$/.test(fp)?fp.slice(3,7):null;
export async function templateDigest(keyOrSecret,ownerId,sourceId,normalized){
  const secret=keyOrSecret?.bytes??keyOrSecret,kid=keyOrSecret?.id??'0000';
  const key=await crypto.subtle.importKey('raw',secret,{name:'HMAC',hash:'SHA-256'},false,['sign']);
  const mac=new Uint8Array(await crypto.subtle.sign('HMAC',key,new TextEncoder().encode(JSON.stringify(['otpanda-template-'+TEMPLATE_VERSION,ownerId,sourceId,normalized]))));
  return TEMPLATE_VERSION+':'+kid+[...mac].map(b=>b.toString(16).padStart(2,'0')).join('').slice(0,60);
}
export const TEMPLATE_DIGEST=/^v1:[0-9a-f]{64}$/;
