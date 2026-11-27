// Redaction of a message body (SMS) or subject (email) before it may be stored as review context. Pure. Fails closed: when it cannot prove the result holds no code, it returns null
// and the caller stores no context. Every digit group that could be a code is masked, independent of which single code the extractor chose, then the chosen code is masked in any
// separator-formatted or case variant, then the result is checked again. Truncation happens only AFTER redaction. The result is never the raw text.
const MASK='******';
const SEP='[ \\-._\\u00a0\\u2010-\\u2015\\u2212]{0,2}';
const DIGITS=new RegExp('(?<!\\p{Nd})\\p{Nd}(?:'+SEP+'\\p{Nd}){3,}','gu'); // 4+ digits of any script with up to two separator characters between digits: 123456, 123-456, 12 34 56, 123  456, 1234.5678
const MIXED=/(?<![A-Za-z0-9])(?=[A-Za-z0-9-]*\d)(?=[A-Za-z0-9-]*[A-Za-z])[A-Za-z0-9][A-Za-z0-9-]{3,31}(?![A-Za-z0-9])/g; // any letter+digit token of 4 to 32 characters could be an alphanumeric code
const URLS=/(?:[a-z][a-z0-9+.-]{1,15}:\/\/|www\.)[^\s<>"']*|(?<![@\w.-])(?:[a-z0-9-]+\.)+[a-z]{2,}\/[^\s<>"']*/gi; // links can carry reusable tokens: the whole link is masked
const LONG=/[A-Za-z0-9_+\/=]{12,}/g;
const opaque=r=>/[\d_+\/=]/.test(r)||/[a-z][A-Z]/.test(r)||r.length>=20; // opaque: digits, symbols, internal capitals, or 20+ letters. Ordinary long words (verification, authentication) stay.
const CONTROL=/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069\ufeff]/g;
const enc=new TextEncoder();
function escapeRe(c){return c.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');}
export function redactContext(text,{code,maxBytes}={}){
  if(typeof text!=='string'||!text||text.length>20000)return null;
  if(typeof code!=='string'||!/^[A-Za-z0-9-]{4,32}$/.test(code))return null;
  if(!Number.isSafeInteger(maxBytes)||maxBytes<16||maxBytes>4096)return null;
  let t=text.normalize('NFKC').replace(CONTROL,' ');
  const chars=[...code.replace(/-/g,'')];
  if(chars.length<4)return null;
  // the chosen code first (so a split like 'ab 12-cd' is masked whole), then every other code-like group
  t=t.replace(new RegExp(chars.map(escapeRe).join('[\\s\\-._\\u00a0]{0,2}'),'gi'),MASK);
  t=t.replace(URLS,MASK).replace(LONG,r=>opaque(r)?MASK:r).replace(DIGITS,MASK).replace(MIXED,MASK);
  // verification, on the redacted text itself
  const flat=t.toLowerCase().replace(/[^a-z0-9]/g,'');
  if(flat.includes(chars.join('').toLowerCase()))return null;
  if(new RegExp(DIGITS.source,'u').test(t)||new RegExp(MIXED.source).test(t)||(t.match(new RegExp(LONG.source,'g'))||[]).some(opaque)||/:\/\/|www\./i.test(t))return null;
  t=t.replace(/\s+/g,' ').trim();
  if(!t)return null;
  const bytes=enc.encode(t);
  if(bytes.length<=maxBytes)return {text:t,truncated:false};
  let cut='';for(const ch of t){if(enc.encode(cut+ch).length>maxBytes)break;cut+=ch;}
  cut=cut.trimEnd();
  return cut?{text:cut,truncated:true}:null;
}
