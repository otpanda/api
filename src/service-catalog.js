// Internal public-reference catalog. Recognition is a suggestion, never sender
// authentication, an account match, source assignment, or permission to read.
// No network, private-message ingestion, database writes, or global learning.
import {normalizeDomain,normalizeEmail,normalizePhone} from './service-metadata.js';
const DAY=86400000,MAX_AGE=90*DAY;
function text(v,max){if(typeof v!=='string'||!v||v!==v.trim()||v.length>max||/[\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069]/u.test(v))throw new TypeError('Invalid public catalog text');return v;}
function exact(v,keys){if(!v||typeof v!=='object'||Array.isArray(v)||Object.keys(v).length!==keys.length||keys.some(k=>!Object.hasOwn(v,k)))throw new TypeError('Invalid public catalog record');}
function host(v){const h=normalizeDomain(v);if(!h.includes('.')||/^[0-9.]+$/.test(h)||h.endsWith('.local')||h.endsWith('.localhost')||h.endsWith('.internal'))throw new TypeError('Public hostname required');return h;}
function url(v){text(v,2048);let u;try{u=new URL(v);}catch{throw new TypeError('Public HTTPS evidence required');}if(u.protocol!=='https:'||u.username||u.password||u.port||u.search||u.hash)throw new TypeError('Public HTTPS evidence required');host(u.hostname);return u.href;}
function key(v){text(v,128);if(!/^[a-z0-9][a-z0-9_.-]*$/.test(v))throw new TypeError('Stable public catalog ID required');return v;}
function region(v){if(typeof v!=='string'||!/^[A-Z]{2}$/.test(v))throw new TypeError('Explicit SMS country code required');return v;}
function sender(kind,value,country){
 if(kind==='email_address'){if(country!==null)throw new TypeError('Unexpected country');return normalizeEmail(text(value,320));}
 if(kind==='email_domain'){if(country!==null)throw new TypeError('Unexpected country');return host(value);}
 if(kind==='sms_number'){if(country!==null)throw new TypeError('Unexpected country');return normalizePhone(value);}
 if(kind==='sms_shortcode'){region(country);if(typeof value!=='string'||!/^\d{3,6}$/.test(value))throw new TypeError('Exact SMS short code required');return value;}
 if(kind==='sms_name'){region(country);if(typeof value!=='string'||!/(?=.{1,11}$)(?=.*[A-Za-z])^[A-Za-z0-9 ]+$/.test(value)||value!==value.trim())throw new TypeError('Exact SMS sender name required');return value;}
 throw new TypeError('Known public origin kind required');
}
export class ServiceCatalog {
 #services=new Map();#mappings=[];#clock;
 constructor({services,mappings,clock=Date.now}={}){
  if(!Array.isArray(services)||services.length>1000||!Array.isArray(mappings)||mappings.length>5000||new TextEncoder().encode(JSON.stringify({services,mappings})).byteLength>2097152)throw new TypeError('Bounded public catalog required');
  if(typeof clock!=='function')throw new TypeError('Clock required');this.#clock=clock;
  for(const s of services){exact(s,['serviceId','name','websiteHost']);const id=key(s.serviceId);if(this.#services.has(id))throw new TypeError('Duplicate service');this.#services.set(id,Object.freeze({serviceId:id,name:text(s.name,120),websiteHost:host(s.websiteHost)}));}
  const ids=new Set();
  for(const m of mappings){
   exact(m,['mappingId','serviceId','originKind','originValue','country','evidence']);const mappingId=key(m.mappingId),service=this.#services.get(m.serviceId);if(!service||ids.has(mappingId))throw new TypeError('Unknown service or duplicate mapping');ids.add(mappingId);
   exact(m.evidence,['kind','url','checkedAt','expiresAt']);const e=m.evidence;
   // A directory or observed user message is not evidence of an OTP sender.
   if(e.kind!=='official_support')throw new TypeError('Official public sender evidence required');
   const evidenceUrl=url(e.url),evidenceHost=new URL(evidenceUrl).hostname;
   if(evidenceHost!==service.websiteHost&&!evidenceHost.endsWith('.'+service.websiteHost))throw new TypeError('Evidence must be on the service website');
   if(!Number.isSafeInteger(e.checkedAt)||e.checkedAt<0||!Number.isSafeInteger(e.expiresAt)||e.expiresAt<=e.checkedAt||e.expiresAt-e.checkedAt>MAX_AGE)throw new TypeError('Bounded evidence freshness required');
   this.#mappings.push(Object.freeze({mappingId,serviceId:service.serviceId,originKind:m.originKind,originValue:sender(m.originKind,m.originValue,m.country),country:m.country,evidence:Object.freeze({kind:e.kind,url:evidenceUrl,checkedAt:e.checkedAt,expiresAt:e.expiresAt})}));
  }
  Object.freeze(this.#mappings);
 }
 suggest({channel,sender:input,country=null}={}){
  if(!['email','sms'].includes(channel))throw new TypeError('Known input channel required');
  const now=this.#clock();if(!Number.isSafeInteger(now)||now<0)throw new TypeError('Valid clock required');
  let address,domain;
  try{if(channel==='email'){address=normalizeEmail(text(input,320));domain=address.slice(address.lastIndexOf('@')+1);}else text(input,32);}catch{return {status:'unrecognized',suggestions:[]};}
  const matches=this.#mappings.filter(m=>{
   if(m.evidence.checkedAt>now||m.evidence.expiresAt<=now)return false;
   if(channel==='email')return m.originKind==='email_address'?m.originValue===address:m.originKind==='email_domain'&&m.originValue===domain;
   if(!m.originKind.startsWith('sms_')||(m.country!==null&&m.country!==country))return false;
   return m.originValue===input;
  });
  const candidates=new Map();
  for(const m of matches){if(!candidates.has(m.serviceId))candidates.set(m.serviceId,{...this.#services.get(m.serviceId),evidence:[]});candidates.get(m.serviceId).evidence.push({...m.evidence,mappingId:m.mappingId,originKind:m.originKind});}
  const suggestions=[...candidates.values()].sort((a,b)=>a.serviceId<b.serviceId?-1:a.serviceId>b.serviceId?1:0);
  // No entryId, receiver, code, private source, or raw sender is returned.
  return {status:suggestions.length>1?'ambiguous':suggestions.length?'suggested':'unrecognized',suggestions};
 }
 toString(){return 'ServiceCatalog(public reference suggestions only)';}
}
