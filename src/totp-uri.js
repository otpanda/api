// Pure, internal provisioning parser. No enrollment, storage, source assignment,
// sharing or logging. Format: Google Authenticator Key URI Format wiki.
import {decodeBase32} from './totp.js';
const fail=()=>{throw new TypeError('Invalid or unsupported TOTP provisioning URI');};
function decode(v){try{if(/%(?![0-9a-f]{2})/i.test(v))return fail();return decodeURIComponent(v);}catch{return fail();}}
function label(v){if(!v||v.length>254||v!==v.trim()||/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069:]/u.test(v))return fail();return v;}
class ProvisionedTotp {
 #bytes;
 constructor({issuer,accountName,algorithm,digits,period,bytes}){Object.assign(this,{issuer,accountName,algorithm,digits,period});this.#bytes=bytes;Object.freeze(this);}
 secretBytes(){return this.#bytes.slice();}
 toString(){return 'ProvisionedTotp(redacted)';}
 toJSON(){return {type:'ProvisionedTotp',redacted:true};}
}
export function parseTotpUri(input){
 try{
  if(typeof input!=='string'||input.length>2048||/[\s\u0000-\u001f\u007f]/u.test(input)||!input.startsWith('otpauth://totp/'))return fail();
  const match=/^otpauth:\/\/totp\/([^/?#]+)\?([^#]+)$/.exec(input);if(!match)return fail();
  const parts=decode(match[1]).split(':');if(parts.length>2)return fail();
  const accountName=label(parts.at(-1).replace(/^ +/,'')),prefix=parts.length===2?label(parts[0]):null;
  const params=new Map();for(const entry of match[2].split('&')){const i=entry.indexOf('=');if(i<1)return fail();const k=decode(entry.slice(0,i)),v=decode(entry.slice(i+1));if(!['secret','issuer','algorithm','digits','period'].includes(k)||params.has(k)||!v)return fail();params.set(k,v);}
  const secret=params.get('secret');if(!secret||secret.length>208||!/^[A-Z2-7]+$/i.test(secret))return fail();const bytes=decodeBase32(secret);if(bytes.length<10||bytes.length>128)return fail();
  const issuer=params.has('issuer')?label(params.get('issuer')):prefix;if(prefix&&issuer!==prefix)return fail();
  const alg=params.get('algorithm')??'SHA1',algorithm={SHA1:'SHA-1',SHA256:'SHA-256',SHA512:'SHA-512'}[alg];if(!algorithm)return fail();
  const d=params.get('digits')??'6';if(!['6','8'].includes(d))return fail();
  const p=params.get('period')??'30';if(!/^[1-9][0-9]{0,4}$/.test(p)||Number(p)>86400)return fail();
  return new ProvisionedTotp({issuer,accountName,algorithm,digits:Number(d),period:Number(p),bytes});
 }catch{return fail();}
}
