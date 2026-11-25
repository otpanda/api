// Native Android passkey SIGNUP (create account with email code + OS passkey). Same services as web signup (SignupEmailService, SignupHandoffService,
// PasskeySignupService); the only differences are the install-bound mailbox binding (renewal key, not a cookie) and an android session instead of a web handoff.
// POST only, API host, NO Origin, no cookie/CORS, exact application/json, exact keys. Responses never reveal quota, delivery or account existence until the mailbox code is proven.
import {json,takeRateLimit} from './sessions.js';
import {importRenewalKey} from './access-renewal.js';
import {canonicalAccountEmail} from './account-identity.js';
import {base64urlEncode} from './tokens.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',REDIRECT='https://otpanda.github.io/app/',PATHS=['/auth/native/signup/email','/auth/native/signup/begin','/auth/native/signup/finish'];
const failure=(status,error,extra={})=>json({error},status,{'Cache-Control':'no-store',...extra});
export const nativeSignupBinding=renewalKey=>'native-signup-v1:'+renewalKey;
async function body(request,keys){
 if(request.headers.get('content-type')!=='application/json'||Number(request.headers.get('content-length')??0)>16384||!request.body)return undefined;
 const reader=request.body.getReader(),chunks=[];let size=0;
 try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>16384){await reader.cancel();return undefined;}chunks.push(value);}
  const all=new Uint8Array(size);let o=0;for(const c of chunks){all.set(c,o);o+=c.byteLength;}
  const d=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(all));
  return d&&typeof d==='object'&&!Array.isArray(d)&&Object.keys(d).sort().join(',')===keys?d:undefined;}catch{return undefined;}
}
const random43=()=>base64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
export function createNativeSignupHttp({db,signupEmail,handoff,native,clock=Date.now,defer}={}){
 if(!db||!signupEmail||!handoff||!native)throw new TypeError('Native signup dependencies required');
 return {async fetch(request,{clientAddress}={}){
  const url=new URL(request.url),p=url.pathname;
  if(url.origin!==API||!PATHS.includes(p))return failure(404,'not_found');
  if(request.method!=='POST')return failure(405,'method_not_allowed');
  if(request.headers.has('origin')||url.search)return failure(403,'forbidden');
  if(typeof clientAddress!=='string'||!clientAddress||clientAddress.length>128)return failure(503,'unavailable');
  if(!(await takeRateLimit(db,'native-signup:'+p+':'+clientAddress,{now:clock(),limit:15})).allowed)return failure(429,'rate_limited',{'Retry-After':'60'});
  const keys={'/auth/native/signup/email':'email,renewal_key','/auth/native/signup/begin':'email,email_code,renewal_key','/auth/native/signup/finish':'renewal_key,response,token'}[p],d=await body(request,keys);
  if(!d||typeof d.renewal_key!=='string'||d.renewal_key.length>512||!await importRenewalKey(d.renewal_key))return failure(400,'invalid_request');
  const cookieBinding=nativeSignupBinding(d.renewal_key);
  if(p.endsWith('/finish')){
   if(typeof d.token!=='string'||d.token.length>200||!d.response||typeof d.response!=='object'||Array.isArray(d.response))return failure(400,'invalid_request');
   let proof;try{proof=await handoff.verifyNative({token:d.token,response:d.response,cookieBinding});}catch{return failure(401,'invalid_grant');}
   const dev=proof&&await native.issuePasskey({proof,renewalKey:d.renewal_key});
   return dev?json({device_id:dev.deviceId,access:dev.access,access_expires_at:dev.accessExpiresAt},200,{'Cache-Control':'no-store'}):failure(401,'invalid_grant');
  }
  let email;try{email=canonicalAccountEmail(d.email);}catch{return failure(400,'invalid_request');}
  if(p.endsWith('/email')){
   if(typeof defer!=='function')return failure(503,'unavailable');
   try{defer(()=>signupEmail.request({email,clientAddress,cookieBinding,allowExisting:true}));}catch{return failure(503,'unavailable',{'Retry-After':'30'});}
   return json({status:'accepted'},202,{'Cache-Control':'no-store'});
  }
  if(typeof d.email_code!=='string'||d.email_code.length>64)return failure(400,'invalid_request');
  let c;try{c=await handoff.beginBrowser({email,emailToken:d.email_code,cookieBinding,challenge:random43(),state:random43(),redirectUri:REDIRECT,resolveExisting:true});}catch{return failure(401,'invalid_grant');}
  if(!c)return failure(401,'invalid_grant');
  if(c.existing===true)return json({existing:true},200,{'Cache-Control':'no-store'});
  return json({token:c.token,options:c.options,expires_at:c.expiresAt},200,{'Cache-Control':'no-store'});
 }};
}
