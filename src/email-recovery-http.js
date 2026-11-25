// Unauthenticated email-recovery surface. Email is not a sign-in method: no
// route here issues a session or opens any data. Responses to code requests are
// generic. Mail is delivered only through the injected server-side deliver().
import {json,securityHeaders,takeRateLimit} from './sessions.js';
import {PasskeyService} from './passkey-service.js';
import {EmailRecovery} from './email-recovery.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',cors={'Access-Control-Allow-Origin':APP,Vary:'Origin'};
export const EMAIL_RECOVERY_STEPS=['request','verify','complete-code','complete-begin','complete-finish'];
const SHAPES={request:'binding,email',verify:'binding,code,email','complete-code':'binding,email','complete-begin':'binding,code,email','complete-finish':'grant,response,token'};
async function body(request){const reader=request.body?.getReader();if(!reader)return;let out='',n=0;const d=new TextDecoder('utf-8',{fatal:true});try{for(;;){const r=await reader.read();if(r.done)break;n+=r.value.byteLength;if(n>24576){await reader.cancel();return;}out+=d.decode(r.value,{stream:true});}return JSON.parse(out+d.decode());}catch{return;}finally{reader.releaseLock();}}
export function createEmailRecoveryHttp({db,deliver,getCipher,clock=Date.now,passkeys=new PasskeyService(db,{clock}),service=new EmailRecovery(db,{clock,deliver,passkeys,getCipher}),native=false}={}){
 return{async fetch(request,{clientAddress,waitUntil}={}){
  const u=new URL(request.url),prefix=native===true?'/auth/native/recovery/email/':'/auth/recovery/email/',step=u.pathname.slice(prefix.length);
  if(u.origin!==API||!u.pathname.startsWith(prefix)||!EMAIL_RECOVERY_STEPS.includes(step)||u.search)return json({error:'not_found'},404);
  // Native: no Origin header at all (a browser always sends one). Web: exactly the app origin.
  if(native===true?request.headers.has('origin'):request.headers.get('origin')!==APP)return json({error:'forbidden'},403);
  if(request.method==='OPTIONS'&&native!==true)return new Response(null,{status:204,headers:{...securityHeaders,...cors,'Access-Control-Allow-Methods':'POST','Access-Control-Allow-Headers':'Content-Type'}});
  if(request.method!=='POST'||request.headers.get('content-type')!=='application/json')return json({error:'invalid_request'},400,cors);
  if(typeof clientAddress!=='string'||!clientAddress)return json({error:'unavailable'},503,cors);
  if(!(await takeRateLimit(db,'recovery-email-http:'+clientAddress,{now:clock(),limit:30})).allowed)return json({error:'busy'},429,cors);
  const v=await body(request);if(!v||Array.isArray(v)||typeof v!=='object'||Object.keys(v).sort().join(',')!==SHAPES[step])return json({error:'invalid_request'},400,cors);
  if(step!=='complete-finish'&&Object.entries(v).some(([k,x])=>typeof x!=='string'||x.length>(k==='binding'?512:320)))return json({error:'invalid_request'},400,cors);
  if(step==='request'||step==='complete-code'){try{await service.requestCode({email:v.email,binding:v.binding,clientAddress,purpose:step==='request'?'request':'complete',defer:typeof waitUntil==='function'?waitUntil:undefined});}catch{return json({error:'unavailable'},503,cors);}return json({status:'accepted'},200,cors);}
  if(step==='verify'){const s=await service.verifyRequest(v);return s?json({status:'waiting',availableAt:s.availableAt},200,cors):json({error:'invalid_code'},403,cors);}
  if(step==='complete-begin'){const c=await service.beginCompletion(v);return c?json(c,200,cors):json({error:'unavailable'},403,cors);}
  if(typeof v.grant!=='string'||typeof v.token!=='string'||!v.response||typeof v.response!=='object')return json({error:'invalid_request'},400,cors);
  return await service.finishCompletion(v)?json({status:'completed',signIn:'with the new passkey'},200,cors):json({error:'unavailable'},403,cors);
 }};
}
