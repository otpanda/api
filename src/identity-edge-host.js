// Inactive pre-D1 guard. Approximate provider limits reduce D1 write
// amplification; they are not authentication or strict financial/global caps.
import{canonicalClientAddress}from'./client-address.js';
import{hashText,json,securityHeaders}from'./sessions.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io';
const methods=new Map([...['begin','exchange','challenge','renew','logout'].map(p=>['/auth/extension/'+p,['POST']]),['/v1/manage/entry/domains',['GET','POST']],...['exchange','challenge','renew','logout','google/begin','google/complete','passkey/begin','passkey/complete','google/continue/begin','google/continue/finish'].map(p=>['/auth/native/'+p,['POST']]),['/auth/native/approve',['GET','POST']],['/app-return',['GET']],['/.well-known/assetlinks.json',['GET']],['/v1/manage/totp',['POST']],['/v1/manage/totp/begin',['POST']],['/v1/manage/totp-code',['GET']],...['status','begin','verify'].map(p=>['/auth/google/protection/'+p,['POST']]),['/auth/google/protection/complete',['GET','POST']],... ['begin','finish','approve','deny','request-change','approve-change','consume-change'].map(p=>['/v1/manage/security/'+p,['POST']]),['/v1/manage/security/status',['GET']],...['email','begin','verify'].map(p=>['/auth/google/continue/'+p,['POST']]),['/auth/google/continue/complete',['GET','POST']],['/auth/google/start',['GET']],['/auth/google/link/start',['GET']],['/v1/manage/google/link/ticket',['POST']],['/auth/callback',['GET']],
 ['/auth/login/start',['GET']],['/auth/login/verify',['POST']],['/auth/login/complete',['GET','POST']],['/auth/restore',['GET','POST']],['/auth/exchange',['POST']],['/auth/renew',['POST']],['/auth/device/logout',['GET','POST']],
 ...['begin','finish'].map(p=>['/v1/manage/first-passkey/'+p,['POST']]),
 ...['verify-begin','verify-finish','register-begin','register-finish'].map(p=>['/v1/manage/passkey/add/'+p,['POST']]),['/v1/manage/passkey/rename',['POST']],['/v1/manage/session/describe',['POST']],
 ...['request','verify','complete-code','complete-begin','complete-finish'].map(p=>['/auth/recovery/email/'+p,['POST']]),...['request','verify','complete-code','complete-begin','complete-finish'].map(p=>['/auth/native/recovery/email/'+p,['POST']]),...['begin','finish'].map(p=>['/v1/manage/google/link/'+p,['POST']]),['/v1/manage/recovery/status',['GET']],...['begin','finish','request-change','approve-begin','approve-change','consume-change','cancel-request'].map(p=>['/v1/manage/recovery/'+p,['POST']]),
 ...['begin','finish','status'].map(p=>['/v1/manage/assignment/'+p,['POST']]),...['rename','account'].map(p=>['/v1/manage/entry/'+p,['POST']]),
 ...['enroll-begin','enroll-finish','enroll-status','adopt-begin','adopt-finish','add-request','add-begin','add-finish'].map(p=>['/v1/manage/device-key/'+p,['POST']]),
 ...['passkey/add/approval-request','passkey/add/approval-authorize','approval/status','approval/approve-begin','approval/approve-finish'].map(p=>['/v1/manage/'+p,['POST']]),
 ...['account','session','entries','active-codes','unassigned','sources'].map(p=>['/v1/manage/'+p,['GET']]),['/v1/manage/organization',['GET','PUT']],['/v1/manage/organization-copy',['POST']]
]);
// Native Android routes: not browser CORS routes, JSON failures, never the Pages retry redirect.
const nativePath=p=>p.startsWith('/auth/native/')||p==='/app-return'||p==='/.well-known/assetlinks.json';
// Exactly the /v1/manage routes the Android client calls. Realtime, batch codes, security, recovery, passkey, assignment and Google-link routes are NOT native.
const nativeManage=new Set(['account','session','entries','active-codes','unassigned','sources','organization','organization-copy','totp-code','totp','totp/begin','session/describe','device-key/enroll-begin','device-key/enroll-finish','device-key/enroll-status','device-key/adopt-begin','device-key/adopt-finish','device-key/add-request','device-key/add-begin','device-key/add-finish','entry/domains','entry/rename','entry/account','approval/status','approval/approve-begin','approval/approve-finish','assignment/begin','assignment/finish','assignment/status','first-passkey/begin','first-passkey/finish','passkey/add/verify-begin','passkey/add/verify-finish','passkey/add/register-begin','passkey/add/register-finish','passkey/rename','recovery/status','recovery/begin','recovery/finish','recovery/request-change','recovery/consume-change','recovery/cancel-request','security/status','security/begin','security/finish','security/approve','security/deny','security/request-change','security/consume-change','google/link/ticket','google/link/begin','google/link/finish'].map(v=>'/v1/manage/'+v));
const corsPath=p=>p==='/auth/extension/begin'||((p.startsWith('/auth/google/continue/')||p.startsWith('/auth/google/protection/'))&&!p.endsWith('/complete'))||p.startsWith('/auth/recovery/email/')||p==='/auth/login/verify'||p==='/auth/exchange'||p==='/auth/renew'||p.startsWith('/v1/');
const headers=p=>({...securityHeaders,...(corsPath(p)?{'Access-Control-Allow-Origin':APP,'Access-Control-Expose-Headers':'Retry-After',Vary:'Origin'}:{})});
export const isIdentityPath=p=>methods.has(p);
const realtimeMethods=new Map([['/auth/realtime/ticket',['POST']],['/auth/realtime',['GET']]]);
// realtime (optional): {edgeAddress, edgeGlobal} are DEDICATED rate-limit bindings for ticket mint and upgrade. They never touch
// the shared auth pool or the read pool. Absent, the realtime paths do not exist (404) and nothing about the other routes changes.
export function createIdentityEdgeHost({initialize,resolveTrustedIngress,edgeAddress,edgeAuthGlobal,edgeReadGlobal,realtime,nativeApi=false,extensionApi=false,extensionOrigins=[]}={}){
 let identity;
  const realtimeFetch=async(request,ctx)=>{
  const url=new URL(request.url),p=url.pathname,allowed=realtimeMethods.get(p),ticket=p==='/auth/realtime/ticket',origin=request.headers.get('origin');
  // Native Android realtime: only when native is enabled, only with NO Origin header, never for a preflight. A browser always sends Origin.
  const nativeRt=nativeApi===true&&origin===null&&request.method!=='OPTIONS';
  const h={...securityHeaders,...(origin===APP?{'Access-Control-Allow-Origin':APP,'Access-Control-Expose-Headers':'Retry-After'}:{}),Vary:'Origin'};
  const fail=(status,error='unavailable')=>json({error},status,{...h,...([429,503].includes(status)?{'Retry-After':'30'}:{})});
  if(url.origin!==API||url.search)return json({error:'not_found'},404);
  if(origin!==APP&&!nativeRt)return fail(403,'forbidden');
  // Preflight is pure: no env, resolver, limiter or D1.
  if(request.method==='OPTIONS'){
   const requested=(request.headers.get('access-control-request-headers')??'').toLowerCase().split(',').map(v=>v.trim()).filter(Boolean);
   return ticket&&request.headers.get('access-control-request-method')==='POST'&&requested.every(v=>v==='authorization')?new Response(null,{status:204,headers:{...h,'Access-Control-Allow-Methods':'POST','Access-Control-Allow-Headers':'authorization'}}):fail(403,'forbidden');
  }
  if(!allowed.includes(request.method))return fail(405,'method_not_allowed');
  try{
   const L=realtime;
   if(typeof initialize!=='function'||typeof resolveTrustedIngress!=='function'||typeof L.edgeAddress?.limit!=='function'||typeof L.edgeGlobal?.limit!=='function')return fail(503);
   const address=canonicalClientAddress(await resolveTrustedIngress(request));if(!address)return fail(503);
   if((await L.edgeAddress.limit({key:await hashText('realtime:'+address)}))?.success!==true)return fail(429,'busy');
   if((await L.edgeGlobal.limit({key:'otpanda-realtime-v1'}))?.success!==true)return fail(429,'busy');
   identity??=Promise.resolve().then(initialize);
   return await(await identity).fetch(request,{waitUntil:typeof ctx?.waitUntil==='function'?q=>ctx.waitUntil(q):undefined});
  }catch{return fail(503);}
  };
 return{async fetch(request,ctx){
  const rt=realtime&&realtimeMethods.get(new URL(request.url).pathname);
  if(rt)return realtimeFetch(request,ctx);
  const url=new URL(request.url),p=url.pathname,allowed=methods.get(p),origin=request.headers.get('origin'),cors=corsPath(p);
  const fail=(status,error='unavailable')=>{const h={...(origin===APP?headers(p):securityHeaders),...([429,503].includes(status)?{'Retry-After':'60'}:{})};return cors||nativePath(p)?json({error},status,h):new Response(null,{status:303,headers:{...h,Location:'https://otpanda.github.io/app/#auth=retry'}});};
  if(url.origin!==API||!allowed)return json({error:'not_found'},404);
  const extRead=extensionApi&&request.method==='GET'&&['/v1/manage/entries','/v1/manage/active-codes','/v1/manage/entry/domains'].includes(p)&&origin!==APP&&(origin===null||extensionOrigins.includes(origin));
  const ext=p.startsWith('/auth/extension/'),extBegin=p==='/auth/extension/begin';
  if(ext&&!extensionApi)return json({error:'not_found'},404);
  if((ext&&!extBegin)||extRead){
   if(!extRead&&request.method!=='POST')return json({error:'method_not_allowed'},405,securityHeaders);
   try{const address=canonicalClientAddress(await resolveTrustedIngress(request));if(!address||typeof edgeAddress?.limit!=='function'||typeof(extRead?edgeReadGlobal:edgeAuthGlobal)?.limit!=='function')return json({error:'unavailable'},503,{...securityHeaders,'Retry-After':'60'});
    if((await edgeAddress.limit({key:await hashText((extRead?'identity:':'extension:')+address)}))?.success!==true||(await(extRead?edgeReadGlobal:edgeAuthGlobal).limit({key:extRead?'otpanda-browser-reads-v1':'otpanda-extension-v1'}))?.success!==true)return json({error:'busy'},429,{...securityHeaders,'Retry-After':'60'});
    identity??=Promise.resolve().then(initialize);return await(await identity).fetch(request,ctx);
   }catch{return json({error:'unavailable'},503,{...securityHeaders,'Retry-After':'60'});}
  }
  if(p.startsWith('/v1/manage/assignment/')&&url.search)return fail(400,'invalid_request');
  if(nativePath(p)&&nativeApi!==true)return json({error:'not_found'},404);
  // Native token routes carry NO Origin header (never a foreign one). Only when native is enabled, only the exact list above, never preflight.
  const nativeNoOrigin=nativeApi===true&&nativeManage.has(p)&&origin===null&&request.method!=='OPTIONS';
  if(cors&&origin!==APP&&!nativeNoOrigin)return fail(403,'forbidden');
  // Preflight is pure: no env/key import, resolver, edge counters or D1.
  if(request.method==='OPTIONS'){
   const requested=(request.headers.get('access-control-request-headers')??'').toLowerCase().split(',').map(v=>v.trim()).filter(Boolean);
   const fields=p.startsWith('/v1/')?((p.startsWith('/v1/manage/totp')||p==='/v1/manage/google/link/ticket'||p.startsWith('/v1/manage/security/')||p.startsWith('/v1/manage/recovery/')||p.includes('organization')||p==='/v1/manage/passkey/rename'||p==='/v1/manage/session/describe'||p.startsWith('/v1/manage/assignment/')||p.startsWith('/v1/manage/entry/')||p.startsWith('/v1/manage/first-passkey/')||p.startsWith('/v1/manage/passkey/add/'))?(p.startsWith('/v1/manage/first-passkey/')||p.startsWith('/v1/manage/passkey/add/')?['authorization','content-type','x-otpanda-enrollment']:['authorization','content-type']):['authorization']):(p==='/auth/renew'||p==='/auth/extension/begin'?['authorization','content-type']:(p.startsWith('/auth/google/continue/')||p.startsWith('/auth/google/protection/'))?['content-type','x-otpanda-continuation','x-otpanda-pending']:['content-type']);
   return cors&&allowed.includes(request.headers.get('access-control-request-method'))&&requested.every(v=>fields.includes(v))?new Response(null,{status:204,headers:{...headers(p),'Access-Control-Allow-Methods':allowed.join(', '),'Access-Control-Allow-Headers':fields.join(', ')}}):fail(403,'forbidden');
  }
  if(!allowed.includes(request.method))return fail(405,'method_not_allowed');
  if(!cors&&!nativePath(p)&&request.method==='POST'&&origin!==API)return fail(403,'forbidden');// native routes enforce their own Origin rules
  try{
   // Mutation ceremonies share the tighter auth budget, not the read budget.
   const readBudget=p==='/app-return'||p==='/.well-known/assetlinks.json'||p.startsWith('/v1/')&&!p.startsWith('/v1/manage/first-passkey/')&&!p.startsWith('/v1/manage/passkey/add/')&&(!p.startsWith('/v1/manage/totp')||p==='/v1/manage/totp-code')&&(!p.startsWith('/v1/manage/security/')||p.endsWith('/status'))&&(!p.startsWith('/v1/manage/recovery/')||p.endsWith('/status'))&&(!p.startsWith('/v1/manage/assignment/')||p.endsWith('/status'));
   const global=readBudget?edgeReadGlobal:edgeAuthGlobal;
   if(typeof initialize!=='function'||typeof resolveTrustedIngress!=='function'||typeof edgeAddress?.limit!=='function'||typeof global?.limit!=='function')return fail(503);
   const address=canonicalClientAddress(await resolveTrustedIngress(request));if(!address)return fail(503);
   if((await edgeAddress.limit({key:await hashText('identity:'+address)}))?.success!==true)return fail(429,'busy');
   if((await global.limit({key:readBudget?'otpanda-browser-reads-v1':'otpanda-browser-auth-v1'}))?.success!==true)return fail(429,'busy');
   // A failed initialization is cached, not retried on an attacker-controlled
   // schedule. Each failure is converted to a generic response here.
   identity??=Promise.resolve().then(initialize);
   return await(await identity).fetch(request,{waitUntil:typeof ctx?.waitUntil==='function'?p=>ctx.waitUntil(p):undefined});
  }catch{return fail(503);}
 }};
}
