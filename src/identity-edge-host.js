// Inactive pre-D1 guard. Approximate provider limits reduce D1 write
// amplification; they are not authentication or strict financial/global caps.
import{canonicalClientAddress}from'./client-address.js';
import{hashText,json,securityHeaders}from'./sessions.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io';
const methods=new Map([
 ['/auth/login/start',['GET']],['/auth/login/verify',['POST']],['/auth/login/complete',['GET','POST']],['/auth/restore',['GET','POST']],['/auth/exchange',['POST']],['/auth/device/logout',['GET','POST']],
 ...['session','entries','active-codes','unassigned','sources'].map(p=>['/v1/manage/'+p,['GET']]),['/v1/manage/organization',['GET','PUT']],['/v1/manage/organization-copy',['POST']]
]);
const corsPath=p=>p==='/auth/login/verify'||p==='/auth/exchange'||p.startsWith('/v1/');
const headers=p=>({...securityHeaders,...(corsPath(p)?{'Access-Control-Allow-Origin':APP,Vary:'Origin'}:{})});
export const isIdentityPath=p=>methods.has(p);
export function createIdentityEdgeHost({initialize,resolveTrustedIngress,edgeAddress,edgeAuthGlobal,edgeReadGlobal}={}){
 let identity;
 return{async fetch(request){
  const url=new URL(request.url),p=url.pathname,allowed=methods.get(p),origin=request.headers.get('origin'),cors=corsPath(p);
  const fail=(status,error='unavailable')=>{const h={...headers(p),...([429,503].includes(status)?{'Retry-After':'60'}:{})};return cors?json({error},status,h):new Response('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>OTPanda sign-in</title><main><h1>Sign-in could not continue.</h1><p>Wait a moment, then return to the app and start again.</p><a href="https://otpanda.github.io/app/">Return to OTPanda</a></main></html>',{status,headers:{...h,'Content-Type':'text/html; charset=utf-8','Content-Security-Policy':"default-src 'none'; frame-ancestors 'none'; base-uri 'none'"}});};
  if(url.origin!==API||!allowed)return json({error:'not_found'},404);
  if(cors&&origin!==APP)return fail(403,'forbidden');
  // Preflight is pure: no env/key import, resolver, edge counters or D1.
  if(request.method==='OPTIONS'){
   const requested=(request.headers.get('access-control-request-headers')??'').toLowerCase().split(',').map(v=>v.trim()).filter(Boolean);
   const fields=p.startsWith('/v1/')?(p.includes('organization')?['authorization','content-type']:['authorization']):['content-type'];
   return cors&&allowed.includes(request.headers.get('access-control-request-method'))&&requested.every(v=>fields.includes(v))?new Response(null,{status:204,headers:{...headers(p),'Access-Control-Allow-Methods':allowed.join(', '),'Access-Control-Allow-Headers':fields.join(', ')}}):fail(403,'forbidden');
  }
  if(!allowed.includes(request.method))return fail(405,'method_not_allowed');
  if(!cors&&request.method==='POST'&&origin!==API)return fail(403,'forbidden');
  try{
   const global=p.startsWith('/v1/')?edgeReadGlobal:edgeAuthGlobal;
   if(typeof initialize!=='function'||typeof resolveTrustedIngress!=='function'||typeof edgeAddress?.limit!=='function'||typeof global?.limit!=='function')return fail(503);
   const address=canonicalClientAddress(await resolveTrustedIngress(request));if(!address)return fail(503);
   if((await edgeAddress.limit({key:await hashText('identity:'+address)}))?.success!==true)return fail(429,'busy');
   if((await global.limit({key:p.startsWith('/v1/')?'otpanda-browser-reads-v1':'otpanda-browser-auth-v1'}))?.success!==true)return fail(429,'busy');
   // A failed initialization is cached, not retried on an attacker-controlled
   // schedule. Each failure is converted to a generic response here.
   identity??=Promise.resolve().then(initialize);
   return await(await identity).fetch(request);
  }catch{return fail(503);}
 }};
}
