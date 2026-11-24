// Inactive pre-D1 guard. Approximate provider limits reduce D1 write
// amplification; they are not authentication or strict financial/global caps.
import{canonicalClientAddress}from'./client-address.js';
import{hashText,json,securityHeaders}from'./sessions.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io';
const methods=new Map([...['status','begin','verify'].map(p=>['/auth/google/protection/'+p,['POST']]),['/auth/google/protection/complete',['GET','POST']],... ['begin','finish','approve','deny','request-change','approve-change','consume-change'].map(p=>['/v1/manage/security/'+p,['POST']]),['/v1/manage/security/status',['GET']],...['email','begin','verify'].map(p=>['/auth/google/continue/'+p,['POST']]),['/auth/google/continue/complete',['GET','POST']],['/auth/google/start',['GET']],['/auth/callback',['GET']],
 ['/auth/login/start',['GET']],['/auth/login/verify',['POST']],['/auth/login/complete',['GET','POST']],['/auth/restore',['GET','POST']],['/auth/exchange',['POST']],['/auth/device/logout',['GET','POST']],
 ...['begin','finish'].map(p=>['/v1/manage/first-passkey/'+p,['POST']]),
 ...['verify-begin','verify-finish','register-begin','register-finish'].map(p=>['/v1/manage/passkey/add/'+p,['POST']]),
 ...['begin','finish','status'].map(p=>['/v1/manage/assignment/'+p,['POST']]),
 ...['account','session','entries','active-codes','unassigned','sources'].map(p=>['/v1/manage/'+p,['GET']]),['/v1/manage/organization',['GET','PUT']],['/v1/manage/organization-copy',['POST']]
]);
const corsPath=p=>((p.startsWith('/auth/google/continue/')||p.startsWith('/auth/google/protection/'))&&!p.endsWith('/complete'))||p==='/auth/login/verify'||p==='/auth/exchange'||p.startsWith('/v1/');
const headers=p=>({...securityHeaders,...(corsPath(p)?{'Access-Control-Allow-Origin':APP,Vary:'Origin'}:{})});
export const isIdentityPath=p=>methods.has(p);
export function createIdentityEdgeHost({initialize,resolveTrustedIngress,edgeAddress,edgeAuthGlobal,edgeReadGlobal}={}){
 let identity;
 return{async fetch(request){
  const url=new URL(request.url),p=url.pathname,allowed=methods.get(p),origin=request.headers.get('origin'),cors=corsPath(p);
  const fail=(status,error='unavailable')=>{const h={...headers(p),...([429,503].includes(status)?{'Retry-After':'60'}:{})};return cors?json({error},status,h):new Response(null,{status:303,headers:{...h,Location:'https://otpanda.github.io/app/#auth=retry'}});};
  if(url.origin!==API||!allowed)return json({error:'not_found'},404);
  if(p.startsWith('/v1/manage/assignment/')&&url.search)return fail(400,'invalid_request');
  if(cors&&origin!==APP)return fail(403,'forbidden');
  // Preflight is pure: no env/key import, resolver, edge counters or D1.
  if(request.method==='OPTIONS'){
   const requested=(request.headers.get('access-control-request-headers')??'').toLowerCase().split(',').map(v=>v.trim()).filter(Boolean);
   const fields=p.startsWith('/v1/')?((p.startsWith('/v1/manage/security/')||p.includes('organization')||p.startsWith('/v1/manage/assignment/')||p.startsWith('/v1/manage/first-passkey/')||p.startsWith('/v1/manage/passkey/add/'))?(p.startsWith('/v1/manage/first-passkey/')||p.startsWith('/v1/manage/passkey/add/')?['authorization','content-type','x-otpanda-enrollment']:['authorization','content-type']):['authorization']):((p.startsWith('/auth/google/continue/')||p.startsWith('/auth/google/protection/'))?['content-type','x-otpanda-continuation','x-otpanda-pending']:['content-type']);
   return cors&&allowed.includes(request.headers.get('access-control-request-method'))&&requested.every(v=>fields.includes(v))?new Response(null,{status:204,headers:{...headers(p),'Access-Control-Allow-Methods':allowed.join(', '),'Access-Control-Allow-Headers':fields.join(', ')}}):fail(403,'forbidden');
  }
  if(!allowed.includes(request.method))return fail(405,'method_not_allowed');
  if(!cors&&request.method==='POST'&&origin!==API)return fail(403,'forbidden');
  try{
   // Mutation ceremonies share the tighter auth budget, not the read budget.
   const readBudget=p.startsWith('/v1/')&&!p.startsWith('/v1/manage/first-passkey/')&&!p.startsWith('/v1/manage/passkey/add/')&&(!p.startsWith('/v1/manage/security/')||p.endsWith('/status'))&&(!p.startsWith('/v1/manage/assignment/')||p.endsWith('/status'));
   const global=readBudget?edgeReadGlobal:edgeAuthGlobal;
   if(typeof initialize!=='function'||typeof resolveTrustedIngress!=='function'||typeof edgeAddress?.limit!=='function'||typeof global?.limit!=='function')return fail(503);
   const address=canonicalClientAddress(await resolveTrustedIngress(request));if(!address)return fail(503);
   if((await edgeAddress.limit({key:await hashText('identity:'+address)}))?.success!==true)return fail(429,'busy');
   if((await global.limit({key:readBudget?'otpanda-browser-reads-v1':'otpanda-browser-auth-v1'}))?.success!==true)return fail(429,'busy');
   // A failed initialization is cached, not retried on an attacker-controlled
   // schedule. Each failure is converted to a generic response here.
   identity??=Promise.resolve().then(initialize);
   return await(await identity).fetch(request);
  }catch{return fail(503);}
 }};
}
