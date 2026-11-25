// Unmounted routes for enrolled-phone approvals. Two WEB routes (Origin, web bearer, CORS) and six ANDROID routes
// (no Origin, no CORS, android bearer). Exact key sets, JSON POST, body <= 4096 bytes. Guard failure is the opaque 409.
import{json,securityHeaders,takeRateLimit}from'./sessions.js';
import{createDeviceSessionAuth}from'./device-session-auth.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',NS={'Cache-Control':'no-store'},cors={'Access-Control-Allow-Origin':APP,Vary:'Origin'};
const R=[
 ['/v1/manage/passkey/add/approval-request','web',[],'requestPasskeyAdd'],
 ['/v1/manage/passkey/add/approval-authorize','web',['changeId'],'authorizePasskeyAdd'],
 ['/v1/manage/approval/status','android',[],'status'],
 ['/v1/manage/approval/approve-begin','android',['changeId','keyId'],'approveBegin'],
 ['/v1/manage/approval/approve-finish','android',['changeId','signature','token'],'approveFinish'],
 ['/v1/manage/device-key/add-request','android',['publicJwk'],'requestDeviceKeyAdd'],
 ['/v1/manage/device-key/add-begin','android',['changeId'],'addBegin'],
 ['/v1/manage/device-key/add-finish','android',['changeId','signature','token'],'addFinish'],
].map(([p,k,keys,m])=>[p,{kind:k,keys:[...keys].sort().join(','),method:m}]);
export const APPROVAL_PATHS=R.map(r=>r[0]);
const routes=new Map(R);
export function createApprovalsHttp({db,sessions,approvals,clock=Date.now}={}){
 const web=createDeviceSessionAuth({sessions}),native=createDeviceSessionAuth({sessions,native:true});
 return{async fetch(request,{clientAddress}={}){
  const url=new URL(request.url),r=routes.get(url.pathname);
  if(url.origin!==API||!r||url.search)return json({error:'not_found'},404,NS);
  const isWeb=r.kind==='web',h=isWeb?{...NS,...cors}:NS,auth=isWeb?web:native;
  if(isWeb?request.headers.get('origin')!==APP:request.headers.has('origin'))return json({error:'forbidden'},403,h);
  if(isWeb&&request.method==='OPTIONS')return request.headers.get('access-control-request-method')==='POST'&&(request.headers.get('access-control-request-headers')??'').toLowerCase().split(',').map(x=>x.trim()).filter(Boolean).every(x=>['authorization','content-type'].includes(x))?new Response(null,{status:204,headers:{...securityHeaders,...cors,'Access-Control-Allow-Methods':'POST','Access-Control-Allow-Headers':'Authorization, Content-Type'}}):json({error:'forbidden'},403,h);
  if(request.method!=='POST')return json({error:'method_not_allowed'},405,h);
  if(request.headers.get('content-type')!=='application/json')return json({error:'invalid_request'},400,h);
  try{
   if(typeof clientAddress!=='string'||!clientAddress||clientAddress.length>128)return json({error:'unavailable'},503,h);
   const lim=await takeRateLimit(db,'approvals-address:'+clientAddress,{now:clock(),limit:20});if(!lim.allowed)return json({error:'rate_limited'},429,{...h,'Retry-After':String(lim.retryAfter)});
   const user=await auth.authenticate(request);if(!user)return json({error:'unauthorized'},401,h);
   const ol=await takeRateLimit(db,'approvals-owner:'+user.ownerId,{now:clock(),limit:30});if(!ol.allowed)return json({error:'rate_limited'},429,{...h,'Retry-After':String(ol.retryAfter)});
   const reader=request.body?.getReader();if(!reader)return json({error:'invalid_request'},400,h);
   let size=0;const parts=[];for(;;){const{value,done}=await reader.read();if(done)break;size+=value.length;if(size>4096){await reader.cancel();return json({error:'invalid_request'},400,h);}parts.push(value);}
   const bytes=new Uint8Array(size);let o=0;for(const p of parts){bytes.set(p,o);o+=p.length;}
   let body;try{body=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}catch{return json({error:'invalid_request'},400,h);}
   if(!body||typeof body!=='object'||Array.isArray(body)||Object.keys(body).sort().join(',')!==r.keys)return json({error:'invalid_request'},400,h);
   if(!Object.entries(body).every(([k,v])=>k==='publicJwk'?v&&typeof v==='object'&&!Array.isArray(v):typeof v==='string'&&v.length<=512))return json({error:'invalid_request'},400,h);
   const result=await approvals[r.method]({user,...body});
   // Finish-type commits linearize at their guarded write; a later revoke must not turn a committed result into a failure.
   const commits=r.method==='approveFinish'||r.method==='addFinish';
   if(!commits&&!await auth.authenticate(request))return json({error:'unauthorized'},401,h);
   return result?json(result,200,h):json({error:'unavailable'},409,h);
  }catch{return json({error:'unavailable'},503,h);}
 }};
}
