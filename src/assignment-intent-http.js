// Unmounted assignment-only browser adapter. Existing bearer authentication is
// required on every request; legacy cookie/automation auth cannot enter here.
import{json,takeRateLimit}from'./sessions.js';
import{createDeviceSessionAuth}from'./device-session-auth.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',cors={'Access-Control-Allow-Origin':APP,Vary:'Origin'};
const paths=new Set(['/v1/manage/assignment/begin','/v1/manage/assignment/finish','/v1/manage/assignment/status']);
export function createAssignmentIntentHttp({db,sessions,intents,clock=Date.now}={}){
 const auth=createDeviceSessionAuth({sessions});
 return{async fetch(request,{clientAddress}={}){
  const url=new URL(request.url);if(url.origin!==API||!paths.has(url.pathname))return json({error:'not_found'},404);
  if(request.headers.get('origin')!==APP)return json({error:'forbidden'},403);
  if(request.method==='OPTIONS'){
   const headers=request.headers.get('access-control-request-headers')?.toLowerCase().split(',').map(x=>x.trim())??[];
   return request.headers.get('access-control-request-method')==='POST'&&headers.every(x=>['authorization','content-type'].includes(x))?new Response(null,{status:204,headers:{...cors,'Cache-Control':'no-store','Access-Control-Allow-Methods':'POST','Access-Control-Allow-Headers':'Authorization, Content-Type'}}):json({error:'forbidden'},403,cors);
  }
  if(request.method!=='POST')return json({error:'method_not_allowed'},405,cors);
  if(url.search||!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(request.headers.get('content-type')??''))return json({error:'invalid_request'},400,cors);
  try{
   if(typeof clientAddress!=='string'||!clientAddress||clientAddress.length>128)return json({error:'unavailable'},503,cors);
   const limit=await takeRateLimit(db,'assignment-address:'+clientAddress,{now:clock(),limit:20});if(!limit.allowed)return json({error:'rate_limited'},429,{...cors,'Retry-After':String(limit.retryAfter)});
   const user=await auth.authenticate(request);if(!user)return json({error:'unauthorized'},401,cors);
   const ownerLimit=await takeRateLimit(db,'assignment-owner:'+user.ownerId,{now:clock(),limit:20});if(!ownerLimit.allowed)return json({error:'rate_limited'},429,{...cors,'Retry-After':String(ownerLimit.retryAfter)});
   // Stream cap rather than trusting Content-Length or buffering arbitrary data.
   const reader=request.body?.getReader();let size=0,parts=[];if(!reader)return json({error:'invalid_request'},400,cors);
   for(;;){const{value,done}=await reader.read();if(done)break;size+=value.length;if(size>32768){await reader.cancel();return json({error:'invalid_request'},400,cors);}parts.push(value);}
   const bytes=new Uint8Array(size);let offset=0;for(const part of parts){bytes.set(part,offset);offset+=part.length;}
   let body;try{body=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}catch{return json({error:'invalid_request'},400,cors);}
   if(!body||Array.isArray(body)||typeof body!=='object')return json({error:'invalid_request'},400,cors);
   const operation=url.pathname.split('/').at(-1),allowed=operation==='begin'?['sourceId','eventId','entryId']:operation==='finish'?['intentId','token','action','response']:['intentId'];
   if(Object.keys(body).some(k=>!allowed.includes(k)))return json({error:'invalid_request'},400,cors);
   const result=operation==='begin'?await intents.begin(user,body):operation==='finish'?await intents.finish(user,body):await intents.status(user,body.intentId);
   // Finish linearizes at the guarded D1 commit. A later revoke must not
   // turn a committed assignment response into an unauthorized failure.
   if(operation!=='finish'&&!await auth.authenticate(request))return json({error:'unauthorized'},401,cors);
   return result?json(result,200,cors):json({error:'unavailable'},409,cors);
  }catch{return json({error:'unavailable'},503,cors);}
 }};
}
