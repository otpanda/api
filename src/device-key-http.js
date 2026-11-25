// Unmounted android-only device-key routes. No Origin header, no CORS, bearer android access token, exact key sets,
// POST JSON, body <= 4096 bytes. Any guard failure or uncertainty is the opaque 409 {error:'unavailable'}; the only
// other 409 is {error:'method_exists'} from enroll-begin.
import{json,takeRateLimit}from'./sessions.js';
import{createDeviceSessionAuth}from'./device-session-auth.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',NS={'Cache-Control':'no-store'};
const KEYS={'enroll-begin':['grant','publicJwk'],'enroll-finish':['grant','signature','token'],'enroll-status':['digest'],'adopt-begin':['digest'],'adopt-finish':['digest','signature','token']};
const paths=new Map(Object.keys(KEYS).map(k=>['/v1/manage/device-key/'+k,k]));
export function createDeviceKeyHttp({db,sessions,enrollment,keys,clock=Date.now}={}){
 const auth=createDeviceSessionAuth({sessions,native:true});
 return{async fetch(request,{clientAddress}={}){
  const url=new URL(request.url),op=paths.get(url.pathname);
  if(url.origin!==API||!op)return json({error:'not_found'},404,NS);
  if(request.headers.has('origin'))return json({error:'forbidden'},403,NS);
  if(request.method!=='POST')return json({error:'method_not_allowed'},405,NS);
  if(url.search||request.headers.get('content-type')!=='application/json')return json({error:'invalid_request'},400,NS);
  try{
   if(typeof clientAddress!=='string'||!clientAddress||clientAddress.length>128)return json({error:'unavailable'},503,NS);
   const lim=await takeRateLimit(db,'device-key-address:'+clientAddress,{now:clock(),limit:20});if(!lim.allowed)return json({error:'rate_limited'},429,{...NS,'Retry-After':String(lim.retryAfter)});
   const user=await auth.authenticate(request);if(!user)return json({error:'unauthorized'},401,NS);
   const ol=await takeRateLimit(db,'device-key-owner:'+user.ownerId,{now:clock(),limit:30});if(!ol.allowed)return json({error:'rate_limited'},429,{...NS,'Retry-After':String(ol.retryAfter)});
   const reader=request.body?.getReader();if(!reader)return json({error:'invalid_request'},400,NS);
   let size=0;const parts=[];for(;;){const{value,done}=await reader.read();if(done)break;size+=value.length;if(size>4096){await reader.cancel();return json({error:'invalid_request'},400,NS);}parts.push(value);}
   const bytes=new Uint8Array(size);let o=0;for(const p of parts){bytes.set(p,o);o+=p.length;}
   let body;try{body=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}catch{return json({error:'invalid_request'},400,NS);}
   if(!body||typeof body!=='object'||Array.isArray(body)||Object.keys(body).sort().join(',')!==KEYS[op].join(','))return json({error:'invalid_request'},400,NS);
   const s=v=>typeof v==='string'&&v.length<=512;
   if(!Object.entries(body).every(([k,v])=>k==='publicJwk'?v&&typeof v==='object'&&!Array.isArray(v):s(v)))return json({error:'invalid_request'},400,NS);
   const result=op==='enroll-begin'?await enrollment.begin({user,publicJwk:body.publicJwk,grant:body.grant})
    :op==='enroll-finish'?await enrollment.finish({user,grant:body.grant,token:body.token,signature:body.signature})
    :op==='enroll-status'?await enrollment.status({user,digest:body.digest})
    :op==='adopt-begin'?await enrollment.adoptBegin({user,digest:body.digest,keys})
    :await enrollment.adoptFinish({user,digest:body.digest,token:body.token,signature:body.signature,keys});
   // Finish linearizes at its guarded commit; a later revoke must not turn a committed result into a failure.
   if(!op.endsWith('finish')&&!await auth.authenticate(request))return json({error:'unauthorized'},401,NS);
   if(result?.error==='method_exists')return op==='enroll-begin'?json({error:'method_exists'},409,NS):json({error:'unavailable'},409,NS);
   return result?json(result,200,NS):json({error:'unavailable'},409,NS);
  }catch{return json({error:'unavailable'},503,NS);}
 }};
}
