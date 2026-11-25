// Signed-in Google link, native finish. The browser leg (ticket, Google consent, link-only continuation) is the existing one; the app then proves
// the OWNER with the OS passkey. Routes: POST /v1/manage/google/link/begin {continuation} and /finish {continuation,token,response}. Bearer android
// token only, no Origin. The continuation must be the link-only one minted for THIS device and owner, so another session cannot finish it.
import {json,takeRateLimit} from './sessions.js';
import {createDeviceSessionAuth} from './device-session-auth.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',TOKEN=/^otpda_[A-Za-z0-9_-]{55}$/;
async function body(request){const reader=request.body?.getReader();if(!reader)return;let out='',n=0;const d=new TextDecoder('utf-8',{fatal:true});try{for(;;){const r=await reader.read();if(r.done)break;n+=r.value.byteLength;if(n>24576){await reader.cancel();return;}out+=d.decode(r.value,{stream:true});}return JSON.parse(out+d.decode());}catch{return;}finally{reader.releaseLock();}}
export function createNativeGoogleLinkHttp({db,sessions,continuations,clock=Date.now}={}){
 const auth=createDeviceSessionAuth({sessions,native:true});
 return{async fetch(request,{clientAddress}={}){
  const u=new URL(request.url),step=u.pathname.slice('/v1/manage/google/link/'.length);
  if(u.origin!==API||!u.pathname.startsWith('/v1/manage/google/link/')||!['begin','finish'].includes(step)||u.search||typeof continuations!=='function')return json({error:'not_found'},404);
  if(request.headers.has('origin'))return json({error:'forbidden'},403);
  if(request.method!=='POST'||request.headers.get('content-type')!=='application/json')return json({error:'invalid_request'},400);
  if(typeof clientAddress!=='string'||!clientAddress)return json({error:'unavailable'},503);
  if(!(await takeRateLimit(db,'native-google-link:'+clientAddress,{now:clock(),limit:30})).allowed)return json({error:'busy'},429);
  const user=await auth.authenticate(request);if(!user)return json({error:'unauthorized'},401);
  const v=await body(request);if(!v||Array.isArray(v)||Object.keys(v).sort().join(',')!==(step==='begin'?'continuation':'continuation,response,token')||typeof v.continuation!=='string'||!TOKEN.test(v.continuation))return json({error:'invalid_request'},400);
  let c,q;try{c=await continuations();q=await c.read(v.continuation);}catch{return json({error:'unavailable'},503);}
  if(!q?.data.linkOnly||q.data.ownerId!==user.ownerId||q.data.linkOnly.deviceId!==user.deviceId||q.data.linkOnly.generation!==user.generation)return json({error:'restart'},403);
  if(step==='begin'){const o=await c.beginLink(v.continuation);return o&&await auth.authenticate(request)?json({token:o.token,options:o.options,expires_at:o.expiresAt},200,{'Cache-Control':'no-store'}):json({error:'restart'},403);}
  if(typeof v.token!=='string'||v.token.length>200||!v.response||typeof v.response!=='object'||Array.isArray(v.response))return json({error:'invalid_request'},400);
  let ok=false;try{ok=await c.verify({token:v.continuation,ceremony:v.token,response:v.response});}catch{ok=false;}
  return ok?json({status:'linked'},200,{'Cache-Control':'no-store'}):json({error:'restart'},403);
 }};
}
