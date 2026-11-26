// Isolated read-only contract, deliberately not wired into any application.
// Accepts only web device-session access, never automation/refresh credentials.
import {json, takeRateLimit} from './sessions.js';
import {createDeviceSessionAuth} from './device-session-auth.js';
const API='https://otpanda-api.abrahammurciano.workers.dev';
const APP='https://otpanda.github.io';
const PATH='/v1/manage/totp-code';
const cors={'Access-Control-Allow-Origin':APP,'Access-Control-Expose-Headers':'Retry-After',Vary:'Origin'};
function entryOf(url){if(url.search.length>512||[...url.searchParams.keys()].length!==1||!url.searchParams.has('entry'))return undefined;const entry=url.searchParams.get('entry');return entry&&entry.length<=256&&!/[\u0000-\u0020\u007f]/u.test(entry)?entry:undefined;}
const same=(a,b)=>a&&b&&a.ownerId===b.ownerId&&a.deviceId===b.deviceId&&a.generation===b.generation;
function timestamp(clock){const now=clock();if(!Number.isSafeInteger(now)||now<0)throw new TypeError('Valid server clock required');return now;}
// extensionOrigins (array, default null = disabled): an EXTENSION-kind session, and only that kind, may GET one entry's current code. No CORS
// headers, no preflight, an owner-keyed 20/min budget on top of the ingress one, and never any other method or path.
export function createTotpReadHttp({db,sessions,generator,clock=Date.now,native=false,extensionOrigins=null}={}){
 if(!db||typeof generator?.generateForActor!=='function'||typeof clock!=='function')throw new TypeError('TOTP read dependencies required');
 const auth=createDeviceSessionAuth({sessions,native}),extAuth=extensionOrigins?createDeviceSessionAuth({sessions,extension:true,extensionOrigins}):undefined;
 return {async fetch(request,{clientAddress}={}){
  const url=new URL(request.url);
  if(url.origin!==API||url.pathname!==PATH)return json({error:'not_found'},404);
  const ext=!!extAuth&&request.method==='GET'&&request.headers.get('origin')!==APP&&extAuth.originAllowed(request);
  if(!ext&&!auth.originAllowed(request))return json({error:'forbidden'},403);
  const authn=async r=>(await auth.authenticate(r))??(ext?await extAuth.authenticate(r):undefined);
  const reply=(body,status=200,headers={})=>json(body,status,{...(ext?{}:cors),...headers});
  if(request.method==='OPTIONS'){
   const headers=(request.headers.get('access-control-request-headers')??'').toLowerCase().split(',').map(v=>v.trim()).filter(Boolean);
   return (!url.search||entryOf(url))&&request.headers.get('access-control-request-method')==='GET'&&headers.every(h=>h==='authorization')?new Response(null,{status:204,headers:{...cors,'Cache-Control':'no-store','Access-Control-Allow-Methods':'GET','Access-Control-Allow-Headers':'Authorization'}}):reply({error:'forbidden'},403);
  }
  if(request.method!=='GET')return reply({error:'method_not_allowed'},405);
  const entry=entryOf(url);if(!entry)return reply({error:'invalid_request'},400);
  if(typeof clientAddress!=='string'||!clientAddress||clientAddress.length>128)return reply({error:'unavailable'},503);
  try{
   const now=timestamp(clock);
   const rate=await takeRateLimit(db,'totp-read:'+clientAddress,{now,limit:60});
   if(!rate.allowed)return reply({error:'rate_limited'},429,{'Retry-After':String(rate.retryAfter)});
   const web=await auth.authenticate(request),viewer=web??(ext?await extAuth.authenticate(request):undefined);if(!viewer)return reply({error:'unauthorized'},401);
   if(ext&&!web){const own=await takeRateLimit(db,'totp-read-ext:'+viewer.ownerId,{now,limit:20});if(!own.allowed)return reply({error:'rate_limited'},429,{'Retry-After':String(own.retryAfter)});}
   const record=await generator.generateForActor(viewer.ownerId,entry,Math.floor(now/1000),{automation:false});
   const current=await authn(request);if(!same(viewer,current))return reply({error:'unauthorized'},401);
   if(!record)return reply({error:'not_found'},404);
   const serverNow=timestamp(clock),end=serverNow/1000;
   // A generation spanning the boundary must not return the old interval.
   if(record.entryId!==entry||!Number.isSafeInteger(record.validFrom)||!Number.isSafeInteger(record.validUntil)||record.validFrom>end||record.validUntil<=end)return reply({error:'unavailable'},503);
   // Explicit allowlist: seed/envelope/source metadata can never enter output.
   if(typeof record.code!=='string'||!/^\d{6,8}$/.test(record.code)||!Number.isSafeInteger(record.period)||record.period<1||record.period>86400||record.validUntil-record.validFrom!==record.period||record.validFrom%record.period!==0)return reply({error:'unavailable'},503);
   return reply({entryId:entry,code:record.code,period:record.period,validFrom:record.validFrom,validUntil:record.validUntil,serverNow});
  }catch{return reply({error:'unavailable'},503);}
 }};
}
