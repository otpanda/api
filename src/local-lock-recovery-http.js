import {json,takeRateLimit} from './sessions.js';
import {createDeviceSessionAuth} from './device-session-auth.js';
import {PasskeyService} from './passkey-service.js';
const API='https://otpanda-api.abrahammurciano.workers.dev';
const INTENTS=new Set(['local-unlock-once','local-lock-disable']);
async function body(request){const reader=request.body?.getReader();if(!reader)return;let text='',n=0;try{const decoder=new TextDecoder('utf-8',{fatal:true});for(;;){const r=await reader.read();if(r.done)break;n+=r.value.byteLength;if(n>24576){await reader.cancel();return;}text+=decoder.decode(r.value,{stream:true});}return JSON.parse(text+decoder.decode());}catch{return;}finally{reader.releaseLock();}}
// This proves only the exact local-lock intent. It never changes account security,
// renews a session, enrolls a device, or authorizes a sensitive account action.
export function createLocalLockRecoveryHttp({db,sessions,passkeys=new PasskeyService(db),clock=Date.now}={}){
 const auth=createDeviceSessionAuth({sessions,native:true});
 return{async fetch(request,{clientAddress}={}){
  const u=new URL(request.url),step=u.pathname.slice('/v1/manage/local-lock/'.length);
  if(u.origin!==API||!u.pathname.startsWith('/v1/manage/local-lock/')||!['begin','finish'].includes(step)||u.search)return json({error:'not_found'},404);
  if(request.headers.has('origin')||!auth.originAllowed(request))return json({error:'forbidden'},403);
  if(request.method!=='POST'||request.headers.get('content-type')!=='application/json')return json({error:'invalid_request'},400);
  if(!clientAddress)return json({error:'unavailable'},503);
  const user=await auth.authenticate(request);if(!user)return json({error:'unauthorized'},401);
  if(!(await takeRateLimit(db,'local-lock:'+user.ownerId+':'+user.deviceId,{now:clock(),limit:20})).allowed)return json({error:'busy'},429);
  const value=await body(request),fields=step==='begin'?'intent,lockGeneration':'intent,lockGeneration,response,token';
  if(!value||Array.isArray(value)||Object.keys(value).sort().join(',')!==fields||!INTENTS.has(value.intent)||typeof value.lockGeneration!=='string'||!/^[A-Za-z0-9_-]{32,128}$/.test(value.lockGeneration))return json({error:'invalid_request'},400);
  if(step==='finish'&&(typeof value.token!=='string'||!/^otpda_[A-Za-z0-9_-]{55}$/.test(value.token)))return json({error:'invalid_request'},400);
  const binding=JSON.stringify(['local-lock-v1',user.ownerId,user.deviceId,user.generation,value.lockGeneration]),action=value.intent;
  if(step==='begin'){const result=await passkeys.begin({purpose:'step-up',ownerId:user.ownerId,binding,action});return result?json(result):json({error:'restart'},403);}
  const proof=await passkeys.finishAuthentication({ownerId:user.ownerId,binding,action,token:value.token,response:value.response});
  const current=proof?await auth.authenticate(request):null;
  if(!proof||!current||current.ownerId!==user.ownerId||current.deviceId!==user.deviceId||current.generation!==user.generation||proof.ownerId!==user.ownerId||proof.generation!==user.generation)return json({error:'restart'},403);
  return json({intent:action,lockGeneration:value.lockGeneration,deviceId:user.deviceId,generation:user.generation});
 }};
}
