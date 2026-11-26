// Bounded batched current/future TOTP codes for the web viewer. Codes only,
// held in client memory; seeds never leave the server. Web device-session
// access only, same Origin/CORS posture as totp-code.
import {json, takeRateLimit} from './sessions.js';
import {createDeviceSessionAuth} from './device-session-auth.js';
import {finalizeCommonHorizon} from './common-horizon-finalizer.js';
import {responsePolicy} from './common-horizon-response-policy.js';
import {maxCodesPerEntry,planCommonHorizon} from './common-horizon-planner.js';
const API='https://otpanda-api.abrahammurciano.workers.dev';
const APP='https://otpanda.github.io';
const PATH='/v1/manage/totp-codes';
// No production cap defaults. Activation requires measured explicit configuration.
const cors={'Access-Control-Allow-Origin':APP,'Access-Control-Expose-Headers':'Retry-After',Vary:'Origin'};
function parse(url,{entryCap,maxWindow}){
 if(url.search.length>2048)return undefined;
 const keys=[...url.searchParams.keys()];if(keys.some(k=>k!=='entry'&&k!=='window'))return undefined;
 const entries=url.searchParams.getAll('entry'),windows=url.searchParams.getAll('window');
 if(entries.length<1||entries.length>entryCap||windows.length>1||new Set(entries).size!==entries.length)return undefined;
 if(entries.some(e=>!e||e.length>64||/[\u0000-\u0020\u007f]/u.test(e)))return undefined;
 let window=maxWindow;
 if(windows.length){if(!/^[0-9]{1,6}$/.test(windows[0]))return undefined;window=Math.min(maxWindow,Number(windows[0]));if(window<1)return undefined;}
 return {entries,window};
}
const same=(a,b)=>a&&b&&a.ownerId===b.ownerId&&a.deviceId===b.deviceId&&a.generation===b.generation;
function timestamp(clock){const now=clock();if(!Number.isSafeInteger(now)||now<0)throw new TypeError('Valid server clock required');return now;}
export function createCommonHorizonBatchHttp({db,sessions,generator,clock=Date.now,horizonPolicy,ratePerMinute,minRemainingMs,native=false}={}){
 if(!horizonPolicy||!Number.isSafeInteger(ratePerMinute)||ratePerMinute<1||!Number.isSafeInteger(minRemainingMs)||minRemainingMs<1)throw new TypeError('Explicit qualified policies required');
 const maxCodes=maxCodesPerEntry(horizonPolicy);
 if(horizonPolicy.entryCap>49)throw new RangeError('D1 revalidation parameter bound exceeded');
 if(horizonPolicy.maxWindow>600||maxCodes>64)throw new RangeError('Generator bounds exceeded');
 planCommonHorizon({...horizonPolicy,now:0,periods:[],requestedWindow:horizonPolicy.maxWindow});
 const policy=responsePolicy({...horizonPolicy,digits:[6,7,8],maxCodesPerEntry:maxCodes});
 if(!db||typeof generator?.generateWindowForActor!=='function'||typeof clock!=='function')throw new TypeError('TOTP batch dependencies required');
 const auth=createDeviceSessionAuth({sessions,native});
 let completedBatch=false;
 return {async fetch(request,{clientAddress}={}){
  const url=new URL(request.url);
  if(url.origin!==API||url.pathname!==PATH)return json({error:'not_found'},404);
  if(!auth.originAllowed(request))return json({error:'forbidden'},403);
  const reply=(body,status=200,headers={})=>json(body,status,{...cors,...headers});
  if(request.method==='OPTIONS'){
   const headers=(request.headers.get('access-control-request-headers')??'').toLowerCase().split(',').map(v=>v.trim()).filter(Boolean);
   return (!url.search||parse(url,horizonPolicy))&&request.headers.get('access-control-request-method')==='GET'&&headers.every(h=>h==='authorization')?new Response(null,{status:204,headers:{...cors,'Cache-Control':'no-store','Access-Control-Allow-Methods':'GET','Access-Control-Allow-Headers':'Authorization'}}):reply({error:'forbidden'},403);
  }
  if(request.method!=='GET')return reply({error:'method_not_allowed'},405);
  const query=parse(url,horizonPolicy);if(!query)return reply({error:'invalid_request'},400);
  if(typeof clientAddress!=='string'||!clientAddress||clientAddress.length>128)return reply({error:'unavailable'},503);
  try{
   const now=timestamp(clock);
   const rate=await takeRateLimit(db,'totp-batch:'+clientAddress,{now,limit:ratePerMinute});
   if(!rate.allowed)return reply({error:'rate_limited'},429,{'Retry-After':String(rate.retryAfter)});
   const viewer=await auth.authenticate(request);if(!viewer)return reply({error:'unauthorized'},401);
   // Conservative first-use work bound, not a CPU timer. Concurrent requests
   // remain minimal until a batch has fully completed. A new isolate resets it.
   const firstUse=!completedBatch;
   const generationPolicy=firstUse?{...horizonPolicy,budget:query.entries.length,entryCap:query.entries.length,minUsefulWindow:1}:horizonPolicy;
   const result=await generator.generateWindowForActor(viewer.ownerId,query.entries,Math.floor(now/1000),{windowSeconds:query.window,horizonPolicy:generationPolicy});
   const current=await auth.authenticate(request);if(!same(viewer,current))return reply({error:'unauthorized'},401);
   const final=finalizeCommonHorizon({requestedIds:query.entries,
    entries:result?.entries,omitted:result?.omitted,coverageUntil:result?.coverageUntil,
    nowMs:timestamp(clock),minRemainingMs:1,policy});
   if(final.status!=='ok')return reply({error:'unavailable'},503);
   const {status,...body}=final;
   completedBatch=true;
   return reply(body);
  }catch{return reply({error:'unavailable'},503);}
 }};
}
