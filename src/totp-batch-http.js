// Bounded batched current/future TOTP codes for the web viewer. Codes only,
// held in client memory; seeds never leave the server. Web device-session
// access only, same Origin/CORS posture as totp-code.
import {json, takeRateLimit} from './sessions.js';
import {createDeviceSessionAuth} from './device-session-auth.js';
const API='https://otpanda-api.abrahammurciano.workers.dev';
const APP='https://otpanda.github.io';
const PATH='/v1/manage/totp-codes';
// Per-request cap 5 (Free Worker CPU headroom; measured p99 8.84ms at 20 left no headroom under 10ms). A 20-entry prefetch is 4 requests.
// Rate: 24 requests/min per address. Old budget was 12 x 20 = 240 entry-windows/min; the new worst case is 24 x 5 = 120 (half), and request count
// doubles. One full 20-entry prefetch costs 4 of the 24, so 6 per minute fit and retries/other tabs on a shared address are not starved.
export const BATCH_MAX_ENTRIES=5,BATCH_RATE_PER_MINUTE=24;
const MAX_ENTRIES=BATCH_MAX_ENTRIES,MAX_WINDOW=600;
const cors={'Access-Control-Allow-Origin':APP,'Access-Control-Expose-Headers':'Retry-After',Vary:'Origin'};
function parse(url){
 if(url.search.length>2048)return undefined;
 const keys=[...url.searchParams.keys()];if(keys.some(k=>k!=='entry'&&k!=='window'))return undefined;
 const entries=url.searchParams.getAll('entry'),windows=url.searchParams.getAll('window');
 if(entries.length<1||entries.length>MAX_ENTRIES||windows.length>1||new Set(entries).size!==entries.length)return undefined;
 if(entries.some(e=>!e||e.length>64||/[\u0000-\u0020\u007f]/u.test(e)))return undefined;
 let window=MAX_WINDOW;
 if(windows.length){if(!/^[0-9]{1,6}$/.test(windows[0]))return undefined;window=Math.min(MAX_WINDOW,Number(windows[0]));if(window<1)return undefined;}
 return {entries,window};
}
const same=(a,b)=>a&&b&&a.ownerId===b.ownerId&&a.deviceId===b.deviceId&&a.generation===b.generation;
function timestamp(clock){const now=clock();if(!Number.isSafeInteger(now)||now<0)throw new TypeError('Valid server clock required');return now;}
export function createTotpBatchHttp({db,sessions,generator,clock=Date.now}={}){
 if(!db||typeof generator?.generateWindowForActor!=='function'||typeof clock!=='function')throw new TypeError('TOTP batch dependencies required');
 const auth=createDeviceSessionAuth({sessions});
 return {async fetch(request,{clientAddress}={}){
  const url=new URL(request.url);
  if(url.origin!==API||url.pathname!==PATH)return json({error:'not_found'},404);
  if(request.headers.get('origin')!==APP)return json({error:'forbidden'},403);
  const reply=(body,status=200,headers={})=>json(body,status,{...cors,...headers});
  if(request.method==='OPTIONS'){
   const headers=(request.headers.get('access-control-request-headers')??'').toLowerCase().split(',').map(v=>v.trim()).filter(Boolean);
   return (!url.search||parse(url))&&request.headers.get('access-control-request-method')==='GET'&&headers.every(h=>h==='authorization')?new Response(null,{status:204,headers:{...cors,'Cache-Control':'no-store','Access-Control-Allow-Methods':'GET','Access-Control-Allow-Headers':'Authorization'}}):reply({error:'forbidden'},403);
  }
  if(request.method!=='GET')return reply({error:'method_not_allowed'},405);
  const query=parse(url);if(!query)return reply({error:'invalid_request'},400);
  if(typeof clientAddress!=='string'||!clientAddress||clientAddress.length>128)return reply({error:'unavailable'},503);
  try{
   const now=timestamp(clock);
   const rate=await takeRateLimit(db,'totp-batch:'+clientAddress,{now,limit:BATCH_RATE_PER_MINUTE});
   if(!rate.allowed)return reply({error:'rate_limited'},429,{'Retry-After':String(rate.retryAfter)});
   const viewer=await auth.authenticate(request);if(!viewer)return reply({error:'unauthorized'},401);
   const result=await generator.generateWindowForActor(viewer.ownerId,query.entries,Math.floor(now/1000),{windowSeconds:query.window});
   const current=await auth.authenticate(request);if(!same(viewer,current))return reply({error:'unauthorized'},401);
   const serverNow=timestamp(clock),end=serverNow/1000;
   // Explicit allowlist and shape check; a result that does not cover the
   // trusted time is dropped to "unavailable", never returned.
   const entries=[],omitted=[];
   // A boundary crossed during generation: drop expired leading codes, shift validFrom. Nothing left means unavailable.
   for(const e of result?.entries??[]){if(e&&Number.isSafeInteger(e.period)&&e.period>0&&Number.isSafeInteger(e.validFrom)&&Array.isArray(e.codes)){let drop=0;while(drop<e.codes.length&&e.validFrom+(drop+1)*e.period<=end)drop++;if(drop){e.codes=e.codes.slice(drop);e.validFrom+=drop*e.period;}}}
   const asked=new Set(query.entries);
   for(const e of result?.entries??[]){
    const ok=asked.has(e.entryId)&&Number.isSafeInteger(e.period)&&e.period>=20&&e.period<=86400&&(e.digits===6||e.digits===8)&&Number.isSafeInteger(e.validFrom)&&e.validFrom%e.period===0&&Array.isArray(e.codes)&&e.codes.length>=1&&e.codes.length<=Math.ceil(query.window/e.period)+1&&e.codes.length<=31&&e.codes.every(c=>typeof c==='string'&&c.length===e.digits&&/^\d+$/.test(c))&&e.validFrom<=end&&e.validFrom+e.period>end;
    if(ok)entries.push({entryId:e.entryId,period:e.period,digits:e.digits,validFrom:e.validFrom,codes:[...e.codes]});else omitted.push({entryId:e.entryId,reason:'unavailable'});
   }
   for(const o of result?.omitted??[])if(asked.has(o.entryId))omitted.push({entryId:o.entryId,reason:o.reason==='period_too_short'?'period_too_short':'unavailable'});
   const seen=new Set([...entries,...omitted].map(e=>e.entryId));
   for(const id of query.entries)if(!seen.has(id))omitted.push({entryId:id,reason:'unavailable'});
   if(!Number.isSafeInteger(result?.windowEnd)||result.windowEnd>end+query.window)return reply({error:'unavailable'},503);
   return reply({serverNow,windowSeconds:query.window,windowExpiresAt:result.windowEnd*1000,entries,omitted});
  }catch{return reply({error:'unavailable'},503);}
 }};
}
