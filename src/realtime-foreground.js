// Post-write drain gating shared by every runtime that can retire a session or bump a security generation. Inactive without a `realtime` dependency.
// A drain costs budget, so it runs only after a route-allowlisted write that actually succeeded, never for reads, anonymous, 4xx or error responses.
import {drainSome,Budget,ROW_MIN_BUDGET,foregroundBudget,FOREGROUND_DELIVERY_MAX} from './realtime-outbox.js';
import {createQueryMeter} from './query-meter.js';
export const WRITERS=new Map([
 ['POST /v1/manage/totp',[201]],
 ['POST /v1/manage/assignment/finish',[200]],['POST /auth/device/logout',[200,204,303]],['GET /auth/device/logout',[200,204,303]],
 ['POST /auth/recovery/email/complete-finish',[200,204]],['POST /v1/manage/recovery/consume-change',[200,204]],['PUT /v1/manage/organization',[200,204]],
 // Every writer of device_sessions.revoked_at and account_security.generation was audited: recovery/finish (session-revoke, passkey-revoke), consume-change,
 // email complete-finish (generation bump), logout, and browser login completion (retires the prior browser session).
 ['POST /v1/manage/recovery/finish',[200,204]],['GET /auth/login/complete',[200,303]],['POST /auth/login/complete',[200,303]]]);
// Google sign-in (/auth/callback, /auth/google/continue/*, /auth/google/protection/*) also retires the prior browser session, but it runs a provider fetch and
// extra edge calls, and no headroom is qualified for that path, so its hints are CRON-ONLY by design: the trigger still writes the outbox row.
export const relevantWrite=(request,response)=>WRITERS.get(request.method+' '+new URL(request.url).pathname)?.includes(response.status)===true;
// Returns {db, wrap(fetch)}: db counts every query of the isolate (over-counts under overlap, never under), and wrap schedules the bounded drain.
export function createForegroundDrain({db:raw,realtime,clock=Date.now}={}){
 const meter=realtime?createQueryMeter(raw):undefined,db=meter?meter.db:raw;
 const wrap=handler=>async(request,ctx={})=>{
  const before=meter?.count()??0,response=await handler(request,ctx);
  if(meter&&realtime?.deliver&&typeof ctx.waitUntil==='function'&&relevantWrite(request,response)){
   // Combined ceiling: what the request already used + this drain's D1 + at most 10 hub calls stay under 45 of the 50 subrequests.
   const budget=foregroundBudget(meter.count()-before);
   if(budget>=ROW_MIN_BUDGET+1)ctx.waitUntil(drainSome({db,deliver:realtime.deliver,clock,budget:new Budget(budget),sends:new Budget(FOREGROUND_DELIVERY_MAX)}).catch(()=>{}));
  }
  return response;
 };
 return {db,wrap,meter};
}
