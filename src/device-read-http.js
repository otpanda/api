// New web-device read boundary only, deliberately not mounted. Mutations need
// their own action-bound step-up and logout protocol, never this read adapter.
import {json,takeRateLimit,hashText} from './sessions.js';
import {createDeviceSessionAuth} from './device-session-auth.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io';
const paths=new Set(['/v1/manage/session','/v1/manage/entries','/v1/manage/active-codes','/v1/manage/unassigned','/v1/manage/unassigned-context','/v1/manage/sources']);
const WEB_CORS={'Access-Control-Allow-Origin':APP,'Access-Control-Expose-Headers':'Retry-After',Vary:'Origin'};
// extensionOrigins (array, default null = disabled): lets an EXTENSION-kind session, and only that kind, GET entries and active-codes. Never any other
// path, never any other method, no CORS headers for it. Pinned origins are a coarse filter; the token kind is what authenticates.
const EXT_PATHS=new Set(['/v1/manage/entries','/v1/manage/active-codes']);
export function createDeviceReadHttp({db,sessions,sources,access,clock=Date.now,native=false,extensionOrigins=null}={}){
 if(!db||!sources||!access)throw new TypeError('Read dependencies required');
 const auth=createDeviceSessionAuth({sessions,native}),extAuth=extensionOrigins?createDeviceSessionAuth({sessions,extension:true,extensionOrigins}):undefined;
 const extOk=(r,path)=>!!extAuth&&r.method==='GET'&&EXT_PATHS.has(path),originOk=(r,path)=>auth.originAllowed(r)||(extOk(r,path)&&extAuth.originAllowed(r)),authn=async(r,path)=>(await auth.authenticate(r))??(extOk(r,path)?await extAuth.authenticate(r):undefined);
 return {async fetch(request,{clientAddress}={}){
  const url=new URL(request.url);if(url.origin!==API||!paths.has(url.pathname))return json({error:'not_found'},404);
  const cors=request.headers.get('origin')===APP?WEB_CORS:{};
  if(!originOk(request,url.pathname))return json({error:'forbidden'},403);
  if(request.method==='OPTIONS'){
   const h=request.headers.get('access-control-request-headers')?.toLowerCase().split(',').map(v=>v.trim())??[];
   return request.headers.get('access-control-request-method')==='GET'&&h.every(v=>v==='authorization')
    ?new Response(null,{status:204,headers:{...cors,'Cache-Control':'no-store','Access-Control-Allow-Methods':'GET','Access-Control-Allow-Headers':'Authorization'}})
    :json({error:'forbidden'},403,cors);
  }
  if(request.method!=='GET')return json({error:'method_not_allowed'},405,cors);
  // Legacy two-key shape is frozen for deployed clients; sessionId is opt-in via the one exact query below.
  const withSession=url.pathname==='/v1/manage/session'&&url.search==='?view=cache-v1';
  if(url.search&&!withSession)return json({error:'invalid_request'},400,cors);
  if(typeof clientAddress!=='string'||!clientAddress||clientAddress.length>128)return json({error:'unavailable'},503,cors);
  const limit=await takeRateLimit(db,'device-read:'+clientAddress,{now:clock(),limit:60});
  if(!limit.allowed)return json({error:'rate_limited'},429,{...cors,'Retry-After':String(limit.retryAfter)});
  const user=await authn(request,url.pathname);if(!user)return json({error:'unauthorized'},401,cors);
  try {
  let result;
  if(url.pathname==='/v1/manage/session'){result={ownerId:user.ownerId,expiresAt:user.expiresAt};if(withSession)result.sessionId=await hashText('otpanda-session-id-v1\n'+user.ownerId+'\n'+user.deviceId);}
  else if(url.pathname==='/v1/manage/entries'){
   const rows=await db.prepare(`SELECT e.entry_id,e.service_id,e.label,e.account_name,e.owner_id AS capability_owner,CASE WHEN e.service_id='custom-totp' THEN e.label ELSE s.name END AS service_name,s.icon_key,e.catalog_id,e.issuer FROM entries e JOIN services s ON s.service_id=e.service_id WHERE e.owner_id=?1 OR EXISTS (SELECT 1 FROM entry_readers m WHERE m.entry_id=e.entry_id AND m.recipient_id=?1 AND m.revoked_at IS NULL) ORDER BY e.entry_id LIMIT 100`).bind(user.ownerId).all();
   result={entries:rows.results.map(({capability_owner,catalog_id,issuer,...entry})=>({...entry,...(catalog_id?{catalogId:catalog_id}:{}),...(issuer?{issuer}:{}),capabilities:{manage:capability_owner===user.ownerId}}))};
  }else if(url.pathname==='/v1/manage/active-codes')result={records:await access.activeRecent(user.ownerId,clock())};
  else if(url.pathname==='/v1/manage/unassigned-context')result={contexts:await sources.contextsForOwner(user.ownerId,clock())};
  else if(url.pathname==='/v1/manage/unassigned')result={records:await sources.unassignedForOwner(user.ownerId,clock())};
  else result={sources:await sources.sourcesForOwner(user.ownerId)};
  // Security reset/device revocation/expiry during decrypt or DB work wins.
  if(!await authn(request,url.pathname))return json({error:'unauthorized'},401,cors);
  if(result.contexts)result.contexts=result.contexts.filter(c=>c.retainedUntil>clock());
  if(result.records)result.records=result.records.filter(r=>r.receivedAt<=clock()&&r.expiresAt>clock());
  return json(result,200,cors);
  }catch{return json({error:'unavailable'},503,cors);}
 }};
}
