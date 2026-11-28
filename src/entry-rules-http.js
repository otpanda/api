import {pinnedAudience} from './action-audience.js';
import {digestKeyId} from './template-fingerprint.js';
import {json,takeRateLimit} from './sessions.js';
import {createDeviceSessionAuth} from './device-session-auth.js';
import {normalizePhrase} from './service-metadata.js';
import {SESSION_METHOD_JOIN as MJ,SESSION_METHOD_ACTIVE as MA} from './session-method.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',ID=/^[A-Za-z0-9_-]{1,128}$/;
const CAP='/v1/manage/rules/capabilities';
const PATHS=new Set([CAP,'/v1/manage/entry/rules','/v1/manage/entry/rule','/v1/manage/entry/rule/delete']);
// Owner-only sender rules (service_routes rows created by Assign). Web device bearer or android bearer, never cookie, extension or token.
//  GET  /v1/manage/entry/rules[?cursor=<ruleId>] -> {next?:ruleId, rules:[{ruleId,entryId,sourceId,sourceLabel,kind,senderKind,sender,phrase|null,createdAt|null}]}
//  POST /v1/manage/entry/rule        {ruleId,phrase|null}  set or clear the optional case-insensitive phrase
//  POST /v1/manage/entry/rule/delete {ruleId}
// A rule is exact sender on one receiving connector (source). It never covers a whole connector or inbox. Only entries the viewer OWNS: a recipient
// has no entry_shares path and gets an empty list / 404. Never returns a code, message text, envelope or event id. Writes are bound to the live session.
export function createEntryRulesHttp({db,sessions,metadata,clock=Date.now,native=false,keyIds=null,capabilities=null,disconnectPolicy=async()=>true,management=async()=>true}={}){
 if(!db||!metadata)throw new TypeError('Rule dependencies required');
 const auth=createDeviceSessionAuth({sessions,native});
 return {async fetch(request){
  const u=new URL(request.url),origin=request.headers.get('origin'),android=origin===null;
  if(u.origin!==API||!PATHS.has(u.pathname))return json({error:'not_found'},404);
  if(origin!==APP&&!(native&&android))return json({error:'forbidden'},403);
  const cors=android?{}:{'Access-Control-Allow-Origin':APP,Vary:'Origin'},reply=(v,s=200,h={})=>json(v,s,{'Cache-Control':'no-store',...cors,...h});
  const cap=u.pathname===CAP,get=cap||u.pathname==='/v1/manage/entry/rules',method=get?'GET':'POST',qs=[...u.searchParams];
  if(u.search&&!(get&&!cap&&qs.every(([k,v])=>(k==='cursor'||k==='entryId')&&ID.test(v))&&new Set(qs.map(q=>q[0])).size===qs.length))return reply({error:'invalid_request'},400);
  if(request.method==='OPTIONS'&&!android){
   const h=(request.headers.get('access-control-request-headers')??'').toLowerCase().split(',').map(v=>v.trim()).filter(Boolean);
   return request.headers.get('access-control-request-method')===method&&h.every(v=>['authorization','content-type'].includes(v))?new Response(null,{status:204,headers:{...cors,'Access-Control-Allow-Methods':method,'Access-Control-Allow-Headers':'Authorization, Content-Type','Cache-Control':'no-store'}}):reply({error:'forbidden'},403);
  }
  if(request.method!==method)return reply({error:'method_not_allowed'},405);
  const viewer=await auth.authenticate(request);if(!viewer)return reply({error:'unauthorized'},401);
  const now=clock(),rate=await takeRateLimit(db,'entry-rules:'+viewer.ownerId,{now,limit:60});if(!rate.allowed)return reply({error:'rate_limited'},429,{'Retry-After':String(rate.retryAfter)});
  try{
   if(cap){const available=capabilities?await capabilities():false;if(!await auth.authenticate(request))return reply({error:'unauthorized'},401);return reply({version:1,rules:{available:available===true,managementAvailable:await management()===true,disconnectPolicy:await disconnectPolicy()===true}});}
   if(!await management())return reply({error:'unavailable'},503);
   if(get){
    const rows=await metadata.routesForOwner(viewer.ownerId,{after:u.searchParams.get('cursor')??'',entryId:u.searchParams.get('entryId'),limit:100}),more=rows.length>100,page=more?rows.slice(0,100):rows;
    if(!await auth.authenticate(request))return reply({error:'unauthorized'},401);
    return reply({rules:page.map(r=>({ruleId:r.route_id,entryId:r.entry_id,sourceId:r.source_id,sourceLabel:r.label,kind:r.kind,senderKind:r.origin_kind,sender:r.origin_value,phrase:r.phrase??null,basis:r.template_fp?'template':r.phrase?'phrase':'sender',status:r.paused_at!=null?'paused':r.template_fp&&keyIds&&!keyIds.includes(digestKeyId(r.template_fp))?'needs_reassign':'active',createdAt:r.created_at??null})),...(more?{next:page.at(-1).route_id}:{})});
   }
   const ct=request.headers.get('content-type')??'';
   if((android?ct!=='application/json':ct.split(';')[0].trim()!=='application/json')||!request.body)return reply({error:'invalid_request'},400);
   const reader=request.body.getReader(),parts=[];let size=0,body;
   for(;;){const p=await reader.read();if(p.done)break;size+=p.value.byteLength;if(size>2048){await reader.cancel();return reply({error:'invalid_request'},400);}parts.push(p.value);}
   try{const bytes=new Uint8Array(size);let i=0;for(const p of parts){bytes.set(p,i);i+=p.byteLength;}body=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}catch{return reply({error:'invalid_request'},400);}
   const del=u.pathname.endsWith('/delete'),keys=del?['ruleId']:['phrase','ruleId'];
   if(!body||typeof body!=='object'||Array.isArray(body)||Object.keys(body).sort().join(',')!==keys.join(',')||typeof body.ruleId!=='string'||!ID.test(body.ruleId))return reply({error:'invalid_request'},400);
   if(!del&&body.phrase!==null&&typeof body.phrase!=='string')return reply({error:'invalid_request'},400);
   // The live-session condition sits INSIDE each write statement (owner, device, generation, client kind, not revoked, unexpired). A revoke between auth and write changes nothing.
   // Any edit except delete can widen what future codes reach (a phrase can match other templates). Entries with recipients or automation tokens are refused until a signed, disclosed confirmation exists.
   const unshared=pinnedAudience('service_routes.entry_id','service_routes.owner_id','?5',0,0);
   const kind=android?'android':'web',active=`EXISTS(SELECT 1 FROM device_sessions d ${MJ} JOIN account_security s ON s.owner_id=d.owner_id WHERE d.device_id=?3 AND d.owner_id=?1 AND d.generation=?4 AND s.generation=?4 AND d.client_kind='${kind}' AND d.revoked_at IS NULL AND ${MA} AND d.created_at<=?5 AND d.expires_at>?5)`;
   if(del){
    const r=await db.prepare(`DELETE FROM service_routes WHERE owner_id=?1 AND route_id=?2 AND entry_id IS NOT NULL AND ${active}`).bind(viewer.ownerId,body.ruleId,viewer.deviceId,viewer.generation,now).run();
    return r.meta.changes>=1?reply({ok:true}):reply({error:'not_found'},404);
   }
   // A basis change (phrase set, changed or cleared) can widen what future codes reach, so it is only accepted as a signed, disclosed action: /v1/manage/rule-intent/*. No unsigned write path exists.
   try{normalizePhrase(body.phrase);}catch{return reply({error:'invalid_request'},400);}
   return reply({error:'signed_action_required'},409);
  }catch{return reply({error:'unavailable'},503);}
 }};
}
