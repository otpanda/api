import {json,takeRateLimit} from './sessions.js';
import {createDeviceSessionAuth} from './device-session-auth.js';
import {SESSION_METHOD_JOIN as MJ,SESSION_METHOD_ACTIVE as MA} from './session-method.js';
import {normalizeWebsiteDomains} from './website-domains.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',PATH='/v1/manage/entry/domains';
// Associations belong to the viewer, not to the entry's owner or its recipients.
const readable=`EXISTS(SELECT 1 FROM entries e WHERE e.entry_id=a.entry_id AND (e.owner_id=?1 OR EXISTS(SELECT 1 FROM entry_readers m WHERE m.entry_id=e.entry_id AND m.recipient_id=?1 AND m.revoked_at IS NULL)))`;
// extensionOrigins (array, default null = disabled): an EXTENSION-kind session may only GET the viewer's own associations. POST stays web/android only.
export function createEntryDomainsHttp({db,sessions,clock=Date.now,native=false,extensionOrigins=null}={}){
 const auth=createDeviceSessionAuth({sessions,native}),extAuth=extensionOrigins?createDeviceSessionAuth({sessions,extension:true,extensionOrigins}):undefined;
 const authn=async(r,get)=>(await auth.authenticate(r))??(extAuth&&get?await extAuth.authenticate(r):undefined);
 return {async fetch(request){
  const u=new URL(request.url),origin=request.headers.get('origin'),android=origin===null;
  if(u.origin!==API||u.pathname!==PATH)return json({error:'not_found'},404);
  const ext=!!extAuth&&request.method==='GET'&&origin!==APP&&extAuth.originAllowed(request);
  if(origin!==APP&&!(native&&android)&&!ext)return json({error:'forbidden'},403);
  const cors=(android||ext)?{}:{'Access-Control-Allow-Origin':APP,Vary:'Origin'},reply=(v,s=200,h={})=>json(v,s,{'Cache-Control':'no-store',...cors,...h});
  if(u.search)return reply({error:'invalid_request'},400);
  if(request.method==='OPTIONS'&&!android){
   const h=(request.headers.get('access-control-request-headers')??'').toLowerCase().split(',').map(v=>v.trim()).filter(Boolean);
   return ['GET','POST'].includes(request.headers.get('access-control-request-method'))&&h.every(v=>['authorization','content-type'].includes(v))?new Response(null,{status:204,headers:{...cors,'Access-Control-Allow-Methods':'GET, POST','Access-Control-Allow-Headers':'Authorization, Content-Type','Cache-Control':'no-store'}}):reply({error:'forbidden'},403);
  }
  if(!['GET','POST'].includes(request.method))return reply({error:'method_not_allowed'},405);
  const viewer=await authn(request,request.method==='GET');if(!viewer)return reply({error:'unauthorized'},401);
  const rate=await takeRateLimit(db,'entry-domains:'+viewer.ownerId,{now:clock(),limit:60});if(!rate.allowed)return reply({error:'rate_limited'},429,{'Retry-After':String(rate.retryAfter)});
  if(request.method==='GET'){
   const rows=(await db.prepare(`SELECT a.entry_id,a.domains_json FROM entry_domain_associations a WHERE a.viewer_id=?1 AND ${readable} ORDER BY a.entry_id LIMIT 1000`).bind(viewer.ownerId).all()).results;
   if(!await authn(request,true))return reply({error:'unauthorized'},401);
   const associations=[];for(const r of rows){try{associations.push({entryId:r.entry_id,domains:normalizeWebsiteDomains(JSON.parse(r.domains_json))});}catch{/* Corrupt metadata never breaks other entries or becomes a rule. */}}
   return reply({associations});
  }
  const ct=request.headers.get('content-type')??'';
  if((android?ct!=='application/json':ct.split(';')[0].trim()!=='application/json')||!request.body)return reply({error:'invalid_request'},400);
  let b,domains;
  try{
   const reader=request.body.getReader(),chunks=[];let size=0;
   for(;;){const p=await reader.read();if(p.done)break;size+=p.value.byteLength;if(size>12288){await reader.cancel();return reply({error:'invalid_request'},400);}chunks.push(p.value);}
   const bytes=new Uint8Array(size);let off=0;for(const p of chunks){bytes.set(p,off);off+=p.length;}
   b=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
   if(!b||Array.isArray(b)||Object.keys(b).length!==2||!Object.hasOwn(b,'entryId')||!Object.hasOwn(b,'domains')||typeof b.entryId!=='string'||!/^[A-Za-z0-9_-]{1,128}$/.test(b.entryId))throw new TypeError();
   domains=normalizeWebsiteDomains(b.domains);
  }catch{return reply({error:'invalid_request'},400);}
  const kind=android?'android':'web',now=clock();
  const active=`EXISTS(SELECT 1 FROM device_sessions d ${MJ} JOIN account_security s ON s.owner_id=d.owner_id WHERE d.device_id=?4 AND d.owner_id=?1 AND d.generation=?5 AND s.generation=?5 AND d.client_kind='${kind}' AND d.revoked_at IS NULL AND ${MA} AND d.created_at<=?6 AND d.expires_at>?6)`;
  const r=await db.prepare(`INSERT INTO entry_domain_associations(viewer_id,entry_id,domains_json) SELECT ?1,e.entry_id,?3 FROM entries e WHERE e.entry_id=?2 AND (e.owner_id=?1 OR EXISTS(SELECT 1 FROM entry_readers m WHERE m.entry_id=e.entry_id AND m.recipient_id=?1 AND m.revoked_at IS NULL)) AND ${active} ON CONFLICT(viewer_id,entry_id) DO UPDATE SET domains_json=excluded.domains_json`).bind(viewer.ownerId,b.entryId,JSON.stringify(domains),viewer.deviceId,viewer.generation,now).run();
  return r.meta.changes>=1?reply({ok:true}):reply({error:'not_found'},404);
 }};
}
