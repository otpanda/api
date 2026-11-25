import {json,takeRateLimit} from './sessions.js';
import {createDeviceSessionAuth} from './device-session-auth.js';
import {normalLabel} from './passkey-providers.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',cors={'Access-Control-Allow-Origin':APP,Vary:'Origin'};
export const BROWSERS=['chrome','edge','firefox','safari','opera','samsung','other'],SYSTEMS=['android','windows','mac','ios','linux','chromeos','other'];
// POST /v1/manage/session/describe {browser,os,name}: the CURRENT session describes itself for the device list. Display only, self-declared and
// spoofable by the account's own session, never used for authority. Low-entropy only: closed browser and OS families; a free-text name exists only
// for native Android (Build.MODEL / device name), never for web, and a native session carries no browser. No identifiers.
export function createDeviceSessionInfoHttp({db,sessions,native=false,clock=Date.now}={}){
 const auth=createDeviceSessionAuth({sessions,native});
 return {async fetch(request){
  const url=new URL(request.url);
  if(url.origin!==API||url.pathname!=='/v1/manage/session/describe')return json({error:'not_found'},404);
  if(request.headers.get('origin')!==APP)return json({error:'forbidden'},403);
  const reply=(body,status=200,headers={})=>json(body,status,{...cors,...headers});
  if(url.search)return reply({error:'invalid_request'},400);
  if(request.method==='OPTIONS'){
   const h=(request.headers.get('access-control-request-headers')??'').toLowerCase().split(',').map(v=>v.trim()).filter(Boolean);
   return request.headers.get('access-control-request-method')==='POST'&&h.every(v=>['authorization','content-type'].includes(v))?new Response(null,{status:204,headers:{...cors,'Cache-Control':'no-store','Access-Control-Allow-Methods':'POST','Access-Control-Allow-Headers':'Authorization, Content-Type','Access-Control-Max-Age':'600'}}):reply({error:'forbidden'},403);
  }
  if(request.method!=='POST')return reply({error:'method_not_allowed'},405);
  const viewer=await auth.authenticate(request);if(!viewer)return reply({error:'unauthorized'},401);
  if((request.headers.get('content-type')??'').split(';')[0].trim()!=='application/json')return reply({error:'invalid_request'},400);
  let text;try{text=await request.text();}catch{return reply({error:'invalid_request'},400);}
  if(text.length>1024)return reply({error:'invalid_request'},400);
  let b;try{b=JSON.parse(text);}catch{return reply({error:'invalid_request'},400);}
  if(!b||typeof b!=='object'||Array.isArray(b)||Object.keys(b).length!==3||!['browser','os','name'].every(k=>Object.hasOwn(b,k)))return reply({error:'invalid_request'},400);
  const web=request.headers.get('origin')===APP,name=b.name===null?null:normalLabel(b.name,60);
  if((b.browser!==null&&!BROWSERS.includes(b.browser))||(b.os!==null&&!SYSTEMS.includes(b.os))||name===undefined||b.name===''||(b.name!==null&&typeof b.name!=='string'))return reply({error:'invalid_request'},400);
  if((web&&name!==null)||(!web&&b.browser!==null))return reply({error:'invalid_request'},400);
  const rate=await takeRateLimit(db,'device-info:'+viewer.ownerId,{now:clock(),limit:30});if(!rate.allowed)return reply({error:'rate_limited'},429,{'Retry-After':String(rate.retryAfter)});
  const r=await db.prepare('INSERT INTO device_session_info(device_id,owner_id,browser,os,name) SELECT ?1,?2,?3,?4,?5 WHERE EXISTS(SELECT 1 FROM device_sessions d WHERE d.device_id=?1 AND d.owner_id=?2 AND d.generation=?6 AND d.revoked_at IS NULL AND d.expires_at>?7) ON CONFLICT(device_id) DO UPDATE SET browser=excluded.browser,os=excluded.os,name=excluded.name').bind(viewer.deviceId,viewer.ownerId,b.browser,b.os,name,viewer.generation,clock()).run();
  if(r.meta.changes<1)return reply({error:'unauthorized'},401);
  return reply({ok:true});
 }};
}
