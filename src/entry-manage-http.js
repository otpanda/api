import {json,takeRateLimit} from './sessions.js';
import {SESSION_METHOD_JOIN as MJ,SESSION_METHOD_ACTIVE as MA} from './session-method.js';
import {createDeviceSessionAuth} from './device-session-auth.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',cors={'Access-Control-Allow-Origin':APP,Vary:'Origin'},ID=/^[A-Za-z0-9_-]{1,128}$/;
const PATHS=new Set(['/v1/manage/entry/rename','/v1/manage/entry/account']);
// POST /v1/manage/entry/rename {entryId,label} and /entry/account {entryId,accountName|null}.
// Web device bearer only (no cookie, automation token or native token), owner-only by SQL: a recipient or stranger gets 404.
// Same stack as passkey rename: no extra proof. The write is bound to the live device session; label/account triggers bump
// entries.mutation_revision (invalidating pending assignments) and write the realtime outbox row.
export function createEntryManageHttp({db,sessions,clock=Date.now}={}){
 const auth=createDeviceSessionAuth({sessions});
 return {async fetch(request){
  const url=new URL(request.url);
  if(url.origin!==API||!PATHS.has(url.pathname))return json({error:'not_found'},404);
  if(request.headers.get('origin')!==APP)return json({error:'forbidden'},403);
  const reply=(body,status=200,headers={})=>json(body,status,{...cors,...headers});
  if(url.search)return reply({error:'invalid_request'},400);
  if(request.method==='OPTIONS'){
   const h=(request.headers.get('access-control-request-headers')??'').toLowerCase().split(',').map(v=>v.trim()).filter(Boolean);
   return request.headers.get('access-control-request-method')==='POST'&&h.every(v=>['authorization','content-type'].includes(v))?new Response(null,{status:204,headers:{...cors,'Cache-Control':'no-store','Access-Control-Allow-Methods':'POST','Access-Control-Allow-Headers':'Authorization, Content-Type','Access-Control-Max-Age':'600'}}):reply({error:'forbidden'},403);
  }
  if(request.method!=='POST')return reply({error:'method_not_allowed'},405);
  const viewer=await auth.authenticate(request);if(!viewer)return reply({error:'unauthorized'},401);
  if((request.headers.get('content-type')??'').split(';')[0].trim()!=='application/json'||!request.body)return reply({error:'invalid_request'},400);
  const reader=request.body.getReader(),parts=[];let size=0;
  try{for(;;){const p=await reader.read();if(p.done)break;size+=p.value.byteLength;if(size>4096){await reader.cancel();return reply({error:'invalid_request'},400);}parts.push(p.value);}}catch{return reply({error:'invalid_request'},400);}
  let body;try{const bytes=new Uint8Array(size);let i=0;for(const p of parts){bytes.set(p,i);i+=p.byteLength;}body=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}catch{return reply({error:'invalid_request'},400);}
  const rename=url.pathname.endsWith('/rename'),key=rename?'label':'accountName';
  if(!body||typeof body!=='object'||Array.isArray(body)||Object.keys(body).length!==2||!Object.hasOwn(body,'entryId')||!Object.hasOwn(body,key)||typeof body.entryId!=='string'||!ID.test(body.entryId))return reply({error:'invalid_request'},400);
  const raw=body[key],value=typeof raw==='string'?raw.trim():raw;
  if(rename?(typeof value!=='string'||!value.trim()||value.length>120):(value!==null&&(typeof value!=='string'||!value.trim()||value.length>120)))return reply({error:'invalid_request'},400);
  const rate=await takeRateLimit(db,'entry-manage:'+viewer.ownerId,{now:clock(),limit:30});if(!rate.allowed)return reply({error:'rate_limited'},429,{'Retry-After':String(rate.retryAfter)});
  // Owner and live-session conditions sit inside the write. Triggers only fire on a real row update, so changes>=1 means this owner's entry changed.
  const now=clock(),column=rename?'label':'account_name';
  const active=`EXISTS(SELECT 1 FROM device_sessions d ${MJ} JOIN account_security s ON s.owner_id=d.owner_id WHERE d.device_id=?4 AND d.owner_id=?3 AND d.generation=?5 AND s.generation=?5 AND d.client_kind='web' AND d.revoked_at IS NULL AND ${MA} AND d.created_at<=?6 AND d.expires_at>?6)`;
  const args=[value,body.entryId,viewer.ownerId,viewer.deviceId,viewer.generation,now];
  const r=await db.prepare(`UPDATE entries SET ${column}=?1 WHERE entry_id=?2 AND owner_id=?3 AND ${column} IS NOT ?1 AND ${active}`).bind(...args).run();
  if(r.meta.changes>=1)return reply({ok:true});
  const same=await db.prepare(`SELECT entry_id FROM entries WHERE entry_id=?2 AND owner_id=?3 AND ${column} IS ?1 AND ${active}`).bind(...args).first();
  return same?reply({ok:true}):reply({error:'not_found'},404);
 }};
}
