import {json,takeRateLimit} from './sessions.js';
import {createDeviceSessionAuth} from './device-session-auth.js';
import {normalLabel} from './passkey-providers.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',cors={'Access-Control-Allow-Origin':APP,Vary:'Origin'},ID=/^[A-Za-z0-9_-]{16,512}$/;
// POST /v1/manage/passkey/rename {credentialId,label}. Web access session only, owner-scoped, live credential only. Cosmetic: grants nothing and
// never changes authentication. Removing or revoking a passkey keeps its own step-up.
export function createPasskeyLabelHttp({db,sessions,clock=Date.now,native=false}={}){
 const auth=createDeviceSessionAuth({sessions,native:native===true});
 return {async fetch(request){
  const url=new URL(request.url);
  if(url.origin!==API||url.pathname!=='/v1/manage/passkey/rename')return json({error:'not_found'},404);
  if(!auth.originAllowed(request))return json({error:'forbidden'},403);
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
  let body;try{body=JSON.parse(text);}catch{return reply({error:'invalid_request'},400);}
  if(!body||typeof body!=='object'||Array.isArray(body)||Object.keys(body).length!==2||!Object.hasOwn(body,'credentialId')||!Object.hasOwn(body,'label')||typeof body.credentialId!=='string'||!ID.test(body.credentialId))return reply({error:'invalid_request'},400);
  const label=normalLabel(body.label);if(label===undefined)return reply({error:'invalid_label'},400);
  const rate=await takeRateLimit(db,'passkey-label:'+viewer.ownerId,{now:clock(),limit:30});if(!rate.allowed)return reply({error:'rate_limited'},429,{'Retry-After':String(rate.retryAfter)});
  // The session must still be the same live device at the write (revocation wins).
  const r=await db.prepare('INSERT INTO passkey_metadata(credential_id,owner_id,label) SELECT ?1,?2,?3 WHERE EXISTS(SELECT 1 FROM passkey_credentials WHERE credential_id=?1 AND owner_id=?2 AND revoked_at IS NULL) AND EXISTS(SELECT 1 FROM device_sessions d WHERE d.device_id=?4 AND d.owner_id=?2 AND d.generation=?5 AND d.revoked_at IS NULL AND d.expires_at>?6) ON CONFLICT(credential_id) DO UPDATE SET label=excluded.label').bind(body.credentialId,viewer.ownerId,label,viewer.deviceId,viewer.generation,clock()).run();
  if(r.meta.changes<1)return reply({error:'not_found'},404);
  return reply({ok:true});
 }};
}
