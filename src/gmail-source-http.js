// Owner source management. Kept unmounted until the ingest policy is ready.
import {createDeviceSessionAuth} from './device-session-auth.js';
import {PasskeyService} from './passkey-service.js';
import {SESSION_METHOD_JOIN,SESSION_METHOD_ACTIVE} from './session-method.js';
import {readCookie,json} from './sessions.js';
import {REFRESH_COOKIE} from './browser-session-http.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io';
const PATH='/v1/manage/gmail-source',CALLBACK='/sources/gmail/oauth/callback';
const cors={'Access-Control-Allow-Origin':APP,Vary:'Origin'};
const actions=new Set(['connect','disconnect']);
export function gmailSessionGuard({ownerId,deviceId,generation},now){
 return {sql:`SELECT 1 FROM device_sessions d ${SESSION_METHOD_JOIN} JOIN account_security s ON s.owner_id=d.owner_id WHERE d.owner_id=? AND d.device_id=? AND d.generation=? AND s.generation=d.generation AND d.revoked_at IS NULL AND d.created_at<=? AND d.expires_at>? AND ${SESSION_METHOD_ACTIVE}`,params:[ownerId,deviceId,Number(generation),now,now]};
}
// With `sync` (label mode capable), the same session-guarded revoke is handed to sync.disconnect as its local step,
// so Google-side cleanup of this app's own label and filter runs only after the guard passed and the token is still
// readable beforehand. Without `sync` the behavior is the original: local revoke only, no Google contact.
export async function disconnectGmailGuarded(db,user,sourceId,now,{sync}={}){
 if(!Number.isSafeInteger(user.expiresAt)||user.expiresAt<=now)return {disconnected:false};
 const g=gmailSessionGuard(user,now);
 // Migration 0051's AFTER UPDATE trigger atomically wipes the refresh envelope.
 const revoke=async()=>(await db.prepare(`UPDATE sources SET revoked_at=COALESCE(revoked_at,?) WHERE owner_id=? AND source_id=? AND kind='gmail' AND EXISTS (${g.sql})`).bind(now,user.ownerId,sourceId,...g.params).run()).meta.changes>=1;
 if(typeof sync?.disconnect==='function'){const r=await sync.disconnect(user.ownerId,sourceId,{revoke});return {disconnected:r.disconnected===true,remoteRevoked:false,googlePermissionRemains:true,...(r.lifecycleBlocked?{lifecycleBlocked:true}:{}),...(r.artifactsRemoved===undefined?{}:{artifactsRemoved:r.artifactsRemoved})};}
 return {disconnected:await revoke(),remoteRevoked:false,googlePermissionRemains:true};
}
async function bodyOf(request){
 if(request.headers.get('content-type')!=='application/json')throw Error();
 const reader=request.body?.getReader();if(!reader)throw Error();let n=0,text='';const d=new TextDecoder('utf-8',{fatal:true});
 try{for(;;){const {done,value}=await reader.read();if(done)break;n+=value.byteLength;if(n>16384){await reader.cancel();throw Error();}text+=d.decode(value,{stream:true});}return JSON.parse(text+d.decode());}finally{reader.releaseLock();}
}
const binding=u=>JSON.stringify(['gmail-source',u.deviceId,u.generation]);
const actionFor=(name,sourceId)=>name==='connect'?'gmail-source-connect':'gmail-source-disconnect:'+sourceId;
export function createGmailSourceHttp({db,sessions,oauth,sync,sourceStore,clock=Date.now,ready=false,passkeys=new PasskeyService(db,{clock})}={}){
 const auth=createDeviceSessionAuth({sessions});
 return {async fetch(request){
  const u=new URL(request.url);if(u.origin!==API||![PATH,PATH+'/begin',PATH+'/status',CALLBACK].includes(u.pathname))return json({error:'not_found'},404);
  if(u.pathname===CALLBACK){
   if(request.method!=='GET')return json({error:'method_not_allowed'},405);
   // No cookie inspection, state consumption, Google exchange or watch while gated.
   if(!ready)return json({error:'collection_not_ready'},503);
   if([...u.searchParams.keys()].some(k=>!['state','code','error','scope','authuser','prompt'].includes(k))||['state','code','error'].some(k=>u.searchParams.getAll(k).length>1))return json({error:'invalid_request'},400);
   // Neutral marker only: the app reads it once and shows a generic message. It never carries a reason, mailbox or account.
   const back=ok=>new Response(null,{status:303,headers:{Location:'https://otpanda.github.io/app/?gmail='+(ok?'connected':'refused')+'#/sources','Cache-Control':'no-store','Referrer-Policy':'no-referrer'}});
   try{const session=await sessions.inspectBrowserRefresh(readCookie(request,REFRESH_COOKIE));const r=await oauth.callback({state:u.searchParams.get('state'),code:u.searchParams.get('code'),error:u.searchParams.get('error'),session});return back(r?.ok===true);}catch{return back(false);}
  }
  const reply=(x,status=200)=>json(x,status,cors);
  if(u.search)return reply({error:'not_found'},404);
  if(request.headers.get('origin')!==APP)return reply({error:'forbidden'},403);
  if(request.method==='OPTIONS'){const h=(request.headers.get('access-control-request-headers')??'').toLowerCase().split(',').map(x=>x.trim()).filter(Boolean);const method=u.pathname.endsWith('/status')?'GET':'POST';return request.headers.get('access-control-request-method')===method&&h.every(x=>['authorization','content-type'].includes(x))?new Response(null,{status:204,headers:{...cors,'Access-Control-Allow-Methods':method,'Access-Control-Allow-Headers':'Authorization, Content-Type','Cache-Control':'no-store'}}):reply({error:'forbidden'},403);}
  if(u.pathname.endsWith('/status')){if(request.method!=='GET')return reply({error:'method_not_allowed'},405);try{const user=await auth.authenticate(request);if(!user)return reply({error:'unauthorized'},401);const row=await db.prepare('SELECT count(*) n FROM passkey_credentials WHERE owner_id=?1 AND revoked_at IS NULL').bind(user.ownerId).first();const pending=sourceStore?await sourceStore.ownerDeferredStatus(user.ownerId,clock()):{pending:0,oldestFirstSeenAt:null,full:false,skipped:{}};const left=typeof sourceStore?.ownerArtifactStatus==='function'?await sourceStore.ownerArtifactStatus(user.ownerId):{};return reply({ready:ready===true,passkeyRequired:!row.n,...pending,...left});}catch{return reply({error:'unavailable'},503);}}
  if(request.method!=='POST')return reply({error:'method_not_allowed'},405);
  if(!ready)return reply({error:'collection_not_ready'},503);
  try{
   const user=await auth.authenticate(request);if(!user)return reply({error:'unauthorized'},401);
   let v;try{v=await bodyOf(request);if(!v||Array.isArray(v)||!actions.has(v.action)||Object.keys(v).sort().join(',')!==(u.pathname.endsWith('/begin')?'action,sourceId':'action,response,sourceId,token')||typeof v.sourceId!=='string'||(v.action==='connect'?v.sourceId!=='':!/^[a-zA-Z0-9_-]{1,128}$/.test(v.sourceId)))throw Error();}catch{return reply({error:'invalid_request'},400);}
   const action=actionFor(v.action,v.sourceId);
   // Disconnect only ever targets a Gmail source this owner holds; checked before any step-up challenge is issued or consumed.
   if(v.action==='disconnect'&&!await db.prepare("SELECT 1 FROM sources WHERE owner_id=?1 AND source_id=?2 AND kind='gmail'").bind(user.ownerId,v.sourceId).first())return reply({error:'not_found'},404);
   if(u.pathname.endsWith('/begin')){
    if(!(await db.prepare('SELECT count(*) n FROM passkey_credentials WHERE owner_id=?1 AND revoked_at IS NULL').bind(user.ownerId).first()).n)return reply({error:'passkey_required'},409);
    return reply(await passkeys.begin({purpose:'step-up',ownerId:user.ownerId,binding:binding(user),action}));
   }
   const proof=await passkeys.finishAuthentication({token:v.token,response:v.response,ownerId:user.ownerId,binding:binding(user),action});
   if(!proof||proof.generation!==user.generation)return reply({error:'reauthenticate'},403);
   const current=await auth.authenticate(request);if(!current||current.ownerId!==user.ownerId||current.deviceId!==user.deviceId||current.generation!==user.generation)return reply({error:'unauthorized'},401);
   if(v.action==='connect')return reply(await oauth.start({...user,stepUp:proof}));
   return reply(await disconnectGmailGuarded(db,user,v.sourceId,clock(),{sync}));
  }catch{return reply({error:'unavailable'},503);}
 }};
}
