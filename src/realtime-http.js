// Ticket mint and WebSocket upgrade for content-free invalidation. Inactive: not in any route allowlist,
// no wrangler binding, not mounted. When mounted, the outer edge host needs the same public-Worker
// preflight and budget treatment as /auth/renew (new paths, own edge limit binding, never the auth pool).
import {json} from './sessions.js';
import {createDeviceSessionAuth} from './device-session-auth.js';
import {base64urlEncode,digestToHex} from './tokens.js';
import {SESSION_METHOD_JOIN as MJ,SESSION_METHOD_ACTIVE as MA} from './session-method.js';
import {hashText} from './sessions.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io';
export const TICKET_TTL_MS=30_000,MAX_TICKETS=4,SUBPROTOCOL='otpanda.v1';
const TICKET=/^rt1\.([A-Za-z0-9_-]{16})\.([A-Za-z0-9_-]{43})$/;
const cors={'Access-Control-Allow-Origin':APP,Vary:'Origin'};
const rand=n=>crypto.getRandomValues(new Uint8Array(n));
const sha=async text=>digestToHex(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(text))));
const ACTIVE=`d.revoked_at IS NULL AND d.created_at<=?3 AND d.expires_at>?3 AND ${MA} AND s.generation=d.generation AND d.client_kind IN ('web','android')`;
// limiter: a dedicated edge rate-limit binding (never the shared auth pool). Missing means fail closed.
// connect(info, request): hands the upgrade to the account's hub.
export function createRealtimeHttp({db,sessions,limiter,connect,clock=Date.now,native=false}={}){
 if(!db||!sessions||typeof connect!=='function')throw new TypeError('Realtime dependencies required');
 const auth=createDeviceSessionAuth({sessions,native});
 const allowed=async key=>typeof limiter?.limit==='function'&&(await limiter.limit({key}))?.success===true;
 return {async fetch(request,{clientAddress}={}){
  const url=new URL(request.url);
  if(url.origin!==API||url.search||!['/auth/realtime/ticket','/auth/realtime'].includes(url.pathname))return json({error:'not_found'},404);
  if(!auth.originAllowed(request))return json({error:'forbidden'},403);
  // A native (no Origin) request is never a CORS preflight.
  if(request.method==='OPTIONS'&&request.headers.get('origin')!==APP)return json({error:'forbidden'},403);
  const ticketRoute=url.pathname==='/auth/realtime/ticket';
  if(request.method==='OPTIONS'){
   const h=request.headers.get('access-control-request-headers')?.toLowerCase().split(',').map(v=>v.trim()).filter(Boolean)??[];
   return ticketRoute&&request.headers.get('access-control-request-method')==='POST'&&h.every(v=>v==='authorization')
    ?new Response(null,{status:204,headers:{...cors,'Cache-Control':'no-store','Access-Control-Allow-Methods':'POST','Access-Control-Allow-Headers':'Authorization'}})
    :json({error:'forbidden'},403,cors);
  }
  if(typeof clientAddress!=='string'||!clientAddress||clientAddress.length>128)return json({error:'unavailable'},503,cors);
  const now=clock();
  if(ticketRoute){
   if(request.method!=='POST')return json({error:'method_not_allowed'},405,cors);
   if(request.headers.has('content-length')&&request.headers.get('content-length')!=='0'||(request.body&&(await request.arrayBuffer()).byteLength>0))return json({error:'invalid_request'},400,cors);
   const user=await auth.authenticate(request);if(!user)return json({error:'unauthorized'},401,cors);
   if(!Number.isSafeInteger(user.expiresAt)||user.expiresAt<=now)return json({error:'unauthorized'},401,cors);
   if(typeof limiter?.limit!=='function')return json({error:'unavailable'},503,cors);
   if(!await allowed('ticket:'+await hashText(user.deviceId)))return json({error:'rate_limited'},429,{...cors,'Retry-After':'30'});
   const id=base64urlEncode(rand(12)),secret=base64urlEncode(rand(32)),expires=now+TICKET_TTL_MS;
   // Guarded insert: device still active in the same statement, bounded outstanding tickets per device.
   const result=await db.prepare(`INSERT INTO realtime_tickets (ticket_id,secret_digest,owner_id,device_id,generation,created_at,expires_at,close_at) SELECT ?1,?2,d.owner_id,d.device_id,d.generation,?3,?4,?5 FROM device_sessions d ${MJ} JOIN account_security s ON s.owner_id=d.owner_id WHERE d.device_id=?6 AND d.owner_id=?7 AND d.generation=?8 AND ${ACTIVE} AND (SELECT count(*) FROM realtime_tickets WHERE device_id=d.device_id AND expires_at>?3)<${MAX_TICKETS}`).bind(id,await sha(secret),now,expires,user.expiresAt,user.deviceId,user.ownerId,user.generation).run();
   if(result.meta.changes<1)return json({error:'busy'},429,{...cors,'Retry-After':'5'});
   return json({ticket:`rt1.${id}.${secret}`,expiresAt:expires,closeAt:user.expiresAt,serverTime:now},200,{...cors,'Cache-Control':'no-store'});
  }
  // Upgrade: GET only. The ticket rides in Sec-WebSocket-Protocol so it is never in a URL.
  if(request.method!=='GET'||request.headers.get('upgrade')?.toLowerCase()!=='websocket')return json({error:'method_not_allowed'},405,cors);
  const offered=(request.headers.get('sec-websocket-protocol')??'').split(',').map(v=>v.trim()).filter(Boolean);
  const match=offered.length===2&&offered[0]===SUBPROTOCOL?TICKET.exec(offered[1]):null;
  if(!match)return json({error:'invalid_request'},400,cors);
  if(typeof limiter?.limit!=='function')return json({error:'unavailable'},503,cors);
  if(!await allowed('connect:'+await hashText(clientAddress)))return json({error:'rate_limited'},429,{...cors,'Retry-After':'30'});
  // One winner: the ticket is deleted in the same statement that checks it, device state and generation included.
  // The ticket must be redeemed by the same client kind that minted it: Origin shape decides (APP = web, none = android).
  const kind=request.headers.get('origin')===APP?'web':'android';
  const row=await db.prepare(`DELETE FROM realtime_tickets WHERE ticket_id=?1 AND secret_digest=?2 AND expires_at>?3 AND close_at>?3 AND EXISTS (SELECT 1 FROM device_sessions d ${MJ} JOIN account_security s ON s.owner_id=d.owner_id WHERE d.device_id=realtime_tickets.device_id AND d.owner_id=realtime_tickets.owner_id AND d.generation=realtime_tickets.generation AND ${ACTIVE} AND d.client_kind=?4) RETURNING owner_id,device_id,close_at`).bind(match[1],await sha(match[2]),now,kind).first();
  if(!row)return json({error:'invalid_grant'},401,cors);
  return connect({ownerId:row.owner_id,deviceId:row.device_id,closeAt:row.close_at},request);
 }};
}
