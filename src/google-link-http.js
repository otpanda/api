// Signed-in Google link, step 1: an authenticated POST mints a single-use launch ticket. The ticket is
// spent by one top-level GET on the API host (google-browser-flow startLink), which sets the browser binding
// cookie that a credentialless cross-origin POST cannot set. Nothing here touches the session or its cookies.
import {json,takeRateLimit,hashText} from './sessions.js';
import {base64urlEncode} from './tokens.js';
import {createDeviceSessionAuth} from './device-session-auth.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',cors={'Access-Control-Allow-Origin':APP,Vary:'Origin'},OPAQUE=/^[A-Za-z0-9_-]{43}$/,ISSUER='https://accounts.google.com',TTL=60000;
export function createGoogleLinkTicketHttp({db,sessions,clock=Date.now,native=false}={}){
 const auth=createDeviceSessionAuth({sessions,native:native===true});
 return{async fetch(request,{clientAddress}={}){
  const u=new URL(request.url);if(u.origin!==API||u.pathname!=='/v1/manage/google/link/ticket'||u.search)return json({error:'not_found'},404);
  if(!auth.originAllowed(request))return json({error:'forbidden'},403);
  if(request.method!=='POST'||request.headers.get('content-type')!=='application/json')return json({error:'invalid_request'},400,cors);
  if(typeof clientAddress!=='string'||!clientAddress)return json({error:'unavailable'},503,cors);
  const now=clock();
  if(!(await takeRateLimit(db,'google-link:address:'+clientAddress,{now,limit:60,windowMs:3600000})).allowed)return json({error:'busy'},429,cors);
  const user=await auth.authenticate(request);if(!user)return json({error:'unauthorized'},401,cors);
  if(!(await takeRateLimit(db,'google-link:owner:'+user.ownerId,{now,limit:10,windowMs:3600000})).allowed)return json({error:'busy'},429,cors);
  let value;try{value=JSON.parse(await request.text());}catch{return json({error:'invalid_request'},400,cors);}
  if(!value||Array.isArray(value)||Object.keys(value).join(',')!=='state'||!OPAQUE.test(value.state))return json({error:'invalid_request'},400,cors);
  if(await db.prepare('SELECT 1 x FROM provider_identities WHERE owner_id=?1 AND issuer=?2 AND revoked_at IS NULL').bind(user.ownerId,ISSUER).first())return json({error:'already_linked'},409,cors);
  // Same rule as unlink: the exact-identity passkey proof comes after Google consent, so an account with no passkey could never finish.
  if(!await db.prepare('SELECT 1 x FROM passkey_credentials WHERE owner_id=?1 AND revoked_at IS NULL').bind(user.ownerId).first())return json({error:'no_passkey'},409,cors);
  const ticket=base64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
  // Bound to the live session and current generation in the same statement that writes it.
  const r=await db.prepare('INSERT INTO google_link_tickets(ticket_digest,owner_id,device_id,generation,app_state,created_at,expires_at) SELECT ?1,d.owner_id,d.device_id,d.generation,?5,?6,?7 FROM device_sessions d JOIN account_security s ON s.owner_id=d.owner_id WHERE d.device_id=?2 AND d.owner_id=?3 AND d.generation=?4 AND s.generation=?4 AND d.revoked_at IS NULL AND d.expires_at>?6').bind(await hashText(ticket),user.deviceId,user.ownerId,user.generation,value.state,now,now+TTL).run();
  if(r.meta.changes<1)return json({error:'unauthorized'},401,cors);
  return json({ticket,expiresAt:now+TTL},200,cors);
 }};
}
