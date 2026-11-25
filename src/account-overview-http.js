import {json,takeRateLimit} from './sessions.js';
import {createDeviceSessionAuth} from './device-session-auth.js';
import {googlePictureUrl} from './account-identity.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',cors={'Access-Control-Allow-Origin':APP,Vary:'Origin'};
export function createAccountOverviewHttp({db,sessions,clock=Date.now}={}){
 const auth=createDeviceSessionAuth({sessions});
 return{async fetch(request,{clientAddress}={}){
  const u=new URL(request.url);if(u.origin!==API||u.pathname!=='/v1/manage/account')return json({error:'not_found'},404);
  if(request.headers.get('origin')!==APP)return json({error:'forbidden'},403);
  if(request.method==='OPTIONS')return request.headers.get('access-control-request-method')==='GET'&&(request.headers.get('access-control-request-headers')??'').toLowerCase().split(',').every(h=>h.trim()==='authorization')?new Response(null,{status:204,headers:{...cors,'Access-Control-Allow-Methods':'GET','Access-Control-Allow-Headers':'Authorization'}}):json({error:'forbidden'},403,cors);
  if(request.method!=='GET'||u.search)return json({error:'invalid_request'},400,cors);
  if(typeof clientAddress!=='string'||!clientAddress)return json({error:'unavailable'},503,cors);
  if(!(await takeRateLimit(db,'account-overview:'+clientAddress,{now:clock(),limit:60})).allowed)return json({error:'busy'},429,cors);
  const user=await auth.authenticate(request);if(!user)return json({error:'unauthorized'},401,cors);
  const row=await db.prepare("SELECT e.email,a.created_at,(SELECT count(*) FROM passkey_credentials p WHERE p.owner_id=e.owner_id AND p.revoked_at IS NULL) AS passkeys,(SELECT count(*) FROM provider_identities i WHERE i.owner_id=e.owner_id AND i.issuer='https://accounts.google.com' AND i.revoked_at IS NULL) AS google,(SELECT count(*) FROM durable_device_keys k WHERE k.owner_id=e.owner_id AND k.revoked_at IS NULL) AS recovery_devices,(SELECT i.picture FROM provider_identities i WHERE i.owner_id=e.owner_id AND i.issuer='https://accounts.google.com' AND i.revoked_at IS NULL LIMIT 1) AS picture FROM account_emails e JOIN accounts a ON a.owner_id=e.owner_id WHERE e.owner_id=?1").bind(user.ownerId).first();
  if(!row||!await auth.authenticate(request))return json({error:'unauthorized'},401,cors);
  return json({email:row.email,createdAt:row.created_at,passkeys:row.passkeys,google:row.google>0,recoveryDevices:row.recovery_devices,...(googlePictureUrl(row.picture)?{picture:row.picture}:{})},200,cors);
 }};
}
