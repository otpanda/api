// Extension session HTTP boundary, NOT mounted (integrator mounts; see CONTRACT). No cookies, no CORS headers on token routes, no wildcard,
// no credentials. begin is called by the signed-in WEB app (web bearer, exact APP Origin) after an explicit confirmation click and returns the
// redirect with the one-use code in the URL FRAGMENT, never the query. exchange/challenge/renew/logout carry no Origin or exactly a pinned
// extension origin and are authenticated by possession (signed nonce) or, for logout via bearer, the extension access token.
import {json,takeRateLimit} from './sessions.js';
import {bearerToken} from './http.js';
import {createDeviceSessionAuth} from './device-session-auth.js';
import {importRenewalKey} from './access-renewal.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',OPAQUE=/^[A-Za-z0-9_-]{43}$/;
const cors={'Access-Control-Allow-Origin':APP,Vary:'Origin'},nostore={'Cache-Control':'no-store'};
const fail=(status,error,extra={})=>json({error},status,{...nostore,...extra});
async function body(request,keys,max=4096){
 if(request.headers.get('content-type')!=='application/json'||Number(request.headers.get('content-length')??0)>max)return undefined;
 const text=await request.text();if(text.length>max)return undefined;let d;try{d=JSON.parse(text);}catch{return undefined;}
 return d&&typeof d==='object'&&!Array.isArray(d)&&keys.includes(Object.keys(d).sort().join(','))?d:undefined;
}
// redirects: {chrome:'https://<id>.chromiumapp.org/', firefox:'...'} exact URIs from config; begin accepts only the KEY, never a URL.
export function createExtensionHttp({sessions,extension,db,redirects,extensionOrigins=[],clock=Date.now}={}){
 if(!sessions||!extension||!db||extension.kind!=='extension')throw new TypeError('Extension dependencies required');
 const keys=Object.keys(redirects??{});if(!keys.length||keys.some(k=>!/^[a-z]{3,12}$/.test(k)||!extension.profile.redirects.includes(redirects[k])))throw new TypeError('Redirect keys must map to allowlisted exact URIs');
 const webAuth=createDeviceSessionAuth({sessions}),extAuth=createDeviceSessionAuth({sessions,extension:true,extensionOrigins});
 return {async fetch(request,{clientAddress}={}){
  const url=new URL(request.url),p=url.pathname;
  if(url.origin!==API||!p.startsWith('/auth/extension/'))return fail(404,'not_found');
  const begin=p==='/auth/extension/begin',token=['/auth/extension/exchange','/auth/extension/challenge','/auth/extension/renew','/auth/extension/logout'].includes(p);
  if(!begin&&!token)return fail(404,'not_found');
  if(url.search)return fail(400,'invalid_request',begin?cors:{});
  if(typeof clientAddress!=='string'||!clientAddress||clientAddress.length>128)return fail(503,'unavailable');
  if(begin){
   // Only the web app may call it; no preflight is answered here beyond the app's own CORS and never for extension origins.
   if(request.headers.get('origin')!==APP)return fail(403,'forbidden');
   if(request.method!=='POST')return fail(405,'method_not_allowed',cors);
   if(!(await takeRateLimit(db,'ext:begin:'+clientAddress,{now:clock(),limit:30})).allowed)return fail(429,'rate_limited',cors);
   const user=await webAuth.authenticate(request);if(!user)return fail(401,'unauthorized',cors);
   if(!(await takeRateLimit(db,'ext:begin:owner:'+user.ownerId,{now:clock(),limit:10})).allowed)return fail(429,'rate_limited',cors);
   const d=await body(request,['challenge,confirm,redirect,state']);
   // confirm must be the literal true sent by the confirmation click handler; a page load can never produce it from a URL.
   if(!d||d.confirm!==true||!OPAQUE.test(d.challenge)||!OPAQUE.test(d.state)||typeof d.redirect!=='string'||!Object.hasOwn(redirects,d.redirect))return fail(400,'invalid_request',cors);
   const uri=redirects[d.redirect],grant=await extension.mint({sourceDeviceId:user.deviceId,challenge:d.challenge,redirectUri:uri});
   if(!grant)return fail(409,'restart',cors);
   const target=new URL(uri);target.hash=new URLSearchParams({code:grant.code,state:d.state}).toString();
   return json({redirect:target.href,expires_at:grant.expiresAt},200,{...nostore,...cors});
  }
  // token routes: no cookie is read, no CORS headers are ever returned; Origin must be absent or a pinned extension origin.
  if(request.method!=='POST')return fail(405,'method_not_allowed');
  if(!extAuth.originAllowed(request))return fail(403,'forbidden');
  if(!(await takeRateLimit(db,'ext:'+p+':'+clientAddress,{now:clock(),limit:30})).allowed)return fail(429,'rate_limited');
  if(p==='/auth/extension/exchange'){
   const d=await body(request,['code,redirect,renewal_key,verifier']);if(!d||typeof d.redirect!=='string'||!Object.hasOwn(redirects,d.redirect)||typeof d.renewal_key!=='string'||d.renewal_key.length>512||!await importRenewalKey(d.renewal_key))return fail(400,'invalid_request');
   const r=await extension.exchange({code:d.code,verifier:d.verifier,redirectUri:redirects[d.redirect],renewalKey:d.renewal_key});
   return r?json({device_id:r.deviceId,access:r.access,access_expires_at:r.accessExpiresAt},200,nostore):fail(401,'invalid_grant');
  }
  if(p==='/auth/extension/challenge'){
   const d=await body(request,['device_id,purpose']);if(!d||typeof d.device_id!=='string'||d.device_id.length>64)return fail(400,'invalid_request');
   if(!(await takeRateLimit(db,'ext:challenge:'+d.device_id,{now:clock(),limit:20})).allowed)return fail(429,'rate_limited');
   const c=await extension.challenge({deviceId:d.device_id,purpose:d.purpose});return json({device_id:c.deviceId,nonce:c.nonce,expires_at:c.expiresAt},200,nostore);
  }
  if(p==='/auth/extension/logout'&&request.headers.has('authorization')){
   const t=bearerToken(request.headers.get('authorization')),a=t&&await sessions.authenticate(t);
   if(!a||a.clientKind!=='extension'||(await request.text())!=='')return fail(401,'invalid_grant');
   return (await extension.logoutAccess({deviceId:a.deviceId}))?new Response(null,{status:204,headers:nostore}):fail(401,'invalid_grant');
  }
  const d=await body(request,['device_id,expires_at,nonce,signature']);if(!d||typeof d.device_id!=='string'||d.device_id.length>64)return fail(400,'invalid_request');
  if(!(await takeRateLimit(db,'ext:device:'+d.device_id,{now:clock(),limit:20})).allowed)return fail(429,'rate_limited');
  const args={deviceId:d.device_id,nonce:d.nonce,expiresAt:d.expires_at,signature:d.signature};
  if(p==='/auth/extension/logout')return (await extension.logout(args))?new Response(null,{status:204,headers:nostore}):fail(401,'invalid_grant');
  const r=await extension.renew(args);
  return r.status==='renewed'?json({access:r.access,access_expires_at:r.accessExpiresAt},200,nostore):fail(401,'invalid_grant');
 }};
}
