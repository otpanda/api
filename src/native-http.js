// Native HTTP boundary, not mounted. API host only. Native token routes carry no cookie and no CORS and refuse any
// browser Origin header. The approve page is the only cookie-reading route: it takes authority from the verified
// first-party web device cookie (rotated exactly like /auth/restore), never from a request-supplied device id.
import {BRAND_FONT_CSS} from './brand-fonts.js';
import {BRAND_MARK} from './brand-mark.js';
import {cookie,readCookie,json,securityHeaders,takeRateLimit,hashText} from './sessions.js';
import {generateAccessToken,base64urlEncode} from './tokens.js';
import {bearerToken} from './http.js';
import {REFRESH_COOKIE} from './browser-session-http.js';
import {NATIVE_REDIRECT} from './native-sessions.js';
import {importRenewalKey} from './access-renewal.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',PACKAGE='app.otpanda',CSRF='__Host-otpanda_native',OPAQUE=/^[A-Za-z0-9_-]{43}$/,FP=/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/;
const none=(status,extra={})=>new Response(null,{status,headers:{...securityHeaders,'Cache-Control':'no-store',...extra}});
async function boundedText(request,max){const reader=request.body?.getReader();if(!reader)return '';const chunks=[];let size=0;try{while(true){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>max){await reader.cancel();return undefined;}chunks.push(value);}const all=new Uint8Array(size);let o=0;for(const c of chunks){all.set(c,o);o+=c.byteLength;}return new TextDecoder('utf-8',{fatal:true}).decode(all);}catch{return undefined;}finally{reader.releaseLock();}}
async function jsonBody(request,keys,max=4096){
 if(request.headers.get('content-type')!=='application/json'||Number(request.headers.get('content-length')??0)>max)return undefined;
 const text=await boundedText(request,max);if(text===undefined)return undefined;
 let d;try{d=JSON.parse(text);}catch{return undefined;}
 return d&&typeof d==='object'&&!Array.isArray(d)&&keys.includes(Object.keys(d).sort().join(','))?d:undefined;
}
const failure=(status,error)=>json({error},status,{'Cache-Control':'no-store'});
// intent binding: the form carries a digest of the cookie token plus the exact native intent
const bindOf=(token,challenge,state)=>hashText(JSON.stringify(['native-approve-v1',token,challenge,state,NATIVE_REDIRECT]));
function page(nonce,body,extra={}){return new Response(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"><title>OTPanda</title><style nonce="${nonce}">${BRAND_FONT_CSS}*{box-sizing:border-box}body{margin:0;background:#f5f8f7;color:#102d23;font:16px/1.5 Figtree,system-ui,sans-serif}.brand{display:flex;align-items:center;gap:10px;font-family:BricolageGrotesque,system-ui,sans-serif;font-size:22px;font-weight:800;margin-bottom:36px}.brand svg{width:44px;height:44px;flex:none}main{max-width:480px;margin:clamp(24px,8vh,80px) auto;padding:28px}h1{font-family:BricolageGrotesque,system-ui,sans-serif;font-size:32px;line-height:1.15;letter-spacing:-.8px;margin:0 0 20px}p{color:#52665e;margin:0 0 24px}button{width:100%;border:0;border-radius:999px;background:#0a7955;color:white;font:600 16px Figtree,system-ui,sans-serif;min-height:48px;padding:12px 20px;cursor:pointer}button:hover{background:#086749}button:focus-visible{outline:3px solid #102d23;outline-offset:4px}@media(max-width:360px){main{padding:24px}h1{font-size:28px}}</style></head><body><main><header class="brand">${BRAND_MARK}<span>OTPanda</span></header>${body}</main></body></html>`,{headers:{...securityHeaders,'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','Referrer-Policy':'same-origin','Content-Security-Policy':`default-src 'none'; style-src 'nonce-${nonce}'; font-src data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`,...extra}});}
// Android apk-key-hash origin for each configured release signer: base64url of the SHA-256 certificate digest.
export function androidOriginsFromFingerprints(prints=[]){return [...new Set(prints.map(p=>{const hex=String(p).replaceAll(':','');if(!/^[0-9A-Fa-f]{64}$/.test(hex))throw new TypeError('SHA-256 certificate fingerprints required');return 'android:apk-key-hash:'+base64urlEncode(Uint8Array.from(hex.match(/../g),h=>parseInt(h,16)));}))];}
export function createNativeHttp({sessions,native,db,google,passkeys,assetFingerprints=[],clock=Date.now}={}){
 if(!sessions||!native||!db)throw new TypeError('Native dependencies required');
 const prints=assetFingerprints.map(String);if(prints.some(p=>!FP.test(p)))throw new TypeError('SHA-256 certificate fingerprints required');
 return {async fetch(request,{clientAddress}={}){
  const url=new URL(request.url),p=url.pathname;
  if(url.origin!==API)return failure(404,'not_found');
  if(p==='/.well-known/assetlinks.json'){
   if(request.method!=='GET'||!prints.length)return none(404);// fail closed until a verified signer is configured
   return json([{relation:['delegate_permission/common.handle_all_urls'],target:{namespace:'android_app',package_name:PACKAGE,sha256_cert_fingerprints:prints}}],200,{'Cache-Control':'public, max-age=300'});
  }
  if(p==='/app-return'){// inert landing when the App Link is not verified; the fragment never reaches the server
   if(request.method!=='GET')return none(405);const nonce=base64urlEncode(crypto.getRandomValues(new Uint8Array(18)));
   return page(nonce,'<h1>Open the OTPanda app</h1><p>Return to the OTPanda app to finish signing in. You can close this page.</p>');
  }
  const approve=p==='/auth/native/approve',tokenRoute=['/auth/native/exchange','/auth/native/challenge','/auth/native/renew','/auth/native/logout','/auth/native/google/begin','/auth/native/google/complete','/auth/native/passkey/begin','/auth/native/passkey/complete','/auth/native/google/continue/begin','/auth/native/google/continue/finish'].includes(p);
  if(!approve&&!tokenRoute)return failure(404,'not_found');
  if(typeof clientAddress!=='string'||!clientAddress||clientAddress.length>128)return failure(503,'unavailable');
  if(tokenRoute){
   if(request.method!=='POST')return failure(405,'method_not_allowed');
   if(request.headers.has('origin')||url.search)return failure(403,'forbidden');// native clients are not browsers
   if(!(await takeRateLimit(db,'native:'+p+':'+clientAddress,{now:clock(),limit:30})).allowed)return failure(429,'rate_limited');
   if(p==='/auth/native/google/begin'||p==='/auth/native/google/complete'){
    if(!google?.configured)return failure(503,'unavailable');// no audience configured: fail closed
    if(p.endsWith('/begin')){if((await boundedText(request,16))!=='')return failure(400,'invalid_request');const b=await google.begin();return b?json({nonce:b.nonce,expires_at:b.expiresAt},200,{'Cache-Control':'no-store'}):failure(503,'unavailable');}
    const d=await jsonBody(request,['id_token,renewal_key','id_token,recognition,renewal_key','id_token,remember,renewal_key','id_token,recognition,remember,renewal_key']);if(!d)return failure(400,'invalid_request');
    if((d.recognition!==undefined&&(typeof d.recognition!=='string'||d.recognition.length>200))||(d.remember!==undefined&&typeof d.remember!=='boolean'))return failure(400,'invalid_request');
    const r=await google.complete({idToken:d.id_token,renewalKey:d.renewal_key,recognition:d.recognition,remember:d.remember});
    if(r.status==='ok')return json({device_id:r.device.deviceId,access:r.device.access,access_expires_at:r.device.accessExpiresAt,...(r.device.enrollGrant?{enroll_grant:r.device.enrollGrant}:{}),...(r.device.recognition?{recognition:r.device.recognition}:{})},200,{'Cache-Control':'no-store'});
    if(r.status==='continue_required')return json({status:'continue_required',kind:'link',continuation:r.continuation.token,email:r.continuation.email,expires_at:r.continuation.expiresAt},200,{'Cache-Control':'no-store'});
    return r.status==='browser_required'?failure(409,'browser_required'):r.status==='unavailable'?failure(503,'unavailable'):failure(401,'invalid_grant');
   }
   if(p==='/auth/native/google/continue/begin'||p==='/auth/native/google/continue/finish'){
    // Existing-account Google link: passkey step-up for the OWNER, bound to the continuation made by google/complete for this install's key.
    if(!google?.configured||typeof google.continueBegin!=='function')return failure(503,'unavailable');
    const begin=p.endsWith('/begin'),d=await jsonBody(request,begin?['continuation,renewal_key']:['continuation,renewal_key,response,token','continuation,recognition,renewal_key,response,token'],16384);
    if(!d||typeof d.continuation!=='string'||d.continuation.length>200||typeof d.renewal_key!=='string'||!d.renewal_key||d.renewal_key.length>512||!await importRenewalKey(d.renewal_key))return failure(400,'invalid_request');
    if(begin){const c=await google.continueBegin({token:d.continuation,renewalKey:d.renewal_key});return c?json({token:c.token,options:c.options,expires_at:c.expiresAt},200,{'Cache-Control':'no-store'}):failure(401,'invalid_grant');}
    if(typeof d.token!=='string'||d.token.length>200||!d.response||typeof d.response!=='object'||Array.isArray(d.response)||(d.recognition!==undefined&&(typeof d.recognition!=='string'||d.recognition.length>200)))return failure(400,'invalid_request');
    const r=await google.continueFinish({token:d.continuation,renewalKey:d.renewal_key,ceremony:d.token,response:d.response,recognition:d.recognition});
    return r.status==='ok'?json({device_id:r.device.deviceId,access:r.device.access,access_expires_at:r.device.accessExpiresAt,...(r.device.recognition?{recognition:r.device.recognition}:{})},200,{'Cache-Control':'no-store'}):failure(401,'invalid_grant');
   }
   if(p==='/auth/native/passkey/begin'||p==='/auth/native/passkey/complete'){
    // OS Credential Manager sign-in. Discoverable ceremony bound to this install's renewal key; no Origin, no cookie. Fails closed if not wired.
    if(!passkeys)return failure(503,'unavailable');
    const begin=p.endsWith('/begin'),d=await jsonBody(request,[begin?'renewal_key':'renewal_key,response,token'],16384);
    if(!d||typeof d.renewal_key!=='string'||!d.renewal_key||d.renewal_key.length>512||!await importRenewalKey(d.renewal_key))return failure(400,'invalid_request');// bad key refused before any OS prompt
    const binding='native-passkey-v1:'+d.renewal_key;
    if(begin){const c=await passkeys.begin({purpose:'authenticate',binding});return c?json({token:c.token,options:c.options,expires_at:c.expiresAt},200,{'Cache-Control':'no-store'}):failure(503,'unavailable');}
    if(typeof d.token!=='string'||d.token.length>200||!d.response||typeof d.response!=='object'||Array.isArray(d.response))return failure(400,'invalid_request');
    let proof;try{proof=await passkeys.finishAuthentication({token:d.token,binding,response:d.response});}catch{return failure(401,'invalid_grant');}
    const dev=proof&&await native.issuePasskey({proof,renewalKey:d.renewal_key});
    return dev?json({device_id:dev.deviceId,access:dev.access,access_expires_at:dev.accessExpiresAt},200,{'Cache-Control':'no-store'}):failure(401,'invalid_grant');
   }
   if(p==='/auth/native/exchange'){
    const d=await jsonBody(request,['code,redirect_uri,renewal_key,verifier']);if(!d)return failure(400,'invalid_request');
    const r=await native.exchange({code:d.code,verifier:d.verifier,redirectUri:d.redirect_uri,renewalKey:d.renewal_key});
    return r?json({device_id:r.deviceId,access:r.access,access_expires_at:r.accessExpiresAt,...(r.enrollGrant?{enroll_grant:r.enrollGrant}:{})},200,{'Cache-Control':'no-store'}):failure(401,'invalid_grant');
   }
   if(p==='/auth/native/challenge'){
    const d=await jsonBody(request,['device_id,purpose']);if(!d||typeof d.device_id!=='string'||d.device_id.length>64)return failure(400,'invalid_request');
    if(!(await takeRateLimit(db,'native:challenge:'+d.device_id,{now:clock(),limit:20})).allowed)return failure(429,'rate_limited');
    const c=await native.challenge({deviceId:d.device_id,purpose:d.purpose});return json({device_id:c.deviceId,nonce:c.nonce,expires_at:c.expiresAt},200,{'Cache-Control':'no-store'});
   }
   if(p==='/auth/native/logout'&&request.headers.has('authorization')){
    const token=bearerToken(request.headers.get('authorization')),a=token&&await sessions.authenticate(token);
    if(!a||a.clientKind!=='android'||(await boundedText(request,16))!=='')return failure(401,'invalid_grant');
    return (await native.logoutAccess({deviceId:a.deviceId}))?none(204):failure(401,'invalid_grant');
   }
   const d=await jsonBody(request,['device_id,expires_at,nonce,signature']);if(!d||typeof d.device_id!=='string'||d.device_id.length>64)return failure(400,'invalid_request');
   if(!(await takeRateLimit(db,'native:device:'+d.device_id,{now:clock(),limit:20})).allowed)return failure(429,'rate_limited');
   const args={deviceId:d.device_id,nonce:d.nonce,expiresAt:d.expires_at,signature:d.signature};
   if(p==='/auth/native/logout')return (await native.logout(args))?none(204):failure(401,'invalid_grant');
   const r=await native.renew(args);
   return r.status==='renewed'?json({access:r.access,access_expires_at:r.accessExpiresAt},200,{'Cache-Control':'no-store'}):failure(401,'invalid_grant');
  }
  // approve: explicit, intent-bound Continue
  if(!(await takeRateLimit(db,'native:approve:'+clientAddress,{now:clock(),limit:30})).allowed)return failure(429,'rate_limited');
  const nonce=base64urlEncode(crypto.getRandomValues(new Uint8Array(18)));
  const intent=d=>{
   const keys=[...d.keys()];if(keys.some(k=>!['challenge','state','redirect_uri','csrf'].includes(k)))return;
   for(const k of ['challenge','state','redirect_uri'])if(d.getAll(k).length!==1)return;
   const challenge=d.get('challenge'),state=d.get('state');
   return OPAQUE.test(challenge)&&OPAQUE.test(state)&&d.get('redirect_uri')===NATIVE_REDIRECT?{challenge,state}:undefined;
  };
  if(request.method==='GET'){
   const i=intent(url.searchParams);if(!i||url.searchParams.has('csrf'))return failure(400,'invalid_request');
   const token=generateAccessToken().token,b=await bindOf(token,i.challenge,i.state);
   return page(nonce,`<h1>Sign in to the OTPanda app?</h1><p>This lets the OTPanda app on this phone use your account. Only continue if you started this on your own phone.</p><form method="post" action="/auth/native/approve"><input type="hidden" name="challenge" value="${i.challenge}"><input type="hidden" name="state" value="${i.state}"><input type="hidden" name="redirect_uri" value="${NATIVE_REDIRECT}"><input type="hidden" name="csrf" value="${b}"><button type="submit">Continue</button></form>`,{'Set-Cookie':cookie(CSRF,token,300)});
  }
  if(request.method!=='POST')return failure(405,'method_not_allowed');
  if(request.headers.get('origin')!==API||url.search||request.headers.get('content-type')!=='application/x-www-form-urlencoded')return failure(403,'forbidden');
  const text=await boundedText(request,2048);if(text===undefined)return failure(400,'invalid_request');
  const data=new URLSearchParams(text),i=intent(data),token=readCookie(request,CSRF);
  if(!i||data.getAll('csrf').length!==1||!token||token.length>200||data.get('csrf')!==await bindOf(token,i.challenge,i.state))return failure(403,'expired');
  const refresh=readCookie(request,REFRESH_COOKIE),result=await sessions.rotate(refresh,{clientKind:'web'});
  if(result.status!=='rotated')return failure(401,'sign_in_required');
  const headers=new Headers({...securityHeaders,'Cache-Control':'no-store','Set-Cookie':cookie(REFRESH_COOKIE,result.refresh,Math.max(0,Math.floor((result.refreshExpiresAt-clock())/1000)))});
  headers.append('Set-Cookie',cookie(CSRF,'',0));
  const grant=await native.mint({sourceDeviceId:result.deviceId,challenge:i.challenge,redirectUri:NATIVE_REDIRECT});
  const target=new URL(NATIVE_REDIRECT);target.hash=new URLSearchParams(grant?{code:grant.code,state:i.state}:{auth:'restart',state:i.state}).toString();
  headers.set('Location',target.href);return new Response(null,{status:303,headers});
 }};
}
