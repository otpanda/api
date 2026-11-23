// API-first-party device logout only. No bearer CORS mutation endpoint.
import {cookie,readCookie,json,securityHeaders,takeRateLimit,hashText} from './sessions.js';
import {generateAccessToken} from './tokens.js';
import {REFRESH_COOKIE} from './browser-session-http.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io/app/';
const CSRF='__Host-otpanda_logout';
function html(body,status=200,extra={}) {return new Response('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>OTPanda sign out</title><style>body{font:16px/1.5 system-ui;background:#f5f8f7;color:#17332a;max-width:460px;padding:24px;margin:10vh auto}button,a{display:inline-block;padding:12px}button{font:inherit}</style><main>'+body+'</main></html>',{status,headers:{...securityHeaders,'Referrer-Policy':'same-origin','Content-Type':'text/html; charset=utf-8','Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",...extra}});}
async function body(request) {const reader=request.body?.getReader();if(!reader)return;let size=0;const parts=[];try{while(true){const x=await reader.read();if(x.done)break;size+=x.value.length;if(size>512){await reader.cancel();return;}parts.push(x.value);}return new TextDecoder('utf-8',{fatal:true}).decode(Uint8Array.from(parts.flatMap(x=>Array.from(x))));}catch{return;}finally{reader.releaseLock();}}
export function createBrowserLogoutHttp({sessions,db,clock=Date.now}={}) {
 if(!sessions||!db)throw new TypeError('Logout dependencies required');
 return {async fetch(request,{clientAddress}={}) {
  const u=new URL(request.url);
  if(u.origin!==API||u.pathname!=='/auth/device/logout')return json({error:'not_found'},404);
  if(!['GET','POST'].includes(request.method))return json({error:'method_not_allowed'},405);
  if(u.search)return html('<h1>Invalid sign-out request</h1>',400);
  if(typeof clientAddress!=='string'||!clientAddress||clientAddress.length>128)return json({error:'unavailable'},503);
  const rate=await takeRateLimit(db,'device-logout:'+clientAddress,{now:clock(),limit:30});
  if(!rate.allowed)return json({error:'rate_limited'},429,{'Retry-After':String(rate.retryAfter)});
  if(request.method==='GET') {
   const csrf=generateAccessToken().token;
   return html('<h1>Sign out of this browser?</h1><p>This revokes this browser device session on the server. Other devices and automation permissions are unchanged.</p><form method="post" action="/auth/device/logout"><input type="hidden" name="csrf" value="'+csrf+'"><button type="submit">Sign out</button></form><a href="'+APP+'">Cancel</a>',200,{'Set-Cookie':cookie(CSRF,csrf,300)});
  }
  if(request.headers.get('origin')!==API||request.headers.get('content-type')!=='application/x-www-form-urlencoded')return html('<h1>Request not allowed</h1>',403);
  const text=await body(request);if(text===undefined)return html('<h1>Invalid request</h1>',400);
  const data=new URLSearchParams(text),csrf=readCookie(request,CSRF);
  if([...data.keys()].join(',')!=='csrf'||!csrf||!/^otpda_[A-Za-z0-9_-]{55}$/.test(csrf)||data.get('csrf')!==csrf)return html('<h1>Sign-out request expired. Start again.</h1>',403);
  const binding=readCookie(request,'__Host-otpanda_login');
  const bindingDigest=typeof binding==='string'&&/^otpda_[A-Za-z0-9_-]{55}$/.test(binding)?await hashText(await hashText(binding)):null;
  await sessions.logoutBrowser(readCookie(request,REFRESH_COOKIE),bindingDigest);
  const response=html('<h1>This browser is signed out</h1><p>Its saved session can no longer restore access. Sign in again to create a new session.</p><a href="'+APP+'">Return to OTPanda</a>');
  response.headers.append('Set-Cookie',cookie(REFRESH_COOKIE,'',0));response.headers.append('Set-Cookie',cookie(CSRF,'',0));for(const name of ['__Host-otpanda_login','__Host-otpanda_login_csrf','__Host-otpanda_restore'])response.headers.append('Set-Cookie',cookie(name,'',0));return response;
 }};
}
