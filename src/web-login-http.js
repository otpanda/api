// Approved browser login HTTP boundary, deliberately unmounted.
import {json,securityHeaders,cookie,readCookie,takeRateLimit} from './sessions.js';
import {generateAccessToken,base64urlEncode} from './tokens.js';
import {REFRESH_COOKIE} from './browser-session-http.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',REDIRECT=APP+'/app/';
const BIND='__Host-otpanda_login',CSRF='__Host-otpanda_login_csrf',OPAQUE=/^[A-Za-z0-9_-]{43}$/;
const cors={'Access-Control-Allow-Origin':APP,Vary:'Origin'};
function page(body,{status=200,nonce,...extra}={}){return new Response(body,{status,headers:{...securityHeaders,'Referrer-Policy':'same-origin','Content-Type':'text/html; charset=utf-8','Content-Security-Policy':`default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://otpanda.github.io/app/; frame-ancestors 'none'; base-uri 'none'${nonce?`; script-src 'nonce-${nonce}'`:''}`,...extra}});}
async function text(request,max){const reader=request.body?.getReader();if(!reader)return '';let size=0;const chunks=[];try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>max){await reader.cancel();return;}chunks.push(value);}return new TextDecoder('utf-8',{fatal:true}).decode(Uint8Array.from(chunks.flatMap(c=>Array.from(c))));}catch{return;}finally{reader.releaseLock();}}
function invalid(status=400,headers={}){return json({error:'invalid_request'},status,headers);}
export function createWebLoginHttp({db,login,clock=Date.now}={}){
 if(!db||!login)throw new TypeError('Login HTTP dependencies required');
 return {async fetch(request,{clientAddress}={}){
  const url=new URL(request.url),path=url.pathname,origin=request.headers.get('origin');
  if(url.origin!==API||!['/auth/login/start','/auth/login/verify','/auth/login/complete'].includes(path))return json({error:'not_found'},404);
  const verify=path==='/auth/login/verify';
  if(verify&&origin!==APP)return invalid(403);
  if(verify&&request.method==='OPTIONS'){
   const headers=request.headers.get('access-control-request-headers')?.toLowerCase().split(',').map(h=>h.trim())??[];
   return request.headers.get('access-control-request-method')==='POST'&&headers.every(h=>h==='content-type')?new Response(null,{status:204,headers:{...securityHeaders,...cors,'Access-Control-Allow-Methods':'POST','Access-Control-Allow-Headers':'Content-Type'}}):invalid(403,cors);
  }
  if(typeof clientAddress!=='string'||!clientAddress||clientAddress.length>128)return invalid(503,verify?cors:{});
  const rate=await takeRateLimit(db,'web-login:'+path+':'+clientAddress,{now:clock(),limit:15});if(!rate.allowed)return json({error:'rate_limited'},429,{...(verify?cors:{}),'Retry-After':String(rate.retryAfter)});
  if(path==='/auth/login/start'){
   if(request.method!=='GET')return invalid(405);
   const q=url.searchParams;if([...q.keys()].sort().join(',')!=='challenge,redirect_uri,state'||!OPAQUE.test(q.get('challenge'))||!OPAQUE.test(q.get('state'))||q.get('redirect_uri')!==REDIRECT)return invalid();
   const binding=generateAccessToken().token,c=await login.beginBrowser({cookieBinding:binding,challenge:q.get('challenge'),state:q.get('state'),redirectUri:REDIRECT});if(!c)return invalid();
   // Fragment payload is data, never script. App validates state/RP/options.
   const target=new URL(REDIRECT);target.hash=new URLSearchParams({login:base64urlEncode(new TextEncoder().encode(JSON.stringify(c))),state:q.get('state')}).toString();
   return new Response(null,{status:303,headers:{...securityHeaders,Location:target.href,'Set-Cookie':cookie(BIND,binding,120)}});
  }
  if(verify){
   if(request.method!=='POST')return invalid(405,cors);
   if(url.search||request.headers.get('content-type')!=='application/json')return invalid(400,cors);
   const raw=await text(request,16384);if(raw===undefined)return invalid(400,cors);let data;try{data=JSON.parse(raw);}catch{return invalid(400,cors);}
   if(!data||Array.isArray(data)||Object.keys(data).sort().join(',')!=='response,token')return invalid(400,cors);
   const result=await login.verifyBrowser(data);return result?json(result,200,cors):invalid(401,cors);
  }
  if(url.search)return invalid();
  if(request.method==='GET'){
   const csrf=generateAccessToken().token,nonce=base64urlEncode(crypto.getRandomValues(new Uint8Array(18)));
   // Lax cookies attach to this top-level GET; the same-origin form POST then
   // carries binding+CSRF. Fragment is removed before parsing or submission.
   return page(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Signing in to OTPanda</title><meta name="color-scheme" content="light"><style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f5f8f7;color:#17332a;font:16px/1.55 system-ui,sans-serif;padding:24px}.card{width:100%;max-width:460px;background:white;border:1px solid #dfe8e2;border-radius:24px;padding:32px;box-shadow:0 12px 36px #17332a0a}.brand{font-weight:800;font-size:21px;letter-spacing:-.5px;color:#0a7955}h1{font-size:28px;line-height:1.2;letter-spacing:-.7px;margin:30px 0 14px}p{color:#52665e;margin:0}.note{font-size:13px;margin-top:24px}@media(max-width:380px){body{padding:16px}.card{padding:24px}h1{font-size:25px}}</style><main class="card"><div class="brand">OTPanda</div><h1>Signing you in.</h1><p id="status">Finishing your secure sign-in.</p><p class="note">Keep this tab open. You will return to the app in a moment.</p><form method="post" action="/auth/login/complete"><input type="hidden" name="csrf" value="${csrf}"><input type="hidden" name="handoff"></form><script nonce="${nonce}">(()=>{'use strict';const hash=location.hash;history.replaceState(null,'',location.pathname);try{if(hash.length>128)throw Error();const q=new URLSearchParams(hash.slice(1));if([...q.keys()].join(',')!=='handoff'||!/^otpda_[A-Za-z0-9_-]{55}$/.test(q.get('handoff')))throw Error();const f=document.querySelector('form');f.elements.handoff.value=q.get('handoff');f.submit();}catch{document.querySelector('h1').textContent='Start sign-in again.';document.getElementById('status').textContent='Sign-in expired. Return to the app and start again.';document.querySelector('.note').textContent='No session was created on this page.';}})();</script></main></html>`,{nonce,'Set-Cookie':cookie(CSRF,csrf,120)});
  }
  if(request.method!=='POST')return invalid(405);
  if(origin!==API||request.headers.get('content-type')!=='application/x-www-form-urlencoded')return invalid(403);
  const raw=await text(request,512);if(raw===undefined)return invalid();const q=new URLSearchParams(raw),csrf=readCookie(request,CSRF),binding=readCookie(request,BIND);
  if([...q.keys()].sort().join(',')!=='csrf,handoff'||!csrf||q.get('csrf')!==csrf||!binding)return invalid(403);
  const result=await login.completeBrowser({handoff:q.get('handoff'),cookieBinding:binding,priorRefresh:readCookie(request,REFRESH_COOKIE)});if(!result)return invalid(401);
  const target=new URL(REDIRECT);target.hash=new URLSearchParams({code:result.code,state:result.state});
  const headers=new Headers({...securityHeaders,Location:target.href});headers.append('Set-Cookie',cookie(REFRESH_COOKIE,result.refresh,Math.max(0,Math.floor((result.refreshExpiresAt-clock())/1000))));headers.append('Set-Cookie',cookie(BIND,'',0));headers.append('Set-Cookie',cookie(CSRF,'',0));return new Response(null,{status:303,headers});
 }};
}
