// Browser signup HTTP boundary, deliberately unmounted. Mirrors the approved
// login boundary: exact origins, trusted-address prelimits, bounded bodies,
// strict shapes and a first-party cookie-bound ceremony. GET never sends mail,
// begins a ceremony or consumes a proof. Mail delivery is delegated to an
// injected bounded defer so the response never awaits an account or delivery
// branch. Completion reuses the existing /auth/login/complete page and shared
// host login-binding cookie; this module adds no second completion surface.
import {json,securityHeaders,cookie,readCookie,takeRateLimit} from './sessions.js';
import {generateAccessToken,base64urlEncode} from './tokens.js';
import {canonicalAccountEmail} from './account-identity.js';
import {canonicalClientAddress} from './client-address.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',REDIRECT=APP+'/app/';
const BIND='__Host-otpanda_login',CSRF='__Host-otpanda_signup_csrf';
const OPAQUE=/^[A-Za-z0-9_-]{43}$/,PROOF=/^otpda_[A-Za-z0-9_-]{55}$/;
const cors={'Access-Control-Allow-Origin':APP,Vary:'Origin'};
const CSP="default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://otpanda.github.io/app/; frame-ancestors 'none'; base-uri 'none'";
function page(body,{status=200,...extra}={}){return new Response(body,{status,headers:{...securityHeaders,'Content-Type':'text/html; charset=utf-8','Referrer-Policy':'same-origin','Content-Security-Policy':CSP,...extra}});}
function escapeAttr(value){return value.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}
async function text(request,max){const reader=request.body?.getReader();if(!reader)return '';let size=0;const chunks=[];try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>max){await reader.cancel();return;}chunks.push(value);}return new TextDecoder('utf-8',{fatal:true}).decode(Uint8Array.from(chunks.flatMap(c=>Array.from(c))));}catch{return;}finally{reader.releaseLock();}}
function invalid(status=400,headers={}){return json({error:'invalid_request'},status,headers);}
function formFields(data,expected){const keys=[...data.keys()].sort();if(keys.join(',')!==expected)return;const out={};for(const k of keys){const v=data.getAll(k);if(v.length!==1)return;out[k]=v[0];}return out;}
function layout(inner){return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>OTPanda signup</title><meta name="color-scheme" content="light"><style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f5f8f7;color:#17332a;font:16px/1.55 system-ui,sans-serif;padding:24px}.card{width:100%;max-width:460px;background:white;border:1px solid #dfe8e2;border-radius:24px;padding:32px;box-shadow:0 12px 36px #17332a0a}.brand{font-weight:800;font-size:21px;letter-spacing:-.5px;color:#0a7955}h1{font-size:26px;line-height:1.2;letter-spacing:-.7px;margin:26px 0 12px}p{color:#52665e;margin:0 0 14px}label{display:block;font-size:13px;font-weight:600;margin:14px 0 4px}input{width:100%;padding:10px 12px;border:1px solid #c6d4cc;border-radius:10px;font:inherit}button{margin-top:16px;width:100%;padding:12px;border:0;border-radius:10px;background:#0a7955;color:white;font:inherit;font-weight:700;cursor:pointer}hr{border:0;border-top:1px solid #e3ece7;margin:26px 0}.note{font-size:13px;margin-top:18px}</style><main class="card"><div class="brand">OTPanda</div>${inner}</main></html>`;}
const SAME_BROWSER='Signup only works in the same browser where you started it. If the email opened in another app or browser, come back here and type the code yourself, or start again in the browser you want to use.';
function startPage(csrf,challenge,state){return layout(`<h1>Create your account.</h1><p>Step 1: request a signup code. Step 2: enter it here and create your passkey.</p><form method="post" action="/auth/signup/email"><input type="hidden" name="csrf" value="${csrf}"><label for="req-email">Email</label><input id="req-email" name="email" type="email" required maxlength="254" autocomplete="email"><button type="submit">Email me a signup code</button></form><hr><form method="post" action="/auth/signup/begin"><input type="hidden" name="csrf" value="${csrf}"><input type="hidden" name="challenge" value="${challenge}"><input type="hidden" name="state" value="${state}"><input type="hidden" name="redirect_uri" value="${REDIRECT}"><label for="begin-email">Email</label><input id="begin-email" name="email" type="email" required maxlength="254" autocomplete="email"><label for="begin-token">Signup code</label><input id="begin-token" name="email_token" type="text" required minlength="61" maxlength="61" autocomplete="off" spellcheck="false"><button type="submit">Create my passkey</button></form><p class="note">${SAME_BROWSER} Codes last ten minutes.</p>`);}
function acceptedPage(){return layout('<h1>Check your email.</h1><p>If this address can sign up, a code is on its way. Go back to the previous page in this browser and enter it there.</p><p class="note">'+SAME_BROWSER+'</p>');}
function recoveryPage(){return page(layout('<h1>Signup could not continue.</h1><p>'+SAME_BROWSER+' Codes expire after ten minutes and each can only be used a few times.</p><p>If you already created your account with this email, sign in with your passkey instead. Otherwise go back to the app and start again.</p><p class="note"><a href="https://otpanda.github.io/app/">Open the OTPanda app</a></p>'),{status:400});}
export function createSignupHttp({db,signupEmail,handoff,clock=Date.now,defer}={}){
 if(!db||!signupEmail||!handoff)throw new TypeError('Signup HTTP dependencies required');
 return {async fetch(request,{clientAddress}={}){
  const url=new URL(request.url),path=url.pathname,origin=request.headers.get('origin');
  if(url.origin!==API||!['/auth/signup/start','/auth/signup/email','/auth/signup/begin','/auth/signup/verify'].includes(path))return json({error:'not_found'},404);
  const verify=path==='/auth/signup/verify';
  // Verify is a cookie-free app fetch from the exact app origin. Everything
  // else is a same-origin first-party page flow.
  if(verify&&origin!==APP)return invalid(403);
  if(!verify&&path!=='/auth/signup/start'&&origin!==API)return invalid(403);
  if(verify&&request.method==='OPTIONS'){
   const headers=request.headers.get('access-control-request-headers')?.toLowerCase().split(',').map(h=>h.trim())??[];
   return request.headers.get('access-control-request-method')==='POST'&&headers.every(h=>h==='content-type')?new Response(null,{status:204,headers:{...securityHeaders,...cors,'Access-Control-Allow-Methods':'POST','Access-Control-Allow-Headers':'Content-Type'}}):invalid(403,cors);
  }
  // Address identity is trusted runtime metadata, canonicalized once here for
  // both the HTTP prelimit and the email service. Never request headers.
  const address=canonicalClientAddress(clientAddress);
  if(address===undefined)return invalid(503,verify?cors:{});
  const rate=await takeRateLimit(db,'web-signup:'+path+':'+address,{now:clock(),limit:15});if(!rate.allowed)return json({error:'rate_limited'},429,{...(verify?cors:{}),'Retry-After':String(rate.retryAfter)});
  if(path==='/auth/signup/start'){
   if(request.method!=='GET')return invalid(405);
   const q=url.searchParams;
   if([...q.keys()].sort().join(',')!=='challenge,redirect_uri,state'||!OPAQUE.test(q.get('challenge'))||!OPAQUE.test(q.get('state'))||q.get('redirect_uri')!==REDIRECT)return invalid();
   // No service call, mail or proof consumption here. The binding cookie is
   // kept if already present so proof retries keep their issuance binding.
   const oldCsrf=readCookie(request,CSRF),csrf=typeof oldCsrf==='string'&&PROOF.test(oldCsrf)?oldCsrf:generateAccessToken().token,binding=readCookie(request,BIND);
   const response=page(startPage(csrf,escapeAttr(q.get('challenge')),escapeAttr(q.get('state'))));
   response.headers.append('Set-Cookie',cookie(CSRF,csrf,600));
   response.headers.append('Set-Cookie',cookie(BIND,typeof binding==='string'&&PROOF.test(binding)?binding:generateAccessToken().token,900));
   return response;
  }
  if(path==='/auth/signup/email'){
   if(request.method!=='POST')return invalid(405);
   if(url.search||!/^application\/x-www-form-urlencoded(?:;\s*charset=UTF-8)?$/i.test(request.headers.get('content-type')??''))return recoveryPage();
   const raw=await text(request,1024);if(raw===undefined)return recoveryPage();
   const fields=formFields(new URLSearchParams(raw),'csrf,email');if(!fields)return recoveryPage();
   const csrf=readCookie(request,CSRF),binding=readCookie(request,BIND);
   if(!csrf||fields.csrf!==csrf||typeof binding!=='string'||!binding||binding.length>512)return recoveryPage();
   let email;try{email=canonicalAccountEmail(fields.email);}catch{return recoveryPage();}
   // Bounded background delivery: the 202 never waits on account, quota or
   // transport branches, so timing reveals none of them. Defer is required.
   if(typeof defer!=='function')return invalid(503);
   try{defer(()=>signupEmail.request({email,clientAddress:address,cookieBinding:binding}));}catch{return page(layout('<h1>Signup is busy.</h1><p>No new email request was accepted. Wait a moment, then return to the signup form in this browser and try again.</p>'),{status:503,'Retry-After':'30'});}
   return page(acceptedPage(),{status:202});
  }
  if(path==='/auth/signup/begin'){
   if(request.method!=='POST')return invalid(405);
   if(url.search||!/^application\/x-www-form-urlencoded(?:;\s*charset=UTF-8)?$/i.test(request.headers.get('content-type')??''))return recoveryPage();
   const raw=await text(request,1024);if(raw===undefined)return recoveryPage();
   const fields=formFields(new URLSearchParams(raw),'challenge,csrf,email,email_token,redirect_uri,state');if(!fields)return recoveryPage();
   const csrf=readCookie(request,CSRF),binding=readCookie(request,BIND);
   if(!csrf||fields.csrf!==csrf)return recoveryPage();
   if(!OPAQUE.test(fields.challenge)||!OPAQUE.test(fields.state)||fields.redirect_uri!==REDIRECT||!PROOF.test(fields.email_token))return recoveryPage();
   // A missing binding means another browser or a lost cookie: fail closed
   // with recovery guidance, never mint a fresh binding to make a link work.
   if(typeof binding!=='string'||!binding||binding.length>512)return recoveryPage();
   let ceremony;try{ceremony=await handoff.beginBrowser({email:fields.email,emailToken:fields.email_token,cookieBinding:binding,challenge:fields.challenge,state:fields.state,redirectUri:REDIRECT});}catch{return recoveryPage();}
   if(!ceremony)return recoveryPage();
   // Fragment payload is data, never script. App validates state/RP/options.
   const target=new URL(REDIRECT);target.hash=new URLSearchParams({signup:base64urlEncode(new TextEncoder().encode(JSON.stringify(ceremony))),state:fields.state}).toString();
   return new Response(null,{status:303,headers:{...securityHeaders,Location:target.href}});
  }
  if(request.method!=='POST')return invalid(405,cors);
  if(url.search||request.headers.get('content-type')!=='application/json')return invalid(400,cors);
  const raw=await text(request,16384);if(raw===undefined)return invalid(400,cors);let data;try{data=JSON.parse(raw);}catch{return invalid(400,cors);}
  if(!data||Array.isArray(data)||Object.keys(data).sort().join(',')!=='response,token')return invalid(400,cors);
  // On success the app receives only {handoff, expiresAt} and posts it through
  // the existing cookie-bound login completion page.
  try{const result=await handoff.verifyBrowser(data);return result?json(result,200,cors):invalid(401,cors);}catch{return invalid(503,cors);}
 }};
}
