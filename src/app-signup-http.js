import {scriptValue} from './silent-bridge.js';
// App-owned signup screens. Only bounded noninteractive first-party bridges
// run here so API cookies never depend on third-party-cookie support.
import {cookie,readCookie,json,securityHeaders,takeRateLimit} from './sessions.js';
import {generateAccessToken,base64urlEncode} from './tokens.js';
import {canonicalAccountEmail} from './account-identity.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io/app/';
const BIND='__Host-otpanda_login',CSRF='__Host-otpanda_signup_csrf',OPAQUE=/^[A-Za-z0-9_-]{43}$/,TOKEN=/^otpda_[A-Za-z0-9_-]{55}$/;
function back(state,auth){const u=new URL(APP);u.hash=new URLSearchParams({auth,state});return new Response(null,{status:303,headers:{...securityHeaders,Location:u.href}});}
async function bounded(request){let size=0,out='';const reader=request.body?.getReader();if(!reader)return;const decoder=new TextDecoder('utf-8',{fatal:true});try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>2048){await reader.cancel();return;}out+=decoder.decode(value,{stream:true});}return out+decoder.decode();}catch{return;}finally{reader.releaseLock();}}
export function createAppSignupHttp({db,signupEmail,handoff,clock=Date.now,defer}={}){
 if(!db||!signupEmail||!handoff)throw new TypeError('Signup dependencies required');
 return {async fetch(request,{clientAddress}={}){
  const u=new URL(request.url),state=u.searchParams.get('state');
  if(u.origin!==API||u.pathname!=='/auth/signup/app')return json({error:'not_found'},404);
  if([...u.searchParams.keys()].sort().join(',')!=='challenge,redirect_uri,state'||!OPAQUE.test(state)||!OPAQUE.test(u.searchParams.get('challenge'))||u.searchParams.get('redirect_uri')!==APP)return back('', 'restart');
  if(typeof clientAddress!=='string'||!clientAddress||clientAddress.length>128)return back(state,'retry');
  const limit=await takeRateLimit(db,'app-signup:'+clientAddress,{now:clock(),limit:15});if(!limit.allowed)return back(state,'retry');
  if(request.method==='GET'){
   const csrf=generateAccessToken().token,prior=readCookie(request,'__Host-otpanda_browser'),binding=TOKEN.test(prior??'')?prior:generateAccessToken().token,nonce=base64urlEncode(crypto.getRandomValues(new Uint8Array(18)));
   const target=u.pathname+u.search;
   // No user-interactive element, text or stylesheet. Fragment removed first.
   const script=`(()=>{'use strict';const raw=location.hash;history.replaceState(null,'',location.pathname+location.search);try{if(raw.length>1500)throw Error();const p=new URLSearchParams(raw.slice(1));const keys=[...p.keys()].sort().join(',');if(!['action,email','action,email,email_token'].includes(keys)||!['email','begin'].includes(p.get('action'))||(p.get('action')==='begin')!==p.has('email_token')||p.get('email').length>254)throw Error();const f=document.createElement('form');f.method='post';f.action=${scriptValue(target)};for(const [name,value] of [...p,['csrf',${scriptValue(csrf)}]]){const i=document.createElement('input');i.type='hidden';i.name=name;i.value=value;f.append(i);}document.body.append(f);f.submit();}catch{location.replace(${scriptValue(APP+'#'+new URLSearchParams({auth:'restart',state}))});}})();`;
   const headers=new Headers({...securityHeaders,'Referrer-Policy':'same-origin','Content-Type':'text/html; charset=utf-8','Content-Security-Policy':`default-src 'none'; script-src 'nonce-${nonce}'; form-action 'self' https://otpanda.github.io/app/; frame-ancestors 'none'; base-uri 'none'`});headers.append('Set-Cookie',cookie(CSRF,csrf,600));headers.append('Set-Cookie',cookie(BIND,binding,900));headers.append('Set-Cookie',cookie('__Host-otpanda_browser',binding,2147483647));return new Response(`<!doctype html><html><head><meta charset="utf-8"><title>OTPanda</title></head><body><script nonce="${nonce}">${script}</script></body></html>`,{headers});
  }
  if(request.method!=='POST'||request.headers.get('origin')!==API||!/^application\/x-www-form-urlencoded(?:;\s*charset=UTF-8)?$/i.test(request.headers.get('content-type')??''))return back(state,'restart');
  const raw=await bounded(request);if(raw===undefined)return back(state,'restart');const p=new URLSearchParams(raw),action=p.get('action'),keys=[...p.keys()].sort().join(',');
  if((action==='email'?keys!=='action,csrf,email':action==='begin'?keys!=='action,csrf,email,email_token':true)||[...p.keys()].some(k=>p.getAll(k).length!==1))return back(state,'restart');
  const csrf=readCookie(request,CSRF),binding=readCookie(request,BIND);if(!TOKEN.test(csrf??'')||p.get('csrf')!==csrf||!TOKEN.test(binding??''))return back(state,'restart');
  let email;try{email=canonicalAccountEmail(p.get('email'));}catch{return back(state,'email-invalid');}
  if(action==='email'){if(typeof defer!=='function')return back(state,'retry');try{defer(()=>signupEmail.request({email,cookieBinding:binding,clientAddress,allowExisting:true}));}catch{return back(state,'retry');}return back(state,'email-sent');}
  if(!TOKEN.test(p.get('email_token')??'')&&!/^[A-HJ-NP-Z2-9]{8}$/i.test((p.get('email_token')??'').replaceAll(' ','')))return back(state,'code-invalid');
  let c;try{c=await handoff.beginBrowser({email,emailToken:p.get('email_token'),cookieBinding:binding,challenge:u.searchParams.get('challenge'),state,redirectUri:APP,resolveExisting:true});}catch{return back(state,'code-invalid');}
  if(!c)return back(state,'code-invalid');if(c.existing===true)return back(state,'existing-account');const target=new URL(APP);target.hash=new URLSearchParams({signup:base64urlEncode(new TextEncoder().encode(JSON.stringify(c))),state});return new Response(null,{status:303,headers:{...securityHeaders,Location:target.href}});
 }};
}
