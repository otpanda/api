import {silentPost,appFailure} from './silent-bridge.js';
// First-party restore boundary. No login/session creation or native clients.
import {cookie,readCookie,json,securityHeaders,takeRateLimit} from './sessions.js';
import {generateAccessToken} from './tokens.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',REDIRECT=APP+'/app/';
export const REFRESH_COOKIE='__Host-otpanda_device';
const CSRF='__Host-otpanda_restore';
const OPAQUE=/^[A-Za-z0-9_-]{43}$/;
const STATE=/^[A-Za-z0-9_-]{32,128}$/;
const cors={'Access-Control-Allow-Origin':APP,'Vary':'Origin'};
function parameters(data){
 if([...data.keys()].some(k=>!['challenge','state','redirect_uri','csrf'].includes(k)))return;
 if(['challenge','state','redirect_uri'].some(k=>data.getAll(k).length!==1))return;
 const challenge=data.get('challenge'),state=data.get('state'),redirectUri=data.get('redirect_uri');
 if(!OPAQUE.test(challenge)||!STATE.test(state)||redirectUri!==REDIRECT)return;
 return {challenge,state,redirectUri};
}
async function boundedText(request,max){const reader=request.body?.getReader();if(!reader)return '';const chunks=[];let size=0;try{while(true){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>max){await reader.cancel();return undefined;}chunks.push(value);}return new TextDecoder('utf-8',{fatal:true}).decode(Uint8Array.from(chunks.flatMap(c=>Array.from(c))));}catch{return undefined;}finally{reader.releaseLock();}}
function html(body,status=200,extra={}){return new Response(body,{status,headers:{...securityHeaders,'Referrer-Policy':'same-origin','Content-Type':'text/html; charset=utf-8','Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://otpanda.github.io/app/; frame-ancestors 'none'; base-uri 'none'",...extra}});}
export function createBrowserSessionHttp({sessions,exchanges,db,clock=Date.now}={}){
 if(!sessions||!exchanges||!db)throw new TypeError('Session dependencies required');
 return {async fetch(request,{clientAddress}={}){
  const url=new URL(request.url);
  if(url.origin!==API)return json({error:'not_found'},404);
  if(!['/auth/restore','/auth/exchange'].includes(url.pathname))return json({error:'not_found'},404);
  const exchange=url.pathname==='/auth/exchange';
  const origin=request.headers.get('origin');
  if(exchange&&origin!==APP)return json({error:'forbidden'},403);
  if(exchange&&request.method==='OPTIONS'){
   const headers=request.headers.get('access-control-request-headers')?.toLowerCase().split(',').map(v=>v.trim())??[];
   if(request.headers.get('access-control-request-method')!=='POST'||headers.some(h=>h!=='content-type'))return json({error:'forbidden'},403);
   return new Response(null,{status:204,headers:{...securityHeaders,...cors,'Access-Control-Allow-Methods':'POST','Access-Control-Allow-Headers':'Content-Type'}});
  }
  if((exchange&&request.method!=='POST')||(!exchange&&!['GET','POST'].includes(request.method)))return json({error:'method_not_allowed'},405);
  // Address is supplied by trusted runtime metadata, never forwarded headers.
  if(typeof clientAddress!=='string'||!clientAddress||clientAddress.length>128)return json({error:'unavailable'},503);
  const limit=await takeRateLimit(db,'browser-session:'+url.pathname+':'+clientAddress,{now:clock(),limit:30});
  if(!limit.allowed)return json({error:'rate_limited'},429,{'Retry-After':String(limit.retryAfter),...(exchange?cors:{})});
  if(exchange){
   if(url.search||request.headers.get('content-type')!=='application/json'||Number(request.headers.get('content-length')??0)>4096)return json({error:'invalid_request'},400,cors);
   const text=await boundedText(request,4096);if(text===undefined)return json({error:'invalid_request'},400,cors);
   let data;try{data=JSON.parse(text);}catch{return json({error:'invalid_request'},400,cors);}
   if(!data||Array.isArray(data)||Object.keys(data).sort().join(',')!=='code,redirect_uri,verifier')return json({error:'invalid_request'},400,cors);
   const result=await exchanges.exchange({code:data.code,verifier:data.verifier,redirectUri:data.redirect_uri});
   return result?json(result,200,cors):json({error:'invalid_grant'},401,cors);
  }
  if(request.method==='GET'){
   const p=parameters(url.searchParams);if(!p||url.searchParams.has('csrf'))return html('<h1>Invalid restoration request</h1>',400);
   const csrf=generateAccessToken().token;
   // All interpolated query values have narrow alphabets or a fixed constant.
   return silentPost('/auth/restore',{challenge:p.challenge,state:p.state,redirect_uri:REDIRECT,csrf},{'Set-Cookie':cookie(CSRF,csrf,300)});
  }
  if(origin!==API||url.search||request.headers.get('content-type')!=='application/x-www-form-urlencoded')return html('<h1>Request not allowed</h1>',403);
  const text=await boundedText(request,2048);if(text===undefined)return html('<h1>Invalid request</h1>',400);
  const data=new URLSearchParams(text),p=parameters(data),csrf=readCookie(request,CSRF);
  if(!p||data.getAll('csrf').length!==1||!csrf||csrf.length>200||data.get('csrf')!==csrf)return html('<h1>Request expired. Start again.</h1>',403);
  const refresh=readCookie(request,REFRESH_COOKIE),result=await sessions.rotate(refresh,{clientKind:'web'});
  if(result.status==='retry')return appFailure(p.state,'retry');
  if(result.status!=='rotated')return appFailure(p.state,'sign-in',{'Set-Cookie':cookie(REFRESH_COOKIE,'',0)});
  const headers=new Headers({...securityHeaders,'Set-Cookie':cookie(REFRESH_COOKIE,result.refresh,Math.max(0,Math.floor((result.refreshExpiresAt-clock())/1000)))});
  headers.append('Set-Cookie',cookie(CSRF,'',0));
  const grant=await exchanges.mint({deviceId:result.deviceId,challenge:p.challenge,redirectUri:REDIRECT});
  if(!grant){headers.set('Location',REDIRECT+'#'+new URLSearchParams({auth:'restart',state:p.state}));return new Response(null,{status:303,headers});}
  const target=new URL(REDIRECT);target.hash=new URLSearchParams({code:grant.code,state:p.state}).toString();
  headers.set('Location',target.href);return new Response(null,{status:303,headers});
 }};
}
