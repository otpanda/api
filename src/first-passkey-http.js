import {json,securityHeaders,takeRateLimit} from './sessions.js';
import {createDeviceSessionAuth} from './device-session-auth.js';
import {FirstPasskeyEnrollment} from './first-passkey-enrollment.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',cors={'Access-Control-Allow-Origin':APP,Vary:'Origin'};
async function body(request){const reader=request.body?.getReader();if(!reader)return;let out='',n=0;const decoder=new TextDecoder('utf-8',{fatal:true});try{for(;;){const r=await reader.read();if(r.done)break;n+=r.value.byteLength;if(n>16384){await reader.cancel();return;}out+=decoder.decode(r.value,{stream:true});}return JSON.parse(out+decoder.decode());}catch{return;}finally{reader.releaseLock();}}
export function createFirstPasskeyHttp({db,sessions,clock=Date.now,enrollment=new FirstPasskeyEnrollment(db,{clock})}={}){
 const auth=createDeviceSessionAuth({sessions});
 return{async fetch(request,{clientAddress}={}){
  const u=new URL(request.url),finish=u.pathname==='/v1/manage/first-passkey/finish';
  if(u.origin!==API||!['/v1/manage/first-passkey/begin','/v1/manage/first-passkey/finish'].includes(u.pathname))return json({error:'not_found'},404);
  if(request.headers.get('origin')!==APP)return json({error:'forbidden'},403);
  if(request.method==='OPTIONS')return request.headers.get('access-control-request-method')==='POST'&&(request.headers.get('access-control-request-headers')??'').toLowerCase().split(',').every(h=>['authorization','content-type','x-otpanda-enrollment'].includes(h.trim()))?new Response(null,{status:204,headers:{...securityHeaders,...cors,'Access-Control-Allow-Methods':'POST','Access-Control-Allow-Headers':'Authorization, Content-Type, X-OTPanda-Enrollment'}}):json({error:'forbidden'},403,cors);
  if(request.method!=='POST'||u.search||request.headers.get('content-type')!=='application/json')return json({error:'invalid_request'},400,cors);
  if(typeof clientAddress!=='string'||!clientAddress)return json({error:'unavailable'},503,cors);
  if(!(await takeRateLimit(db,'first-passkey:'+clientAddress,{now:clock(),limit:15})).allowed)return json({error:'busy'},429,cors);
  const user=await auth.authenticate(request);if(!user)return json({error:'unauthorized'},401,cors);
  const grant=request.headers.get('x-otpanda-enrollment');if(!/^otpda_[A-Za-z0-9_-]{55}$/.test(grant??''))return json({error:'reauthenticate'},403,cors);
  const value=await body(request);if(!value||Array.isArray(value)||Object.keys(value).sort().join(',')!==(finish?'response,token':''))return json({error:'invalid_request'},400,cors);
  const result=finish?await enrollment.finish({user,grant,token:value.token,response:value.response}):await enrollment.begin({user,grant});
  if(!await auth.authenticate(request))return json({error:'unauthorized'},401,cors);
  return result?json(finish?{status:'registered'}:result,200,cors):json({error:'reauthenticate'},403,cors);
 }};
}
