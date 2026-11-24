import {json,securityHeaders,takeRateLimit} from './sessions.js';
import {createDeviceSessionAuth} from './device-session-auth.js';
import {AddPasskeyEnrollment,ADD_ACTION} from './additional-passkey.js';
import {PasskeyService} from './passkey-service.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',cors={'Access-Control-Allow-Origin':APP,Vary:'Origin'};
const PATHS=['verify-begin','verify-finish','register-begin','register-finish'];
async function body(request){const reader=request.body?.getReader();if(!reader)return;let out='',n=0;const d=new TextDecoder('utf-8',{fatal:true});try{for(;;){const r=await reader.read();if(r.done)break;n+=r.value.byteLength;if(n>24576){await reader.cancel();return;}out+=d.decode(r.value,{stream:true});}return JSON.parse(out+d.decode());}catch{return;}finally{reader.releaseLock();}}
export function createAddPasskeyHttp({db,sessions,clock=Date.now,passkeys=new PasskeyService(db,{clock}),enrollment=new AddPasskeyEnrollment(db,{clock,passkeys})}={}){
 const auth=createDeviceSessionAuth({sessions});
 return{async fetch(request,{clientAddress}={}){
  const u=new URL(request.url),step=u.pathname.slice('/v1/manage/passkey/add/'.length);
  if(u.origin!==API||!u.pathname.startsWith('/v1/manage/passkey/add/')||!PATHS.includes(step)||u.search)return json({error:'not_found'},404);
  if(request.headers.get('origin')!==APP)return json({error:'forbidden'},403);
  if(request.method==='OPTIONS')return request.headers.get('access-control-request-method')==='POST'&&(request.headers.get('access-control-request-headers')??'').toLowerCase().split(',').map(h=>h.trim()).filter(Boolean).every(h=>['authorization','content-type','x-otpanda-enrollment'].includes(h))?new Response(null,{status:204,headers:{...securityHeaders,...cors,'Access-Control-Allow-Methods':'POST','Access-Control-Allow-Headers':'Authorization, Content-Type, X-OTPanda-Enrollment'}}):json({error:'forbidden'},403,cors);
  if(request.method!=='POST'||request.headers.get('content-type')!=='application/json')return json({error:'invalid_request'},400,cors);
  if(typeof clientAddress!=='string'||!clientAddress)return json({error:'unavailable'},503,cors);
  if(!(await takeRateLimit(db,'add-passkey:'+clientAddress,{now:clock(),limit:20})).allowed)return json({error:'busy'},429,cors);
  const user=await auth.authenticate(request);if(!user)return json({error:'unauthorized'},401,cors);
  const value=await body(request);if(!value||Array.isArray(value))return json({error:'invalid_request'},400,cors);
  const keys=Object.keys(value).sort().join(','),expected={'verify-begin':'','verify-finish':'response,token','register-begin':'','register-finish':'response,token'}[step];
  if(keys!==expected)return json({error:'invalid_request'},400,cors);
  const binding=JSON.stringify(['add-passkey',user.deviceId,user.generation]);
  if(step==='verify-begin'){const c=await passkeys.begin({purpose:'step-up',ownerId:user.ownerId,binding,action:ADD_ACTION});return c&&await auth.authenticate(request)?json(c,200,cors):json({error:'reauthenticate'},403,cors);}
  if(step==='verify-finish'){
   const proof=await passkeys.finishAuthentication({token:value.token,response:value.response,ownerId:user.ownerId,binding,action:ADD_ACTION});
   const grant=proof?await enrollment.authorize({user,proof}):undefined;
   return grant&&await auth.authenticate(request)?json(grant,200,cors):json({error:'reauthenticate'},403,cors);
  }
  const grant=request.headers.get('x-otpanda-enrollment');if(!/^otpda_[A-Za-z0-9_-]{55}$/.test(grant??''))return json({error:'reauthenticate'},403,cors);
  const finish=step==='register-finish',result=finish?await enrollment.finish({user,grant,token:value.token,response:value.response}):await enrollment.begin({user,grant});
  if(!await auth.authenticate(request))return json({error:'unauthorized'},401,cors);
  return result?json(finish?{status:'registered'}:result,200,cors):json({error:'reauthenticate'},403,cors);
 }};
}
