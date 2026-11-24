import {json,securityHeaders,takeRateLimit} from './sessions.js';
import {createDeviceSessionAuth} from './device-session-auth.js';
import {RecoveryControls,KINDS,recoveryAction} from './recovery-controls.js';
import {PasskeyService} from './passkey-service.js';
import {EmailRecovery} from './email-recovery.js';
import {DurableDeviceKeys} from './durable-device-keys.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',cors={'Access-Control-Allow-Origin':APP,Vary:'Origin'};
export const RECOVERY_STEPS=['status','begin','finish','request-change','approve-begin','approve-change','consume-change','cancel-request'];
async function body(request){const reader=request.body?.getReader();if(!reader)return;let out='',n=0;const d=new TextDecoder('utf-8',{fatal:true});try{for(;;){const r=await reader.read();if(r.done)break;n+=r.value.byteLength;if(n>24576){await reader.cancel();return;}out+=d.decode(r.value,{stream:true});}return JSON.parse(out+d.decode());}catch{return;}finally{reader.releaseLock();}}
export function createRecoveryControlsHttp({db,sessions,clock=Date.now,passkeys=new PasskeyService(db,{clock}),service=new RecoveryControls(db,{clock}),emailRecovery=new EmailRecovery(db,{clock,passkeys}),deviceKeys=new DurableDeviceKeys(db,{clock})}={}){
 const auth=createDeviceSessionAuth({sessions});
 return{async fetch(request,{clientAddress}={}){
  const u=new URL(request.url),step=u.pathname.slice('/v1/manage/recovery/'.length);
  if(u.origin!==API||!u.pathname.startsWith('/v1/manage/recovery/')||!RECOVERY_STEPS.includes(step)||u.search)return json({error:'not_found'},404);
  if(request.headers.get('origin')!==APP)return json({error:'forbidden'},403);
  const method=step==='status'?'GET':'POST';
  if(request.method==='OPTIONS')return new Response(null,{status:204,headers:{...securityHeaders,...cors,'Access-Control-Allow-Methods':method,'Access-Control-Allow-Headers':'Authorization, Content-Type'}});
  if(request.method!==method||(method==='POST'&&request.headers.get('content-type')!=='application/json'))return json({error:'invalid_request'},400,cors);
  if(typeof clientAddress!=='string'||!clientAddress)return json({error:'unavailable'},503,cors);
  if(!(await takeRateLimit(db,'recovery:'+clientAddress,{now:clock(),limit:30})).allowed)return json({error:'busy'},429,cors);
  const user=await auth.authenticate(request);if(!user)return json({error:'unauthorized'},401,cors);
  if(step==='status'){const s={...await service.status(user),emailRecoveryRequest:await emailRecovery.status(user.ownerId)??null};return await auth.authenticate(request)?json(s,200,cors):json({error:'unauthorized'},401,cors);}
  const v=await body(request);if(!v||Array.isArray(v))return json({error:'invalid_request'},400,cors);
  if(step==='approve-begin'||step==='approve-change'){
   // Approver proof is a verifier-produced device-key signature over the exact
   // change. No caller-supplied proof object, no session-only approval.
   // Fails closed: no verifier-enforced local verification exists yet.
   if(!service.approvalAvailable)return json({error:'unavailable',reason:'local_verification_unavailable'},503,cors);
   const shape=step==='approve-begin'?'changeId,keyId':'changeId,signature,token';
   if(Object.keys(v).sort().join(',')!==shape||Object.values(v).some(x=>typeof x!=='string'||x.length>2048))return json({error:'invalid_request'},400,cors);
   if(step==='approve-begin'){const c=await service.beginApproval({user,changeId:v.changeId,keyId:v.keyId,deviceKeys});return c&&await auth.authenticate(request)?json(c,200,cors):json({error:'unavailable'},409,cors);}
   const ok=await service.approveChange({user,changeId:v.changeId,token:v.token,signature:v.signature,deviceKeys});
   return ok&&await auth.authenticate(request)?json({status:'ok'},200,cors):json({error:'unavailable'},409,cors);
  }
  if(['consume-change','cancel-request'].includes(step)){
   const key=step==='cancel-request'?'requestId':'changeId';
   if(Object.keys(v).join(',')!==key||typeof v[key]!=='string'||v[key].length>128)return json({error:'invalid_request'},400,cors);
   const ok=step==='consume-change'?await service.consumeChange({...user,changeId:v.changeId}):await emailRecovery.cancel({...user,requestId:v.requestId});
   return ok?json(step==='consume-change'?ok:{status:'ok'},200,cors):json({error:'waiting'},409,cors);
  }
  if(!KINDS.includes(v.kind))return json({error:'invalid_request'},400,cors);
  const needsTarget=v.kind==='passkey-revoke'||v.kind==='session-revoke',on=v.kind==='email-escape-on';
  const expected=['kind',...(needsTarget?['target']:[]),...(on?['warningAccepted']:[]),...(step==='finish'?['response','token']:[])].sort().join(',');
  if(Object.keys(v).sort().join(',')!==expected||(needsTarget&&(typeof v.target!=='string'||v.target.length>512))||(on&&v.warningAccepted!==true))return json({error:'invalid_request'},400,cors);
  if(step==='request-change'){const c=await service.createChange({...user,kind:v.kind,target:v.target,warningAccepted:v.warningAccepted});return c?json(c,200,cors):json({error:'restart'},403,cors);}
  const action=recoveryAction(v.kind,v.target),binding=JSON.stringify(['recovery',user.deviceId,user.generation]);
  if(step==='begin'){const c=await passkeys.begin({purpose:'step-up',ownerId:user.ownerId,binding,action});return c&&await auth.authenticate(request)?json(c,200,cors):json({error:'reauthenticate'},403,cors);}
  const proof=await passkeys.finishAuthentication({token:v.token,response:v.response,ownerId:user.ownerId,binding,action});
  const result=proof?await service.apply({user,kind:v.kind,target:v.target,proof,warningAccepted:v.warningAccepted}):undefined;
  const self=v.kind==='session-revoke'&&v.target===user.deviceId;
  return result&&(self||await auth.authenticate(request))?json(result,200,cors):json({error:'reauthenticate'},403,cors);
 }};
}
