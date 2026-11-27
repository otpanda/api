// Inactive, unmounted, flag default OFF (404 before any limiter, D1 or key access). Android-only routes: no Origin, bearer android access
// token, exact key sets, POST JSON. Opaque 409 {error:'unavailable'} for every guard failure. The only specific 409 codes are the signed-shape
// definitive answers 'key-revoked' and 'generation-changed', returned only for a request whose signature verified.
import {json,takeRateLimit,hashText} from './sessions.js';
import {createDeviceSessionAuth} from './device-session-auth.js';
import {seedSyncEnrollAction,seedSyncEnrollBinding} from './seed-sync.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',NS={'Cache-Control':'no-store'},BASE='/v1/manage/seed-sync/';
const KEYS={'stepup-begin':['installId','keyId','publicJwk'],'enroll-begin':['installId','keyId','publicJwk','response','token'],'enroll-finish':['signature','token'],'snapshot-begin':['epoch','keyId'],'snapshot-finish':['signature','token'],'batch-begin':['entries','ephemeralKey','epoch','keyId'],'batch-finish':['signature','token'],'status-begin':['keyId'],'status-finish':['signature','token'],'revoke-begin':['keyId'],'revoke-finish':['signature','token'],list:[],context:[]};
const MAX_BYTES={'enroll-begin':16384};
export function createSeedSyncHttp({db,sessions,service,passkeys,enabled=false,clock=Date.now}={}){
 const auth=createDeviceSessionAuth({sessions,native:true});
 return{async fetch(request,{clientAddress}={}){
  const url=new URL(request.url),op=url.pathname.startsWith(BASE)?url.pathname.slice(BASE.length):'';
  if(enabled!==true||url.origin!==API||!Object.hasOwn(KEYS,op))return json({error:'not_found'},404,NS);
  if(request.headers.has('origin'))return json({error:'forbidden'},403,NS);
  if(request.method!=='POST')return json({error:'method_not_allowed'},405,NS);
  if(url.search||request.headers.get('content-type')!=='application/json')return json({error:'invalid_request'},400,NS);
  try{
   if(typeof clientAddress!=='string'||!clientAddress||clientAddress.length>128)return json({error:'unavailable'},503,NS);
   const lim=await takeRateLimit(db,'seed-sync-address:'+clientAddress,{now:clock(),limit:30});if(!lim.allowed)return json({error:'rate_limited'},429,{...NS,'Retry-After':String(lim.retryAfter)});
   // status-* are the only session-less operations: authority is possession of the enrolled key (a signed-out device has no session).
   const open=op.startsWith('status-'),user=open?undefined:await auth.authenticate(request);if(!open&&!user)return json({error:'unauthorized'},401,NS);
   if(user){const ol=await takeRateLimit(db,'seed-sync-owner:'+user.ownerId,{now:clock(),limit:60});if(!ol.allowed)return json({error:'rate_limited'},429,{...NS,'Retry-After':String(ol.retryAfter)});}
   const max=MAX_BYTES[op]??4096,reader=request.body?.getReader();if(!reader)return json({error:'invalid_request'},400,NS);
   let size=0;const parts=[];for(;;){const{value,done}=await reader.read();if(done)break;size+=value.length;if(size>max){await reader.cancel();return json({error:'invalid_request'},400,NS);}parts.push(value);}
   const bytes=new Uint8Array(size);let o=0;for(const p of parts){bytes.set(p,o);o+=p.length;}
   let b;try{b=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}catch{return json({error:'invalid_request'},400,NS);}
   if(!b||typeof b!=='object'||Array.isArray(b)||Object.keys(b).sort().join(',')!==KEYS[op].join(','))return json({error:'invalid_request'},400,NS);
   const s=v=>typeof v==='string'&&v.length<=512,obj=v=>v&&typeof v==='object'&&!Array.isArray(v);
   const shape={installId:s,token:s,signature:s,keyId:s,reason:s,ephemeralKey:s,publicJwk:obj,response:obj,entries:Array.isArray,epoch:Number.isSafeInteger};
   if(!Object.entries(b).every(([k,v])=>shape[k](v)))return json({error:'invalid_request'},400,NS);
   let result;
   if(op==='status-begin'){const c=await service.statusBegin({keyId:b.keyId});return json(c,200,NS);}
   if(op==='status-finish'){const r=await service.statusFinish({token:b.token,signature:b.signature});return r?json(r,200,NS):json({error:'unavailable'},409,NS);}
   if(op==='stepup-begin'||op==='enroll-begin'){
    if(!passkeys)return json({error:'unavailable'},409,NS);
    if(!/^[0-9a-f]{32}$/.test(b.keyId))return json({error:'invalid_request'},400,NS);
    const actionDigest=await seedSyncEnrollAction({ownerId:user.ownerId,installId:b.installId,keyId:b.keyId,publicJwk:b.publicJwk,generation:user.generation}),binding=await seedSyncEnrollBinding(user.ownerId,user.deviceId,actionDigest),action='seed-sync-enroll:'+actionDigest;
    if(op==='stepup-begin')result=await passkeys.begin({purpose:'step-up',ownerId:user.ownerId,binding,action});
    else{
     const proof=await passkeys.finishAuthentication({token:b.token,response:b.response,ownerId:user.ownerId,binding,action});
     // finishAuthentication enforced the exact action text; the service re-derives the digest and requires an equal one.
     result=proof&&proof.purpose==='step-up'&&proof.ownerId===user.ownerId&&proof.generation===user.generation&&typeof proof.credentialId==='string'?await service.enrollBegin({user,installId:b.installId,keyId:b.keyId,publicJwk:b.publicJwk,strongProof:{purpose:'step-up',ownerId:user.ownerId,generation:proof.generation,credentialId:proof.credentialId,actionDigest,verifiedAt:Number.isSafeInteger(proof.verifiedAt)?proof.verifiedAt:clock()}}):undefined;
    }
   }
   else if(op==='context')result=await service.context({user});
   else if(op==='enroll-finish')result=await service.enrollFinish({user,token:b.token,signature:b.signature});
   else if(op==='snapshot-begin')result=await service.snapshotBegin({user,keyId:b.keyId,epoch:b.epoch});
   else if(op==='snapshot-finish')result=await service.snapshotFinish({user,token:b.token,signature:b.signature});
   else if(op==='batch-begin')result=await service.batchBegin({user,keyId:b.keyId,epoch:b.epoch,ephemeralKey:b.ephemeralKey,entries:b.entries});
   else if(op==='revoke-begin')result=await service.revokeBegin({user,keyId:b.keyId});
   else if(op==='revoke-finish')result=await service.revokeFinish({user,token:b.token,signature:b.signature});
   else if(op==='list')result=await service.listKeys({user});
   else result=await service.batchFinish({user,token:b.token,signature:b.signature});
   // A finish linearizes at its guarded commit; others require the session to still be live after the work.
   if(!op.endsWith('finish')&&!await auth.authenticate(request))return json({error:'unauthorized'},401,NS);
   if(result?.error)return json({error:result.error},409,NS);
   return result?json(result,200,NS):json({error:'unavailable'},409,NS);
  }catch{return json({error:'unavailable'},503,NS);}
 }};
}
