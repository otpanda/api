import {json,takeRateLimit} from './sessions.js';
import {createDeviceSessionAuth} from './device-session-auth.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io';
const cors={'Access-Control-Allow-Origin':APP,Vary:'Origin'};
async function bodyOf(request){
 if((request.headers.get('content-type')??'').split(';')[0].trim()!=='application/json'||!request.body)throw new TypeError();
 const reader=request.body.getReader(),parts=[];let size=0,done=false;
 try{while(true){const part=await reader.read();if(part.done){done=true;break;}size+=part.value.byteLength;if(size>131072)throw new RangeError();parts.push(part.value);}const bytes=new Uint8Array(size);let i=0;for(const p of parts){bytes.set(p,i);i+=p.byteLength;}const value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));if(!value||typeof value!=='object'||Array.isArray(value))throw new TypeError();return value;}finally{if(!done)await reader.cancel();reader.releaseLock();}
}
function fields(body,keys){if(Object.keys(body).length!==keys.length||keys.some(k=>!Object.hasOwn(body,k)))throw new TypeError();}
// Unmounted adapter. Only authenticated web access sessions, never automation
// tokens. No user identifier is accepted from the client. Preference mutations
// do not grant access or change shared entry metadata.
export function createPersonalOrganizationHttp({db,sessions,organization,clock=Date.now}={}){
 const auth=createDeviceSessionAuth({sessions});
 return {async fetch(request){
  const url=new URL(request.url);
  if(url.origin!==API||!['/v1/manage/organization','/v1/manage/organization-copy'].includes(url.pathname))return json({error:'not_found'},404);
  if(request.headers.get('origin')!==APP)return json({error:'forbidden'},403);
  const reply=(body,status=200,headers={})=>json(body,status,{...cors,...headers});
  if(url.search)return reply({error:'invalid_request'},400);
  const copy=url.pathname.endsWith('-copy');
  const methods=copy?['POST']:['GET','PUT'];
  if(request.method==='OPTIONS'){
   const headers=(request.headers.get('access-control-request-headers')??'').toLowerCase().split(',').map(v=>v.trim()).filter(Boolean);
   return methods.includes(request.headers.get('access-control-request-method'))&&headers.every(v=>['authorization','content-type'].includes(v))?new Response(null,{status:204,headers:{...cors,'Cache-Control':'no-store','Access-Control-Allow-Methods':methods.join(', '),'Access-Control-Allow-Headers':'Authorization, Content-Type'}}):reply({error:'forbidden'},403);
  }
  if(!methods.includes(request.method))return reply({error:'method_not_allowed'},405);
  const viewer=await auth.authenticate(request);if(!viewer)return reply({error:'unauthorized'},401);
  const rate=await takeRateLimit(db,'organization:'+viewer.ownerId,{now:clock(),limit:120});if(!rate.allowed)return reply({error:'rate_limited'},429,{'Retry-After':String(rate.retryAfter)});
  try{
   let result;
   if(request.method==='GET')result={...await organization.read(viewer.ownerId),ranking:await organization.ranking(viewer.ownerId)};
   else{
    const body=await bodyOf(request);
    const current=await auth.authenticate(request);if(!current||current.ownerId!==viewer.ownerId||current.deviceId!==viewer.deviceId||current.generation!==viewer.generation)return reply({error:'unauthorized'},401);
    if(copy){fields(body,['entryId','receiptId','createdAt']);result=await organization.recordSuccessfulCopy(viewer.ownerId,body,current);}
    else{fields(body,['revision','document']);result=await organization.replace(viewer.ownerId,body.revision,body.document,current);if(!result.ok)return reply({error:'conflict'},409);}
   }
   const current=await auth.authenticate(request);if(!current||current.ownerId!==viewer.ownerId||current.deviceId!==viewer.deviceId||current.generation!==viewer.generation)return reply({error:'unauthorized'},401);
   return reply(result);
  }catch(error){if(error instanceof RangeError)return reply({error:'request_too_large'},413);if(error instanceof TypeError||error instanceof SyntaxError)return reply({error:'invalid_request'},400);throw error;}
 }};
}
