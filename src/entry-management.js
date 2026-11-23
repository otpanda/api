import {json,takeRateLimit} from './sessions.js';
async function bodyOf(request){
 if((request.headers.get('content-type')??'').split(';')[0].trim()!=='application/json')throw new TypeError('JSON required');
 if(!request.body)throw new TypeError('Body required');
 const reader=request.body.getReader();let size=0;const chunks=[];
 while(true){const {value,done}=await reader.read();if(done)break;size+=value.byteLength;if(size>4096){await reader.cancel();throw new RangeError('Body too large');}chunks.push(value);}
 const data=new Uint8Array(size);let offset=0;for(const part of chunks){data.set(part,offset);offset+=part.length;}
 const body=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(data));
 if(!body||typeof body!=='object'||Array.isArray(body))throw new TypeError('Object required');return body;
}
function fields(body,allowed,required=allowed){
 if(Object.keys(body).some(k=>!allowed.includes(k))||required.some(k=>!Object.hasOwn(body,k)))throw new TypeError('Unexpected fields');
}
function text(value,max=256){if(typeof value!=='string'||!value.trim()||value.length>max)throw new TypeError('Bounded text required');return value;}
// Only browser sessions may manage entries or mint automation tokens. Sharing
// invitations and source enrollment remain separate, deliberately unmounted.
export function createEntryManagement({db,sessions,sources,metadata,access,tokens,clock=Date.now}){
 return {async fetch(request,auth){
  const url=new URL(request.url),now=clock();
  const rate=await takeRateLimit(db,'entry-management:'+auth.ownerId,{now,limit:30});
  if(!rate.allowed)return json({error:'rate_limited'},429,{'Retry-After':String(rate.retryAfter)});
  if(url.pathname==='/v1/manage/session'&&request.method==='GET')return json({ownerId:auth.ownerId,expiresAt:auth.expiresAt});
  if(url.pathname==='/v1/manage/sources'&&request.method==='GET')return json({sources:await sources.sourcesForOwner(auth.ownerId)});
  const revoke=/^\/v1\/manage\/tokens\/([A-Za-z0-9_-]{12})$/.exec(url.pathname);
  if(revoke&&request.method==='DELETE'){await tokens.revoke(auth.ownerId,revoke[1],now);return json({ok:true});}
  if(!['POST','PATCH','DELETE'].includes(request.method))return json({error:'not_found'},404);
  let body;
  try{
   body=await bodyOf(request);
   // A session may expire while its body streams.
   if(!await sessions.authenticate(request,{mutation:true}))return json({error:'unauthorized'},401);
   if(url.pathname==='/v1/manage/entries'&&request.method==='POST'){
    fields(body,['serviceId','label','accountName'],['serviceId','label']);
    text(body.serviceId,128);text(body.label,120);if(body.accountName!==undefined&&body.accountName!==null)text(body.accountName,120);
    const entryId=await sources.createEntry(auth.ownerId,body.serviceId,body.label,now,{accountName:body.accountName??null});
    return json({entryId},201);
   }
   if(url.pathname==='/v1/manage/entries'&&request.method==='PATCH'){
    fields(body,['entryId','label']);text(body.entryId);text(body.label,120);
    return await access.updateEntry(auth.ownerId,body.entryId,body.label)?json({ok:true}):json({error:'not_found'},404);
   }
   if(url.pathname==='/v1/manage/entries'&&request.method==='DELETE'){
    fields(body,['entryId']);text(body.entryId);
    return await access.deleteEntry(auth.ownerId,body.entryId)?json({ok:true}):json({error:'not_found'},404);
   }
   if(url.pathname==='/v1/manage/tokens'&&request.method==='POST'){
    fields(body,['entryId','clientId','ttlMs']);text(body.entryId);
    const minted=await tokens.mint(auth.ownerId,body.entryId,body.clientId,body.ttlMs,now);
    return minted?json(minted,201):json({error:'forbidden'},403);
   }
   if(url.pathname==='/v1/manage/entry-account'&&request.method==='PATCH'){
    fields(body,['entryId','accountName']);text(body.entryId);if(body.accountName!==null)text(body.accountName,120);
    return await metadata.setEntryAccount(auth.ownerId,body.entryId,body.accountName)?json({ok:true}):json({error:'not_found'},404);
   }
   return json({error:'not_found'},404);
  }catch(error){if(error instanceof RangeError)return json({error:'request_too_large'},413);if(error instanceof TypeError||error instanceof SyntaxError)return json({error:'invalid_request'},400);throw error;}
 }};
}
