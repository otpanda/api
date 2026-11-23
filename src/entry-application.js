import { json,takeRateLimit } from './sessions.js';
import { createEntryReadHandler } from './entry-tokens.js';

// The integrated entry application does not mount service-only foundation
// routes or accept provider events from public HTTP callers. Connectors must
// authenticate and normalize events before calling sources.receive internally.
export function createEntryApplication({db,sessions,access,tokens,signIn,trustedRequestKey,clock=Date.now}){
 const reads=createEntryReadHandler({tokens,access,clock});
 return {async fetch(request){
  try{
   const url=new URL(request.url);
   if(url.origin!==sessions.origin)return json({error:'not_found'},404);
   const key=trustedRequestKey(request);
   if(typeof key!=='string'||!key||key.length>256)return json({error:'unavailable'},503);
   const rate=await takeRateLimit(db,'entry-request:'+key,{now:clock(),limit:60});
   if(!rate.allowed)return json({error:'rate_limited'},429,{'Retry-After':String(rate.retryAfter)});
   if(url.pathname==='/health'&&request.method==='GET')return json({status:'development-only'});
   if(url.pathname==='/auth/start')return await signIn.start(request);
   if(url.pathname==='/auth/callback')return await signIn.callback(request);
   if(url.pathname==='/v1/entries/code')return await reads.fetch(request);
   if(!url.pathname.startsWith('/v1/manage/'))return json({error:'not_found'},404);
   const auth=await sessions.authenticate(request,{mutation:request.method!=='GET'});
   if(!auth)return json({error:'unauthorized'},401);
   if(url.pathname==='/v1/manage/entries'&&request.method==='GET'){
    const rows=await db.prepare('SELECT e.entry_id,e.service_id,e.label,e.account_name,s.name AS service_name,s.icon_key FROM entries e JOIN services s ON s.service_id=e.service_id WHERE e.owner_id=?1 OR EXISTS (SELECT 1 FROM entry_shares m WHERE m.entry_id=e.entry_id AND m.recipient_id=?1 AND m.revoked_at IS NULL) ORDER BY e.entry_id LIMIT 100').bind(auth.ownerId).all();return json({entries:rows.results});
   }
   if(url.pathname==='/v1/manage/entry-code'&&request.method==='GET'){
    const record=await access.latest(auth.ownerId,url.searchParams.get('entry'),clock());
    if(!await sessions.authenticate(request))return json({error:'unauthorized'},401);
    return record?json(record):json({error:'not_found'},404);
   }
   if(url.pathname==='/v1/manage/tokens'&&request.method==='GET')return json({tokens:await tokens.list(auth.ownerId)});
   if(url.pathname==='/v1/manage/logout'&&request.method==='POST'){
    await sessions.revoke(auth.sessionId);const response=json({ok:true});sessions.clearCookies(response.headers);return response;
   }
   return json({error:'not_found'},404);
  }catch{return json({error:'unavailable'},503);}
 }};
}
