import { json,takeRateLimit } from './sessions.js';
import { createEntryReadHandler } from './entry-tokens.js';
import { createEntryManagement } from './entry-management.js';

// The integrated entry application does not mount service-only foundation
// routes or accept provider events from public HTTP callers. Connectors must
// authenticate and normalize events before calling sources.receive internally.
export function createEntryApplication({db,sessions,sources,metadata,access,tokens,trustedRequestKey,clock=Date.now}){
 if(!db||!sessions||!access||!tokens||typeof trustedRequestKey!=='function')throw new TypeError('Complete entry dependencies required');
 const reads=createEntryReadHandler({tokens,access,clock});
 const management=createEntryManagement({db,sessions,sources,metadata,access,tokens,clock});
 return {async fetch(request){
  try{
   const url=new URL(request.url);
   if(url.origin!==sessions.origin)return json({error:'not_found'},404);
   const key=trustedRequestKey(request);
   if(typeof key!=='string'||!key||key.length>256)return json({error:'unavailable'},503);
   const rate=await takeRateLimit(db,'entry-request:'+key,{now:clock(),limit:60});
   if(!rate.allowed)return json({error:'rate_limited'},429,{'Retry-After':String(rate.retryAfter)});
   if(url.pathname==='/health'&&request.method==='GET')return json({status:'development-only'});
   if(url.pathname==='/v1/entries/code')return await reads.fetch(request);
   if(!url.pathname.startsWith('/v1/manage/'))return json({error:'not_found'},404);
   const auth=await sessions.authenticate(request,{mutation:request.method!=='GET'});
   if(!auth)return json({error:'unauthorized'},401);
   if(url.pathname==='/v1/manage/entries'&&request.method==='GET'){
    const rows=await db.prepare('SELECT e.entry_id,e.service_id,e.label,e.account_name,e.catalog_id,e.issuer,e.owner_id AS capability_owner,s.name AS service_name,s.icon_key FROM entries e JOIN services s ON s.service_id=e.service_id WHERE e.owner_id=?1 OR EXISTS (SELECT 1 FROM entry_shares m WHERE m.entry_id=e.entry_id AND m.recipient_id=?1 AND m.revoked_at IS NULL) ORDER BY e.entry_id LIMIT 100').bind(auth.ownerId).all();if(!await sessions.authenticate(request))return json({error:'unauthorized'},401);
    return json({entries:rows.results.map(({capability_owner,catalog_id,issuer,...entry})=>({...entry,...(catalog_id===null||catalog_id===undefined?{}:{catalogId:catalog_id}),...(issuer?{issuer}:{}),capabilities:{manage:capability_owner===auth.ownerId}}))});
   }
   if(url.pathname==='/v1/manage/unassigned-context'&&request.method==='GET'){
    const contexts=await sources.contextsForOwner(auth.ownerId,clock());
    if(!await sessions.authenticate(request))return json({error:'unauthorized'},401);
    return json({contexts:contexts.filter(c=>c.retainedUntil>clock())});
   }
   if(url.pathname==='/v1/manage/unassigned'&&request.method==='GET'){
    const records=await sources.unassignedForOwner(auth.ownerId,clock());
    if(!await sessions.authenticate(request))return json({error:'unauthorized'},401);
    return json({records:records.filter(record=>record.expiresAt>clock())});
   }
   if(url.pathname==='/v1/manage/active-codes'&&request.method==='GET'){
    const records=await access.activeRecent(auth.ownerId,clock());
    if(!await sessions.authenticate(request))return json({error:'unauthorized'},401);
    return json({records:records.filter(record=>record.receivedAt<=clock()&&record.expiresAt>clock())});
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
   return await management.fetch(request,auth);
  }catch{return json({error:'unavailable'},503);}
 },
 async cleanup(){
  const now=clock();
  // Fixed identifiers only. Bounded batches prevent expiry work from taking
  // unbounded time and make repeated housekeeping safe.
  for(const [table,column] of [['incoming_codes','expires_at'],['sessions','expires_at'],['oauth_transactions','expires_at'],['entry_tokens','expires_at'],['rate_buckets','resets_at']]){
   await db.prepare(`DELETE FROM ${table} WHERE rowid IN (SELECT rowid FROM ${table} WHERE ${column} <= ?1 LIMIT 100)`).bind(now).run();
  }
 }
 };
}
