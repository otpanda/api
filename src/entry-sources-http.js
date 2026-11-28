import {json,takeRateLimit} from './sessions.js';
import {createDeviceSessionAuth} from './device-session-auth.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',PATH='/v1/manage/entry/sources';
// GET /v1/manage/entry/sources: owner-only, read-only provenance of the viewer's OWN entries.
// For each entry it lists the sources that delivered a still-live (received, unexpired) code assigned to it, from incoming_codes.
// It reads only sources the owner holds unrevoked, only entries the viewer OWNS (a shared recipient gets nothing: owner_id join, no entry_shares).
// It never returns a code, envelope, sender, receiving address, event id or any recipient data, and it writes nothing (no assignment_rules).
// Provenance lasts only as long as the code row (24h at most, then cleanup deletes it): it is NOT a durable account-to-source link.
export function createEntrySourcesHttp({db,sessions,clock=Date.now,native=false}={}){
 if(!db)throw new TypeError('Database required');
 const auth=createDeviceSessionAuth({sessions,native});
 return {async fetch(request){
  const u=new URL(request.url),origin=request.headers.get('origin'),android=origin===null;
  if(u.origin!==API||u.pathname!==PATH)return json({error:'not_found'},404);
  if(origin!==APP&&!(native&&android))return json({error:'forbidden'},403);
  const cors=android?{}:{'Access-Control-Allow-Origin':APP,Vary:'Origin'},reply=(v,s=200,h={})=>json(v,s,{'Cache-Control':'no-store',...cors,...h});
  if(u.search)return reply({error:'invalid_request'},400);
  if(request.method==='OPTIONS'&&!android){
   const h=(request.headers.get('access-control-request-headers')??'').toLowerCase().split(',').map(v=>v.trim()).filter(Boolean);
   return request.headers.get('access-control-request-method')==='GET'&&h.every(v=>v==='authorization')?new Response(null,{status:204,headers:{...cors,'Access-Control-Allow-Methods':'GET','Access-Control-Allow-Headers':'Authorization','Cache-Control':'no-store'}}):reply({error:'forbidden'},403);
  }
  if(request.method!=='GET')return reply({error:'method_not_allowed'},405);
  const viewer=await auth.authenticate(request);if(!viewer)return reply({error:'unauthorized'},401);
  const now=clock(),rate=await takeRateLimit(db,'entry-sources:'+viewer.ownerId,{now,limit:60});if(!rate.allowed)return reply({error:'rate_limited'},429,{'Retry-After':String(rate.retryAfter)});
  let rows;
  try{rows=(await db.prepare("SELECT i.entry_id,i.source_id,s.kind,s.label,count(*) AS codes,max(i.received_at) AS latest,sum(i.assignment='confirmed') AS confirmed,sum(i.assignment='rule') AS by_rule FROM incoming_codes i JOIN sources s ON s.source_id=i.source_id AND s.owner_id=i.owner_id JOIN entries e ON e.entry_id=i.entry_id AND e.owner_id=i.owner_id WHERE i.owner_id=?1 AND i.entry_id IS NOT NULL AND i.assignment IN('confirmed','rule') AND s.revoked_at IS NULL AND i.received_at<=?2 AND i.expires_at>?2 GROUP BY i.entry_id,i.source_id ORDER BY i.entry_id,latest DESC LIMIT 200").bind(viewer.ownerId,now).all()).results;}
  catch{return reply({error:'unavailable'},503);}
  if(!await auth.authenticate(request))return reply({error:'unauthorized'},401);
  const byEntry=new Map();
  for(const r of rows){if(!byEntry.has(r.entry_id))byEntry.set(r.entry_id,[]);byEntry.get(r.entry_id).push({sourceId:r.source_id,kind:r.kind,label:r.label,activeCodeCount:r.codes,latestReceivedAt:r.latest,confirmedCount:r.confirmed,ruleCount:r.by_rule});}
  return reply({entries:[...byEntry].map(([entryId,sources])=>({entryId,sources}))});
 }};
}
