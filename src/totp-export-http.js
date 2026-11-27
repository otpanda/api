// Owner-only sealed TOTP export. Fresh UV passkey per attempt, bound to the exact frozen set (entry ids + seed versions), the
// device/generation and the client's ephemeral key. Seeds leave only sealed to that key; no plaintext fallback exists. No storage,
// no email or notice, no logging of bodies. Source only: not registered in any runtime until primary composes it.
//   POST /v1/manage/totp/export-begin   {ephemeralKey, entryIds?}                      -> {token, options, expiresAt, entries:[{entryId,version,label,account,issuer,catalogId}], unavailable:[entryId]}
//   POST /v1/manage/totp/export-finish  {ephemeralKey, entries:[{entryId,version}], token, response}
//                                       -> 200 {serverPublicKey, entries:[{entryId,version,label,account,issuer,algorithm,digits,period,nonce,ciphertext}]}
import {PasskeyService} from './passkey-service.js';
import {hashText,json,takeRateLimit} from './sessions.js';
import {createDeviceSessionAuth} from './device-session-auth.js';
import {importClientEphemeral,sealExport,sha256Hex} from './totp-export-seal.js';
import {SESSION_METHOD_JOIN,SESSION_METHOD_ACTIVE} from './session-method.js';
import {base64urlDecode} from './tokens.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',BASE='/v1/manage/totp/';
export const MAX_EXPORT_ENTRIES=200,MAX_BODY_BYTES=32768,HOUR=3600000;
const cors={'Access-Control-Allow-Origin':APP,Vary:'Origin'};
const ID=/^[A-Za-z0-9._-]{1,256}$/,VERSION=/^[0-9a-f]{64}$/;
async function bodyOf(request){
 if(request.headers.get('content-type')!=='application/json')throw Error();
 const reader=request.body?.getReader();if(!reader)throw Error();let size=0,text='';const decoder=new TextDecoder('utf-8',{fatal:true});
 try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>MAX_BODY_BYTES){await reader.cancel();throw Error();}text+=decoder.decode(value,{stream:true});}return JSON.parse(text+decoder.decode());}finally{reader.releaseLock();}
}
const exactKeys=(o,...sets)=>o&&typeof o==='object'&&!Array.isArray(o)&&sets.includes(Object.keys(o).sort().join(','));
const idList=v=>Array.isArray(v)&&v.length>=1&&v.length<=MAX_EXPORT_ENTRIES&&v.every(x=>typeof x==='string'&&ID.test(x))&&new Set(v).size===v.length;
// Digest input is the sorted frozen set. Seed versions are sha256 of the stored envelope, so any re-seed changes them.
const digestOf=(user,pairs,ephemeralDigest)=>hashText(JSON.stringify(['totp-export-v1',user.ownerId,user.deviceId,user.generation,pairs.map(p=>[p.entryId,p.version]),ephemeralDigest]));
export function createTotpExportHttp({db,sessions,getSeedCipher,clock=Date.now,native=false,seal=sealExport,passkeys=new PasskeyService(db,{clock})}){
 const auth=createDeviceSessionAuth({sessions,native});
 // Owner rows only: shared-in entries belong to another owner_id and never match. Sorted by entry id.
 const owned=async(ownerId,ids)=>{
  const where=ids?' AND e.entry_id IN (SELECT value FROM json_each(?2))':'';
  const rows=(await db.prepare(`SELECT e.entry_id,e.label,e.account_name,e.issuer,e.catalog_id,s.envelope FROM entries e LEFT JOIN totp_seeds s ON s.owner_id=e.owner_id AND s.entry_id=e.entry_id WHERE e.owner_id=?1${where} ORDER BY e.entry_id LIMIT 201`).bind(...(ids?[ownerId,JSON.stringify(ids)]:[ownerId])).all()).results;
  return rows;
 };
 return{async fetch(request,{clientAddress}={}){
  const u=new URL(request.url),reply=(v,status=200)=>json(v,status,{...cors,'Cache-Control':'no-store'});
  const step=u.pathname.startsWith(BASE)?u.pathname.slice(BASE.length):'';
  if(u.origin!==API||!['export-begin','export-finish'].includes(step)||u.search)return json({error:'not_found'},404);
  if(!auth.originAllowed(request))return json({error:'forbidden'},403);
  if(request.method==='OPTIONS'){
   const h=(request.headers.get('access-control-request-headers')??'').toLowerCase().split(',').map(v=>v.trim()).filter(Boolean);
   return request.headers.get('access-control-request-method')==='POST'&&h.every(v=>['authorization','content-type'].includes(v))?new Response(null,{status:204,headers:{...cors,'Cache-Control':'no-store','Access-Control-Allow-Methods':'POST','Access-Control-Allow-Headers':'Authorization, Content-Type'}}):reply({error:'forbidden'},403);
  }
  if(request.method!=='POST')return reply({error:'method_not_allowed'},405);
  if(!clientAddress)return reply({error:'unavailable'},503);
  try{
   const ip=await takeRateLimit(db,'totp-export-ip:'+clientAddress,{now:clock(),limit:20});if(!ip.allowed)return reply({error:'rate_limited'},429);
   const user=await auth.authenticate(request);if(!user)return reply({error:'unauthorized'},401);
   // A few attempts per owner per hour, counted on both steps so a stolen session cannot probe.
   const rate=await takeRateLimit(db,'totp-export-owner-'+step+':'+user.ownerId,{now:clock(),limit:6,windowMs:HOUR});if(!rate.allowed)return reply({error:'rate_limited'},429);
   let value,client,asked,pairs;
   try{
    value=await bodyOf(request);
    if(step==='export-begin'){
     if(!exactKeys(value,'ephemeralKey','entryIds,ephemeralKey'))throw Error();
     if(Object.hasOwn(value,'entryIds')){if(!idList(value.entryIds))throw Error();asked=[...value.entryIds];}
    }else{
     if(!exactKeys(value,'entries,ephemeralKey,response,token')||!Array.isArray(value.entries)||value.entries.length<1||value.entries.length>MAX_EXPORT_ENTRIES)throw Error();
     pairs=value.entries.map(e=>{if(!exactKeys(e,'entryId,version')||typeof e.entryId!=='string'||!ID.test(e.entryId)||typeof e.version!=='string'||!VERSION.test(e.version))throw Error();return{entryId:e.entryId,version:e.version};});
     if(new Set(pairs.map(p=>p.entryId)).size!==pairs.length||pairs.some((p,i)=>i&&pairs[i-1].entryId>=p.entryId))throw Error();// sorted, unique: one canonical frozen set
    }
    client=await importClientEphemeral(value.ephemeralKey);if(!client)throw Error();
   }catch{return reply({error:'invalid_request'},400);}
   const ephemeralDigest=await sha256Hex(client.raw);
   if(step==='export-begin'){
    if(!(await db.prepare('SELECT count(*) n FROM passkey_credentials WHERE owner_id=?1 AND revoked_at IS NULL').bind(user.ownerId).first()).n)return reply({error:'passkey_required'},409);
    const rows=await owned(user.ownerId,asked);
    if(asked&&rows.length!==asked.length)return reply({error:'invalid_request'},400);// a foreign, shared-in or missing id: same answer, nothing revealed
    if(rows.length>MAX_EXPORT_ENTRIES)return reply({error:'too_many',max:MAX_EXPORT_ENTRIES},413);
    const usable=rows.filter(r=>r.envelope),unavailable=rows.filter(r=>!r.envelope).map(r=>r.entry_id);
    if(asked&&unavailable.length)return reply({error:'invalid_request'},400);// an explicit selection must be fully exportable
    if(!usable.length)return reply({error:'nothing_to_export',unavailable},409);
    if(usable.length>MAX_EXPORT_ENTRIES)return reply({error:'too_many',count:usable.length,max:MAX_EXPORT_ENTRIES},413);
    const entries=[];for(const r of usable)entries.push({entryId:r.entry_id,version:await hashText(r.envelope),label:r.label,account:r.account_name,issuer:r.issuer,catalogId:r.catalog_id});
    const digest=await digestOf(user,entries,ephemeralDigest);
    const challenge=await passkeys.begin({purpose:'step-up',ownerId:user.ownerId,binding:JSON.stringify(['totp-export',user.ownerId,user.deviceId,user.generation,digest]),action:'totp-export:'+digest});
    return challenge?reply({...challenge,entries,unavailable}):reply({error:'reauthenticate'},403);
   }
   // finish: the set is exactly what the client echoes; it is re-resolved after the proof and must match to the version.
   const digest=await digestOf(user,pairs,ephemeralDigest);
   const proof=await passkeys.finishAuthentication({token:value.token,response:value.response,ownerId:user.ownerId,binding:JSON.stringify(['totp-export',user.ownerId,user.deviceId,user.generation,digest]),action:'totp-export:'+digest});
   if(!proof||proof.generation!==user.generation)return reply({error:'reauthenticate'},403);
   const rows=await owned(user.ownerId,pairs.map(p=>p.entryId));
   if(rows.length!==pairs.length)return reply({error:'changed'},409);
   const items=[],meta=[],cipher=await getSeedCipher();
   try{
    for(const [i,r] of rows.entries()){
     if(!r.envelope||r.entry_id!==pairs[i].entryId||await hashText(r.envelope)!==pairs[i].version)return reply({error:'changed'},409);// re-seeded or removed since begin: nothing sealed
     const p=JSON.parse(await cipher.decrypt(JSON.parse(r.envelope),{ownerId:user.ownerId,entryId:r.entry_id}));
     const secret=base64urlDecode(p.secret,Math.floor(String(p.secret).length*6/8));if(!secret)return reply({error:'unavailable'},503);
     if(secret.length<10||secret.length>128||!['SHA-1','SHA-256','SHA-512'].includes(p.algorithm)||![6,7,8].includes(p.digits)||!Number.isInteger(p.period)||p.period<1||p.period>86400){secret.fill(0);return reply({error:'unavailable'},503);}
     items.push({aad:{label:r.label,account:r.account_name,issuer:r.issuer,catalogId:r.catalog_id,ownerId:user.ownerId,deviceId:user.deviceId,generation:user.generation,entryId:r.entry_id,seedVersion:pairs[i].version,algorithm:p.algorithm,digits:p.digits,period:p.period},secret});
     meta.push({entryId:r.entry_id,version:pairs[i].version,label:r.label,account:r.account_name,issuer:r.issuer,catalogId:r.catalog_id,algorithm:p.algorithm,digits:p.digits,period:p.period});
    }
    // Session must still be live after the slow steps; revocation wins.
    const current=await auth.authenticate(request);
    if(!current||current.ownerId!==user.ownerId||current.deviceId!==user.deviceId||current.generation!==user.generation)return reply({error:'unauthorized'},401);
    const live=await db.prepare(`SELECT 1 ok FROM device_sessions d ${SESSION_METHOD_JOIN} JOIN account_security s ON s.owner_id=d.owner_id WHERE d.device_id=?1 AND d.owner_id=?2 AND d.generation=?3 AND s.generation=?3 AND d.revoked_at IS NULL AND d.expires_at>?4 AND ${SESSION_METHOD_ACTIVE}`).bind(user.deviceId,user.ownerId,user.generation,clock()).first();
    if(!live)return reply({error:'unauthorized'},401);
    const sealed=await seal({client,actionDigest:digest,ephemeralDigest,items});
    // Final linearization read after all asynchronous decryption and sealing.
    // One D1 statement checks method/session revocation and exact row snapshots.
    const expected=JSON.stringify(rows.map(r=>({id:r.entry_id,envelope:r.envelope,label:r.label,account:r.account_name,issuer:r.issuer,catalog:r.catalog_id})));
    const final=await db.prepare(`SELECT 1 ok FROM device_sessions d ${SESSION_METHOD_JOIN} JOIN account_security s ON s.owner_id=d.owner_id
      WHERE d.device_id=?1 AND d.owner_id=?2 AND d.generation=?3 AND s.generation=?3 AND d.revoked_at IS NULL AND d.expires_at>?4 AND ${SESSION_METHOD_ACTIVE}
      AND NOT EXISTS(SELECT 1 FROM json_each(?5) j WHERE NOT EXISTS(SELECT 1 FROM entries e JOIN totp_seeds t ON t.owner_id=e.owner_id AND t.entry_id=e.entry_id
        WHERE e.owner_id=?2 AND e.entry_id=json_extract(j.value,'$.id') AND t.envelope=json_extract(j.value,'$.envelope')
        AND e.label IS json_extract(j.value,'$.label') AND e.account_name IS json_extract(j.value,'$.account')
        AND e.issuer IS json_extract(j.value,'$.issuer') AND e.catalog_id IS json_extract(j.value,'$.catalog')))`)
      .bind(user.deviceId,user.ownerId,user.generation,clock(),expected).first();
    if(!final)return reply({error:'changed'},409);
    return reply({serverPublicKey:sealed.serverPublicKey,entries:meta.map((m,i)=>({...m,...sealed.entries[i]}))});
   }finally{for(const i of items)i.secret.fill(0);}
  }catch{return reply({error:'unavailable'},503);}
 }};
}
