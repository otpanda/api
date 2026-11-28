// Owner-only whole-batch TOTP import. One passkey step-up covers the exact reviewed batch; the commit is ONE
// transaction (all entries and seeds, or none). Never replaces or exports a seed. No raw body or secret logging.
// Protocol2 handler, reached only by explicit protocol dispatch; feature remains default off.
//   POST /v1/manage/totp/batch-begin    {items, batchNonce}                  -> challenge, or the stored result for a repeated nonce
//   POST /v1/manage/totp/batch-finish   {items, batchNonce, token, response} -> 201 {entryIds}
//   POST /v1/manage/totp/batch-outcome  {batchNonce}                         -> {status:'saved',entryIds}|{status:'none'}
import {PasskeyService} from './passkey-service.js';
import {hashText,json,takeRateLimit} from './sessions.js';
import {createDeviceSessionAuth} from './device-session-auth.js';
import {parseTotpUri} from './totp-uri.js';
import {decodeBase32} from './totp.js';
import {base64urlEncode} from './tokens.js';
import {SESSION_METHOD_JOIN,SESSION_METHOD_ACTIVE} from './session-method.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',BASE='/v1/manage/totp/';
export const MAX_BATCH_ITEMS=50,MAX_BODY_BYTES=65536;
const CATALOG_ID=/^[a-z0-9][a-z0-9._-]{0,127}$/,NONCE=/^v2:[A-Za-z0-9_-]{22,61}$/;
const cors={'Access-Control-Allow-Origin':APP,Vary:'Origin'};
async function bodyOf(request){
 if(request.headers.get('content-type')!=='application/json')throw Error();
 const reader=request.body?.getReader();if(!reader)throw Error();let size=0,text='';const decoder=new TextDecoder('utf-8',{fatal:true});
 try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>MAX_BODY_BYTES){await reader.cancel();throw Error();}text+=decoder.decode(value,{stream:true});}return JSON.parse(text+decoder.decode());}finally{reader.releaseLock();}
}
const exactKeys=(o,...sets)=>o&&typeof o==='object'&&!Array.isArray(o)&&sets.includes(Object.keys(o).sort().join(','));
// Same per-item rules as the single add (totp-management-http.js). Returns the parsed item or throws.
function parseItem(v){
 if(!exactKeys(v,'account,label,secret','account,catalogId,label,secret'))throw Error();
 if(Object.hasOwn(v,'catalogId')&&(typeof v.catalogId!=='string'||!CATALOG_ID.test(v.catalogId)))throw Error();
 if(typeof v.label!=='string'||!v.label.trim()||v.label.length>120||typeof v.account!=='string'||v.account.length>120||typeof v.secret!=='string'||v.secret.length>2048)throw Error();
 let secret,algorithm='SHA-1',digits=6,period=30,issuer=null;
 if(v.secret.startsWith('otpauth:')){const p=parseTotpUri(v.secret);secret=p.secretBytes();({algorithm,digits,period}=p);issuer=typeof p.issuer==='string'&&p.issuer.trim()&&p.issuer.length<=254?p.issuer:null;}
 else secret=decodeBase32(v.secret.replaceAll(' ','').replaceAll('-',''));
 if(secret.byteLength<10||secret.byteLength>128){secret.fill(0);throw Error();}
 return{label:v.label.trim(),account:v.account.trim()||null,catalogId:Object.hasOwn(v,'catalogId')?v.catalogId:null,secret,algorithm,digits,period,issuer};
}
const wipe=items=>{for(const i of items??[])i.secret?.fill(0);};
// Digest input: secrets enter only as hashes. The nonce is inside, so the token is bound to this one attempt.
async function digestOf(user,nonce,raw){
 const rows=[];for(const v of raw)rows.push([v.label.trim(),v.account.trim(),Object.hasOwn(v,'catalogId')?v.catalogId:null,await hashText(v.secret)]);
 return hashText(JSON.stringify(['totp-batch-import-v1',user.ownerId,user.deviceId,user.generation,nonce,rows]));
}
export function createTotpBatchImportV2Http({db,sessions,getSeedCipher,clock=Date.now,native=false,passkeys=new PasskeyService(db,{clock})}){
 const auth=createDeviceSessionAuth({sessions,native});
 const stored=async(ownerId,nonce)=>db.prepare('SELECT action_digest,entry_ids,import_admission_id,import_device_id FROM totp_batch_imports WHERE owner_id=?1 AND batch_nonce=?2').bind(ownerId,nonce).first();
 return{async fetch(request,{clientAddress}={}){
  const u=new URL(request.url),reply=(v,status=200)=>json(v,status,{...cors,'Cache-Control':'no-store'});
  const step=u.pathname.startsWith(BASE)?u.pathname.slice(BASE.length):'';
  if(u.origin!==API||!['batch-begin','batch-finish','batch-outcome'].includes(step)||u.search)return json({error:'not_found'},404);
  if(!auth.originAllowed(request))return json({error:'forbidden'},403);
  if(request.method==='OPTIONS'){
   const h=(request.headers.get('access-control-request-headers')??'').toLowerCase().split(',').map(v=>v.trim()).filter(Boolean);
   return request.headers.get('access-control-request-method')==='POST'&&h.every(v=>['authorization','content-type'].includes(v))?new Response(null,{status:204,headers:{...cors,'Cache-Control':'no-store','Access-Control-Allow-Methods':'POST','Access-Control-Allow-Headers':'Authorization, Content-Type'}}):reply({error:'forbidden'},403);
  }
  if(request.method!=='POST')return reply({error:'method_not_allowed'},405);
  if(!clientAddress)return reply({error:'unavailable'},503);
  let items=[];
  try{
   // Parent dispatcher already enforces the route address rate limit.
   const user=await auth.authenticate(request);if(!user)return reply({error:'unauthorized'},401);
   let value,digest;
   try{
    value=await bodyOf(request);
    if(step==='batch-outcome'){if(!exactKeys(value,'admissionId,batchNonce,fence,protocol')||value.protocol!==2||value.fence!==true||typeof value.admissionId!=='string'||!/^[-A-Za-z0-9_]{22,64}$/.test(value.admissionId)||typeof value.batchNonce!=='string'||!NONCE.test(value.batchNonce))throw Error();}
    else{
     if(!exactKeys(value,step==='batch-begin'?'batchNonce,items,protocol':'admissionId,batchNonce,items,protocol,response,token')||value.protocol!==2||typeof value.batchNonce!=='string'||!NONCE.test(value.batchNonce)||!Array.isArray(value.items)||value.items.length<1||value.items.length>MAX_BATCH_ITEMS)throw Error();
     for(const v of value.items)items.push(parseItem(v));// any invalid item rejects the whole batch; no index or secret is echoed
     digest=await digestOf(user,value.batchNonce,value.items);
    }
   }catch{wipe(items);return reply({error:'invalid_request'},400);}
   if(step==='batch-outcome'){
    // Never allocate recovery storage. Absent admission is terminal for THIS
    // identity only; a later begin gets a new, proof-bound admission identity.
    const known=await db.prepare('SELECT * FROM totp_import_admissions WHERE admission_id=?1').bind(value.admissionId).first();
    const active=await db.prepare('SELECT admission_id FROM totp_import_admissions WHERE owner_id=?1 AND batch_nonce=?2 AND expires_at>unixepoch()*1000').bind(user.ownerId,value.batchNonce).first();
    if(!known&&active&&active.admission_id!==value.admissionId)return reply({error:'different_admission_active'},409);
    if(known&&(known.owner_id!==user.ownerId||known.device_id!==user.deviceId||known.batch_nonce!==value.batchNonce))return reply({error:'identity_mismatch'},409);
    await db.prepare('UPDATE totp_import_admissions SET fenced=1 WHERE owner_id=?1 AND admission_id=?2 AND device_id=?3 AND batch_nonce=?4').bind(user.ownerId,value.admissionId,user.deviceId,value.batchNonce).run();
    const row=await stored(user.ownerId,value.batchNonce);
    if(row&&known&&row.action_digest!==known.digest)return reply({status:'fenced'});
    if(row&&!known&&(row.import_admission_id!==value.admissionId||row.import_device_id!==user.deviceId))return reply({error:'identity_conflict'},409);
    return row?reply({status:'saved',entryIds:JSON.parse(row.entry_ids)}):reply({status:'fenced'});
   }
   // Repeated nonce: the same batch already committed (return it, no new prompt) or the nonce belongs to a different batch.
   const prior=await stored(user.ownerId,value.batchNonce);
   if(prior){wipe(items);return prior.action_digest===digest?reply({status:'saved',protocol:2,admissionId:prior.import_admission_id,entryIds:JSON.parse(prior.entry_ids)}):reply({error:'nonce_reused'},409);}
   let admission;
   if(step==='batch-begin'){
    if(!(await db.prepare('SELECT count(*) n FROM passkey_credentials WHERE owner_id=?1 AND revoked_at IS NULL').bind(user.ownerId).first()).n){wipe(items);return reply({error:'passkey_required'},409);}
    // Bounded sweep, then atomic cap+insert. Even fenced rows count until
    // removed, so recovery calls cannot bypass storage limits.
    await db.prepare("DELETE FROM totp_import_admissions WHERE admission_id IN (SELECT admission_id FROM totp_import_admissions WHERE expires_at <= unixepoch()*1000 LIMIT 256)").run();
    const id=base64urlEncode(crypto.getRandomValues(new Uint8Array(24)));
    await db.prepare(`INSERT OR IGNORE INTO totp_import_admissions(owner_id,admission_id,batch_nonce,device_id,generation,digest,expires_at,fenced) SELECT ?1,?2,?3,?4,?5,?6,unixepoch()*1000+120000,0 WHERE (SELECT count(*) FROM totp_import_admissions WHERE owner_id=?1)<4 AND (SELECT count(*) FROM totp_import_admissions)<256`).bind(user.ownerId,id,value.batchNonce,user.deviceId,user.generation,digest).run();
    admission=await db.prepare('SELECT * FROM totp_import_admissions WHERE owner_id=?1 AND batch_nonce=?2').bind(user.ownerId,value.batchNonce).first();
    if(admission&&(admission.digest!==digest||admission.device_id!==user.deviceId||admission.generation!==user.generation)){wipe(items);return reply({error:'nonce_reused'},409);}
    if(admission?.fenced){wipe(items);return reply({error:'fenced'},409);}
    if(!admission){wipe(items);return reply({error:'import_capacity'},429);}
   }else{
    if(typeof value.admissionId!=='string'||!/^[-A-Za-z0-9_]{22,64}$/.test(value.admissionId)){wipe(items);return reply({error:'invalid_request'},400);}
    admission=await db.prepare('SELECT * FROM totp_import_admissions WHERE owner_id=?1 AND admission_id=?2 AND batch_nonce=?3 AND device_id=?4 AND generation=?5 AND digest=?6 AND fenced=0 AND expires_at>unixepoch()*1000').bind(user.ownerId,value.admissionId,value.batchNonce,user.deviceId,user.generation,digest).first();
    if(!admission){wipe(items);return reply({error:'fenced'},409);}
   }
   const binding=JSON.stringify(['totp-batch-import-v2',user.ownerId,user.deviceId,user.generation,digest,admission.admission_id,admission.expires_at]),action='totp-batch-import-v2:'+digest+':'+admission.admission_id;
   if(step==='batch-begin'){
    wipe(items);items=[];
    const challenge=await passkeys.begin({purpose:'step-up',ownerId:user.ownerId,binding,action});
    return challenge?reply({...challenge,protocol:2,admissionId:admission.admission_id}):reply({error:'reauthenticate'},403);
   }
   const proof=await passkeys.finishAuthentication({token:value.token,response:value.response,ownerId:user.ownerId,binding,action});
   if(!proof||proof.generation!==user.generation){wipe(items);return reply({error:'reauthenticate'},403);}
   const cipher=await getSeedCipher(),ids=[],rows=[];
   try{
    for(const i of items){const id=crypto.randomUUID();ids.push(id);rows.push({id,label:i.label,account:i.account,catalog:i.catalogId,issuer:i.issuer,algorithm:i.algorithm,digits:i.digits,period:i.period,seedBytes:i.secret.byteLength,envelope:JSON.stringify(await cipher.encrypt(JSON.stringify({secret:base64urlEncode(i.secret),algorithm:i.algorithm,digits:i.digits,period:i.period}),{ownerId:user.ownerId,entryId:id}))});}
   }finally{wipe(items);items=[];}
   const payload=JSON.stringify(rows);
   if(payload.length>90000)return reply({error:'invalid_request'},400);// D1 statement size; the 50-item cap keeps real batches far below
   const current=await auth.authenticate(request);if(!current||current.ownerId!==user.ownerId||current.deviceId!==user.deviceId||current.generation!==user.generation)return reply({error:'unauthorized'},401);
   const now=clock(),idsJson=JSON.stringify(ids);
   try{
    await db.batch([
     db.prepare("INSERT OR IGNORE INTO services(service_id,name) VALUES ('custom-totp','Authenticator')"),
     // Session still live and this nonce unused, else CHECK fails and the transaction rolls back.
     db.prepare(`INSERT INTO tx_assert SELECT CASE WHEN ?4>unixepoch()*1000 AND EXISTS(SELECT 1 FROM device_sessions d ${SESSION_METHOD_JOIN} JOIN account_security s ON s.owner_id=d.owner_id WHERE d.device_id=?1 AND d.owner_id=?2 AND d.generation=?5 AND s.generation=?5 AND d.revoked_at IS NULL AND d.expires_at>unixepoch()*1000 AND ${SESSION_METHOD_ACTIVE}) AND EXISTS(SELECT 1 FROM totp_import_admissions WHERE owner_id=?2 AND admission_id=?6 AND batch_nonce=?7 AND device_id=?1 AND generation=?5 AND digest=?8 AND fenced=0 AND expires_at>unixepoch()*1000) THEN 1 ELSE 0 END`).bind(user.deviceId,user.ownerId,now,user.expiresAt,user.generation,admission.admission_id,value.batchNonce,digest),
     db.prepare('INSERT INTO totp_batch_imports(owner_id,batch_nonce,action_digest,entry_ids,created_at,import_admission_id,import_device_id) VALUES (?1,?2,?3,?4,?5,?6,?7)').bind(user.ownerId,value.batchNonce,digest,idsJson,now,admission.admission_id,user.deviceId),
     db.prepare("INSERT INTO entries(entry_id,owner_id,service_id,label,created_at,account_name,catalog_id,issuer) SELECT json_extract(value,'$.id'),?1,'custom-totp',json_extract(value,'$.label'),?2,json_extract(value,'$.account'),json_extract(value,'$.catalog'),json_extract(value,'$.issuer') FROM json_each(?3)").bind(user.ownerId,now,payload),
     db.prepare("INSERT INTO totp_seeds(owner_id,entry_id,envelope,created_at,updated_at,algorithm,digits,period,seed_bytes) SELECT ?1,json_extract(value,'$.id'),json_extract(value,'$.envelope'),?2,?2,json_extract(value,'$.algorithm'),json_extract(value,'$.digits'),json_extract(value,'$.period'),json_extract(value,'$.seedBytes') FROM json_each(?3)").bind(user.ownerId,now,payload),
     // Trigger-independent proof that every entry and seed landed; failure rolls the whole batch back.
     db.prepare('INSERT INTO tx_assert SELECT CASE WHEN (SELECT count(*) FROM entries WHERE owner_id=?1 AND entry_id IN (SELECT value FROM json_each(?2)))=?3 AND (SELECT count(*) FROM totp_seeds WHERE owner_id=?1 AND entry_id IN (SELECT value FROM json_each(?2)))=?3 THEN 1 ELSE 0 END').bind(user.ownerId,idsJson,ids.length),
    ]);
   }catch(error){
    const message=String(error?.message??error);
    if(/UNIQUE constraint failed: totp_batch_imports/i.test(message)){const row=await stored(user.ownerId,value.batchNonce);return row&&row.action_digest===digest?reply({status:'saved',entryIds:JSON.parse(row.entry_ids)}):reply({error:'nonce_reused'},409);}
    if(/CHECK constraint failed/i.test(message))return reply({error:'fenced'},409);
    throw error;
   }
   return reply({status:'saved',entryIds:ids},201);
  }catch{wipe(items);return reply({error:'unavailable'},503);}
 }};
}
