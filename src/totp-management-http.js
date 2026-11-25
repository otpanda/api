// Owner-only create, never replace/export a seed. No raw body or secret logging.
import {PasskeyService} from './passkey-service.js';
import {hashText} from './sessions.js';
import {json,takeRateLimit} from './sessions.js';
import {createDeviceSessionAuth} from './device-session-auth.js';
import {parseTotpUri} from './totp-uri.js';
import {decodeBase32} from './totp.js';
import {base64urlEncode} from './tokens.js';
import {SESSION_METHOD_JOIN,SESSION_METHOD_ACTIVE} from './session-method.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',PATH='/v1/manage/totp';
const cors={'Access-Control-Allow-Origin':APP,Vary:'Origin'};
async function bodyOf(request){
 if(request.headers.get('content-type')!=='application/json')throw Error();
 const reader=request.body?.getReader();if(!reader)throw Error();let size=0,text='';const decoder=new TextDecoder('utf-8',{fatal:true});
 try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>24576){await reader.cancel();throw Error();}text+=decoder.decode(value,{stream:true});}return JSON.parse(text+decoder.decode());}finally{reader.releaseLock();}
}
export function createTotpManagementHttp({db,sessions,getSeedCipher,clock=Date.now,passkeys=new PasskeyService(db,{clock})}){
 const auth=createDeviceSessionAuth({sessions});
 return{async fetch(request,{clientAddress}={}){
  const u=new URL(request.url),reply=(v,status=200)=>json(v,status,cors);
  if(u.origin!==API||![PATH,PATH+'/begin'].includes(u.pathname)||u.search)return json({error:'not_found'},404);
  if(request.headers.get('origin')!==APP)return json({error:'forbidden'},403);
  if(request.method==='OPTIONS'){
   const h=(request.headers.get('access-control-request-headers')??'').toLowerCase().split(',').map(v=>v.trim()).filter(Boolean);
   return request.headers.get('access-control-request-method')==='POST'&&h.every(v=>['authorization','content-type'].includes(v))?new Response(null,{status:204,headers:{...cors,'Cache-Control':'no-store','Access-Control-Allow-Methods':'POST','Access-Control-Allow-Headers':'Authorization, Content-Type'}}):reply({error:'forbidden'},403);
  }
  if(request.method!=='POST')return reply({error:'method_not_allowed'},405);
  if(!clientAddress)return reply({error:'unavailable'},503);
  try{
   const rate=await takeRateLimit(db,'totp-create:'+clientAddress,{now:clock(),limit:15});if(!rate.allowed)return reply({error:'rate_limited'},429);
   const user=await auth.authenticate(request);if(!user)return reply({error:'unauthorized'},401);
   let value,secret,algorithm='SHA-1',digits=6,period=30;
   try{
    value=await bodyOf(request);
    if(!value||Array.isArray(value)||Object.keys(value).sort().join(',')!==(u.pathname.endsWith('/begin')?'account,label,secret':'account,label,response,secret,token')||typeof value.label!=='string'||!value.label.trim()||value.label.length>120||typeof value.account!=='string'||value.account.length>120||typeof value.secret!=='string'||value.secret.length>2048)throw Error();
    if(value.secret.startsWith('otpauth:')){const p=parseTotpUri(value.secret);secret=p.secretBytes();({algorithm,digits,period}=p);}
    else secret=decodeBase32(value.secret.replaceAll(' ','').replaceAll('-',''));
    if(secret.byteLength<10||secret.byteLength>128)throw Error();
   }catch{return reply({error:'invalid_request'},400);}
   const binding=JSON.stringify(['totp-create',user.deviceId,user.generation]);
   const action='totp-create:'+await hashText(JSON.stringify([value.label,value.account,base64urlEncode(secret),algorithm,digits,period]));
   if(u.pathname.endsWith('/begin')){
    secret.fill(0);value.secret='';
    if(!(await db.prepare('SELECT count(*) n FROM passkey_credentials WHERE owner_id=?1 AND revoked_at IS NULL').bind(user.ownerId).first()).n)return reply({error:'passkey_required'},409);
    const challenge=await passkeys.begin({purpose:'step-up',ownerId:user.ownerId,binding,action});
    return challenge?reply(challenge):reply({error:'reauthenticate'},403);
   }
   const proof=await passkeys.finishAuthentication({token:value.token,response:value.response,ownerId:user.ownerId,binding,action});
   if(!proof||proof.generation!==user.generation){secret.fill(0);return reply({error:'reauthenticate'},403);}
   const entryId=crypto.randomUUID(),cipher=await getSeedCipher();let envelope;
   try{envelope=await cipher.encrypt(JSON.stringify({secret:base64urlEncode(secret),algorithm,digits,period}),{ownerId:user.ownerId,entryId});}finally{secret.fill(0);value.secret='';}
   const current=await auth.authenticate(request);if(!current||current.ownerId!==user.ownerId||current.deviceId!==user.deviceId||current.generation!==user.generation)return reply({error:'unauthorized'},401);
   const now=clock();
   const rows=await db.batch([
    db.prepare("INSERT OR IGNORE INTO services(service_id,name) VALUES ('custom-totp','Authenticator')"),
    db.prepare(`INSERT INTO entries(entry_id,owner_id,service_id,label,created_at,account_name) SELECT ?1,?2,?3,?4,?5,?6 WHERE ?9>?5 AND EXISTS(SELECT 1 FROM device_sessions d ${SESSION_METHOD_JOIN} JOIN account_security s ON s.owner_id=d.owner_id WHERE d.device_id=?7 AND d.owner_id=?2 AND d.generation=?8 AND s.generation=?8 AND d.revoked_at IS NULL AND d.expires_at>?5 AND ${SESSION_METHOD_ACTIVE.replaceAll('?3','?5')})`).bind(entryId,user.ownerId,'custom-totp',value.label.trim(),now,value.account.trim()||null,user.deviceId,user.generation,user.expiresAt),
    db.prepare('INSERT INTO totp_seeds(owner_id,entry_id,envelope,created_at,updated_at) SELECT ?1,?2,?3,?4,?4 WHERE EXISTS(SELECT 1 FROM entries WHERE owner_id=?1 AND entry_id=?2)').bind(user.ownerId,entryId,JSON.stringify(envelope),now),
   ]);
   // exact-count-ok: rows[2] inserts totp_seeds, which has no row-writing trigger.
   return rows[2]/*exact-count-ok: untriggered totp_seeds insert*/.meta.changes===1?reply({entryId},201):reply({error:'unauthorized'},401);
  }catch{return reply({error:'unavailable'},503);}
 }};
   }
