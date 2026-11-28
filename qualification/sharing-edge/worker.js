// ISOLATED fixture only. Never production. No real accounts or credentials.
import {createAuthOnlyWorker} from '../../src/auth-only-worker.js';
import {SourceEntryStore} from '../../src/source-entries.js';
import {CodeCipher} from '../../src/code-cipher.js';
import {importBrowserKeyring} from '../../src/browser-keyring.js';
import {DeviceSessionService} from '../../src/device-sessions.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io';
const yes={limit:async()=>({success:true})};
let app,state,measured,configured;
function configuration(env,db){const e={DEPLOYMENT_STAGE:'auth-only',AUTH_ONLY_SIGNUP_MODE:'public',SHARING_ENABLED:'1',DB:db,ACTIVE_KEY_ID:'synthetic',ENCRYPTION_KEYRING:JSON.stringify([{id:'synthetic',key:'CwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCws'}])};for(const k of ['IDENTITY_ADDRESS_LIMIT','IDENTITY_AUTH_GLOBAL_LIMIT','IDENTITY_READ_GLOBAL_LIMIT'])e[k]=yes;return e;}
function meter(db){let calls=0,read=0,written=0;const take=x=>{const m=x?.meta??{};read+=m.rows_read??0;written+=m.rows_written??0;return x;};const statement=s=>new Proxy(s,{get(t,k){if(k==='bind')return(...a)=>statement(t.bind(...a));if(['all','run','raw'].includes(k))return async(...a)=>{calls++;return take(await t[k](...a));};if(k==='first')return async(column)=>{calls++;const r=take(await t.all());const row=r.results?.[0]??null;return column&&row?row[column]:row;};const v=t[k];return typeof v==='function'?v.bind(t):v;}});return{db:{prepare:s=>statement(db.prepare(s)),batch:async ss=>{calls++;return(await db.batch(ss)).map(take);}},reset:()=>{calls=0;read=0;written=0;},result:()=>({d1ApiCalls:calls,rowsRead:read,rowsWritten:written})};}
async function invoke(env,path,body,token,query=''){
 const h={'CF-Connecting-IP':'192.0.2.1',Authorization:'Bearer '+token};if(!path.startsWith('/v1/machine/')){h.Origin=APP;h['Content-Type']='application/json';}
 const r=Object.assign(new Request(API+path+query,{method:body?'POST':'GET',headers:h,...(body?{body:JSON.stringify(body)}:{})}),{cf:{colo:'TLV',httpProtocol:'HTTP/2',tlsVersion:'TLSv1.3'}});
 app??=createAuthOnlyWorker();return app.fetch(r,env,{waitUntil:()=>{}});
}
export default{async fetch(request,env){
 const u=new URL(request.url),prefix='/'+env.FIXTURE_PREFIX;if(request.method!=='POST'||!u.pathname.startsWith(prefix+'/'))return new Response(null,{status:404});
 const action=u.pathname.slice(prefix.length+1);try{
 if(action==='setup'){
  if(state)return new Response(null,{status:409});const setupMeter=meter(env.DB);env={...env,DB:setupMeter.db};const now=Date.now();
  await env.DB.batch(['own','rec'].flatMap(a=>[env.DB.prepare('INSERT INTO accounts VALUES(?1,?2)').bind(a,now),env.DB.prepare('INSERT INTO account_security(owner_id,generation) VALUES(?1,0)').bind(a),env.DB.prepare("INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) VALUES(?1,?2,x'00',0,'[]','singleDevice',0,?3)").bind('c-'+a,a,now)]));
  // One bounded bulk insert, fixture initialization is not a measured product request.
  await env.DB.prepare("WITH RECURSIVE n(x) AS(VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<999) INSERT INTO entries(entry_id,owner_id,service_id,label,created_at) SELECT 'e'||x,'own','test','Synthetic',?1 FROM n").bind(now).run();
  const sessions=new DeviceSessionService(env.DB);state={};for(const a of ['own','rec']){state[a]=await sessions.issue({proof:{ownerId:a,credentialId:'c-'+a,generation:0,purpose:'authenticate',verifiedAt:Date.now()},clientKind:'web'});if(!state[a])throw Error();}state.profiles={};
  const keys=await importBrowserKeyring(configuration(env,env.DB)),sources=new SourceEntryStore(env.DB,new CodeCipher(keys));
  const source=await sources.createSource('own','gmail','Synthetic',now);await sources.receive('own',{sourceId:source,eventId:'fixture',code:'123456',receivedAt:now,expiresAt:now+300000});await sources.confirm('own',source,'fixture','e0',now);
  return Response.json({synthetic:true,accounts:2,entries:1000,...setupMeter.result()});
 }
 if(!state)return new Response(null,{status:409});measured??=meter(env.DB);configured??=configuration(env,measured.db);measured.reset();const m=measured,e=configured;let r;
 if(['allow','deny','all'].includes(action)){
  r=await invoke(e,'/v1/manage/machine/profile/create',{name:'Synthetic',mode:action,entryIds:action==='all'?[]:Array.from({length:99},(_,i)=>'e'+i)},state.own.access);if(r.status===200)state.profiles[action]=(await r.json()).profileId;
 }else if(action==='token'){
  r=await invoke(e,'/v1/manage/machine/token/create',{profileId:state.profiles.allow,ttlSeconds:300},state.own.access);if(r.status===200){const b=await r.json();state.machine=b.token;state.tokenId=b.tokenId;}
 }else if(action==='machine'||action==='revoked-machine')r=await invoke(e,'/v1/machine/code',null,state.machine,'?entry=e0&source=all');
 else if(action==='revoke')r=await invoke(e,'/v1/manage/machine/token/revoke',{profileId:state.profiles.allow,tokenId:state.tokenId},state.own.access);
 else if(action==='session')r=await invoke(e,'/v1/manage/session',null,state.own.access);
 else return new Response(null,{status:404});
 const status=r.status;let codeOk=true;if(action==='machine'&&status===200){const b=await r.json();codeOk=b.codes?.email?.code==='123456';}else if(!r.bodyUsed)await r.body?.cancel();const expected=action==='revoked-machine'?401:200;const result={synthetic:true,action,status,pass:status===expected&&codeOk,...m.result()};return Response.json(result);
 }catch{return Response.json({synthetic:true,action,pass:false,error:'fixture_failure'},{status:500});}
}};
