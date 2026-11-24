// Temporary synthetic platform qualification only. Never production entry.
import {RealtimeHub as ReviewedHub,hubConnect,hubDeliver} from '../../src/realtime-hub.js';
import {PersonalOrganizationStore} from '../../src/personal-organization.js';
import {drainOutbox,Budget} from '../../src/realtime-outbox.js';
const OWNER='qualification_owner', DEVICE='qualification_device';
export class QualificationHub extends ReviewedHub {
 constructor(...args){super(...args);this.instance=crypto.randomUUID();}
 async fetch(request){if(new URL(request.url).pathname==='/inspection')return Response.json({instance:this.instance,sockets:this.state.getWebSockets().length});return super.fetch(request);}
}
function counted(db){let count=0;const stmt=s=>new Proxy(s,{get(t,k){if(k==='target')return t;if(k==='bind')return(...a)=>stmt(t.bind(...a));if(['run','all','first','raw'].includes(k))return(...a)=>{count++;return t[k](...a);};const v=t[k];return typeof v==='function'?v.bind(t):v;}});return {count:()=>count,db:new Proxy(db,{get(t,k){if(k==='prepare')return q=>stmt(t.prepare(q));if(k==='batch')return list=>{count++;return t.batch(list.map(x=>x.target??x));};const v=t[k];return typeof v==='function'?v.bind(t):v;}})};}
export default {async fetch(request,env){
 const url=new URL(request.url);let response;
 const key=request.headers.get('authorization')?.replace(/^Bearer /,'')??request.headers.get('sec-websocket-protocol')?.split(',').map(x=>x.trim()).find(x=>x.startsWith('qualification.'))?.slice(14);
 if(!env.QUALIFICATION_KEY||key!==env.QUALIFICATION_KEY)return new Response(null,{status:404});
 try{
  if(url.pathname==='/connect')return hubConnect(env.HUB,{ownerId:OWNER,deviceId:DEVICE,closeAt:Date.now()+Number(url.searchParams.get('ttl')||60000)},request);
  if(url.pathname==='/inspection')return env.HUB.get(env.HUB.idFromName(OWNER)).fetch('https://hub/inspection');
  if(url.pathname==='/prepare'){
   const now=Date.now();await env.DB.batch([
    env.DB.prepare('INSERT OR IGNORE INTO accounts(owner_id,created_at) VALUES (?1,?2)').bind(OWNER,now),
    env.DB.prepare('INSERT OR REPLACE INTO realtime_activity(account_id,last_ticket_at) VALUES (?1,?2)').bind(OWNER,now)]);
   await env.DB.prepare('DELETE FROM realtime_outbox').run();response={ready:true};
  }else if(url.pathname==='/write'){
   const meter=counted(env.DB),store=new PersonalOrganizationStore(meter.db),old=await store.read(OWNER);
   const written=await store.replace(OWNER,old.revision,{tags:[{id:'synthetic',label:'Synthetic '+(old.revision+1)}],entries:[]});
   let hubCalls=0;const deliver=hubDeliver(env.HUB),before=meter.count();
   const drain=await drainOutbox({db:meter.db,deliver:async(...args)=>{hubCalls++;return deliver(...args);},budget:new Budget(20),sends:new Budget(10)});
   response={written,drain,d1Calls:meter.count(),drainD1:meter.count()-before,hubCalls,combined:meter.count()+hubCalls};
  }else if(url.pathname==='/close'){
   response={closed:await hubDeliver(env.HUB)(OWNER,{v:1,t:'close',deviceId:DEVICE})};
  }else if(url.pathname==='/health')response={synthetic:true};
  else return new Response(null,{status:404});
  console.log(JSON.stringify({qualification:true,path:url.pathname,result:response}));
  return Response.json(response);
 }catch(error){console.log(JSON.stringify({qualification:true,error:String(error)}));return Response.json({error:String(error)},{status:500});}
}};
