// Test-only wrapper so the real RealtimeHub class runs in local workerd. Not a deployment entry.
import {RealtimeHub,hubConnect,hubDeliver} from '../src/realtime-hub.js';
export {RealtimeHub};
export default {async fetch(request,env){
 const url=new URL(request.url),acct=url.searchParams.get('a')??'acct_aaaa1111';
 if(url.pathname==='/connect')return hubConnect(env.HUB,{ownerId:acct,deviceId:url.searchParams.get('d'),closeAt:Number(url.searchParams.get('c'))},request);
 if(url.pathname==='/notify'){const ok=await hubDeliver(env.HUB)(acct,await request.json());return new Response(null,{status:ok?204:502});}
 return new Response('no',{status:404});
}};
