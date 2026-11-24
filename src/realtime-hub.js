// Per-account Durable Object (hibernatable WebSockets). Inactive: no wrangler binding and no mounted
// route reaches it. It stores nothing: tickets live in D1, and a message never carries data.
// Reachable only through a Worker binding, so the x-hub-* headers below are set by this API, never by a client.
export const HUB_MESSAGE=JSON.stringify({v:1,t:'changed'});
export const MAX_SOCKETS=16,MAX_CLOSE_AHEAD_MS=10*60*1000;
const ID=/^[A-Za-z0-9_-]{8,64}$/;
export const CLOSE_REVOKED=4401,CLOSE_EXPIRED=4408,CLOSE_REPLACED=4429;
export class RealtimeHub {
 constructor(state,env,{now=Date.now,createPair=()=>new WebSocketPair(),upgrade=(client)=>new Response(null,{status:101,webSocket:client,headers:{'Sec-WebSocket-Protocol':'otpanda.v1'}})}={}){
  this.state=state;this.now=now;this.createPair=createPair;this.upgrade=upgrade;
  if(typeof state.setWebSocketAutoResponse==='function'&&typeof globalThis.WebSocketRequestResponsePair==='function')state.setWebSocketAutoResponse(new globalThis.WebSocketRequestResponsePair('ping','pong'));
 }
 async fetch(request){
  const url=new URL(request.url);
  if(request.method==='GET'&&url.pathname==='/connect')return this.#connect(request);
  if(request.method==='POST'&&url.pathname==='/notify')return this.#notify(request);
  return new Response(null,{status:404});
 }
 async #connect(request){
  const device=request.headers.get('x-hub-device'),closeAt=Number(request.headers.get('x-hub-close-at')),now=this.now();
  if(request.headers.get('upgrade')?.toLowerCase()!=='websocket')return new Response(null,{status:426});
  if(!ID.test(device??'')||!Number.isSafeInteger(closeAt)||closeAt<=now||closeAt>now+MAX_CLOSE_AHEAD_MS)return new Response(null,{status:400});
  // At the cap the oldest socket is replaced, so a refresh loop can never lock the user out.
  const open=this.state.getWebSockets().map(ws=>({ws,at:ws.deserializeAttachment()?.c??0})).sort((a,b)=>a.at-b.at);
  while(open.length>=MAX_SOCKETS){const {ws}=open.shift();try{ws.close(CLOSE_REPLACED,'replaced');}catch{}}
  const pair=this.createPair(),client=pair[0],server=pair[1];
  this.state.acceptWebSocket(server,['d:'+device]);
  server.serializeAttachment({d:device,c:closeAt});
  await this.#sweep();
  return this.upgrade(client);
 }
 async #notify(request){
  let body;try{body=await request.json();}catch{return new Response(null,{status:400});}
  if(body?.v!==1)return new Response(null,{status:400});
  if(body.t==='changed'){for(const ws of this.state.getWebSockets()){try{ws.send(HUB_MESSAGE);}catch{}}return new Response(null,{status:204});}
  if(body.t==='closeAll'){for(const ws of this.state.getWebSockets()){try{ws.close(CLOSE_REVOKED,'revoked');}catch{}}await this.#sweep();return new Response(null,{status:204});}
  if(body.t==='close'&&ID.test(body.deviceId??'')){for(const ws of this.state.getWebSockets('d:'+body.deviceId)){try{ws.close(CLOSE_REVOKED,'revoked');}catch{}}return new Response(null,{status:204});}
  return new Response(null,{status:400});
 }
 // Close what is due, then arm the alarm for the earliest FUTURE expiry only; with none left, clear it. A socket that is
 // closed but still listed always has an expiry in the past (or is skipped here), so the alarm can never re-arm in the past.
 async #sweep(){
  const now=this.now();let next;
  for(const ws of this.state.getWebSockets()){
   const c=ws.deserializeAttachment()?.c;
   if(!Number.isSafeInteger(c)||c<=now){try{ws.close(CLOSE_EXPIRED,'expired');}catch{}continue;}
   if(next===undefined||c<next)next=c;
  }
  if(next!==undefined)await this.state.storage.setAlarm(next);else await this.state.storage.deleteAlarm();
 }
 // The socket never outlives the access handle its ticket came from (the client re-tickets after renewal).
 async alarm(){await this.#sweep();}
 async webSocketMessage(ws){try{ws.close(1008,'unexpected');}catch{}}
 async webSocketClose(ws){try{ws.close(1000,'');}catch{}}
 async webSocketError(){}
}
export function hubDeliver(namespace){
 return async(accountId,message)=>{
  const response=await namespace.get(namespace.idFromName(accountId)).fetch('https://hub/notify',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(message)});
  return response.ok;
 };
}
export function hubConnect(namespace,{ownerId,deviceId,closeAt},request){
 return namespace.get(namespace.idFromName(ownerId)).fetch(new Request('https://hub/connect',{method:'GET',headers:{upgrade:request.headers.get('upgrade'),'x-hub-device':deviceId,'x-hub-close-at':String(closeAt)}}));
}
