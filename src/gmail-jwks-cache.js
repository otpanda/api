// Shared Google public-key cache. No account data, tokens or message content is cached.
async function boundedJson(response){
 if(!response.ok)throw Error('keys unavailable');
 const reader=response.body?.getReader();if(!reader)throw Error('keys unavailable');
 let bytes=0,text='';const decoder=new TextDecoder('utf-8',{fatal:true});
 try{for(;;){const {done,value}=await reader.read();if(done)break;bytes+=value.byteLength;if(bytes>65536){await reader.cancel();throw Error('keys too large');}text+=decoder.decode(value,{stream:true});}const v=JSON.parse(text+decoder.decode());if(!Array.isArray(v.keys)||v.keys.length>16)throw Error('invalid keys');return v;}finally{reader.releaseLock();}
}
export function createGmailJwksCache({clock=Date.now}={}) {
 let cached,expires=0,inflight,cooldown=0;
 return async function keys(f){
  const now=clock();if(cached&&now<expires)return cached;if(inflight)return inflight;
  if(now<cooldown)throw Error('key retry cooldown');cooldown=now+60000;
  inflight=(async()=>{const v=await boundedJson(await f('https://www.googleapis.com/oauth2/v3/certs',{redirect:'error',signal:AbortSignal.timeout(5000)}));cached=v;expires=clock()+300000;return v;})();
  try{return await inflight;}finally{inflight=undefined;}
 };
}
