import {json} from './sessions.js';

// Host composition, not an environment binding/key parser. The deployment
// entrypoint must provide approved configuration and authenticated metadata.
// Cache identity is explicit so two binding/key configurations never share a
// runtime accidentally. A failed initialization is removed, allowing recovery.
export function createHost({initialize,assets,origin}={}){
 if(typeof initialize!=='function')throw new TypeError('Runtime initializer required');
 const url=new URL(origin);if(url.protocol!=='https:'||url.origin!==origin)throw new TypeError('Exact HTTPS origin required');
 if(assets!==undefined&&typeof assets.fetch!=='function')throw new TypeError('Asset binding required');
 let pending;
 async function runtime(){
  if(!pending){const attempt=Promise.resolve().then(initialize);pending=attempt;attempt.catch(()=>{if(pending===attempt)pending=undefined;});}
  return pending;
 }
 return {
  async fetch(request){
   try{
    const url=new URL(request.url);if(url.origin!==origin)return json({error:'not_found'},404);
    // Reserved API/auth routes never fall through to an SPA or static asset.
    if(url.pathname==='/v1'||url.pathname.startsWith('/v1/')||url.pathname==='/auth'||url.pathname.startsWith('/auth/')||url.pathname==='/health')return await (await runtime()).fetch(request);
    if(!['GET','HEAD'].includes(request.method)||!assets)return json({error:'not_found'},404);
    return await assets.fetch(request);
   }catch{return json({error:'unavailable'},503);}
  },
  async scheduled(){await (await runtime()).cleanup();}
 };
}
