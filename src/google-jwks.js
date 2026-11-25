// Google ID-token signing keys for native sign-in. Fetches the public JWKS over HTTPS, caches by the response max-age
// (bounded), and refetches at most once per minute for an unknown kid. Returns an RSA public JWK or undefined (fail closed).
const TIMEOUT=4000,URL_JWKS='https://www.googleapis.com/oauth2/v3/certs',MIN_TTL=60000,MAX_TTL=3600000,RETRY=60000;
export function createGoogleJwks({fetchImpl=(...a)=>globalThis.fetch(...a),clock=Date.now}={}){
 let keys=new Map(),expires=0,lastTry=-Infinity,inflight;
 async function load(){
  const now=clock();lastTry=now;
  // Bounded: one shared in-flight refresh, aborted after 4 s (headers and body), fail closed.
  const ac=new AbortController(),timer=setTimeout(()=>ac.abort(),TIMEOUT);
  let r,body;
  try{
   r=await fetchImpl(URL_JWKS,{headers:{Accept:'application/json'},signal:ac.signal});
   body=r&&r.ok?await Promise.race([r.json(),new Promise((_,rej)=>ac.signal.addEventListener('abort',()=>rej(new Error('timeout'))))]):undefined;
  }catch{r=undefined;}finally{clearTimeout(timer);}
  const fail=()=>{if(now>=expires)keys=new Map();};// never serve expired keys when the refresh fails
  if(!r||!r.ok||body===undefined)return fail();
  const next=new Map();
  if(!body||!Array.isArray(body.keys)||body.keys.length>16)return fail();
  for(const k of body.keys)if(k&&k.kty==='RSA'&&typeof k.kid==='string'&&k.kid.length<=128&&typeof k.n==='string'&&typeof k.e==='string'&&(k.alg===undefined||k.alg==='RS256')&&(k.use===undefined||k.use==='sig'))next.set(k.kid,{kty:'RSA',n:k.n,e:k.e,alg:'RS256',use:'sig'});
  if(!next.size)return fail();
  const m=/max-age=(\d+)/.exec(r.headers?.get?.('cache-control')??''),ttl=Math.min(MAX_TTL,Math.max(MIN_TTL,m?Number(m[1])*1000:MIN_TTL));
  keys=next;expires=now+ttl;
 }
 return async kid=>{
  try{
   if(typeof kid!=='string'||!kid||kid.length>128)return undefined;
   const now=clock();
   if(now>=expires||(!keys.has(kid)&&now-lastTry>=RETRY)){inflight??=load().catch(()=>{if(clock()>=expires)keys=new Map();}).finally(()=>{inflight=undefined;});await inflight;}
   return keys.get(kid);
  }catch{return undefined;}
 };
}
