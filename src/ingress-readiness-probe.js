// TEMPORARY bootstrap-only probe. No IP/header/cf/binding values, logs, D1,
// provider messages, counters, cookies or CORS. Remove after live evidence.
import{canonicalClientAddress}from'./client-address.js';
import{resolveCloudflareDirectIngress}from'./cloudflare-ingress.js';
const API='https://otpanda-api.abrahammurciano.workers.dev';
export const INGRESS_PROBE_PATH='/setup-check/471ab8b4-f3c0-44e9-9ffb-dff4d6ab90ea';
function result(accepted){return new Response(accepted?'1':'0',{status:200,headers:{'Content-Type':'text/plain','Cache-Control':'no-store','Content-Length':'1','X-Content-Type-Options':'nosniff','Content-Security-Policy':"default-src 'none'",'Referrer-Policy':'no-referrer'}});}
export function createIngressReadinessProbe({fetchImpl=(...args)=>globalThis.fetch(...args)}={}){
 return{async fetch(request,env){
  const url=new URL(request.url),suffix=url.pathname.slice(INGRESS_PROBE_PATH.length);
  if(!url.pathname.startsWith(INGRESS_PROBE_PATH))return;
  if(env?.DEPLOYMENT_STAGE!=='bootstrap'||url.origin!==API||request.method!=='GET'||url.search||!['/direct','/subrequest'].includes(suffix))return new Response(null,{status:404,headers:{'Cache-Control':'no-store'}});
  if(suffix==='/direct'){const address=resolveCloudflareDirectIngress(request),expected=request.headers.get('X-Probe-Expect');return result(address!==undefined&&(expected===null||address===canonicalClientAddress(expected)));}
  // Same-account network Worker subrequest, not direct function invocation.
  // Forged nonsecret documentation IPs test whether the host trusts spoofing.
  try{const response=await fetchImpl(API+INGRESS_PROBE_PATH+'/direct',{headers:{'CF-Connecting-IP':'192.0.2.241','X-Real-IP':'192.0.2.242'},redirect:'manual',signal:AbortSignal.timeout(2000)});const text=await response.text();return response.status===200&&(text==='0'||text==='1')?result(text==='1'):new Response(null,{status:503,headers:{'Cache-Control':'no-store'}});}catch{return new Response(null,{status:503,headers:{'Cache-Control':'no-store'}});}
 }};
}
