// UNMOUNTED host adapter. The host must establish trusted direct ingress and
// provision separate approximate edge budgets. Injected tests are not proof of
// actual provider provenance, free-plan bindings or production observability.
import{createSignupPreparationRuntime}from'./signup-preparation-runtime.js';
import{createSignupMailDelivery}from'./signup-mail-transport.js';
import{canonicalClientAddress}from'./client-address.js';
import{hashText,json,securityHeaders}from'./sessions.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io';
const paths=new Set(['/auth/signup/app','/auth/signup/start','/auth/signup/email','/auth/signup/begin','/auth/signup/verify']);
const cors={'Access-Control-Allow-Origin':APP,Vary:'Origin'};
function failure(verify,status){const headers={...securityHeaders,'Retry-After':'60',...(verify?cors:{})};return verify?json({error:status===429?'busy':'unavailable'},status,headers):new Response('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>OTPanda signup</title><main><h1>Signup is busy.</h1><p>No new request was accepted. Wait a moment, then return to the signup form in this browser and try again.</p></main></html>',{status,headers:{...headers,'Content-Type':'text/html; charset=utf-8','Content-Security-Policy':"default-src 'none'; frame-ancestors 'none'; base-uri 'none'"}});}
export function createSignupHost({db,mail,edgeAddress,edgeGlobal,edgeVerifyAddress,edgeVerifyGlobal,resolveTrustedIngress,clock=Date.now,signupAllowed}={}){
 let runtime;
 return{async fetch(request,ctx){
  const url=new URL(request.url);if(url.origin!==API||!paths.has(url.pathname))return json({error:'not_found'},404);
  const verify=url.pathname==='/auth/signup/verify';
  const failed=(status)=>url.pathname==='/auth/signup/app'?new Response(null,{status:303,headers:{...securityHeaders,Location:'https://otpanda.github.io/app/#'+new URLSearchParams({auth:'retry',state:/^[A-Za-z0-9_-]{43}$/.test(url.searchParams.get('state'))?url.searchParams.get('state'):''})}}):failure(verify,status);
  // Preflight uses no ingress resolver, edge counter, runtime or D1 write.
  if(verify&&request.method==='OPTIONS'){
   const headers=request.headers.get('access-control-request-headers')?.toLowerCase().split(',').map(h=>h.trim())??[];
   return request.headers.get('origin')===APP&&request.headers.get('access-control-request-method')==='POST'&&headers.every(h=>h==='content-type')?new Response(null,{status:204,headers:{...securityHeaders,...cors,'Access-Control-Allow-Methods':'POST','Access-Control-Allow-Headers':'Content-Type'}}):json({error:'invalid_request'},403,{...cors});
  }
  try{
   const individual=verify?edgeVerifyAddress:edgeAddress,global=verify?edgeVerifyGlobal:edgeGlobal;
   if(!db||typeof ctx?.waitUntil!=='function'||typeof resolveTrustedIngress!=='function'||typeof individual?.limit!=='function'||typeof global?.limit!=='function')return failed(503);
   const address=canonicalClientAddress(await resolveTrustedIngress(request));if(!address)return failed(503);
   // Denied addresses never consume shared capacity. Verify has its own
   // counters so mail floods cannot spend the credential-verification budget.
   if((await individual.limit({key:await hashText((verify?'verify:':'signup:')+address)}))?.success!==true)return failed(429);
   if((await global.limit({key:verify?'otpanda-signup-verify-v1':'otpanda-signup-v1'}))?.success!==true)return failed(429);
   runtime??=createSignupPreparationRuntime({db,deliver:createSignupMailDelivery(mail),clock,signupAllowed});
   return await runtime.fetch(request,{clientAddress:address,waitUntil:p=>ctx.waitUntil(p)});
  }catch{return failed(503);}
 }};
}
