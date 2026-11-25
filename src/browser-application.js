// Inactive composition of reviewed browser identity and signup boundaries.
// Never use this as a deployment entry until readiness is explicitly resolved.
// No legacy session/OIDC/account mutations or paused recovery code are mounted.
import{createIdentityRuntime}from'./identity-runtime.js';
import{json}from'./sessions.js';
import{createSignupHost}from'./signup-host.js';
const signupPaths=new Set(['/auth/signup/start','/auth/signup/email','/auth/signup/begin','/auth/signup/verify','/auth/native/signup/email','/auth/native/signup/begin','/auth/native/signup/finish']);
export function createBrowserApplication({db,keys,activeKeyId,resolveTrustedIngress,mail,edgeAddress,edgeGlobal,edgeVerifyAddress,edgeVerifyGlobal,clock=Date.now}={}){
 let identity;
 const identityPaths=new Set(['/auth/login/start','/auth/login/verify','/auth/login/complete','/auth/restore','/auth/exchange','/auth/renew','/auth/device/logout','/v1/manage/session','/v1/manage/entries','/v1/manage/active-codes','/v1/manage/unassigned','/v1/manage/sources','/v1/manage/organization','/v1/manage/organization-copy']);
 const getIdentity=()=>identity??=createIdentityRuntime({db,keys,activeKeyId,trustedRequestKey:resolveTrustedIngress,clock});
 const signup=createSignupHost({db,mail,edgeAddress,edgeGlobal,edgeVerifyAddress,edgeVerifyGlobal,resolveTrustedIngress,clock});
 return{async fetch(request,ctx){
  const url=new URL(request.url);
  if(url.origin!=='https://otpanda-api.abrahammurciano.workers.dev')return json({error:'not_found'},404);
  if(signupPaths.has(url.pathname))return signup.fetch(request,ctx);
  if(!identityPaths.has(url.pathname))return json({error:'not_found'},404);
  try{return await getIdentity().fetch(request);}catch{return json({error:'unavailable'},503);}
 },cleanup:()=>getIdentity().cleanup()};
}
