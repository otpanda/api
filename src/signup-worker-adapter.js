// UNMOUNTED module-shaped integration. One host per deployed module/isolate
// keeps four deferred slots per isolate, not a global concurrency cap.
// The slots are shared across requests, not reset
// for each fetch. Context is per-request and never mistaken for environment.
import{createSignupHost}from'./signup-host.js';
export function createSignupWorkerAdapter({resolveTrustedIngress,fetchImpl=(...args)=>globalThis.fetch(...args),clock=Date.now,signupAllowed}={}){
 let host,configuration;
 return{async fetch(request,env,ctx){
  const url=new URL(request.url);
  if(url.origin!=='https://otpanda-api.abrahammurciano.workers.dev'||!['/auth/signup/start','/auth/signup/email','/auth/signup/begin','/auth/signup/verify'].includes(url.pathname))return createSignupHost().fetch(request,ctx);
  if(!env||typeof env!=='object')return createSignupHost().fetch(request,ctx);
  // A new deployment creates a new module. A changed live config fails closed
  // in an existing isolate instead of resetting an active delivery counter.
  const current=[env.SIGNUP_CONFIGURATION_VERSION,env.BREVO_API_KEY,env.BREVO_SENDER_EMAIL,env.BREVO_REPLY_TO_EMAIL];
  if(configuration&&current.some((value,i)=>value!==configuration[i]))return createSignupHost().fetch(request,ctx);
  if(!host){host=createSignupHost({db:env.DB,mail:{apiKey:env.BREVO_API_KEY,senderEmail:env.BREVO_SENDER_EMAIL,replyToEmail:env.BREVO_REPLY_TO_EMAIL,fetchImpl},edgeAddress:env.SIGNUP_ADDRESS_LIMIT,edgeGlobal:env.SIGNUP_GLOBAL_LIMIT,edgeVerifyAddress:env.SIGNUP_VERIFY_ADDRESS_LIMIT,edgeVerifyGlobal:env.SIGNUP_VERIFY_GLOBAL_LIMIT,resolveTrustedIngress,clock,signupAllowed});configuration=current;}
  return host.fetch(request,ctx);
 }};
}
