import {createGoogleBrowserRuntime} from './google-browser-runtime.js';
import * as oauth from 'oauth4webapi';
// INACTIVE. No deployment mount or generated secrets. Existing bootstrap stays
// in charge of health/readiness. One adapter per deployed module/isolate.
import{createIdentityRuntime}from'./identity-runtime.js';
import{createSignupWorkerAdapter}from'./signup-worker-adapter.js';
import{createRecoveryMailDelivery}from'./recovery-mail-transport.js';
import{createIdentityEdgeHost,isIdentityPath}from'./identity-edge-host.js';
import{importBrowserKeyring}from'./browser-keyring.js';
import{json}from'./sessions.js';
const API='https://otpanda-api.abrahammurciano.workers.dev';
const signupPaths=new Set(['/auth/signup/app','/auth/signup/start','/auth/signup/email','/auth/signup/begin','/auth/signup/verify']);
export function createBrowserWorkerAdapter({resolveTrustedIngress,fetchImpl=(...args)=>globalThis.fetch(...args),clock=Date.now,signupAllowed}={}){
 const signup=createSignupWorkerAdapter({resolveTrustedIngress,fetchImpl,clock,signupAllowed});let identity,configuration,google,googleConfiguration;
 return{async fetch(request,env,ctx){
  const u=new URL(request.url);if(u.origin!==API)return json({error:'not_found'},404);
  if(signupPaths.has(u.pathname))return signup.fetch(request,env,ctx);
  if(['/auth/google/start','/auth/callback'].includes(u.pathname)||u.pathname.startsWith('/auth/google/continue/')||u.pathname.startsWith('/auth/google/protection/')){
   const current=[env?.DB,env?.ACTIVE_KEY_ID,env?.ENCRYPTION_KEYRING,env?.GOOGLE_CLIENT_ID,env?.GOOGLE_CLIENT_SECRET,env?.IDENTITY_ADDRESS_LIMIT,env?.IDENTITY_AUTH_GLOBAL_LIMIT,env?.BREVO_API_KEY,env?.BREVO_SENDER_EMAIL,env?.BREVO_REPLY_TO_EMAIL];if(googleConfiguration&&current.some((v,i)=>v!==googleConfiguration[i]))return createIdentityEdgeHost().fetch(request);googleConfiguration??=current;
   google??=createIdentityEdgeHost({resolveTrustedIngress,edgeAddress:env?.IDENTITY_ADDRESS_LIMIT,edgeAuthGlobal:env?.IDENTITY_AUTH_GLOBAL_LIMIT,initialize:async()=>{const runtime=await createGoogleBrowserRuntime({db:env.DB,...await importBrowserKeyring(env),clientId:env.GOOGLE_CLIENT_ID,clientSecret:env.GOOGLE_CLIENT_SECRET,clock,mail:{apiKey:env.BREVO_API_KEY,senderEmail:env.BREVO_SENDER_EMAIL,replyToEmail:env.BREVO_REPLY_TO_EMAIL,fetchImpl},oauthOptions:{[oauth.customFetch]:fetchImpl}});return{fetch:async request=>runtime.fetch(request,{clientAddress:await resolveTrustedIngress(request)})};}});
   return google.fetch(request);
  }
  if(!isIdentityPath(u.pathname))return json({error:'not_found'},404);
  // No setup dependency is required for CORS preflights.
  if(request.method==='OPTIONS')return createIdentityEdgeHost().fetch(request);
  const unavailable=()=>createIdentityEdgeHost().fetch(request);
  if(!env||typeof env!=='object')return unavailable();
  const current=[env.BROWSER_CONFIGURATION_VERSION,env.DB,env.ACTIVE_KEY_ID,env.ENCRYPTION_KEYRING,env.IDENTITY_ADDRESS_LIMIT,env.IDENTITY_AUTH_GLOBAL_LIMIT,env.IDENTITY_READ_GLOBAL_LIMIT,env.BREVO_API_KEY,env.BREVO_SENDER_EMAIL,env.BREVO_REPLY_TO_EMAIL];
  if(configuration&&current.some((v,i)=>v!==configuration[i]))return unavailable();
  if(!identity){configuration=current;identity=createIdentityEdgeHost({resolveTrustedIngress,edgeAddress:env.IDENTITY_ADDRESS_LIMIT,edgeAuthGlobal:env.IDENTITY_AUTH_GLOBAL_LIMIT,edgeReadGlobal:env.IDENTITY_READ_GLOBAL_LIMIT,initialize:async()=>createIdentityRuntime({db:env.DB,loadCodeKeys:()=>importBrowserKeyring(env),trustedRequestKey:resolveTrustedIngress,deliverRecoveryMail:env.BREVO_API_KEY?createRecoveryMailDelivery({apiKey:env.BREVO_API_KEY,senderEmail:env.BREVO_SENDER_EMAIL,replyToEmail:env.BREVO_REPLY_TO_EMAIL,fetchImpl}):undefined,clock})});}
  return identity.fetch(request,ctx);
 }};
}
