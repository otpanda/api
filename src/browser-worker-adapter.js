import {hubConnect,hubDeliver} from './realtime-hub.js';
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
const realtimePaths=new Set(['/auth/realtime/ticket','/auth/realtime']);
// Realtime exists only when ALL of its bindings are present: the account hub namespace and three DEDICATED limiters (edge address, edge global, per-ticket).
// Anything missing means the paths do not exist (404) and nothing else about this adapter changes. Never uses the shared auth or read pools.
export const realtimeConfiguration=env=>{
 const hub=env?.REALTIME_HUB,ok=typeof hub?.idFromName==='function'&&typeof hub?.get==='function'&&['REALTIME_ADDRESS_LIMIT','REALTIME_GLOBAL_LIMIT','REALTIME_TICKET_LIMIT'].every(k=>typeof env[k]?.limit==='function');
 return ok?{edgeAddress:env.REALTIME_ADDRESS_LIMIT,edgeGlobal:env.REALTIME_GLOBAL_LIMIT,limiter:env.REALTIME_TICKET_LIMIT,connect:(info,request)=>hubConnect(hub,info,request),deliver:hubDeliver(hub)}:undefined;
};
const signupPaths=new Set(['/auth/signup/app','/auth/signup/start','/auth/signup/email','/auth/signup/begin','/auth/signup/verify']);
export function createBrowserWorkerAdapter({resolveTrustedIngress,fetchImpl=(...args)=>globalThis.fetch(...args),clock=Date.now,signupAllowed}={}){
 const signup=createSignupWorkerAdapter({resolveTrustedIngress,fetchImpl,clock,signupAllowed});let identity,configuration,google,googleConfiguration;
 return{async fetch(request,env,ctx){
  const u=new URL(request.url);if(u.origin!==API)return json({error:'not_found'},404);
  if(signupPaths.has(u.pathname))return signup.fetch(request,env,ctx);
  if(['/auth/google/start','/auth/google/link/start','/auth/callback'].includes(u.pathname)||u.pathname.startsWith('/auth/google/continue/')||u.pathname.startsWith('/auth/google/protection/')){
   const current=[env?.DB,env?.ACTIVE_KEY_ID,env?.ENCRYPTION_KEYRING,env?.GOOGLE_CLIENT_ID,env?.GOOGLE_CLIENT_SECRET,env?.IDENTITY_ADDRESS_LIMIT,env?.IDENTITY_AUTH_GLOBAL_LIMIT,env?.BREVO_API_KEY,env?.BREVO_SENDER_EMAIL,env?.BREVO_REPLY_TO_EMAIL];if(googleConfiguration&&current.some((v,i)=>v!==googleConfiguration[i]))return createIdentityEdgeHost().fetch(request);googleConfiguration??=current;
   google??=createIdentityEdgeHost({resolveTrustedIngress,edgeAddress:env?.IDENTITY_ADDRESS_LIMIT,edgeAuthGlobal:env?.IDENTITY_AUTH_GLOBAL_LIMIT,initialize:async()=>{const runtime=await createGoogleBrowserRuntime({db:env.DB,...await importBrowserKeyring(env),clientId:env.GOOGLE_CLIENT_ID,clientSecret:env.GOOGLE_CLIENT_SECRET,clock,mail:{apiKey:env.BREVO_API_KEY,senderEmail:env.BREVO_SENDER_EMAIL,replyToEmail:env.BREVO_REPLY_TO_EMAIL,fetchImpl},oauthOptions:{[oauth.customFetch]:fetchImpl}});return{fetch:async request=>runtime.fetch(request,{clientAddress:await resolveTrustedIngress(request)})};}});
   return google.fetch(request);
  }
  const rt=realtimeConfiguration(env),realtimePath=!!rt&&realtimePaths.has(u.pathname);
  if(!isIdentityPath(u.pathname)&&!realtimePath)return json({error:'not_found'},404);
  // No setup dependency is required for CORS preflights.
  if(request.method==='OPTIONS')return createIdentityEdgeHost({realtime:realtimePath?{}:undefined}).fetch(request);
  const unavailable=()=>createIdentityEdgeHost().fetch(request);
  if(!env||typeof env!=='object')return unavailable();
  const current=[env.BROWSER_CONFIGURATION_VERSION,env.DB,env.ACTIVE_KEY_ID,env.ENCRYPTION_KEYRING,env.IDENTITY_ADDRESS_LIMIT,env.IDENTITY_AUTH_GLOBAL_LIMIT,env.IDENTITY_READ_GLOBAL_LIMIT,env.BREVO_API_KEY,env.BREVO_SENDER_EMAIL,env.BREVO_REPLY_TO_EMAIL,env.REALTIME_HUB,env.REALTIME_ADDRESS_LIMIT,env.REALTIME_GLOBAL_LIMIT,env.REALTIME_TICKET_LIMIT];
  if(configuration&&current.some((v,i)=>v!==configuration[i]))return unavailable();
  if(!identity){configuration=current;identity=createIdentityEdgeHost({resolveTrustedIngress,edgeAddress:env.IDENTITY_ADDRESS_LIMIT,edgeAuthGlobal:env.IDENTITY_AUTH_GLOBAL_LIMIT,edgeReadGlobal:env.IDENTITY_READ_GLOBAL_LIMIT,realtime:rt?{edgeAddress:rt.edgeAddress,edgeGlobal:rt.edgeGlobal}:undefined,initialize:async()=>createIdentityRuntime({db:env.DB,realtime:rt?{limiter:rt.limiter,connect:rt.connect,deliver:rt.deliver}:undefined,loadCodeKeys:()=>importBrowserKeyring(env),trustedRequestKey:resolveTrustedIngress,deliverRecoveryMail:env.BREVO_API_KEY?createRecoveryMailDelivery({apiKey:env.BREVO_API_KEY,senderEmail:env.BREVO_SENDER_EMAIL,replyToEmail:env.BREVO_REPLY_TO_EMAIL,fetchImpl}):undefined,clock})});}
  return identity.fetch(request,ctx);
 }};
}
