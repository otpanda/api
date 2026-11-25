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
import{createGoogleJwks}from'./google-jwks.js';
// Audiences accepted for native Google ID tokens: explicit NATIVE_GOOGLE_AUDIENCES, else the project's web OAuth client id (the
// serverClientId Credential Manager requests tokens for). Empty keeps the Google routes 503.
export const nativeGoogleAudiences=env=>String(env?.NATIVE_GOOGLE_AUDIENCES??env?.GOOGLE_CLIENT_ID??'').split(',').map(v=>v.trim()).filter(Boolean);
import{json}from'./sessions.js';
import{extensionProfile}from'./native-sessions.js';
const API='https://otpanda-api.abrahammurciano.workers.dev';
export const extensionConfiguration=env=>{if(env?.EXTENSION_AUTH_ENABLED!=='1')return undefined;try{const redirects=JSON.parse(env.EXTENSION_REDIRECTS??'{}'),origins=JSON.parse(env.EXTENSION_ORIGINS??'[]');if(!redirects||Array.isArray(redirects)||!Object.keys(redirects).length||!Array.isArray(origins))return undefined;extensionProfile(Object.values(redirects));if(Object.keys(redirects).some(k=>!['chrome','firefox'].includes(k)))return undefined;if(origins.some(o=>typeof o!=='string'||!/^(chrome-extension|moz-extension):\/\/[a-z0-9-]+$/.test(o)))return undefined;return{enabled:true,redirects,origins};}catch{return undefined;}};
const realtimePaths=new Set(['/auth/realtime/ticket','/auth/realtime']);
// Realtime exists only when ALL of its bindings are present: the account hub namespace and three DEDICATED limiters (edge address, edge global, per-ticket).
// Anything missing means the paths do not exist (404) and nothing else about this adapter changes. Never uses the shared auth or read pools.
export const realtimeConfiguration=env=>{
 const hub=env?.REALTIME_HUB,ok=typeof hub?.idFromName==='function'&&typeof hub?.get==='function'&&['REALTIME_ADDRESS_LIMIT','REALTIME_GLOBAL_LIMIT','REALTIME_TICKET_LIMIT'].every(k=>typeof env[k]?.limit==='function');
 return ok?{edgeAddress:env.REALTIME_ADDRESS_LIMIT,edgeGlobal:env.REALTIME_GLOBAL_LIMIT,limiter:env.REALTIME_TICKET_LIMIT,connect:(info,request)=>hubConnect(hub,info,request),deliver:hubDeliver(hub)}:undefined;
};
// Native Android routes exist only when the deployment explicitly sets NATIVE_AUTH_ENABLED to the string 1. Default is off: 404 before any
// setup, limiter or database access, for every native path.
const nativePaths=new Set(['/auth/native/exchange','/auth/native/challenge','/auth/native/renew','/auth/native/logout','/auth/native/google/begin','/auth/native/google/complete','/auth/native/passkey/begin','/auth/native/passkey/complete',...['request','verify','complete-code','complete-begin','complete-finish'].map(p=>'/auth/native/recovery/email/'+p),'/auth/native/google/continue/begin','/auth/native/google/continue/finish','/auth/native/approve','/app-return','/.well-known/assetlinks.json']);
const signupPaths=new Set(['/auth/signup/app','/auth/signup/start','/auth/signup/email','/auth/signup/begin','/auth/signup/verify','/auth/native/signup/email','/auth/native/signup/begin','/auth/native/signup/finish']);
export function createBrowserWorkerAdapter({resolveTrustedIngress,fetchImpl=(...args)=>globalThis.fetch(...args),clock=Date.now,signupAllowed}={}){
 const signup=createSignupWorkerAdapter({resolveTrustedIngress,fetchImpl,clock,signupAllowed});let identity,configuration,google,googleConfiguration;
 return{async fetch(request,env,ctx){
  const u=new URL(request.url);if(u.origin!==API)return json({error:'not_found'},404);
  if(nativePaths.has(u.pathname)&&env?.NATIVE_AUTH_ENABLED!=='1')return json({error:'not_found'},404);
  if(u.pathname.startsWith('/auth/native/signup/')&&env?.NATIVE_AUTH_ENABLED!=='1')return json({error:'not_found'},404);
  if(signupPaths.has(u.pathname))return signup.fetch(request,env,ctx);
  if(['/auth/google/start','/auth/google/link/start','/auth/callback'].includes(u.pathname)||u.pathname.startsWith('/auth/google/continue/')||u.pathname.startsWith('/auth/google/protection/')){
   const current=[env?.DB,env?.ACTIVE_KEY_ID,env?.ENCRYPTION_KEYRING,env?.GOOGLE_CLIENT_ID,env?.GOOGLE_CLIENT_SECRET,env?.IDENTITY_ADDRESS_LIMIT,env?.IDENTITY_AUTH_GLOBAL_LIMIT,env?.BREVO_API_KEY,env?.BREVO_SENDER_EMAIL,env?.BREVO_REPLY_TO_EMAIL];if(googleConfiguration&&current.some((v,i)=>v!==googleConfiguration[i]))return createIdentityEdgeHost().fetch(request);googleConfiguration??=current;
   google??=createIdentityEdgeHost({resolveTrustedIngress,edgeAddress:env?.IDENTITY_ADDRESS_LIMIT,edgeAuthGlobal:env?.IDENTITY_AUTH_GLOBAL_LIMIT,initialize:async()=>{const runtime=await createGoogleBrowserRuntime({db:env.DB,...await importBrowserKeyring(env),clientId:env.GOOGLE_CLIENT_ID,clientSecret:env.GOOGLE_CLIENT_SECRET,clock,mail:{apiKey:env.BREVO_API_KEY,senderEmail:env.BREVO_SENDER_EMAIL,replyToEmail:env.BREVO_REPLY_TO_EMAIL,fetchImpl},oauthOptions:{[oauth.customFetch]:fetchImpl}});return{fetch:async request=>runtime.fetch(request,{clientAddress:await resolveTrustedIngress(request)})};}});
   return google.fetch(request);
  }
  const ext=extensionConfiguration(env);if(u.pathname.startsWith('/auth/extension/')&&!ext)return json({error:'not_found'},404);
  const rt=realtimeConfiguration(env),realtimePath=!!rt&&realtimePaths.has(u.pathname);
  if(!isIdentityPath(u.pathname)&&!realtimePath)return json({error:'not_found'},404);
  // No setup dependency is required for CORS preflights.
  if(request.method==='OPTIONS')return createIdentityEdgeHost({extensionApi:!!ext,extensionOrigins:ext?.origins??[],realtime:realtimePath?{}:undefined}).fetch(request);
  const unavailable=()=>createIdentityEdgeHost().fetch(request);
  if(!env||typeof env!=='object')return unavailable();
  const current=[env.EXTENSION_AUTH_ENABLED,env.EXTENSION_REDIRECTS,env.EXTENSION_ORIGINS,env.BROWSER_CONFIGURATION_VERSION,env.DB,env.ACTIVE_KEY_ID,env.ENCRYPTION_KEYRING,env.IDENTITY_ADDRESS_LIMIT,env.IDENTITY_AUTH_GLOBAL_LIMIT,env.IDENTITY_READ_GLOBAL_LIMIT,env.BREVO_API_KEY,env.BREVO_SENDER_EMAIL,env.BREVO_REPLY_TO_EMAIL,env.REALTIME_HUB,env.REALTIME_ADDRESS_LIMIT,env.REALTIME_GLOBAL_LIMIT,env.REALTIME_TICKET_LIMIT,env.NATIVE_ASSET_FINGERPRINTS,env.NATIVE_AUTH_ENABLED,env.NATIVE_GOOGLE_AUDIENCES,env.NATIVE_GOOGLE_AUTHORIZED_PARTIES,env.GOOGLE_CLIENT_ID];
  if(configuration&&current.some((v,i)=>v!==configuration[i]))return unavailable();
  if(!identity){configuration=current;identity=createIdentityEdgeHost({extensionApi:!!ext,extensionOrigins:ext?.origins??[],nativeApi:env.NATIVE_AUTH_ENABLED==='1',resolveTrustedIngress,edgeAddress:env.IDENTITY_ADDRESS_LIMIT,edgeAuthGlobal:env.IDENTITY_AUTH_GLOBAL_LIMIT,edgeReadGlobal:env.IDENTITY_READ_GLOBAL_LIMIT,realtime:rt?{edgeAddress:rt.edgeAddress,edgeGlobal:rt.edgeGlobal}:undefined,initialize:async()=>createIdentityRuntime({db:env.DB,extension:ext,native:{enabled:env.NATIVE_AUTH_ENABLED==='1',assetFingerprints:String(env.NATIVE_ASSET_FINGERPRINTS??'').split(',').map(v=>v.trim()).filter(Boolean),googleAudiences:nativeGoogleAudiences(env),googleAuthorizedParties:String(env.NATIVE_GOOGLE_AUTHORIZED_PARTIES??'').split(',').map(v=>v.trim()).filter(Boolean),googleGetKey:createGoogleJwks({fetchImpl,clock})},realtime:rt?{limiter:rt.limiter,connect:rt.connect,deliver:rt.deliver}:undefined,loadCodeKeys:()=>importBrowserKeyring(env),trustedRequestKey:resolveTrustedIngress,deliverRecoveryMail:env.BREVO_API_KEY?createRecoveryMailDelivery({apiKey:env.BREVO_API_KEY,senderEmail:env.BREVO_SENDER_EMAIL,replyToEmail:env.BREVO_REPLY_TO_EMAIL,fetchImpl}):undefined,clock})});}
  return identity.fetch(request,ctx);
 }};
}
