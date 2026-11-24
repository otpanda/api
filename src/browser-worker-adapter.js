// INACTIVE. No deployment mount or generated secrets. Existing bootstrap stays
// in charge of health/readiness. One adapter per deployed module/isolate.
import{createIdentityRuntime}from'./identity-runtime.js';
import{createSignupWorkerAdapter}from'./signup-worker-adapter.js';
import{createIdentityEdgeHost,isIdentityPath}from'./identity-edge-host.js';
import{importBrowserKeyring}from'./browser-keyring.js';
import{json}from'./sessions.js';
const API='https://otpanda-api.abrahammurciano.workers.dev';
const signupPaths=new Set(['/auth/signup/start','/auth/signup/email','/auth/signup/begin','/auth/signup/verify']);
export function createBrowserWorkerAdapter({resolveTrustedIngress,fetchImpl=(...args)=>globalThis.fetch(...args),clock=Date.now}={}){
 const signup=createSignupWorkerAdapter({resolveTrustedIngress,fetchImpl,clock});let identity,configuration;
 return{async fetch(request,env,ctx){
  const u=new URL(request.url);if(u.origin!==API)return json({error:'not_found'},404);
  if(signupPaths.has(u.pathname))return signup.fetch(request,env,ctx);
  if(!isIdentityPath(u.pathname))return json({error:'not_found'},404);
  // No setup dependency is required for CORS preflights.
  if(request.method==='OPTIONS')return createIdentityEdgeHost().fetch(request);
  const unavailable=()=>createIdentityEdgeHost().fetch(request);
  if(!env||typeof env!=='object')return unavailable();
  const current=[env.BROWSER_CONFIGURATION_VERSION,env.DB,env.ACTIVE_KEY_ID,env.ENCRYPTION_KEYRING,env.IDENTITY_ADDRESS_LIMIT,env.IDENTITY_AUTH_GLOBAL_LIMIT,env.IDENTITY_READ_GLOBAL_LIMIT];
  if(configuration&&current.some((v,i)=>v!==configuration[i]))return unavailable();
  if(!identity){configuration=current;identity=createIdentityEdgeHost({resolveTrustedIngress,edgeAddress:env.IDENTITY_ADDRESS_LIMIT,edgeAuthGlobal:env.IDENTITY_AUTH_GLOBAL_LIMIT,edgeReadGlobal:env.IDENTITY_READ_GLOBAL_LIMIT,initialize:async()=>createIdentityRuntime({db:env.DB,loadCodeKeys:()=>importBrowserKeyring(env),trustedRequestKey:resolveTrustedIngress,clock})});}
  return identity.fetch(request);
 }};
}
