// Qualification-only Gmail push mount. No source, watch or ingestion is started.
// A verified hint gets 503 so Pub/Sub retains it instead of losing messages.
import {createGoogleOidcVerifier} from './google-oidc.js';
import {createGmailPushHttp} from './gmail-push-http.js';
import {createRequestBudget,budgetedFetch} from './request-budget.js';
import {createGmailJwksCache} from './gmail-jwks-cache.js';
import {json} from './sessions.js';
import {canonicalClientAddress} from './client-address.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',PATH='/sources/gmail/push';
const AUDIENCE=API+PATH,ACCOUNT='gmail-push-oidc@otpanda.iam.gserviceaccount.com';
const SUBSCRIPTION='projects/otpanda/subscriptions/gmail-push-sub';
export function createGmailQualificationHost({fetchImpl=fetch,resolveTrustedIngress,clock=Date.now}={}){
 const keys=createGmailJwksCache({clock});
 return {async fetch(request,env){
  const u=new URL(request.url);if(u.origin!==API||u.pathname!==PATH||u.search)return json({error:'not_found'},404);
  if(request.method!=='POST')return json({error:'method_not_allowed'},405,{Allow:'POST'});
  // Fixed expected identity, not values a request or mutable flag can widen.
  if(env?.GMAIL_PUSH_AUDIENCE!==AUDIENCE||env?.GMAIL_PUSH_SERVICE_ACCOUNT!==ACCOUNT||typeof resolveTrustedIngress!=='function'||typeof env?.IDENTITY_ADDRESS_LIMIT?.limit!=='function'||typeof env?.IDENTITY_AUTH_GLOBAL_LIMIT?.limit!=='function')return json({error:'unavailable'},503);
  try{
   const address=canonicalClientAddress(await resolveTrustedIngress(request));if(!address)return json({error:'unavailable'},503);
   if((await env.IDENTITY_ADDRESS_LIMIT.limit({key:'gmail-push:'+address}))?.success!==true||(await env.IDENTITY_AUTH_GLOBAL_LIMIT.limit({key:'otpanda-gmail-push-v1'}))?.success!==true)return json({error:'busy'},429,{'Retry-After':'60'});
   const budget=createRequestBudget(50),f=budgetedFetch(fetchImpl,budget);
   let keysUnavailable=false;
   const verifier=createGoogleOidcVerifier({audience:AUDIENCE,serviceAccountEmail:ACCOUNT,fetchKeys:async()=>{try{return await keys(f);}catch{keysUnavailable=true;throw Error('keys unavailable');}},clock});
   const handler=createGmailPushHttp({verifier,expectedSubscription:SUBSCRIPTION,sync:{async syncMailbox(){throw Error('ingestion not enabled');}}});
   const response=await handler.fetch(request);
   return keysUnavailable?json({error:'unavailable'},503):response;
  }catch{return json({error:'unavailable'},503);}
 }};
}
