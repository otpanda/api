import {contextStoreOptions} from './context-config.js';
import {parseDigestSecret,parseDigestKeys} from './template-fingerprint.js';
// Dev-mailbox-only source composition. Nothing runs unless the deployment sets the single exact enable value below AND every
// pinned identity is present (mailbox, source client and secret, push audience, push service account). Any other value or a
// missing piece leaves the routes unmounted (enable var) or fails closed with 503 (enabled but misconfigured).
import {createRequestBudget,budgetedDb,budgetedFetch} from './request-budget.js';
import {GmailSourceStore,canonicalMailbox} from './gmail-source-store.js';
import {GmailSourceOauth} from './gmail-source-oauth.js';
import {createGmailJwksCache} from './gmail-jwks-cache.js';
import {GmailSync} from './gmail-sync.js';
import {GMAIL_CODE_FILTER} from './gmail-label-filter.js';
import {runGmailDevMaintenance} from './gmail-dev-maintenance.js';
import {GmailTokenCipher} from './gmail-token-cipher.js';
import {DeviceSessionService} from './device-sessions.js';
import {SourceEntryStore,createSourceEntryStore} from './source-entries.js';
import {ServiceMetadata} from './service-metadata.js';
import {CodeCipher} from './code-cipher.js';
import {createGmailSourceHttp,gmailSessionGuard} from './gmail-source-http.js';
import {createGmailPushHttp} from './gmail-push-http.js';
import {createGoogleOidcVerifier} from './google-oidc.js';
import {canonicalClientAddress} from './client-address.js';
import {json} from './sessions.js';
import {importBrowserKeyring} from './browser-keyring.js';
const API='https://otpanda-api.abrahammurciano.workers.dev';
// The Gmail source OAuth client. It must be the one the live app bridge pins, and never the sign-in/native client, because a
// grant revoke or consent change on one client must not touch the other's grants.
const SOURCE_CLIENT_ID='367143149550-cu61adcdqclntipnl84e096kp35vduvk.apps.googleusercontent.com';
export const GMAIL_DEV_ENABLE_VALUE='dev-mailbox-only';
export const gmailDevEnabled=env=>env?.GMAIL_DEV_COLLECTION===GMAIL_DEV_ENABLE_VALUE;
// Gmail maintenance shares the */5 invocation with the realtime drain. Per-category worst case, nothing else spends in this run:
// D1 <= 20 (realtime) + 25 (Gmail, counted together with Google fetches) = 45 of 50; Google fetch <= 25 of 50; Durable Object <= 25 of 1000.
// Operations in total can reach 70, so the 45 "combined" ceiling in realtime-outbox.js does NOT cover Gmail; only the per-category reading does.
// Per-invocation CPU (Free: 10 ms) is not bounded by these counters and is unproven.
export const GMAIL_CRON_BUDGET=25;
export async function createGmailSourceServices(env,{clock=Date.now,fetchImpl=fetch,budgetLimit=50,ready=false}={}){
 // DEV ONLY: label mode is the only mode this factory builds, and it is bound to exactly one mailbox named by a
 // non-secret var. No default and no fallback: without it the services are not built (fail closed, never INBOX mode).
 if(typeof env.GMAIL_DEV_MAILBOX!=='string'||!env.GMAIL_DEV_MAILBOX.trim())throw new TypeError('GMAIL_DEV_MAILBOX required');
 const devMailbox=canonicalMailbox(env.GMAIL_DEV_MAILBOX.trim());
 if(env.GMAIL_SOURCE_CLIENT_ID!==SOURCE_CLIENT_ID||[env.GOOGLE_CLIENT_ID,...String(env.NATIVE_GOOGLE_AUDIENCES??'').split(',').map(v=>v.trim())].includes(env.GMAIL_SOURCE_CLIENT_ID))throw new TypeError('Gmail source OAuth client mismatch');
 if(typeof env.GMAIL_SOURCE_CLIENT_SECRET!=='string'||!env.GMAIL_SOURCE_CLIENT_SECRET)throw new TypeError('Gmail source client secret required');
 const budget=createRequestBudget(budgetLimit),db=budgetedDb(env.DB,budget),f=budgetedFetch(fetchImpl,budget);
 const keys=await importBrowserKeyring(env),sessions=new DeviceSessionService(db,{clock}),store=new GmailSourceStore(db,new GmailTokenCipher(keys));
 const sources=createSourceEntryStore(db,new CodeCipher(keys),{matcher:new ServiceMetadata(db),templateSecret:parseDigestSecret(env.CONTEXT_DIGEST_SECRET)?env.CONTEXT_DIGEST_SECRET:null,templateKeyring:parseDigestKeys(null,env.CONTEXT_DIGEST_KEYRING)?env.CONTEXT_DIGEST_KEYRING:null,...contextStoreOptions(env)});
 const sync=new GmailSync({store,sources,fetchImpl:f,clientId:env.GMAIL_SOURCE_CLIENT_ID,clientSecret:env.GMAIL_SOURCE_CLIENT_SECRET,topicName:'projects/otpanda/topics/gmail-push',clock,budget,maxMessageUnits:1,labelFilter:GMAIL_CODE_FILTER});
 // OAuth's proof consumer is created per start invocation. It accepts only the
 // exact cryptographically verified object from the same HTTP handler call.
 let accepted;
 const oauth=new GmailSourceOauth({store,sync,fetchImpl:f,clientId:env.GMAIL_SOURCE_CLIENT_ID,clientSecret:env.GMAIL_SOURCE_CLIENT_SECRET,redirectUri:API+'/sources/gmail/oauth/callback',devMailbox,clock,
  verifyStepUp:async({ownerId,deviceId,generation,action,proof})=>{const p=accepted;accepted=undefined;return !!p&&proof===p.proof&&ownerId===p.ownerId&&deviceId===p.deviceId&&generation===String(p.generation)&&action==='gmail-source-connect';},
  isCurrent:async c=>{const g=gmailSessionGuard(c,clock());return !!await db.prepare(g.sql).bind(...g.params).first();},
  sessionGuard:async c=>gmailSessionGuard(c,clock()),
 });
 const gatedOauth={callback:v=>oauth.callback(v),async start(v){accepted={...v,proof:v.stepUp};try{return await oauth.start(v);}finally{accepted=undefined;}}};
 return {db,f,budget,store,sync,oauth,devMailbox,http:createGmailSourceHttp({db,sessions,oauth:gatedOauth,sync,sourceStore:store,clock,ready})};
}

// Every call constructs fresh budget, sync, auth counter and resolver cache.
export function createGmailCollectionHost({clock=Date.now,fetchImpl=fetch,resolveTrustedIngress}={}) {
 const keys=createGmailJwksCache({clock});
 return {
  async fetch(request,env) {
   const u=new URL(request.url);
   if(u.origin!==API)return json({error:'not_found'},404);
   if(u.pathname!=='/sources/gmail/push'){if(!gmailDevEnabled(env))return json({error:'not_found'},404);
    // Same baseline as the other public routes, before any keyring import, database or Google work. The push route below keeps its own.
    const caller=canonicalClientAddress(await resolveTrustedIngress?.(request));
    if(!caller)return json({error:'unavailable'},503);
    if((await env.IDENTITY_ADDRESS_LIMIT?.limit({key:'gmail-source:'+caller}))?.success!==true||(await env.IDENTITY_AUTH_GLOBAL_LIMIT?.limit({key:'otpanda-gmail-source-v1'}))?.success!==true)return json({error:'busy'},429);
    let svc;try{svc=await createGmailSourceServices(env,{clock,fetchImpl,ready:true});}catch{return json({error:'collection_not_ready'},503);}return svc.http.fetch(request);}
   if(request.method!=='POST')return json({error:'method_not_allowed'},405);
   if(!gmailDevEnabled(env))return json({error:'not_found'},404);
   const address=canonicalClientAddress(await resolveTrustedIngress?.(request));
   if(!address||env.GMAIL_PUSH_AUDIENCE!==API+'/sources/gmail/push'||env.GMAIL_PUSH_SERVICE_ACCOUNT!=='gmail-push-oidc@otpanda.iam.gserviceaccount.com')return json({error:'unavailable'},503);
   if((await env.IDENTITY_ADDRESS_LIMIT?.limit({key:'gmail-push:'+address}))?.success!==true||(await env.IDENTITY_AUTH_GLOBAL_LIMIT?.limit({key:'otpanda-gmail-push-v1'}))?.success!==true)return json({error:'busy'},429);
   let svc;try{svc=await createGmailSourceServices(env,{clock,fetchImpl});}catch{return json({error:'unavailable'},503);}
   const {sync,f}=svc;
   let keysUnavailable=false;
   const verifier=createGoogleOidcVerifier({audience:API+'/sources/gmail/push',serviceAccountEmail:'gmail-push-oidc@otpanda.iam.gserviceaccount.com',clock,fetchKeys:async()=>{
    try{return await keys(f);}catch{keysUnavailable=true;throw Error('keys unavailable');}
   }});
   const response=await createGmailPushHttp({verifier,sync,expectedSubscription:'projects/otpanda/subscriptions/gmail-push-sub'}).fetch(request);
   return keysUnavailable?json({error:'unavailable'},503):response;
  },
  async scheduled(event,env) {
   if(!gmailDevEnabled(env))return {ready:false};
   let svc;try{svc=await createGmailSourceServices(env,{clock,fetchImpl,budgetLimit:GMAIL_CRON_BUDGET,ready:true});}catch{return {ready:false};}
   // Scoped to the one dev mailbox in SQL; the result carries counts only (the mailbox address is dropped).
   const {mailbox,...r}=await runGmailDevMaintenance({sync:svc.sync,store:svc.store,budget:svc.budget,clock,mailbox:svc.devMailbox});
   return {ready:true,...r};
  }
 };
}
export async function createGmailSourceRuntime(env,options={}) {return (await createGmailSourceServices(env,options)).http;}
