// Public auth-only deployment entry. Interactive screens belong to the app.
// Auth-only is deliberately smaller than the complete browser adapter.
import {deliverRecoveryNotifications,drainRecoveryCodeJobs,recoveryDeliveryHealth,expireRecoveryCodeJobs} from './recovery-notifier.js';
import {CodeCipher} from './code-cipher.js';
import {importBrowserKeyring} from './browser-keyring.js';
import {createRecoveryNotificationDelivery,createRecoveryMailDelivery} from './recovery-mail-transport.js';
import {createBrowserWorkerAdapter} from './browser-worker-adapter.js';
import {resolveCloudflareDirectIngress} from './cloudflare-ingress.js';
import {cleanupIdentity} from './identity-cleanup.js';
import {drainSome,Budget,CRON_QUERY_MAX,CRON_DELIVERY_MAX,REALTIME_CRON} from './realtime-outbox.js';
import {hubDeliver} from './realtime-hub.js';
export {RealtimeHub} from './realtime-hub.js';
import {realtimeConfiguration} from './browser-worker-adapter.js';
import {canonicalAccountEmail} from './account-identity.js';
import {json} from './sessions.js';
import {appFailure} from './silent-bridge.js';
const API='https://otpanda-api.abrahammurciano.workers.dev';
const paths=new Set([
 '/auth/native/exchange','/auth/native/challenge','/auth/native/renew','/auth/native/logout','/auth/native/google/begin','/auth/native/google/complete','/auth/native/approve','/app-return','/.well-known/assetlinks.json','/v1/manage/totp','/v1/manage/totp/begin','/v1/manage/totp-code',...['enroll-begin','enroll-finish','enroll-status','adopt-begin','adopt-finish','add-request','add-begin','add-finish'].map(p=>'/v1/manage/device-key/'+p),...['passkey/add/approval-request','passkey/add/approval-authorize','approval/status','approval/approve-begin','approval/approve-finish'].map(p=>'/v1/manage/'+p),...['status','begin','finish','request-change','approve-begin','approve-change','consume-change','cancel-request'].map(p=>'/v1/manage/recovery/'+p),...['request','verify','complete-code','complete-begin','complete-finish'].map(p=>'/auth/recovery/email/'+p),...['verify-begin','verify-finish','register-begin','register-finish'].map(p=>'/v1/manage/passkey/add/'+p),...['status','begin','verify','complete'].map(p=>'/auth/google/protection/'+p),...['status','begin','finish','approve','deny','request-change','approve-change','consume-change'].map(p=>'/v1/manage/security/'+p),...['email','begin','verify','complete'].map(p=>'/auth/google/continue/'+p),'/auth/google/start','/auth/google/link/start','/v1/manage/google/link/ticket','/auth/callback',
 '/auth/signup/app','/auth/signup/start','/auth/signup/email','/auth/signup/begin','/auth/signup/verify',
 '/auth/login/start','/auth/login/verify','/auth/login/complete',
 ...['begin','finish','status'].map(p=>'/v1/manage/assignment/'+p),...['rename','account'].map(p=>'/v1/manage/entry/'+p),
 '/auth/restore','/auth/exchange','/auth/renew','/auth/device/logout','/v1/manage/entries','/v1/manage/active-codes','/v1/manage/unassigned','/v1/manage/sources','/v1/manage/session','/v1/manage/account','/v1/manage/organization','/v1/manage/organization-copy','/v1/manage/passkey/rename','/v1/manage/session/describe','/v1/manage/first-passkey/begin','/v1/manage/first-passkey/finish',
]);
const realtimePaths=new Set(['/auth/realtime/ticket','/auth/realtime']);
export function createAuthOnlyWorker({fetchImpl=(...args)=>globalThis.fetch(...args),clock=Date.now}={}) {
 let owner,mode,configured=false,invalid=false;
 const signupAllowed=email=>!invalid&&configured&&(mode==='public'||email===owner);
 const configure=env=>{
  const currentMode=env.AUTH_ONLY_SIGNUP_MODE??'owner';
  let current;
  if(currentMode==='owner'){try{current=canonicalAccountEmail(env.AUTH_ONLY_SIGNUP_EMAIL);}catch{invalid=true;}}
  else if(currentMode==='public'){if(env.AUTH_ONLY_SIGNUP_EMAIL!==undefined)invalid=true;}
  else invalid=true;
  if((currentMode==='owner'&&!current)||(configured&&(currentMode!==mode||current!==owner)))invalid=true;
  if(invalid)return false;
  if(!configured){owner=current;mode=currentMode;configured=true;}
  return true;
 };
 const browser=createBrowserWorkerAdapter({resolveTrustedIngress:resolveCloudflareDirectIngress,fetchImpl,clock,signupAllowed});
 return {
  async fetch(request,env,ctx) {
   const url=new URL(request.url);
   if(url.origin!==API)return json({error:'not_found'},404);
   // Stage must be deliberate; no flag value can widen the route list.
   if(env?.DEPLOYMENT_STAGE!=='auth-only')return json({error:'setup_required'},503);
   if(url.pathname==='/health'&&['GET','HEAD'].includes(request.method))return json({service:'otpanda-api',status:'auth-only',authentication:'staged',codes:'authenticated-received-and-totp',totp:'passkey-enrollment-code-only-read',sources:'authenticated-read-only',recovery:'email-escape-opt-in',enrolledClientApproval:'unavailable'},200);
   if(url.pathname==='/ready'&&request.method==='GET') {
    try {
     if(!env.DB?.prepare || !['SIGNUP_ADDRESS_LIMIT','SIGNUP_GLOBAL_LIMIT','SIGNUP_VERIFY_ADDRESS_LIMIT','SIGNUP_VERIFY_GLOBAL_LIMIT','IDENTITY_ADDRESS_LIMIT','IDENTITY_AUTH_GLOBAL_LIMIT','IDENTITY_READ_GLOBAL_LIMIT'].every(k=>typeof env[k]?.limit==='function'))throw Error();
     if(!configure(env))throw Error();
     if(typeof env.BREVO_API_KEY!=='string'||!env.BREVO_API_KEY||env.BREVO_SENDER_EMAIL!=='otpanda.app@gmail.com'||env.BREVO_REPLY_TO_EMAIL!=='otpanda.app@gmail.com')throw Error();
     await env.DB.prepare('SELECT c.challenge_id FROM auth_challenges c LEFT JOIN device_sessions d ON d.owner_id=c.owner_id LEFT JOIN signup_mail_bindings s ON s.proof_id=c.challenge_id WHERE 0').all();
     const recoveryDelivery=await recoveryDeliveryHealth({db:env.DB,clock});
     return json({service:'otpanda-api',stage:'auth-only',database:'available',recoveryDelivery:(recoveryDelivery.deadNotifications+recoveryDelivery.deadCodeJobs)>0?'attention':'ok',edgeBindings:'configured',mail:'configured-not-delivery-proof',application:'staged'},200);
    }catch{return json({error:'unavailable'},503);}
   }
   if(!paths.has(url.pathname)&&!(realtimePaths.has(url.pathname)&&realtimeConfiguration(env)))return json({error:'not_found'},404);
   // Public registration requires an explicit mode with no owner binding.
   // Existing isolates latch policy and refuse runtime scope changes.
   if(url.pathname.startsWith('/auth/signup/')&&request.method!=='OPTIONS') {
    if(!configure(env))return json({error:'setup_required'},503);
   }
   if(['/auth/signup/start','/auth/signup/email','/auth/signup/begin'].includes(url.pathname))return new Response(null,{status:303,headers:{Location:'https://otpanda.github.io/app/','Cache-Control':'no-store'}});
   const result=await browser.fetch(request,env,ctx);
   // Top-level GET failures return to the app. API/fetch and POST denials keep
   // their status, so this changes presentation, never authentication decisions.
   if(request.method==='GET'&&['/auth/restore','/auth/device/logout','/auth/login/start','/auth/login/complete','/auth/signup/app'].includes(url.pathname)&&result.status>=400)return appFailure(url.searchParams.get('state')??'',url.pathname==='/auth/device/logout'?'logout-incomplete':'restart');
   return result;
  },
  async scheduled(event,env,ctx) {
   if(env?.DEPLOYMENT_STAGE!=='auth-only'||!env.DB?.prepare)return;
   // Realtime delivery runs in its OWN cron invocation (its own 50 query allowance), never next to the identity cleanup.
   if(event?.cron===REALTIME_CRON){if(!env.REALTIME_HUB)return;const drain=drainSome({db:env.DB,deliver:hubDeliver(env.REALTIME_HUB),clock,budget:new Budget(CRON_QUERY_MAX),sends:new Budget(CRON_DELIVERY_MAX)}).catch(()=>{});if(ctx?.waitUntil)ctx.waitUntil(drain);else await drain;return;}
   // Classify lapsed jobs as expired failures BEFORE cleanup can delete them,
   // then log counts only (no ids, addresses or codes) when anything is dead.
   const work=(async()=>{await expireRecoveryCodeJobs({db:env.DB,clock}).catch(()=>{});const h=await recoveryDeliveryHealth({db:env.DB,clock}).catch(()=>undefined);if(h&&(h.deadNotifications||h.deadCodeJobs))console.warn('recovery-delivery-attention',JSON.stringify(h));return Promise.all([cleanupIdentity({db:env.DB,clock,limit:100}),env.BREVO_API_KEY?deliverRecoveryNotifications({db:env.DB,clock,deliver:createRecoveryNotificationDelivery({apiKey:env.BREVO_API_KEY,senderEmail:env.BREVO_SENDER_EMAIL,replyToEmail:env.BREVO_REPLY_TO_EMAIL}),limit:10}):undefined,env.BREVO_API_KEY?(async()=>{try{await drainRecoveryCodeJobs({db:env.DB,clock,cipher:new CodeCipher(await importBrowserKeyring(env)),deliver:createRecoveryMailDelivery({apiKey:env.BREVO_API_KEY,senderEmail:env.BREVO_SENDER_EMAIL,replyToEmail:env.BREVO_REPLY_TO_EMAIL}),limit:10});}catch{}})():undefined]);})();
   if(ctx?.waitUntil)ctx.waitUntil(work);else await work;
  },
 };
}
export default createAuthOnlyWorker();
