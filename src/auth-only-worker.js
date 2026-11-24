// INACTIVE entry candidate. wrangler still selects cloudflare-worker.js.
// Auth-only is deliberately smaller than the complete browser adapter.
import {createBrowserWorkerAdapter} from './browser-worker-adapter.js';
import {resolveCloudflareDirectIngress} from './cloudflare-ingress.js';
import {cleanupIdentity} from './identity-cleanup.js';
import {canonicalAccountEmail} from './account-identity.js';
import {json} from './sessions.js';
const API='https://otpanda-api.abrahammurciano.workers.dev';
const paths=new Set([
 '/auth/signup/start','/auth/signup/email','/auth/signup/begin','/auth/signup/verify',
 '/auth/login/start','/auth/login/verify','/auth/login/complete',
 '/auth/restore','/auth/exchange','/auth/device/logout','/v1/manage/session',
]);
export function createAuthOnlyWorker({fetchImpl=(...args)=>globalThis.fetch(...args),clock=Date.now}={}) {
 let owner,configured=false,invalid=false;
 const signupAllowed=email=>!invalid&&configured&&email===owner;
 const configure=env=>{
  let current;try{current=canonicalAccountEmail(env.AUTH_ONLY_SIGNUP_EMAIL);}catch{invalid=true;}
  if(!current||(configured&&current!==owner))invalid=true;
  if(invalid)return false;
  if(!configured){owner=current;configured=true;}
  return true;
 };
 const browser=createBrowserWorkerAdapter({resolveTrustedIngress:resolveCloudflareDirectIngress,fetchImpl,clock,signupAllowed});
 return {
  async fetch(request,env,ctx) {
   const url=new URL(request.url);
   if(url.origin!==API)return json({error:'not_found'},404);
   // Stage must be deliberate; no flag value can widen the route list.
   if(env?.DEPLOYMENT_STAGE!=='auth-only')return json({error:'setup_required'},503);
   if(url.pathname==='/health'&&['GET','HEAD'].includes(request.method))return json({service:'otpanda-api',status:'auth-only',authentication:'staged',codes:'unavailable',sources:'unavailable',recovery:'unavailable'},200);
   if(url.pathname==='/ready'&&request.method==='GET') {
    try {
     if(!env.DB?.prepare || !['SIGNUP_ADDRESS_LIMIT','SIGNUP_GLOBAL_LIMIT','SIGNUP_VERIFY_ADDRESS_LIMIT','SIGNUP_VERIFY_GLOBAL_LIMIT','IDENTITY_ADDRESS_LIMIT','IDENTITY_AUTH_GLOBAL_LIMIT','IDENTITY_READ_GLOBAL_LIMIT'].every(k=>typeof env[k]?.limit==='function'))throw Error();
     if(!configure(env))throw Error();
     if(typeof env.BREVO_API_KEY!=='string'||!env.BREVO_API_KEY||env.BREVO_SENDER_EMAIL!=='otpanda.app@gmail.com'||env.BREVO_REPLY_TO_EMAIL!=='otpanda.app@gmail.com')throw Error();
     await env.DB.prepare('SELECT c.challenge_id FROM auth_challenges c LEFT JOIN device_sessions d ON d.owner_id=c.owner_id LEFT JOIN signup_mail_bindings s ON s.proof_id=c.challenge_id WHERE 0').all();
     return json({service:'otpanda-api',stage:'auth-only',database:'available',edgeBindings:'configured',mail:'configured-not-delivery-proof',application:'staged'},200);
    }catch{return json({error:'unavailable'},503);}
   }
   if(!paths.has(url.pathname))return json({error:'not_found'},404);
   // No implicit public-registration mode. Existing isolates latch configuration
   // and refuse changes instead of silently changing the allowed identity.
   if(url.pathname.startsWith('/auth/signup/')&&request.method!=='OPTIONS') {
    if(!configure(env))return json({error:'setup_required'},503);
   }
   return browser.fetch(request,env,ctx);
  },
  async scheduled(event,env,ctx) {
   if(env?.DEPLOYMENT_STAGE!=='auth-only'||!env.DB?.prepare)return;
   const work=cleanupIdentity({db:env.DB,clock,limit:100});
   if(ctx?.waitUntil)ctx.waitUntil(work);else await work;
  },
 };
}
export default createAuthOnlyWorker();
