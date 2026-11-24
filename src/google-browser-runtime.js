import {googleVerifyEmail} from './email-templates.js';
import {ExtraVerification} from './extra-verification.js';
import {createGoogleProtectionHttp} from './google-protection-http.js';
import {createGoogleContinuationHttp} from './google-continuation-http.js';
import {GoogleContinuation} from './google-continuation.js';
import {BrevoMailTransport} from './brevo-mail.js';
import {FirstPasskeyEnrollment} from './first-passkey-enrollment.js';
import * as oauth from 'oauth4webapi';
import {createGoogleBrowserFlow} from './google-browser-flow.js';
import {GoogleAccountService} from './google-account.js';
import {CodeCipher} from './code-cipher.js';
import {DeviceSessionService} from './device-sessions.js';
import {readCookie,cookie,securityHeaders,hashText} from './sessions.js';
import {appFailure} from './silent-bridge.js';
const ISSUER='https://accounts.google.com',APP='https://otpanda.github.io/app/';
export async function createGoogleBrowserRuntime({db,keys,activeKeyId,clientId,clientSecret,clock=Date.now,oauthOptions={},mail}={}){
 if(typeof clientId!=='string'||!clientId.endsWith('.apps.googleusercontent.com')||typeof clientSecret!=='string'||!clientSecret)throw new TypeError('Google client configuration required');
 const discovery=await oauth.discoveryRequest(new URL(ISSUER),oauthOptions),server=await oauth.processDiscoveryResponse(new URL(ISSUER),discovery);
 if(server.issuer!==ISSUER||!server.code_challenge_methods_supported?.includes('S256')||!server.id_token_signing_alg_values_supported?.includes('RS256')||!server.token_endpoint_auth_methods_supported?.includes('client_secret_post'))throw Error('Unexpected Google metadata');
 const sessions=new DeviceSessionService(db,{clock}),accounts=new GoogleAccountService(db,{clock}),cipher=new CodeCipher({keys,activeKeyId});
 const protection=new ExtraVerification(db,{clock});
 const transport=mail?new BrevoMailTransport(mail):null,continuations=new GoogleContinuation(db,{cipher,clock,deliver:transport?proof=>transport.submit({to:proof.to,...googleVerifyEmail(proof.code??proof.token)}):undefined});
 const complete=async({identity,appState,challenge,remember,verifiedAt,expectedGeneration,request,protectionPending})=>{
  const account=await accounts.resolve(identity);
  if(!account||!['created','linked'].includes(account.status)){
   if(!['existing-account','verify-email'].includes(account?.status))return appFailure(appState,account?.status==='legacy-account'?'legacy-account':'restart');
   if(expectedGeneration!==undefined&&account.generation!==expectedGeneration)return appFailure(appState,'restart');
  const binding=readCookie(request,new URL(request.url).pathname.startsWith('/auth/google/protection/')?'__Host-otpanda_google_pending':new URL(request.url).pathname.startsWith('/auth/google/continue/')?'__Host-otpanda_google_continue':'__Host-otpanda_google');if(!binding)return appFailure(appState,'restart');
   const pending=await continuations.create({identity,appState,challenge,remember,binding});if(!pending)return appFailure(appState,'restart');
   const target=new URL(APP);target.hash=new URLSearchParams({google:JSON.stringify(pending),state:appState});return new Response(null,{status:303,headers:{...securityHeaders,Location:target.href,'Set-Cookie':cookie('__Host-otpanda_google_continue',binding,600)}});
  }
  if(expectedGeneration!==undefined&&account.generation!==expectedGeneration)return appFailure(appState,'restart');
  const binding=readCookie(request,new URL(request.url).pathname.startsWith('/auth/google/protection/')?'__Host-otpanda_google_pending':new URL(request.url).pathname.startsWith('/auth/google/continue/')?'__Host-otpanda_google_continue':'__Host-otpanda_google');if(!binding)return appFailure(appState,'restart');
  const recognition=await protection.parseToken(readCookie(request,'__Host-otpanda_recognition')),validRecognition=recognition?await db.prepare("SELECT 1 x FROM recognized_browsers r JOIN provider_identities g ON g.identity_id=r.provider_identity_id WHERE r.recognition_id=?1 AND r.secret_digest=?2 AND r.owner_id=?3 AND r.generation=?4 AND r.revoked_at IS NULL AND g.revoked_at IS NULL AND g.issuer=?5 AND g.subject=?6").bind(recognition.id,recognition.digest,account.ownerId,account.generation,identity.issuer,identity.subject).first():null,newRecognition=remember&&!validRecognition?await protection.newRecognition():undefined;
  const issued=await sessions.issueBrowserLogin({proof:{authMethod:'google',issuer:identity.issuer,subject:identity.subject,email:identity.email,ownerId:account.ownerId,generation:account.generation,verifiedAt,purpose:'authenticate'},browserBindingDigest:await hashText(await hashText(binding)),priorRefresh:readCookie(request,'__Host-otpanda_device'),challenge,redirectUri:APP,deadline:protectionPending?clock()+60000:verifiedAt+60000,protection:{recognition,pending:protectionPending,newRecognition}});
  if(!issued){
   if(protectionPending||!await protection.enabled(account.ownerId))return appFailure(appState,'restart');
   const now=clock(),expiresAt=now+600000,context={ownerId:'protected-google',recordId:'pending',serviceId:ISSUER,receivedAt:now,expiresAt},encrypted=await cipher.encrypt(JSON.stringify({identity,appState,challenge,remember,verifiedAt,generation:account.generation}),context);
   const pending=await protection.createPending({ownerId:account.ownerId,generation:account.generation,issuer:identity.issuer,subject:identity.subject,challenge,browserBindingDigest:await hashText(await hashText(binding)),remember,context:JSON.stringify({...encrypted,receivedAt:now,expiresAt})});if(!pending)return appFailure(appState,'retry');const target=new URL(APP);target.hash=new URLSearchParams({protection:JSON.stringify(pending),state:appState});return new Response(null,{status:303,headers:{...securityHeaders,Location:target.href,'Set-Cookie':cookie('__Host-otpanda_google_pending',binding,600)}});
  }
  const enroll=await new FirstPasskeyEnrollment(db,{clock}).issue({ownerId:account.ownerId,deviceId:issued.deviceId,generation:account.generation,issuer:identity.issuer,subject:identity.subject,verifiedAt});
  const target=new URL(APP);target.hash=new URLSearchParams({code:issued.code,state:appState,...(enroll?{enrollment:enroll.token}:{})});
  const headers=new Headers({...securityHeaders,Location:target.href});headers.append('Set-Cookie',cookie('__Host-otpanda_device',issued.refresh,Math.max(0,Math.floor((issued.refreshExpiresAt-clock())/1000))));if(newRecognition)headers.append('Set-Cookie',cookie('__Host-otpanda_recognition',newRecognition.token,2147483647));return new Response(null,{status:303,headers});
 };
 const flow=createGoogleBrowserFlow({db,cipher,server,client:{client_id:clientId,id_token_signed_response_alg:'RS256'},clientAuthentication:oauth.ClientSecretPost(clientSecret),clock,oauthOptions,complete});
 const protectionHttp=createGoogleProtectionHttp({db,service:protection,cipher,complete,clock});
 const continuationHttp=createGoogleContinuationHttp({db,continuations,complete,clock});
 return{continuations,async fetch(request,metadata){if(new URL(request.url).pathname.startsWith('/auth/google/protection/'))return protectionHttp.fetch(request,metadata);if(new URL(request.url).pathname.startsWith('/auth/google/continue/'))return continuationHttp.fetch(request,metadata);return new URL(request.url).pathname==='/auth/google/start'?flow.start(request):flow.callback(request);}};
}
