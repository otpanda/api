import {SeedCipher} from './seed-cipher.js';
import {TotpSeedStore,EntryTotpGenerator} from './totp-seeds.js';
import {createTotpReadHttp} from './totp-read-http.js';
import {createNativeHttp} from './native-http.js';
import {NativeSessionService} from './native-sessions.js';
import {NativeGoogle} from './native-google.js';
import {createTotpManagementHttp} from './totp-management-http.js';
import {createExtraVerificationHttp} from './extra-verification-http.js';
import {createFirstPasskeyHttp} from './first-passkey-http.js';
import {createAddPasskeyHttp} from './additional-passkey-http.js';
import {createRecoveryControlsHttp} from './recovery-controls-http.js';
import {createEmailRecoveryHttp} from './email-recovery-http.js';
import {createAccountOverviewHttp} from './account-overview-http.js';
import {createGoogleLinkTicketHttp} from './google-link-http.js';
// Inactive browser identity composition. Never mounts legacy mutations,
// OIDC, signup delivery or automatic account creation. Deployment stays gated.
import {createEntryManageHttp} from './entry-manage-http.js';
import {AssignmentIntents} from './assignment-intents.js';
import {createAssignmentIntentHttp} from './assignment-intent-http.js';
import {createDeviceKeyHttp} from './device-key-http.js';
import {createApprovalsHttp,APPROVAL_PATHS} from './approvals-http.js';
import {EnrolledApprovals} from './enrolled-approvals.js';
import {GoogleDeviceEnrollment} from './google-device-enrollment.js';
import {DurableDeviceKeys} from './durable-device-keys.js';
import {CodeCipher} from './code-cipher.js';
import {SourceEntryStore} from './source-entries.js';
import {ServiceMetadata} from './service-metadata.js';
import {EntryAccess} from './entry-access.js';
import {PasskeyService} from './passkey-service.js';
import {DeviceSessionService} from './device-sessions.js';
import {BrowserExchangeService} from './browser-exchanges.js';
import {WebLoginHandoffService} from './web-login-handoff.js';
import {createBrowserSessionHttp} from './browser-session-http.js';
import {AccessRenewal} from './access-renewal.js';
import {createWebLoginHttp} from './web-login-http.js';
import {createBrowserLogoutHttp} from './browser-logout-http.js';
import {createDeviceReadHttp} from './device-read-http.js';
import {cleanupIdentity} from './identity-cleanup.js';
import {json} from './sessions.js';
import {canonicalClientAddress} from './client-address.js';
import {PersonalOrganizationStore} from './personal-organization.js';
import {createDeviceSessionInfoHttp} from './device-session-info-http.js';
import {createPasskeyLabelHttp} from './passkey-label-http.js';
import {createPersonalOrganizationHttp} from './personal-organization-http.js';
import {createRealtimeHttp} from './realtime-http.js';
import {createForegroundDrain} from './realtime-foreground.js';
export function createIdentityRuntime({db:rawDb,keys,activeKeyId,trustedRequestKey,loadCodeKeys,deliverRecoveryMail,realtime,native,clock=Date.now}={}) {
 if(!rawDb||typeof trustedRequestKey!=='function')throw new TypeError('Trusted runtime configuration required');
 // With realtime configured every query of this isolate is counted, so a post-write drain can only spend what the request left of the
 // Free plan's 50 queries per invocation. Without realtime the database object is used untouched.
 const foreground=createForegroundDrain({db:rawDb,realtime,clock}),db=foreground.db;
 const sessions=new DeviceSessionService(db,{clock}),exchanges=new BrowserExchangeService(db,{clock,redirectUri:'https://otpanda.github.io/app/'}),passkeys=new PasskeyService(db,{clock});
 const login=new WebLoginHandoffService(db,{sessions,exchanges,passkeys,clock});
 // Authentication and metadata do not need code encryption. Import code keys
 // only after authorization on a key-dependent read. Cache failures as well.
 let codeDependencies;
 const encrypted=()=>codeDependencies??=Promise.resolve().then(async()=>{
  const configuration=loadCodeKeys?await loadCodeKeys():{keys,activeKeyId};
  const cipher=new CodeCipher(configuration),metadata=new ServiceMetadata(db),sources=new SourceEntryStore(db,cipher,{matcher:metadata});
  const access=new EntryAccess(db,sources),seedCipher=new SeedCipher(configuration),seeds=new TotpSeedStore(db,seedCipher);
  return{cipher,sources,access,seedCipher,generator:new EntryTotpGenerator(db,seeds,access)};
 });
 const sources={
  unassignedForOwner:async(...args)=>(await encrypted()).sources.unassignedForOwner(...args),
  sourcesForOwner:async(...args)=>(await encrypted()).sources.sourcesForOwner(...args),
 };
 const access={activeRecent:async(...args)=>(await encrypted()).access.activeRecent(...args)};
 const nativeOn=native?.enabled===true;// explicit default-off activation: native token acceptance and native routes both depend on it
 const loginHttp=createWebLoginHttp({db,login,clock}),sessionHttp=createBrowserSessionHttp({db,sessions,exchanges,renewals:new AccessRenewal(db,{clock}),clock}),logoutHttp=createBrowserLogoutHttp({db,sessions,clock}),reads=createDeviceReadHttp({db,sessions,sources,access,native:nativeOn,clock});
// Native Android boundary. Without native.assetFingerprints assetlinks is 404; without native.google the Google routes are 503.
 const nativeSessionService=new NativeSessionService(db,{clock});
 // Google routes need an injected NativeGoogle OR audiences plus a key lookup; with neither they stay 503 (fail closed).
 const nativeGoogle=native?.google??(Array.isArray(native?.googleAudiences)&&native.googleAudiences.length&&typeof native.googleGetKey==='function'?new NativeGoogle(db,{native:nativeSessionService,audiences:native.googleAudiences,authorizedParties:native.googleAuthorizedParties??[],getKey:native.googleGetKey,clock}):undefined);
 const nativeHttp=createNativeHttp({sessions,native:nativeSessionService,db,google:nativeGoogle,assetFingerprints:native?.assetFingerprints??[],clock});
 const nativePaths=new Set(['/auth/native/exchange','/auth/native/challenge','/auth/native/renew','/auth/native/logout','/auth/native/google/begin','/auth/native/google/complete','/auth/native/approve','/app-return','/.well-known/assetlinks.json']);
 const totpRead=createTotpReadHttp({db,sessions,generator:{generateForActor:async(...args)=>(await encrypted()).generator.generateForActor(...args)},native:nativeOn,clock});
 const totpManage=createTotpManagementHttp({db,sessions,getSeedCipher:async()=>(await encrypted()).seedCipher,native:nativeOn,clock});
 const security=createExtraVerificationHttp({db,sessions,clock});
 const firstPasskey=createFirstPasskeyHttp({db,sessions,clock}),addPasskey=createAddPasskeyHttp({db,sessions,clock,passkeys}),recovery=createRecoveryControlsHttp({db,sessions,clock,passkeys}),emailRecovery=createEmailRecoveryHttp({db,deliver:deliverRecoveryMail,getCipher:async()=>(await encrypted()).cipher,clock,passkeys});
 const deviceInfo=createDeviceSessionInfoHttp({db,sessions,native:nativeOn,clock}),passkeyLabel=createPasskeyLabelHttp({db,sessions,clock}),overview=createAccountOverviewHttp({db,sessions,native:nativeOn,clock}),googleLink=createGoogleLinkTicketHttp({db,sessions,clock});
 const organization=createPersonalOrganizationHttp({db,sessions,organization:new PersonalOrganizationStore(db,{clock}),native:nativeOn,clock});
 const assignment=createAssignmentIntentHttp({db,sessions,intents:new AssignmentIntents({db,passkeys,deviceKeys:new DurableDeviceKeys(db,{clock}),clock,prepare:async()=>{await encrypted();},cipher:{decrypt:async(...args)=>(await encrypted()).cipher.decrypt(...args),encrypt:async(...args)=>(await encrypted()).cipher.encrypt(...args)}}),clock,native:nativeOn});
 // Inactive unless a deployment passes {limiter,connect,deliver}: without it the realtime paths are not_found and nothing drains.
 const entryManage=createEntryManageHttp({db,sessions,clock,native:nativeOn});
 const realtimeHttp=realtime?createRealtimeHttp({db,sessions,limiter:realtime.limiter,connect:realtime.connect,native:nativeOn,clock}):undefined;
 const deviceKey=createDeviceKeyHttp({db,sessions,enrollment:new GoogleDeviceEnrollment(db,{clock}),keys:new DurableDeviceKeys(db,{clock}),clock});
 const approvals=createApprovalsHttp({db,sessions,approvals:new EnrolledApprovals(db,{clock,keys:new DurableDeviceKeys(db,{clock})}),clock});
 const approvalPaths=new Set(APPROVAL_PATHS);
 const deviceKeyPaths=new Set(['enroll-begin','enroll-finish','enroll-status','adopt-begin','adopt-finish'].map(p=>'/v1/manage/device-key/'+p));
 const assignmentPaths=new Set(['begin','finish','status'].map(p=>'/v1/manage/assignment/'+p));
 const readPaths=new Set(['/v1/manage/session','/v1/manage/entries','/v1/manage/active-codes','/v1/manage/unassigned','/v1/manage/sources']);
 const loginPaths=new Set(['/auth/login/start','/auth/login/verify','/auth/login/complete']);
 const inner=async(request,{waitUntil}={})=>{
  try {
   const url=new URL(request.url);
   if(url.origin!=='https://otpanda-api.abrahammurciano.workers.dev')return json({error:'not_found'},404);
   let handler;
   if(nativePaths.has(url.pathname)){if(!nativeOn)return json({error:'not_found'},404);handler=nativeHttp;}
   else if(approvalPaths.has(url.pathname)){if(!nativeOn)return json({error:'not_found'},404);handler=approvals;}
   else if(deviceKeyPaths.has(url.pathname)){if(!nativeOn)return json({error:'not_found'},404);handler=deviceKey;}
   else if(url.pathname==='/v1/manage/totp-code')handler=totpRead;
   else if(['/v1/manage/totp','/v1/manage/totp/begin'].includes(url.pathname))handler=totpManage;
   else if(url.pathname.startsWith('/v1/manage/security/'))handler=security;
   else if(['/v1/manage/first-passkey/begin','/v1/manage/first-passkey/finish'].includes(url.pathname))handler=firstPasskey;
   else if(url.pathname.startsWith('/v1/manage/passkey/add/'))handler=addPasskey;
   else if(url.pathname==='/v1/manage/passkey/rename')handler=passkeyLabel;
   else if(url.pathname==='/v1/manage/session/describe')handler=deviceInfo;
   else if(url.pathname.startsWith('/v1/manage/recovery/'))handler=recovery;
   else if(url.pathname.startsWith('/auth/recovery/email/'))handler=emailRecovery;
   else if(url.pathname==='/v1/manage/account')handler=overview;
   else if(url.pathname==='/v1/manage/google/link/ticket')handler=googleLink;
   else if(loginPaths.has(url.pathname))handler=loginHttp;
   else if(['/auth/restore','/auth/exchange','/auth/renew'].includes(url.pathname))handler=sessionHttp;
   else if(url.pathname==='/auth/device/logout')handler=logoutHttp;
   else if(readPaths.has(url.pathname))handler=reads;
   else if(assignmentPaths.has(url.pathname))handler=assignment;
   else if(['/v1/manage/entry/rename','/v1/manage/entry/account'].includes(url.pathname))handler=entryManage;
   else if(['/v1/manage/organization','/v1/manage/organization-copy'].includes(url.pathname))handler=organization;
   else if(realtimeHttp&&['/auth/realtime/ticket','/auth/realtime'].includes(url.pathname))handler=realtimeHttp;
   else return json({error:'not_found'},404);
   const clientAddress=canonicalClientAddress(await trustedRequestKey(request));
   if(!clientAddress)return json({error:'unavailable'},503);
   const response=await handler.fetch(request,{clientAddress,waitUntil});
   return response;
  }catch{return json({error:'unavailable'},503);}
 };
 // A committed write already has its outbox row; deliver bounded and best effort after the response. Failures stay for cron.
 return {fetch:foreground.wrap(inner),async cleanup(){return cleanupIdentity({db,clock,limit:100});}};
}
