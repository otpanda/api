// New read-only browser identity composition. Never mounts legacy mutations,
// OIDC, signup delivery or automatic account creation. Deployment stays gated.
import {CodeCipher} from './code-cipher.js';
import {SourceEntryStore} from './source-entries.js';
import {ServiceMetadata} from './service-metadata.js';
import {EntryAccess} from './entry-access.js';
import {PasskeyService} from './passkey-service.js';
import {DeviceSessionService} from './device-sessions.js';
import {BrowserExchangeService} from './browser-exchanges.js';
import {WebLoginHandoffService} from './web-login-handoff.js';
import {createBrowserSessionHttp} from './browser-session-http.js';
import {createWebLoginHttp} from './web-login-http.js';
import {createBrowserLogoutHttp} from './browser-logout-http.js';
import {createDeviceReadHttp} from './device-read-http.js';
import {cleanupIdentity} from './identity-cleanup.js';
import {json} from './sessions.js';
import {canonicalClientAddress} from './client-address.js';
import {PersonalOrganizationStore} from './personal-organization.js';
import {createPersonalOrganizationHttp} from './personal-organization-http.js';
export function createIdentityRuntime({db,keys,activeKeyId,trustedRequestKey,clock=Date.now}={}) {
 if(!db||typeof trustedRequestKey!=='function')throw new TypeError('Trusted runtime configuration required');
 const sessions=new DeviceSessionService(db,{clock}),exchanges=new BrowserExchangeService(db,{clock,redirectUri:'https://otpanda.github.io/app/'}),passkeys=new PasskeyService(db,{clock});
 const login=new WebLoginHandoffService(db,{sessions,exchanges,passkeys,clock});
 const metadata=new ServiceMetadata(db),sources=new SourceEntryStore(db,new CodeCipher({keys,activeKeyId}),{matcher:metadata}),access=new EntryAccess(db,sources);
 const loginHttp=createWebLoginHttp({db,login,clock}),sessionHttp=createBrowserSessionHttp({db,sessions,exchanges,clock}),logoutHttp=createBrowserLogoutHttp({db,sessions,clock}),reads=createDeviceReadHttp({db,sessions,sources,access,clock});
 const organization=createPersonalOrganizationHttp({db,sessions,organization:new PersonalOrganizationStore(db,{clock}),clock});
 const readPaths=new Set(['/v1/manage/session','/v1/manage/entries','/v1/manage/active-codes','/v1/manage/unassigned','/v1/manage/sources']);
 const loginPaths=new Set(['/auth/login/start','/auth/login/verify','/auth/login/complete']);
 return {async fetch(request) {
  try {
   const url=new URL(request.url);
   if(url.origin!=='https://otpanda-api.abrahammurciano.workers.dev')return json({error:'not_found'},404);
   let handler;
   if(loginPaths.has(url.pathname))handler=loginHttp;
   else if(['/auth/restore','/auth/exchange'].includes(url.pathname))handler=sessionHttp;
   else if(url.pathname==='/auth/device/logout')handler=logoutHttp;
   else if(readPaths.has(url.pathname))handler=reads;
   else if(['/v1/manage/organization','/v1/manage/organization-copy'].includes(url.pathname))handler=organization;
   else return json({error:'not_found'},404);
   const clientAddress=canonicalClientAddress(await trustedRequestKey(request));
   if(!clientAddress)return json({error:'unavailable'},503);
   return await handler.fetch(request,{clientAddress});
  }catch{return json({error:'unavailable'},503);}
 },async cleanup(){return cleanupIdentity({db,clock,limit:100});}};
}
