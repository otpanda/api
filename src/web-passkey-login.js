// Internal web login composition only. Not a route or a client proof API.
import {hashText} from './sessions.js';
const REDIRECT='https://otpanda.github.io/app/';
async function ceremonyBinding({binding,challenge,redirectUri}={}){
 if(typeof binding!=='string'||!binding||binding.length>512||typeof challenge!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(challenge)||redirectUri!==REDIRECT)return undefined;
 return hashText(JSON.stringify(['web-passkey-login-v1',binding,challenge,redirectUri]));
}
export class WebPasskeyLoginService {
 constructor({passkeys,sessions,exchanges}={}){
  if(!passkeys||!sessions||!exchanges)throw new TypeError('Web login dependencies required');
  this.passkeys=passkeys;this.sessions=sessions;this.exchanges=exchanges;
 }
 async begin(context){
  const binding=await ceremonyBinding(context);if(!binding)return undefined;
  return this.passkeys.begin({purpose:'authenticate',binding});
 }
 async finish({token,response,...context}={}){
  const binding=await ceremonyBinding(context);if(!binding)return undefined;
  const proof=await this.passkeys.finishAuthentication({token,response,binding});
  if(!proof)return undefined;
  const device=await this.sessions.issue({proof,clientKind:'web'});if(!device)return undefined;
  let completed=false;
  try{
   const grant=await this.exchanges.mint({deviceId:device.deviceId,challenge:context.challenge,redirectUri:REDIRECT});
   // Device/credential revocation or generation reset while minting wins.
   if(!grant||!await this.sessions.authenticate(device.access))return undefined;
   completed=true;
   // HTTP layer alone may place refresh in its host-only HttpOnly cookie.
   // No access token or owner-selected redirect crosses this boundary.
   return {deviceId:device.deviceId,refresh:device.refresh,refreshExpiresAt:device.refreshExpiresAt,code:grant.code,codeExpiresAt:grant.expiresAt};
  }finally{
   if(!completed)await this.sessions.revoke({ownerId:proof.ownerId,deviceId:device.deviceId});
  }
 }
}
