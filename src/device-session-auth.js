// Adapter for the new persistent-device access handles. Not mounted. This does
// not accept legacy cookies or entry-scoped automation tokens as user sessions.
import {bearerToken} from './http.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io';
export function createDeviceSessionAuth({sessions,native=false}={}){
 if(!sessions||typeof sessions.authenticate!=='function')throw new TypeError('Device sessions required');
 return Object.freeze({
 // Web: exact app Origin. Native (opt-in per route): NO Origin header at all; any other Origin is refused.
 originAllowed(request){const o=request.headers.get('origin');return o===APP||(native&&o===null);},
 async authenticate(request){
  const origin=request.headers.get('origin');
  if(new URL(request.url).origin!==API||(origin!==APP&&!(native&&origin===null)))return undefined;
  const token=bearerToken(request.headers.get('authorization'));if(!token)return undefined;
  const auth=await sessions.authenticate(token);
  // A web access handle may not stand in for native/extension or vice versa. Kind must match the Origin shape.
  if(auth?.clientKind!==(origin===APP?'web':'android'))return undefined;
  return {ownerId:auth.ownerId,deviceId:auth.deviceId,generation:auth.generation,expiresAt:auth.expiresAt};
 }});
}
