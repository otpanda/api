// Adapter for the new persistent-device access handles. Not mounted. This does
// not accept legacy cookies or entry-scoped automation tokens as user sessions.
import {bearerToken} from './http.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io';
// Modes: web (default: Origin exactly APP, kind web), native=true (additionally no Origin, kind android; unchanged), extension=true (EXTENSION-ONLY:
// no Origin or exactly a pinned extension origin, kind extension; APP origin refused). Origin is only a coarse filter: Chrome omits it on
// extension GETs and Firefox's is per-install random (w3c/webextensions#777), so the bearer token and its kind are what authenticate.
export function createDeviceSessionAuth({sessions,native=false,extension=false,extensionOrigins=[]}={}){
 if(!sessions||typeof sessions.authenticate!=='function')throw new TypeError('Device sessions required');
 if(native&&extension)throw new TypeError('One client kind per route');
 if(extension&&(!Array.isArray(extensionOrigins)||extensionOrigins.some(o=>typeof o!=='string'||!/^(chrome-extension|moz-extension):\/\/[a-z0-9-]+$/.test(o))))throw new TypeError('Exact extension origins required');
 const exts=new Set(extensionOrigins),allowed=o=>extension?(o===null||exts.has(o)):(o===APP||(native&&o===null));
 const kindFor=o=>extension?'extension':o===APP?'web':'android';
 return Object.freeze({
 originAllowed(request){return allowed(request.headers.get('origin'));},
 async authenticate(request){
  const origin=request.headers.get('origin');
  if(new URL(request.url).origin!==API||!allowed(origin))return undefined;
  const token=bearerToken(request.headers.get('authorization'));if(!token)return undefined;
  const auth=await sessions.authenticate(token);
  // A handle of one kind never stands in for another, whatever Origin says.
  if(!auth||auth.clientKind!==kindFor(origin))return undefined;
  return {ownerId:auth.ownerId,deviceId:auth.deviceId,generation:auth.generation,expiresAt:auth.expiresAt};
 }});
}
