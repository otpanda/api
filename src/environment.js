import {createHost} from './host.js';
import {createRuntime} from './runtime.js';
import {base64urlDecode} from './tokens.js';

// Provisioning contract only. No key generation, persistence, registration or
// platform-header trust is implied. The deployment entrypoint must supply its
// own verified request-key resolver, not a caller-controlled forwarding header.
const keyId=/^[A-Za-z0-9_-]{1,64}$/;
function text(value,max){
 if(typeof value!=='string'||!value||value.length>max||value.trim()!==value)throw new TypeError('Invalid deployment configuration');
 return value;
}
export function snapshotEnvironment(env){
 if(!env||typeof env!=='object')throw new TypeError('Deployment bindings required');
 const {DB,ASSETS}=env;
 if(!DB||typeof DB.prepare!=='function'||typeof DB.batch!=='function')throw new TypeError('D1 binding required');
 if(ASSETS!==undefined&&typeof ASSETS.fetch!=='function')throw new TypeError('Asset binding required');
 const origin=text(env.APP_ORIGIN,2048),url=new URL(origin);
 if(url.protocol!=='https:'||url.origin!==origin||url.username||url.password)throw new TypeError('Exact HTTPS application origin required');
 const clientId=text(env.GOOGLE_CLIENT_ID,256),clientSecret=text(env.GOOGLE_CLIENT_SECRET,4096);
 if(!/^[A-Za-z0-9_-]+\.apps\.googleusercontent\.com$/.test(clientId))throw new TypeError('Registered Google web client required');
 const activeKeyId=text(env.ACTIVE_KEY_ID,64);
 if(!keyId.test(activeKeyId))throw new TypeError('Invalid active key identifier');
 let entries;
 try{entries=JSON.parse(text(env.ENCRYPTION_KEYRING,4096));}catch{throw new TypeError('Invalid encryption keyring');}
 // An array preserves duplicate identifiers for validation. At most eight
 // rotation keys; every key is an exact canonical 32-byte base64url value.
 if(!Array.isArray(entries)||entries.length<1||entries.length>8)throw new TypeError('Invalid encryption keyring');
 const raw=new Map();
 for(const entry of entries){
  if(!entry||typeof entry!=='object'||Array.isArray(entry)||Object.keys(entry).sort().join(',')!=='id,key'||typeof entry.id!=='string'||!keyId.test(entry.id)||raw.has(entry.id))throw new TypeError('Invalid encryption keyring');
  const bytes=base64urlDecode(entry.key,32);
  if(!bytes)throw new TypeError('Invalid encryption keyring');
  raw.set(entry.id,bytes);
 }
 if(!raw.has(activeKeyId))throw new TypeError('Active encryption key missing');
 // Secret fields remain inside this closure, not enumerable return values.
 return Object.freeze({origin,assets:ASSETS,async initialize(trustedRequestKey){
  if(typeof trustedRequestKey!=='function')throw new TypeError('Trusted request resolver required');
  const keys=new Map();
  for(const [id,bytes] of raw)keys.set(id,await crypto.subtle.importKey('raw',bytes,{name:'AES-GCM'},false,['encrypt','decrypt']));
  return createRuntime({db:DB,origin,keys,activeKeyId,clientId,clientSecret,trustedRequestKey});
 }});
}
export function createConfiguredHost(env,{trustedRequestKey}={}){
 if(typeof trustedRequestKey!=='function')throw new TypeError('Trusted request resolver required');
 const config=snapshotEnvironment(env);
 return createHost({origin:config.origin,assets:config.assets,initialize:()=>config.initialize(trustedRequestKey)});
}
