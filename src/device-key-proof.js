// Internal cryptographic primitive, unmounted. A signature proves possession of
// the enrolled key, not Android hardware storage or an OS verification prompt.
// Caller owns trusted enrollment, one-use challenge claim, rate limits and the
// final transactional account-generation/revocation check before any effect.
import {base64urlEncode} from './tokens.js';
const text=(v,max=128)=>typeof v==='string'&&v.length>=1&&v.length<=max&&/^[A-Za-z0-9_-]+$/.test(v);
export function deviceProofMessage(c) {
 if(!c||Object.keys(c).sort().join(',')!=='actionDigest,challenge,expiresAt,generation,keyId,ownerId,purpose'||!text(c.ownerId)||!text(c.keyId)||!text(c.challenge,43)||c.challenge.length!==43||!['enroll','step-up','recover-access'].includes(c.purpose)||!/^[a-f0-9]{64}$/.test(c.actionDigest)||!Number.isSafeInteger(c.generation)||c.generation<0||!Number.isSafeInteger(c.expiresAt)||c.expiresAt<0)throw new TypeError('Exact bounded device challenge required');
 return new TextEncoder().encode(JSON.stringify(['otpanda-device-proof-v1',c.purpose,c.ownerId,c.keyId,c.generation,c.challenge,c.actionDigest,c.expiresAt]));
}
export async function importDevicePublicKey(jwk) {
 if(!jwk||Object.keys(jwk).sort().join(',')!=='crv,kty,x,y'||jwk.kty!=='EC'||jwk.crv!=='P-256'||![jwk.x,jwk.y].every(v=>typeof v==='string'&&/^[A-Za-z0-9_-]{43}$/.test(v)))throw new TypeError('Public P-256 key required');
 return crypto.subtle.importKey('jwk',jwk,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
}
export async function verifyDeviceKeyProof({jwk,challenge,signature,now=Date.now()}) {
 try {
  if(!Number.isSafeInteger(now)||now<0||challenge.expiresAt<=now||challenge.expiresAt>now+120000||typeof signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(signature))return false;
  const bytes=Uint8Array.from(atob(signature.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0));
  if(bytes.length!==64||base64urlEncode(bytes)!==signature)return false;
  return await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},await importDevicePublicKey(jwk),bytes,deviceProofMessage(challenge));
 }catch{return false;}
}
