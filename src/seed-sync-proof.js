// Inactive. Signed proofs for native seed sync. Three purposes, each with its own label, exact field set and field order, so a
// signature for one purpose can never verify as another. The device builds the message itself (never from Dart-provided bytes).
import {importDevicePublicKey} from './device-key-proof.js';
import {base64urlEncode} from './tokens.js';
export const PROOF_LABEL='otpanda-seed-sync-v1';
export const PROOF_TTL=120000;
const id=v=>typeof v==='string'&&/^[A-Za-z0-9_-]{1,128}$/.test(v);
const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const nat=v=>Number.isSafeInteger(v)&&v>=0;
const FIELD={ownerId:id,keyId:id,deviceId:id,installId:v=>typeof v==='string'&&/^[A-Za-z0-9_-]{22,64}$/.test(v),generation:nat,epoch:nat,challenge:v=>typeof v==='string'&&/^[A-Za-z0-9_-]{43}$/.test(v),actionDigest:hex,ephemeralDigest:hex,entriesDigest:hex,expiresAt:nat};
export const PURPOSE_FIELDS=Object.freeze({
 'seed-sync-enroll':['ownerId','keyId','installId','generation','challenge','actionDigest','expiresAt'],
 'seed-sync-snapshot':['ownerId','keyId','deviceId','generation','epoch','challenge','expiresAt'],
 'seed-sync-revoke':['ownerId','keyId','deviceId','generation','challenge','expiresAt'],
 'seed-sync-status':['keyId','challenge','expiresAt'],
 'seed-sync-batch':['ownerId','keyId','deviceId','generation','epoch','challenge','ephemeralDigest','entriesDigest','expiresAt'],
});
export function seedSyncProofMessage(purpose,c){
 const fields=PURPOSE_FIELDS[purpose];
 if(!fields||!c||Object.keys(c).sort().join(',')!==[...fields].sort().join(',')||!fields.every(f=>FIELD[f](c[f])))throw new TypeError('Exact bounded seed-sync challenge required');
 return new TextEncoder().encode(JSON.stringify([PROOF_LABEL,purpose,...fields.map(f=>c[f])]));
}
export async function verifySeedSyncProof({jwk,purpose,challenge,signature,now=Date.now()}){
 try{
  if(!Number.isSafeInteger(now)||now<0||challenge.expiresAt<=now||challenge.expiresAt>now+PROOF_TTL||typeof signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(signature))return false;
  const bytes=Uint8Array.from(atob(signature.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0));
  if(bytes.length!==64||base64urlEncode(bytes)!==signature)return false;
  return await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},await importDevicePublicKey(jwk),bytes,seedSyncProofMessage(purpose,challenge));
 }catch{return false;}
}
