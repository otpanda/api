// Inactive. Seals exported TOTP seeds to the client's ephemeral P-256 key: ECDH (fresh server key per export), HKDF-SHA256, AES-256-GCM,
// one fresh nonce per entry. Derived from seed-sync-seal.js (stage commit 2feae7c, not on this branch) with its own label, so a sealed
// export can never be opened as a seed-sync batch or the reverse. The plaintext is the seed bytes only. The AAD is rebuilt independently by
// the client from what it approved; the server sends no AAD. No claim is made that either side erases keys or derived secrets.
import {base64urlEncode,base64urlDecode} from './tokens.js';
export const EXPORT_SEAL_LABEL='otpanda-totp-export-seal-v1';
const enc=new TextEncoder(),hexOf=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join(''),unhex=h=>Uint8Array.from(h.match(/../g),x=>parseInt(x,16));
export const sha256Hex=async b=>hexOf(await crypto.subtle.digest('SHA-256',b));
export function exportAad({ownerId,deviceId,generation,entryId,seedVersion,algorithm,digits,period,actionDigest,ephemeralDigest,label=null,account=null,issuer=null,catalogId=null}){
 return enc.encode(JSON.stringify([EXPORT_SEAL_LABEL,ownerId,deviceId,generation,entryId,seedVersion,algorithm,digits,period,actionDigest,ephemeralDigest,label,account,issuer,catalogId]));
}
export async function importClientEphemeral(rawB64){
 if(typeof rawB64!=='string'||rawB64.length>100)return undefined;
 const raw=base64urlDecode(rawB64,65);
 if(!raw||raw.length!==65||raw[0]!==4||base64urlEncode(raw)!==rawB64)return undefined;
 try{return {raw,key:await crypto.subtle.importKey('raw',raw,{name:'ECDH',namedCurve:'P-256'},false,[])};}catch{return undefined;}
}
async function sessionKey({privateKey,peerPublic,actionDigest,ephemeralDigest,serverDigest}){
 const bits=await crypto.subtle.deriveBits({name:'ECDH',public:peerPublic},privateKey,256);
 const base=await crypto.subtle.importKey('raw',bits,'HKDF',false,['deriveKey']);
 return crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:unhex(actionDigest),info:enc.encode(`${EXPORT_SEAL_LABEL}|${ephemeralDigest}|${serverDigest}`)},base,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
// items: [{aad (fields above except actionDigest/ephemeralDigest), secret:Uint8Array}]. serverKeyPair/nonces are injectable for known-answer tests only.
export async function sealExport({client,actionDigest,ephemeralDigest,items,serverKeyPair,nonces}){
 const pair=serverKeyPair??await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
 const serverRaw=new Uint8Array(await crypto.subtle.exportKey('raw',pair.publicKey)),serverDigest=await sha256Hex(serverRaw);
 const key=await sessionKey({privateKey:pair.privateKey,peerPublic:client.key,actionDigest,ephemeralDigest,serverDigest});
 const out=[];
 for(const [i,it] of items.entries()){
  const nonce=nonces?.[i]??crypto.getRandomValues(new Uint8Array(12));
  const ct=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce,additionalData:exportAad({...it.aad,actionDigest,ephemeralDigest}),tagLength:128},key,it.secret));
  out.push({nonce:base64urlEncode(nonce),ciphertext:base64urlEncode(ct)});
 }
 return {serverPublicKey:base64urlEncode(serverRaw),entries:out};
}
// Reference opener (what the client must do), used by tests. Throws on any mismatch.
export async function openExport({clientPrivateKey,serverPublicKey,actionDigest,ephemeralDigest,aad,nonce,ciphertext}){
 const raw=base64urlDecode(serverPublicKey,65),pub=await crypto.subtle.importKey('raw',raw,{name:'ECDH',namedCurve:'P-256'},false,[]);
 const key=await sessionKey({privateKey:clientPrivateKey,peerPublic:pub,actionDigest,ephemeralDigest,serverDigest:await sha256Hex(raw)});
 return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:base64urlDecode(nonce,12),additionalData:exportAad({...aad,actionDigest,ephemeralDigest}),tagLength:128},key,base64urlDecode(ciphertext,Math.floor(ciphertext.length*6/8))));
}
