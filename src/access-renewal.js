// Silent access renewal for a browser tab that holds a memory-only P-256 key.
// The key is bound only by BrowserExchangeService.exchange (one-use code plus PKCE).
// A renewal needs the unexpired, unrenewed access handle of that exact lineage AND
// an ECDSA signature over a message naming the domain, endpoint, lineage, that
// handle and a short request expiry. It spends the handle (single winner), issues
// one successor in the same lineage, and extends only the device idle expiry.
// It mints no refresh cookie, code, session, recognition or fresh-proof, and never
// touches the auth method. A bad signature spends and revokes nothing.
import {SESSION_METHOD_JOIN as MJ,SESSION_METHOD_ACTIVE as MA} from './session-method.js';
import {generateAccessToken,parseAccessToken,digestSecret,digestToHex,base64urlDecode} from './tokens.js';
export const RENEW_DOMAIN='otpanda-renew-v1',RENEW_ENDPOINT='POST /auth/renew',RENEW_SKEW_MS=60_000;
const ACCESS=300_000,IDLE=30*24*60*60*1000,MAX_ACCESS=64,MAX_LINEAGES=16;
export {MAX_LINEAGES};
const ID=/^[A-Za-z0-9_-]{8,64}$/,SIG=/^[A-Za-z0-9_-]{86}$/,KEY=/^[A-Za-z0-9_-]{87}$/;
const ACTIVE=`d.revoked_at IS NULL AND d.created_at<=?3 AND d.expires_at>?3 AND ${MA} AND s.generation=d.generation AND d.client_kind='web'`;
export function renewalMessage({lineageId,handleId,expiresAt}){return new TextEncoder().encode([RENEW_DOMAIN,RENEW_ENDPOINT,lineageId,handleId,String(expiresAt)].join('\n'));}
// Strict public key: 65 raw bytes, uncompressed (0x04) and a valid P-256 point.
// Canonical first-party cookie deadline: the cookie value is the one unused refresh handle, set with
// Max-Age to (its creation + IDLE). Rotation (any tab) marks the old handle used, so the newest unused
// handle IS the cookie in the shared jar. Signed renewals never touch this table. Undefined when none.
export async function firstPartyExpiresAt(db,deviceId){
 const r=await db.prepare('SELECT max(created_at) AS c FROM device_refresh_handles WHERE device_id=?1 AND used_at IS NULL').bind(deviceId).first();
 return Number.isSafeInteger(r?.c)?r.c+IDLE:undefined;
}
export async function importRenewalKey(text){
 if(typeof text!=='string'||!KEY.test(text))return undefined;
 let raw;try{raw=base64urlDecode(text,65);}catch{return undefined;}
 if(!raw||raw.length!==65||raw[0]!==4)return undefined;
 try{return await crypto.subtle.importKey('raw',raw,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);}catch{return undefined;}
}
async function digest(token){const p=parseAccessToken(token);return p?{id:p.tokenId,hash:digestToHex(await digestSecret(p.secret))}:undefined;}
export class AccessRenewal{
 constructor(db,{clock=Date.now}={}){this.db=db;this.clock=clock;}
 now(){const n=this.clock();if(!Number.isSafeInteger(n)||n<0)throw new TypeError('Valid instant required');return n;}
 // status: renewed | renewed-elsewhere (spent: replay or lost race) | denied
 async renew({token,lineageId,signature,expiresAt}){
  if(typeof lineageId!=='string'||!ID.test(lineageId)||typeof signature!=='string'||!SIG.test(signature)||!Number.isSafeInteger(expiresAt))return {status:'denied'};
  const t=await digest(token);if(!t)return {status:'denied'};const now=this.now();
  if(expiresAt<now||expiresAt>now+RENEW_SKEW_MS)return {status:'denied'};
  const row=await this.db.prepare(`SELECT a.renewed_at,a.device_id,l.public_key FROM device_access_handles a JOIN access_lineages l ON l.lineage_id=a.lineage_id AND l.device_id=a.device_id JOIN device_sessions d ON d.device_id=a.device_id ${MJ} JOIN account_security s ON s.owner_id=d.owner_id WHERE a.handle_id=?1 AND a.secret_digest=?2 AND a.lineage_id=?4 AND a.created_at<=?3 AND a.expires_at>?3 AND ${ACTIVE}`).bind(t.id,t.hash,now,lineageId).first();
  if(!row)return {status:'denied'};
  if(row.renewed_at!==null)return {status:'renewed-elsewhere'};
  const key=await importRenewalKey(row.public_key);if(!key)return {status:'denied'};
  let ok=false;try{ok=await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,base64urlDecode(signature,64),renewalMessage({lineageId,handleId:t.id,expiresAt}));}catch{}
  if(!ok)return {status:'denied'};
  const next=generateAccessToken(),nextHash=digestToHex(await digestSecret(next.secret)),receipt=generateAccessToken().tokenId,at=this.now();
  const guard=`EXISTS(SELECT 1 FROM device_sessions d ${MJ} JOIN account_security s ON s.owner_id=d.owner_id WHERE d.device_id=a.device_id AND ${ACTIVE})`;
  const results=await this.db.batch([
   // Single winner: only an unrenewed handle of this lineage under current guards.
   this.db.prepare(`UPDATE device_access_handles AS a SET renewed_at=?3,renew_receipt=?5 WHERE a.handle_id=?1 AND a.secret_digest=?2 AND a.lineage_id=?4 AND a.renewed_at IS NULL AND a.expires_at>?3 AND ${guard}`).bind(t.id,t.hash,at,lineageId,receipt),
   this.db.prepare(`INSERT INTO device_access_handles (handle_id,secret_digest,device_id,created_at,expires_at,lineage_id) SELECT ?6,?7,a.device_id,?3,?8,a.lineage_id FROM device_access_handles a WHERE a.handle_id=?1 AND a.renew_receipt=?5 AND a.lineage_id=?4 AND (SELECT count(*) FROM device_access_handles WHERE device_id=a.device_id AND expires_at>?3)<${MAX_ACCESS} AND ${guard}`).bind(t.id,t.hash,at,lineageId,receipt,next.tokenId,nextHash,at+ACCESS),
   // Activity-driven idle extension, only when the successor exists; never shortens.
   this.db.prepare('UPDATE device_sessions SET last_used_at=?1,expires_at=max(expires_at,?2) WHERE device_id=(SELECT device_id FROM device_access_handles WHERE handle_id=?3) AND EXISTS(SELECT 1 FROM device_access_handles WHERE handle_id=?3)').bind(at,at+IDLE,next.tokenId),
   // Capacity refused the successor: give the handle back instead of stranding the tab.
   this.db.prepare('UPDATE device_access_handles SET renewed_at=NULL,renew_receipt=NULL WHERE handle_id=?1 AND renew_receipt=?2 AND NOT EXISTS(SELECT 1 FROM device_access_handles WHERE handle_id=?3)').bind(t.id,receipt,next.tokenId),
  ]);
  if(results[1].meta.changes===1){const fp=await firstPartyExpiresAt(this.db,row.device_id);return {status:'renewed',access:next.token,accessExpiresAt:at+ACCESS,renewal:{lineageId,handleId:next.tokenId,serverTime:at,...(fp===undefined?{}:{firstPartyExpiresAt:fp})}};}
  return {status:results[0].meta.changes===1?'denied':'renewed-elsewhere'};
 }
}
