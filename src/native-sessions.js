// Native Android sessions, isolated. A native device is created only inside the one-use PKCE
// claim; the Keystore P-256 public key is bound there and nowhere else. There is no bearer
// refresh secret: renewal and logout are signed server nonces. Device ID alone is never authority.
import {SESSION_METHOD_JOIN as MJ,SESSION_METHOD_ACTIVE as MA} from './session-method.js';
import {generateAccessToken,parseAccessToken,digestSecret,digestToHex,base64urlDecode} from './tokens.js';
import {importRenewalKey} from './access-renewal.js';
import {pkceChallenge} from './browser-exchanges.js';
export const NATIVE_REDIRECT='https://otpanda-api.abrahammurciano.workers.dev/app-return';
export const NATIVE_DOMAIN='otpanda-native-v1',NATIVE_ENDPOINTS=Object.freeze({renew:'POST /auth/native/renew',logout:'POST /auth/native/logout'});
const TTL=60_000,ACCESS=900_000,IDLE=30*24*60*60*1000,CHALLENGE_TTL=60_000,MAX_OUTSTANDING=8,MAX_EXCHANGES=8,MAX_ACCESS=64,MAX_DEVICES=50;
const CH=/^[A-Za-z0-9_-]{43}$/,SIG=/^[A-Za-z0-9_-]{86}$/,ID=/^[A-Za-z0-9_-]{12}$/;
// Message the device signs (nonce is the full opaque token string returned by challenge): UTF-8, LF separators, no trailing newline, expiry as the decimal integer the server returned.
export const EXTENSION_DOMAIN='otpanda-extension-v1',EXTENSION_ENDPOINTS=Object.freeze({renew:'POST /auth/extension/renew',logout:'POST /auth/extension/logout'});
// A profile fixes the device kind, the signed-message domain and the EXACT redirect URIs a code may be minted for. Redirects are compared with ===.
export const NATIVE_PROFILE=Object.freeze({kind:'android',domain:NATIVE_DOMAIN,endpoints:NATIVE_ENDPOINTS,redirects:Object.freeze([NATIVE_REDIRECT])});
export function extensionProfile(redirects){
 if(!Array.isArray(redirects)||!redirects.length||redirects.length>8)throw new TypeError('Exact extension redirect URIs required');
 for(const r of redirects){let u;try{u=new URL(r);}catch{throw new TypeError('Exact extension redirect URIs required');}
  if(u.protocol!=='https:'||u.username||u.password||u.port||u.search||u.hash||u.pathname!=='/'||u.href!==r||u.hostname.includes('*')||/^(otpanda-api|otpanda)\./.test(u.hostname))throw new TypeError('Exact extension redirect URIs required');}
 return Object.freeze({kind:'extension',domain:EXTENSION_DOMAIN,endpoints:EXTENSION_ENDPOINTS,redirects:Object.freeze([...new Set(redirects)])});
}
export function nativeMessage({purpose,deviceId,nonce,expiresAt,profile=NATIVE_PROFILE}){
 return new TextEncoder().encode([profile.domain,profile.endpoints[purpose],deviceId,nonce,String(expiresAt)].join('\n'));
}
async function digest(token){const p=parseAccessToken(token);return p?{id:p.tokenId,hash:digestToHex(await digestSecret(p.secret))}:undefined;}
const ACTIVE=(n,kind)=>`d.revoked_at IS NULL AND d.created_at<=?${n} AND d.expires_at>?${n} AND ${MA} AND s.generation=d.generation AND d.client_kind='${kind}'`;
export class NativeSessionService{
 constructor(db,{clock=Date.now,profile=NATIVE_PROFILE}={}){if(!['android','extension'].includes(profile?.kind))throw new TypeError('Known session profile required');this.db=db;this.clock=clock;this.profile=profile;this.kind=profile.kind;}
 now(){const n=this.clock();if(!Number.isSafeInteger(n)||n<0)throw new TypeError('Valid instant required');return n;}
 // Authority: an ACTIVE web device chosen by the HTTP boundary from its verified first-party cookie. The method,
 // owner and generation are copied from that device row, never from a request.
 async mint({sourceDeviceId,challenge,redirectUri}){
  if(typeof sourceDeviceId!=='string'||typeof challenge!=='string'||!CH.test(challenge)||!this.profile.redirects.includes(redirectUri))return undefined;
  const secret=generateAccessToken(),hash=digestToHex(await digestSecret(secret.secret)),now=this.now();
  const r=await this.db.prepare(`INSERT INTO native_exchanges (exchange_id,secret_digest,owner_id,credential_id,provider_identity_id,generation,challenge,redirect_uri,created_at,expires_at,client_kind,source_device_id) SELECT ?1,?2,d.owner_id,d.credential_id,d.provider_identity_id,d.generation,?4,?5,?3,?6,?8,CASE WHEN ?8='extension' THEN d.device_id END FROM device_sessions d ${MJ} JOIN account_security s ON s.owner_id=d.owner_id WHERE d.device_id=?7 AND d.revoked_at IS NULL AND d.created_at<=?3 AND d.expires_at>?3 AND ${MA} AND s.generation=d.generation AND d.client_kind='web' AND (d.credential_id IS NOT NULL OR NOT EXISTS(SELECT 1 FROM new_device_verification v WHERE v.owner_id=d.owner_id)) AND (SELECT count(*) FROM native_exchanges WHERE owner_id=d.owner_id AND expires_at>?3)<${MAX_EXCHANGES}`).bind(secret.tokenId,hash,now,challenge,redirectUri,now+TTL,sourceDeviceId,this.kind).run();
  if(r.meta.changes<1)return undefined;
  // Optional: carry this web device's live first-method grant so the exchange can hand the phone a fresh 120 s grant (never longer than the web grant).
  await this.db.prepare('UPDATE native_exchanges SET carried_web_grant_id=(SELECT g.grant_id FROM google_enrollment_grants g WHERE g.device_id=?2 AND g.owner_id=native_exchanges.owner_id AND g.consumed_at IS NULL AND g.expires_at>?3 ORDER BY g.created_at DESC LIMIT 1) WHERE exchange_id=?1').bind(secret.tokenId,sourceDeviceId,now).run().catch(()=>undefined);
  return {code:secret.token,expiresAt:now+TTL};
 }
 // The device, its key and its first access handle commit together or not at all.
 async exchange({code,verifier,redirectUri,renewalKey}){
  if(!this.profile.redirects.includes(redirectUri)||!await importRenewalKey(renewalKey))return undefined; // refused before the code is spent
  const c=await digest(code),challenge=await pkceChallenge(verifier);if(!c||!challenge)return undefined;
  const now=this.now();
  const claimed=await this.db.prepare('DELETE FROM native_exchanges WHERE exchange_id=?1 AND secret_digest=?2 AND challenge=?3 AND redirect_uri=?4 AND created_at<=?5 AND expires_at>?5 AND client_kind=?6 RETURNING owner_id,credential_id,provider_identity_id,generation,expires_at,carried_web_grant_id,source_device_id').bind(c.id,c.hash,challenge,redirectUri,now,this.kind).first();
  if(!claimed)return undefined;
  const at=this.now();if(at<now||at>=claimed.expires_at)return undefined;
  const dev=generateAccessToken().tokenId,access=generateAccessToken(),hash=digestToHex(await digestSecret(access.secret));
  const methodOk=`EXISTS(SELECT 1 FROM account_security s WHERE s.owner_id=?2 AND s.generation=?4) AND ((?3 IS NOT NULL AND EXISTS(SELECT 1 FROM passkey_credentials p WHERE p.credential_id=?3 AND p.owner_id=?2 AND p.revoked_at IS NULL)) OR (?7 IS NOT NULL AND EXISTS(SELECT 1 FROM provider_identities g WHERE g.identity_id=?7 AND g.owner_id=?2 AND g.revoked_at IS NULL)))`;
  const results=await this.db.batch([
   this.db.prepare(`INSERT INTO device_sessions (device_id,owner_id,credential_id,provider_identity_id,generation,client_kind,created_at,last_used_at,expires_at) SELECT ?1,?2,?3,?7,?4,'${this.kind}',?5,?5,?6 WHERE (SELECT count(*) FROM device_sessions WHERE owner_id=?2 AND revoked_at IS NULL AND expires_at>?5)<${MAX_DEVICES} AND ${methodOk} AND (?3 IS NOT NULL OR NOT EXISTS(SELECT 1 FROM new_device_verification v WHERE v.owner_id=?2)) AND (${this.kind==='android'?'?8 IS NULL OR ':''}EXISTS(SELECT 1 FROM device_sessions w WHERE w.device_id=?8 AND w.owner_id=?2 AND w.client_kind='web' AND w.revoked_at IS NULL AND w.expires_at>?5 AND w.generation=?4))`).bind(dev,claimed.owner_id,claimed.credential_id,claimed.generation,at,at+IDLE,claimed.provider_identity_id,claimed.source_device_id??null),
   this.db.prepare('INSERT INTO native_keys (device_id,public_key,created_at) SELECT ?1,?2,?3 WHERE EXISTS(SELECT 1 FROM device_sessions WHERE device_id=?1)').bind(dev,renewalKey,at),
   this.db.prepare('INSERT INTO device_access_handles (handle_id,secret_digest,device_id,created_at,expires_at) SELECT ?1,?2,?3,?4,?5 WHERE EXISTS(SELECT 1 FROM native_keys WHERE device_id=?3)').bind(access.tokenId,hash,dev,at,at+ACCESS),
  ]);
  if(results[2].meta.changes<1)return undefined;
  const out={deviceId:dev,access:access.token,accessExpiresAt:at+ACCESS,idleExpiresAt:at+IDLE};
  if(claimed.carried_web_grant_id){
   // Best effort and optional: absence never fails the exchange. Claim the web grant once and mint a new one for this device, capped at the web grant's expiry.
   const g=generateAccessToken(),gh=digestToHex(await digestSecret(g.secret));
   try{const rs=await this.db.batch([
    this.db.prepare('UPDATE google_enrollment_grants SET consumed_at=?1 WHERE grant_id=?2 AND owner_id=?3 AND consumed_at IS NULL AND expires_at>?1 AND EXISTS(SELECT 1 FROM device_sessions WHERE device_id=?4 AND owner_id=?3 AND revoked_at IS NULL)').bind(at,claimed.carried_web_grant_id,claimed.owner_id,dev),
    this.db.prepare('INSERT INTO google_enrollment_grants(grant_id,secret_digest,owner_id,device_id,generation,issuer,subject,created_at,expires_at) SELECT ?1,?2,w.owner_id,?3,w.generation,w.issuer,w.subject,?4,min(w.expires_at,?4+120000) FROM google_enrollment_grants w WHERE w.grant_id=?5 AND w.consumed_at=?4 AND w.generation=?6 AND changes()=1').bind(g.tokenId,gh,dev,at,claimed.carried_web_grant_id,claimed.generation),
   ]);if(rs[1].meta.changes>=1)out.enrollGrant=g.token;}catch{}
  }
  return out;
 }
 // Provider (Google) native device. The identity link, generation and "extra verification" gate are re-checked inside the write;
 // a protected owner (new_device_verification) is refused so the browser flow, which can verify, must be used.
 // recognition: {id,digest} presented by this install (same recognized_browsers row web uses). newRecognition: {id,digest} to record in the same batch.
 async issueProvider({ownerId,generation,issuer,subject,renewalKey,recognition,newRecognition,strong=false}){
  if(this.kind!=='android'||!await importRenewalKey(renewalKey)||typeof ownerId!=='string'||!Number.isSafeInteger(generation)||typeof issuer!=='string'||typeof subject!=='string')return undefined;
  const at=this.now(),dev=generateAccessToken().tokenId,access=generateAccessToken(),hash=digestToHex(await digestSecret(access.secret));
  const link=`(SELECT g.identity_id FROM provider_identities g WHERE g.issuer=?7 AND g.subject=?8 AND g.owner_id=?2 AND g.revoked_at IS NULL)`;
  const results=await this.db.batch([
   this.db.prepare(`INSERT INTO device_sessions (device_id,owner_id,credential_id,provider_identity_id,generation,client_kind,created_at,last_used_at,expires_at) SELECT ?1,?2,NULL,${link},?4,'${this.kind}',?5,?5,?6 WHERE ${link} IS NOT NULL AND EXISTS(SELECT 1 FROM account_security s WHERE s.owner_id=?2 AND s.generation=?4) AND (SELECT count(*) FROM device_sessions WHERE owner_id=?2 AND revoked_at IS NULL AND expires_at>?5)<${MAX_DEVICES} AND (${strong===true?'1=1 OR ':''}NOT EXISTS(SELECT 1 FROM new_device_verification v WHERE v.owner_id=?2) OR EXISTS(SELECT 1 FROM recognized_browsers r WHERE r.recognition_id=?9 AND r.secret_digest=?10 AND r.owner_id=?2 AND r.generation=?4 AND r.revoked_at IS NULL AND r.provider_identity_id=${link}))`).bind(dev,ownerId,null,generation,at,at+IDLE,issuer,subject,recognition?.id??'',recognition?.digest??''),
   this.db.prepare('INSERT INTO native_keys (device_id,public_key,created_at) SELECT ?1,?2,?3 WHERE EXISTS(SELECT 1 FROM device_sessions WHERE device_id=?1)').bind(dev,renewalKey,at),
   this.db.prepare('INSERT INTO device_access_handles (handle_id,secret_digest,device_id,created_at,expires_at) SELECT ?1,?2,?3,?4,?5 WHERE EXISTS(SELECT 1 FROM native_keys WHERE device_id=?3)').bind(access.tokenId,hash,dev,at,at+ACCESS),
   this.db.prepare('INSERT INTO recognized_browsers (recognition_id,secret_digest,owner_id,provider_identity_id,generation,created_at) SELECT ?1,?2,d.owner_id,d.provider_identity_id,d.generation,?4 FROM device_sessions d WHERE length(?1)>0 AND d.device_id=?3 AND d.provider_identity_id IS NOT NULL AND EXISTS(SELECT 1 FROM device_access_handles WHERE device_id=?3)').bind(newRecognition?.id??'',newRecognition?.digest??'',dev,at),
  ]);
  if(results[2].meta.changes<1)return undefined;
  return {deviceId:dev,access:access.token,accessExpiresAt:at+ACCESS,idleExpiresAt:at+IDLE,recorded:!!newRecognition&&results[3].meta.changes>=1};
 }
 // Passkey native device: proof comes from a just-verified discoverable assertion (<=120 s). Credential, generation and device cap are
 // re-checked inside the write. A passkey is itself a strong method, so the extra-verification gate does not apply.
 async issuePasskey({proof,renewalKey}){
  if(this.kind!=='android'||!await importRenewalKey(renewalKey)||!proof||proof.purpose!=='authenticate'||typeof proof.ownerId!=='string'||typeof proof.credentialId!=='string'||!Number.isSafeInteger(proof.generation)||!Number.isSafeInteger(proof.verifiedAt))return undefined;
  const at=this.now();if(proof.verifiedAt>at||at-proof.verifiedAt>=120_000)return undefined;
  const dev=generateAccessToken().tokenId,access=generateAccessToken(),hash=digestToHex(await digestSecret(access.secret));
  const results=await this.db.batch([
   this.db.prepare(`INSERT INTO device_sessions (device_id,owner_id,credential_id,provider_identity_id,generation,client_kind,created_at,last_used_at,expires_at) SELECT ?1,?2,?3,NULL,?4,'${this.kind}',?5,?5,?6 WHERE EXISTS(SELECT 1 FROM passkey_credentials p WHERE p.credential_id=?3 AND p.owner_id=?2 AND p.revoked_at IS NULL) AND EXISTS(SELECT 1 FROM account_security s WHERE s.owner_id=?2 AND s.generation=?4) AND (SELECT count(*) FROM device_sessions WHERE owner_id=?2 AND revoked_at IS NULL AND expires_at>?5)<${MAX_DEVICES}`).bind(dev,proof.ownerId,proof.credentialId,proof.generation,at,at+IDLE),
   this.db.prepare('INSERT INTO native_keys (device_id,public_key,created_at) SELECT ?1,?2,?3 WHERE EXISTS(SELECT 1 FROM device_sessions WHERE device_id=?1)').bind(dev,renewalKey,at),
   this.db.prepare('INSERT INTO device_access_handles (handle_id,secret_digest,device_id,created_at,expires_at) SELECT ?1,?2,?3,?4,?5 WHERE EXISTS(SELECT 1 FROM native_keys WHERE device_id=?3)').bind(access.tokenId,hash,dev,at,at+ACCESS),
  ]);
  if(results[2].meta.changes<1)return undefined;
  return {deviceId:dev,access:access.token,accessExpiresAt:at+ACCESS,idleExpiresAt:at+IDLE};
 }
 // Oracle-free: the response shape is identical whether or not the device exists. A row is stored only for an active native device
 // and only under the outstanding cap. The nonce alone grants nothing; it must be signed with the bound key.
 async challenge({deviceId,purpose}){
  const secret=generateAccessToken(),hash=digestToHex(await digestSecret(secret.secret)),now=this.now(),expiresAt=now+CHALLENGE_TTL;
  const out={deviceId:typeof deviceId==='string'?deviceId:'',nonce:secret.token,expiresAt};
  if(!['renew','logout'].includes(purpose)||typeof deviceId!=='string'||!ID.test(deviceId))return out;
  await this.db.prepare(`INSERT INTO native_challenges (challenge_id,secret_digest,device_id,purpose,created_at,expires_at) SELECT ?1,?2,d.device_id,?4,?3,?5 FROM device_sessions d ${MJ} JOIN account_security s ON s.owner_id=d.owner_id WHERE d.device_id=?6 AND ${ACTIVE(3,this.kind)} AND (SELECT count(*) FROM native_challenges WHERE device_id=d.device_id AND used_at IS NULL AND expires_at>?3)<${MAX_OUTSTANDING}`).bind(secret.tokenId,hash,now,purpose,expiresAt,deviceId).run();
  return out;
 }
 // Shared by renew and logout. Verify first (a bad signature spends nothing), then spend the nonce atomically with the effect.
 async verified({deviceId,nonce,expiresAt,signature,purpose}){
  if(typeof deviceId!=='string'||!ID.test(deviceId)||typeof signature!=='string'||!SIG.test(signature)||!Number.isSafeInteger(expiresAt))return undefined;
  const n=await digest(nonce);if(!n)return undefined;const now=this.now();
  const row=await this.db.prepare(`SELECT k.public_key FROM native_challenges c JOIN device_sessions d ON d.device_id=c.device_id ${MJ} JOIN account_security s ON s.owner_id=d.owner_id JOIN native_keys k ON k.device_id=d.device_id WHERE c.challenge_id=?1 AND c.secret_digest=?2 AND c.device_id=?4 AND c.purpose=?5 AND c.used_at IS NULL AND c.expires_at=?6 AND c.created_at<=?3 AND c.expires_at>?3 AND ${ACTIVE(3,this.kind)}`).bind(n.id,n.hash,now,deviceId,purpose,expiresAt).first();
  if(!row)return undefined;
  const key=await importRenewalKey(row.public_key);if(!key)return undefined;
  let ok=false;try{ok=await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,base64urlDecode(signature,64),nativeMessage({purpose,deviceId,nonce,expiresAt,profile:this.profile}));}catch{}
  return ok?{nonceId:n.id,hash:n.hash}:undefined;
 }
 async renew({deviceId,nonce,expiresAt,signature}){
  const v=await this.verified({deviceId,nonce,expiresAt,signature,purpose:'renew'});if(!v)return {status:'denied'};
  const access=generateAccessToken(),hash=digestToHex(await digestSecret(access.secret)),at=this.now();
  const guard=`EXISTS(SELECT 1 FROM device_sessions d ${MJ} JOIN account_security s ON s.owner_id=d.owner_id WHERE d.device_id=?3 AND ${ACTIVE(4,this.kind)})`;
  const results=await this.db.batch([
   // Single winner: only an unused, unexpired nonce of this device and purpose under current guards.
   this.db.prepare(`UPDATE native_challenges SET used_at=?4,receipt=?5 WHERE challenge_id=?1 AND secret_digest=?2 AND device_id=?3 AND purpose='renew' AND used_at IS NULL AND expires_at>?4 AND ${guard}`).bind(v.nonceId,v.hash,deviceId,at,access.tokenId),
   this.db.prepare(`INSERT INTO device_access_handles (handle_id,secret_digest,device_id,created_at,expires_at) SELECT ?1,?2,?3,?4,?5 WHERE EXISTS(SELECT 1 FROM native_challenges WHERE challenge_id=?6 AND receipt=?1) AND (SELECT count(*) FROM device_access_handles WHERE device_id=?3 AND expires_at>?4)<${MAX_ACCESS} AND ${guard}`).bind(access.tokenId,hash,deviceId,at,at+ACCESS,v.nonceId),
   this.db.prepare('UPDATE device_sessions SET last_used_at=?1,expires_at=max(expires_at,?2) WHERE device_id=?3 AND EXISTS(SELECT 1 FROM device_access_handles WHERE handle_id=?4)').bind(at,at+IDLE,deviceId,access.tokenId),
  ]);
  if(results[1].meta.changes<1)return {status:results[0].meta.changes>=1?'denied':'replayed'};
  return {status:'renewed',access:access.token,accessExpiresAt:at+ACCESS,idleExpiresAt:at+IDLE};
 }
 // Signed logout. Access-bearer logout is logoutAccess. Revokes only this device.
 async logout({deviceId,nonce,expiresAt,signature}){
  const v=await this.verified({deviceId,nonce,expiresAt,signature,purpose:'logout'});if(!v)return false;
  const at=this.now(),receipt=generateAccessToken().tokenId,r=await this.db.batch([
   this.db.prepare("UPDATE native_challenges SET used_at=?3,receipt=?5 WHERE challenge_id=?1 AND secret_digest=?2 AND purpose='logout' AND used_at IS NULL AND expires_at>?3 AND device_id=?4").bind(v.nonceId,v.hash,at,deviceId,receipt),
   this.db.prepare(`UPDATE device_sessions SET revoked_at=?1 WHERE device_id=?2 AND client_kind='${this.kind}' AND revoked_at IS NULL AND EXISTS(SELECT 1 FROM native_challenges WHERE challenge_id=?3 AND receipt=?4)`).bind(at,deviceId,v.nonceId,receipt),
  ]);
  return r[1].meta.changes>=1;
 }
 async logoutAccess({deviceId}){const r=await this.db.prepare(`UPDATE device_sessions SET revoked_at=?1 WHERE device_id=?2 AND client_kind='${this.kind}' AND revoked_at IS NULL`).bind(this.now(),deviceId).run();return r.meta.changes>=1;}
 async cleanup({limit=100}={}){
  if(!Number.isSafeInteger(limit)||limit<1||limit>500)throw new TypeError('Bounded cleanup required');const now=this.now();
  const r=await this.db.batch([
   this.db.prepare('DELETE FROM native_exchanges WHERE exchange_id IN (SELECT exchange_id FROM native_exchanges WHERE expires_at<=?1 ORDER BY expires_at LIMIT ?2)').bind(now,limit),
   this.db.prepare('DELETE FROM native_challenges WHERE challenge_id IN (SELECT challenge_id FROM native_challenges WHERE expires_at<=?1 ORDER BY expires_at LIMIT ?2)').bind(now,limit),
  ]);return r.map(x=>x.meta.changes);
 }
}
