// Internal persistent-session store. No cookie, CORS or token exchange endpoint.
// Only this server may pass results of cryptographic verification to issue().
import { generateAccessToken, parseAccessToken, digestSecret, digestToHex } from './tokens.js';
const IDLE=30*24*60*60*1000,ACCESS=5*60*1000,PROOF=120_000,GRACE=10_000;
async function tokenDigest(token) { const p=parseAccessToken(token);return p?{id:p.tokenId,digest:digestToHex(await digestSecret(p.secret))}:undefined; }
async function freshHandle() { const h=generateAccessToken();return {...h,digest:digestToHex(await digestSecret(h.secret))}; }
const ACTIVE=`d.revoked_at IS NULL AND d.created_at <= ?3 AND d.expires_at > ?3 AND p.revoked_at IS NULL AND p.owner_id=d.owner_id AND s.generation=d.generation`;
export class DeviceSessionService {
  constructor(db,{clock=Date.now}={}){this.db=db;this.clock=clock;}
  now(){const n=this.clock();if(!Number.isSafeInteger(n)||n<0)throw new TypeError('Valid instant required');return n;}
  async issue({proof,clientKind}) {
    let now=this.now();
    if(!['web','android','extension'].includes(clientKind)||!proof||proof.purpose!=='authenticate'||!Number.isSafeInteger(proof.verifiedAt)||proof.verifiedAt>now||now-proof.verifiedAt>=PROOF||!Number.isSafeInteger(proof.generation)||typeof proof.ownerId!=='string'||typeof proof.credentialId!=='string')return undefined;
    const deviceId=crypto.randomUUID(),refresh=await freshHandle(),access=await freshHandle();
    now=this.now();
    if(proof.verifiedAt>now||now-proof.verifiedAt>=PROOF)return undefined;
    // The final write checks generation and revocation, closing the race after
    // signature verification. Child inserts require that exact device row.
    await this.db.batch([
      this.db.prepare('INSERT INTO device_sessions (device_id,owner_id,credential_id,generation,client_kind,created_at,last_used_at,expires_at) SELECT ?1,?2,?3,?4,?5,?6,?6,?7 WHERE EXISTS (SELECT 1 FROM passkey_credentials p JOIN account_security s ON s.owner_id=p.owner_id WHERE p.credential_id=?3 AND p.owner_id=?2 AND p.revoked_at IS NULL AND s.generation=?4)').bind(deviceId,proof.ownerId,proof.credentialId,proof.generation,clientKind,now,now+IDLE),
      this.db.prepare('INSERT INTO device_refresh_handles (handle_id,secret_digest,device_id,created_at) SELECT ?1,?2,?3,?4 WHERE EXISTS (SELECT 1 FROM device_sessions WHERE device_id=?3)').bind(refresh.tokenId,refresh.digest,deviceId,now),
      this.db.prepare('INSERT INTO device_access_handles (handle_id,secret_digest,device_id,created_at,expires_at) SELECT ?1,?2,?3,?4,?5 WHERE EXISTS (SELECT 1 FROM device_sessions WHERE device_id=?3)').bind(access.tokenId,access.digest,deviceId,now,now+ACCESS),
    ]);
    const row=await this.db.prepare('SELECT device_id FROM device_sessions WHERE device_id=?1').bind(deviceId).first();
    return row?{deviceId,refresh:refresh.token,access:access.token,accessExpiresAt:now+ACCESS,refreshExpiresAt:now+IDLE}:undefined;
  }
  async authenticate(token){
    const t=await tokenDigest(token);if(!t)return undefined;const now=this.now();
    const row=await this.db.prepare(`SELECT d.owner_id,d.device_id,d.generation,d.client_kind,a.expires_at FROM device_access_handles a JOIN device_sessions d ON d.device_id=a.device_id JOIN passkey_credentials p ON p.credential_id=d.credential_id JOIN account_security s ON s.owner_id=d.owner_id WHERE a.handle_id=?1 AND a.secret_digest=?2 AND a.created_at<=?3 AND a.expires_at>?3 AND ${ACTIVE}`).bind(t.id,t.digest,now).first();
    return row?{ownerId:row.owner_id,deviceId:row.device_id,generation:row.generation,clientKind:row.client_kind,expiresAt:row.expires_at}:undefined;
  }
  async rotate(token){
    const t=await tokenDigest(token);if(!t)return {status:'denied'};let now=this.now();
    const row=await this.db.prepare(`SELECT r.used_at,d.device_id,d.owner_id,d.generation FROM device_refresh_handles r JOIN device_sessions d ON d.device_id=r.device_id JOIN passkey_credentials p ON p.credential_id=d.credential_id JOIN account_security s ON s.owner_id=d.owner_id WHERE r.handle_id=?1 AND r.secret_digest=?2 AND r.created_at<=?3 AND ${ACTIVE}`).bind(t.id,t.digest,now).first();
    if(!row)return {status:'denied'};
    if(row.used_at!==null){
      if(now-row.used_at<=GRACE)return {status:'retry'};
      await this.db.prepare('UPDATE device_sessions SET revoked_at=?1 WHERE device_id=?2 AND revoked_at IS NULL').bind(now,row.device_id).run();return {status:'denied'};
    }
    const next=await freshHandle(),access=await freshHandle();
    now=this.now();
    // A random successor handle is the transaction's unique winner marker.
    // INSERT..SELECT only wins while the parent handle is unused and active.
    const results=await this.db.batch([
      this.db.prepare(`INSERT INTO device_refresh_handles (handle_id,secret_digest,device_id,created_at) SELECT ?4,?5,d.device_id,?3 FROM device_refresh_handles r JOIN device_sessions d ON d.device_id=r.device_id JOIN passkey_credentials p ON p.credential_id=d.credential_id JOIN account_security s ON s.owner_id=d.owner_id WHERE r.handle_id=?1 AND r.secret_digest=?2 AND r.used_at IS NULL AND ${ACTIVE}`).bind(t.id,t.digest,now,next.tokenId,next.digest),
      this.db.prepare('UPDATE device_refresh_handles SET used_at=?1 WHERE handle_id=?2 AND used_at IS NULL AND EXISTS (SELECT 1 FROM device_refresh_handles WHERE handle_id=?3)').bind(now,t.id,next.tokenId),
      this.db.prepare('UPDATE device_sessions SET last_used_at=?1,expires_at=?2 WHERE device_id=?3 AND EXISTS (SELECT 1 FROM device_refresh_handles WHERE handle_id=?4)').bind(now,now+IDLE,row.device_id,next.tokenId),
      this.db.prepare('INSERT INTO device_access_handles (handle_id,secret_digest,device_id,created_at,expires_at) SELECT ?1,?2,?3,?4,?5 WHERE EXISTS (SELECT 1 FROM device_refresh_handles WHERE handle_id=?6)').bind(access.tokenId,access.digest,row.device_id,now,now+ACCESS,next.tokenId),
    ]);
    if(results[0].meta.changes!==1)return {status:'retry'};
    return {status:'rotated',deviceId:row.device_id,refresh:next.token,access:access.token,accessExpiresAt:now+ACCESS,refreshExpiresAt:now+IDLE};
  }
  async cleanup({limit=100}={}){
    if(!Number.isSafeInteger(limit)||limit<1||limit>500)throw new TypeError('Bounded cleanup required');const now=this.now();
    // Old spent handles beyond the inactivity window may be forgotten. Replay
    // then denies generically rather than revoking an otherwise active device.
    const results=await this.db.batch([
      this.db.prepare('DELETE FROM device_access_handles WHERE handle_id IN (SELECT handle_id FROM device_access_handles WHERE expires_at<=?1 ORDER BY expires_at LIMIT ?2)').bind(now,limit),
      this.db.prepare('DELETE FROM device_refresh_handles WHERE handle_id IN (SELECT handle_id FROM device_refresh_handles WHERE used_at IS NOT NULL AND used_at<=?1 ORDER BY used_at LIMIT ?2)').bind(now-IDLE,limit),
      this.db.prepare('DELETE FROM device_sessions WHERE device_id IN (SELECT device_id FROM device_sessions WHERE expires_at<=?1 OR revoked_at IS NOT NULL ORDER BY expires_at LIMIT ?2)').bind(now,limit),
    ]);return results.map(r=>r.meta.changes);
  }
  async revoke({ownerId,deviceId}){const r=await this.db.prepare('UPDATE device_sessions SET revoked_at=?1 WHERE owner_id=?2 AND device_id=?3 AND revoked_at IS NULL').bind(this.now(),ownerId,deviceId).run();return r.meta.changes===1;}
  async revokeAll(ownerId){const r=await this.db.prepare('UPDATE device_sessions SET revoked_at=?1 WHERE owner_id=?2 AND revoked_at IS NULL').bind(this.now(),ownerId).run();return r.meta.changes;}
      }
