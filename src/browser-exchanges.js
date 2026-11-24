// Internal PKCE exchange storage, not a mounted restoration/callback endpoint.
// The HTTP boundary must establish first-party refresh-cookie authority before
// mint(), validate exact Origin on exchange(), rate-limit and clean callback URL.
import { generateAccessToken, parseAccessToken, digestSecret, digestToHex, base64urlEncode } from './tokens.js';
import {importRenewalKey,firstPartyExpiresAt,MAX_LINEAGES} from './access-renewal.js';
import {SESSION_METHOD_JOIN as MJ,SESSION_METHOD_ACTIVE as MA} from './session-method.js';
const MAX_EXCHANGES=32,MAX_ACCESS=64;
const TTL=60_000,ACCESS=300_000;
const ACTIVE=`d.revoked_at IS NULL AND d.created_at<=?3 AND d.expires_at>?3 AND ${MA} AND s.generation=d.generation AND d.client_kind='web'`;
const CHALLENGE=/^[A-Za-z0-9_-]{43}$/;
const VERIFIER=/^[A-Za-z0-9._~-]{43,128}$/;
async function digest(token){const p=parseAccessToken(token);return p?{id:p.tokenId,hash:digestToHex(await digestSecret(p.secret))}:undefined;}
export async function pkceChallenge(verifier){if(typeof verifier!=='string'||!VERIFIER.test(verifier))return undefined;return base64urlEncode(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(verifier))));}
export class BrowserExchangeService {
  constructor(db,{redirectUri,clock=Date.now}={}){
    // Configuration, never request-selected. Only the canonical app callback.
    if(redirectUri!=='https://otpanda.github.io/app/')throw new TypeError('Approved exact browser redirect required');
    this.db=db;this.redirectUri=redirectUri;this.clock=clock;
  }
  now(){const n=this.clock();if(!Number.isSafeInteger(n)||n<0)throw new TypeError('Valid instant required');return n;}
  async mint({deviceId,challenge,redirectUri}){
    if(typeof deviceId!=='string'||typeof challenge!=='string'||!CHALLENGE.test(challenge)||redirectUri!==this.redirectUri)return undefined;
    const secret=generateAccessToken(),hash=digestToHex(await digestSecret(secret.secret)),now=this.now();
    const result=await this.db.prepare(`INSERT INTO browser_exchanges (exchange_id,secret_digest,device_id,challenge,redirect_uri,created_at,expires_at) SELECT ?1,?2,d.device_id,?4,?5,?3,?6 FROM device_sessions d ${MJ} JOIN account_security s ON s.owner_id=d.owner_id WHERE d.device_id=?7 AND (SELECT count(*) FROM browser_exchanges WHERE device_id=d.device_id AND expires_at>?3)<${MAX_EXCHANGES} AND ${ACTIVE}`)
      .bind(secret.tokenId,hash,now,challenge,redirectUri,now+TTL,deviceId).run();
    return result.meta.changes===1?{code:secret.token,expiresAt:now+TTL}:undefined;
  }
  // renewalKey is optional (capability fallback). It is validated BEFORE the code is claimed so a
  // malformed key cannot burn a legitimate code, and it can be bound nowhere else.
  async exchange({code,verifier,redirectUri,renewalKey}){
    if(redirectUri!==this.redirectUri)return undefined;
    if(renewalKey!==undefined&&!await importRenewalKey(renewalKey))return undefined;
    const c=await digest(code),challenge=await pkceChallenge(verifier);if(!c||!challenge)return undefined;
    const now=this.now();
    // A wrong PKCE/redirect cannot consume another tab's legitimate code. A
    // correctly bound code is consumed even if security checks later deny.
    const claimed=await this.db.prepare('DELETE FROM browser_exchanges WHERE exchange_id=?1 AND secret_digest=?2 AND challenge=?3 AND redirect_uri=?4 AND created_at<=?5 AND expires_at>?5 RETURNING device_id,expires_at').bind(c.id,c.hash,challenge,redirectUri,now).first();
    if(!claimed)return undefined;
    const access=generateAccessToken(),hash=digestToHex(await digestSecret(access.secret)),completed=this.now();
    if(completed<now||completed>=claimed.expires_at)return undefined;
    const guard=`(SELECT count(*) FROM device_access_handles WHERE device_id=d.device_id AND expires_at>?3)<${MAX_ACCESS} AND ${ACTIVE}`;
    if(renewalKey===undefined){
    const result=await this.db.prepare(`INSERT INTO device_access_handles (handle_id,secret_digest,device_id,created_at,expires_at) SELECT ?1,?2,d.device_id,?3,?4 FROM device_sessions d ${MJ} JOIN account_security s ON s.owner_id=d.owner_id WHERE d.device_id=?5 AND ${guard}`)
      .bind(access.tokenId,hash,completed,completed+ACCESS,claimed.device_id).run();
    return result.meta.changes===1?{access:access.token,accessExpiresAt:completed+ACCESS}:undefined;
    }
    // The lineage and its first handle commit together or not at all (same guards).
    const lineage=generateAccessToken().tokenId;
    const results=await this.db.batch([
      this.db.prepare(`DELETE FROM access_lineages WHERE lineage_id IN (SELECT lineage_id FROM access_lineages WHERE device_id=?1 ORDER BY created_at DESC,rowid DESC LIMIT -1 OFFSET ${MAX_LINEAGES-1}) AND EXISTS(SELECT 1 FROM device_sessions d ${MJ} JOIN account_security s ON s.owner_id=d.owner_id WHERE d.device_id=?1 AND ${ACTIVE.replaceAll('?3','?2')})`).bind(claimed.device_id,completed),
      this.db.prepare(`INSERT INTO access_lineages (lineage_id,device_id,public_key,created_at) SELECT ?1,d.device_id,?2,?3 FROM device_sessions d ${MJ} JOIN account_security s ON s.owner_id=d.owner_id WHERE d.device_id=?5 AND ${guard}`).bind(lineage,renewalKey,completed,completed+ACCESS,claimed.device_id),
      this.db.prepare(`INSERT INTO device_access_handles (handle_id,secret_digest,device_id,created_at,expires_at,lineage_id) SELECT ?1,?2,d.device_id,?3,?4,?6 FROM device_sessions d ${MJ} JOIN account_security s ON s.owner_id=d.owner_id WHERE d.device_id=?5 AND EXISTS(SELECT 1 FROM access_lineages WHERE lineage_id=?6 AND device_id=d.device_id) AND ${guard}`).bind(access.tokenId,hash,completed,completed+ACCESS,claimed.device_id,lineage),
    ]);
    if(results[2].meta.changes!==1){await this.db.prepare('DELETE FROM access_lineages WHERE lineage_id=?1').bind(lineage).run();return undefined;}
    const fp=await firstPartyExpiresAt(this.db,claimed.device_id);
    return {access:access.token,accessExpiresAt:completed+ACCESS,renewal:{lineageId:lineage,handleId:access.tokenId,serverTime:completed,...(fp===undefined?{}:{firstPartyExpiresAt:fp})}};
  }
  async cleanup({limit=100}={}){if(!Number.isSafeInteger(limit)||limit<1||limit>500)throw new TypeError('Bounded cleanup required');const r=await this.db.prepare('DELETE FROM browser_exchanges WHERE exchange_id IN (SELECT exchange_id FROM browser_exchanges WHERE expires_at<=?1 ORDER BY expires_at LIMIT ?2)').bind(this.now(),limit).run();return r.meta.changes;}
}
