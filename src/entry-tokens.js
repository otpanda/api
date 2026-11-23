import { generateAccessToken, digestSecret, timingSafeEqual } from './tokens.js';
import { opaqueDigest, json } from './sessions.js';
import { bearerToken, unauthorized } from './http.js';

// Entry-scoped replacement for the service-only foundation grants. Tokens
// name a recipient actor, not an owner; live entry permissions decide access.
export class EntryTokenStore {
  constructor(db,access){this.db=db;this.access=access;}
  async mint(actorId,entryId,clientId,ttlMs,now=Date.now()){
    if(typeof clientId!=='string'||!/^[A-Za-z0-9_.-]{1,128}$/.test(clientId)||!Number.isSafeInteger(ttlMs)||ttlMs<1||ttlMs>366*86400000)throw new TypeError('Bounded client and expiry required');
    if(!await this.access.canRead(actorId,entryId,{automation:true}))return undefined;
    const generated=generateAccessToken();
    await this.db.prepare('INSERT INTO entry_tokens (token_id,token_digest,actor_id,entry_id,client_id,created_at,expires_at,revoked_at) VALUES (?1,?2,?3,?4,?5,?6,?7,NULL)').bind(generated.tokenId,Array.from(await digestSecret(generated.secret)),actorId,entryId,clientId,now,now+ttlMs).run();
    // If sharing was revoked during mint, discard the new credential entirely.
    if(!await this.access.canRead(actorId,entryId,{automation:true})){
      await this.db.prepare('DELETE FROM entry_tokens WHERE token_id = ?1').bind(generated.tokenId).run();return undefined;
    }
    return {token:generated.token,tokenId:generated.tokenId,entryId,clientId,expiresAt:now+ttlMs,scopes:['codes:read']};
  }
  async verify(token,now=Date.now()){
    const parsed=await opaqueDigest(token);if(!parsed)return undefined;
    const row=await this.db.prepare('SELECT token_digest,actor_id,entry_id,client_id,expires_at,revoked_at FROM entry_tokens WHERE token_id = ?1').bind(parsed.id).first();
    if(!row||row.revoked_at!==null||row.expires_at<=now||!timingSafeEqual(parsed.digest,new Uint8Array(row.token_digest)))return undefined;
    if(!await this.access.canRead(row.actor_id,row.entry_id,{automation:true}))return undefined;
    return {actorId:row.actor_id,entryId:row.entry_id,clientId:row.client_id,expiresAt:row.expires_at};
  }
  async revoke(actorId,tokenId,now=Date.now()){
    await this.db.prepare('UPDATE entry_tokens SET revoked_at = COALESCE(revoked_at,?1) WHERE actor_id = ?2 AND token_id = ?3').bind(now,actorId,tokenId).run();
  }
  async list(actorId){return (await this.db.prepare('SELECT token_id,entry_id,client_id,created_at,expires_at,revoked_at FROM entry_tokens WHERE actor_id = ?1 ORDER BY created_at DESC LIMIT 100').bind(actorId).all()).results;}
}
export function createEntryReadHandler({tokens,access,clock=Date.now}){
  return {async fetch(request){
    const url=new URL(request.url);
    if(url.pathname!=='/v1/entries/code'||request.method!=='GET')return json({error:'not_found'},404);
    const grant=await tokens.verify(bearerToken(request.headers.get('authorization')),clock());
    if(!grant)return unauthorized();
    if(url.searchParams.get('entry')!==grant.entryId)return json({error:'forbidden'},403);
    const record=await access.latest(grant.actorId,grant.entryId,clock(),{automation:true});
    if(!record)return json({error:'not_found'},404);
    // Verify the token again after asynchronous decryption as well as checking
    // live sharing membership inside access.latest.
    if(!await tokens.verify(bearerToken(request.headers.get('authorization')),clock()))return unauthorized();
    return json(record);
  }};
}
