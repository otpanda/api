// Internal browser login handoff store. HTTP must enforce exact origins,
// trusted address limits, first-party cookie binding and callback cleanup.
import {hashText} from './sessions.js';
import {generateAccessToken,parseAccessToken,digestSecret,digestToHex} from './tokens.js';
const REDIRECT='https://otpanda.github.io/app/',TTL=60_000;
function context({binding,challenge,state,redirectUri}={}){
 return typeof binding==='string'&&binding.length>=32&&binding.length<=512&&typeof challenge==='string'&&/^[A-Za-z0-9_-]{43}$/.test(challenge)&&typeof state==='string'&&/^[A-Za-z0-9_-]{43}$/.test(state)&&redirectUri===REDIRECT;
}
async function bound(c){return hashText(JSON.stringify(['web-login-handoff-v1',c.binding,c.challenge,c.state,REDIRECT]));}
export class WebLoginHandoffService {
 constructor(db,{passkeys,sessions,exchanges,clock=Date.now}={}){
  if(!db||!passkeys||!sessions||!exchanges)throw new TypeError('Login dependencies required');
  Object.assign(this,{db,passkeys,sessions,exchanges,clock});
 }
 now(){const now=this.clock();if(!Number.isSafeInteger(now)||now<0)throw new TypeError('Valid instant required');return now;}
 async beginBrowser({cookieBinding,...c}={}){
  if(typeof cookieBinding!=='string'||cookieBinding.length<32||cookieBinding.length>512)return undefined;
  const cookieDigest=await hashText(cookieBinding),ceremony=await this.begin({...c,binding:cookieDigest});if(!ceremony)return undefined;
  const parsed=parseAccessToken(ceremony.token),now=this.now();
  await this.db.prepare('INSERT INTO web_login_starts (ceremony_id,secret_digest,cookie_digest,challenge,state,created_at,expires_at) VALUES (?1,?2,?3,?4,?5,?6,?7)').bind(parsed.tokenId,digestToHex(await digestSecret(parsed.secret)),cookieDigest,c.challenge,c.state,now,ceremony.expiresAt).run();
  return ceremony;
 }
 async verifyBrowser({token,response}={}){
  const parsed=parseAccessToken(token);if(!parsed)return undefined;const now=this.now();
  const row=await this.db.prepare('DELETE FROM web_login_starts WHERE ceremony_id=?1 AND secret_digest=?2 AND created_at<=?3 AND expires_at>?3 RETURNING cookie_digest,challenge,state').bind(parsed.tokenId,digestToHex(await digestSecret(parsed.secret)),now).first();
  if(!row)return undefined;
  return this.verify({token,response,binding:row.cookie_digest,challenge:row.challenge,state:row.state,redirectUri:REDIRECT});
 }
 async completeBrowser({handoff,cookieBinding,priorRefresh}={}){
  if(typeof cookieBinding!=='string'||cookieBinding.length<32||cookieBinding.length>512)return undefined;
  return this.complete({handoff,binding:await hashText(cookieBinding),priorRefresh});
 }
 async begin(c){if(!context(c))return undefined;return this.passkeys.begin({purpose:'authenticate',binding:await bound(c)});}
 async verify({token,response,...c}={}){
  if(!context(c))return undefined;
  const proof=await this.passkeys.finishAuthentication({token,response,binding:await bound(c)});if(!proof)return undefined;
  const secret=generateAccessToken(),digest=digestToHex(await digestSecret(secret.secret)),binding=await hashText(c.binding),now=this.now();
  if(proof.purpose!=='authenticate'||proof.verifiedAt>now||now-proof.verifiedAt>=120000)return undefined;
  const result=await this.db.prepare('INSERT INTO web_login_handoffs (handoff_id,secret_digest,binding_digest,owner_id,credential_id,generation,verified_at,challenge,state,created_at,expires_at) SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11 WHERE EXISTS (SELECT 1 FROM passkey_credentials p JOIN account_security s ON s.owner_id=p.owner_id WHERE p.credential_id=?5 AND p.owner_id=?4 AND p.revoked_at IS NULL AND s.generation=?6)').bind(secret.tokenId,digest,binding,proof.ownerId,proof.credentialId,proof.generation,proof.verifiedAt,c.challenge,c.state,now,Math.min(now+TTL,proof.verifiedAt+120000)).run();
  return result.meta.changes===1?{handoff:secret.token,expiresAt:Math.min(now+TTL,proof.verifiedAt+120000)}:undefined;
 }
 async complete({handoff,binding,priorRefresh}={}){
  const parsed=parseAccessToken(handoff);if(!parsed||typeof binding!=='string'||binding.length<32||binding.length>512)return undefined;
  const now=this.now(),row=await this.db.prepare('DELETE FROM web_login_handoffs WHERE handoff_id=?1 AND secret_digest=?2 AND binding_digest=?3 AND created_at<=?4 AND expires_at>?4 RETURNING owner_id,credential_id,generation,verified_at,challenge,state,expires_at,binding_digest').bind(parsed.tokenId,digestToHex(await digestSecret(parsed.secret)),await hashText(binding),now).first();
  if(!row||this.now()>=row.expires_at)return undefined;
  const proof={ownerId:row.owner_id,credentialId:row.credential_id,generation:row.generation,verifiedAt:row.verified_at,purpose:'authenticate'};
  const device=await this.sessions.issueBrowserLogin({proof,browserBindingDigest:row.binding_digest,priorRefresh,challenge:row.challenge,redirectUri:REDIRECT,deadline:row.expires_at});
  if(!device)return undefined;
  return {refresh:device.refresh,refreshExpiresAt:device.refreshExpiresAt,code:device.code,state:row.state,redirectUri:REDIRECT};
 }
 async cleanup({limit=100}={}){if(!Number.isSafeInteger(limit)||limit<1||limit>500)throw new TypeError('Bounded cleanup required');const now=this.now(),results=await this.db.batch([this.db.prepare('DELETE FROM web_login_handoffs WHERE handoff_id IN (SELECT handoff_id FROM web_login_handoffs WHERE expires_at<=?1 ORDER BY expires_at LIMIT ?2)').bind(now,limit),this.db.prepare('DELETE FROM web_login_starts WHERE ceremony_id IN (SELECT ceremony_id FROM web_login_starts WHERE expires_at<=?1 ORDER BY expires_at LIMIT ?2)').bind(now,limit)]);return results[0].meta.changes;}
}
