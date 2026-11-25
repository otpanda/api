// Provider verification only. Completion must enforce current account/session
// policy; this adapter never creates legacy sessions or links by email.
import * as oauth from 'oauth4webapi';
import {generateAccessToken} from './tokens.js';
import {hashText,readCookie,cookie,securityHeaders,takeRateLimit} from './sessions.js';
import {googleEmailEvidence} from './account-identity.js';
import {appFailure} from './silent-bridge.js';
// Link failures return to the plain app URL with no #auth hash and no cookie change, so they can never look like a sign-in result.
const linkFailure=(state,reason,clear=true)=>{const t=new URL('https://otpanda.github.io/app/');t.hash=new URLSearchParams({link:reason,state:/^[A-Za-z0-9_-]{43}$/.test(state)?state:''});const h=new Headers({...securityHeaders,Location:t.href,'Referrer-Policy':'no-referrer'});if(clear){h.append('Set-Cookie',cookie('__Host-otpanda_google','',0));h.append('Set-Cookie',cookie('__Host-otpanda_google_link','',0));}return new Response(null,{status:303,headers:h});};
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io/app/',CALLBACK=API+'/auth/callback',BIND='__Host-otpanda_google',MARK='__Host-otpanda_google_link',TTL=300000,OPAQUE=/^[A-Za-z0-9_-]{43}$/;
export function createGoogleBrowserFlow({db,cipher,server,client,clientAuthentication,complete,completeLink,clock=Date.now,oauthOptions={}}={}){
 if(!db||!cipher||server?.issuer!=='https://accounts.google.com'||!client?.client_id||typeof complete!=='function')throw new TypeError('Google browser dependencies required');
 const context=(id,createdAt,expiresAt)=>({ownerId:'oauth-transaction',recordId:id,serviceId:server.issuer,receivedAt:createdAt,expiresAt});
 return {async start(request){
  const u=new URL(request.url),q=u.searchParams;
  if(u.origin!==API||u.pathname!=='/auth/google/start'||request.method!=='GET'||[...q.keys()].sort().join(',')!=='challenge,redirect_uri,remember,state'||!OPAQUE.test(q.get('challenge'))||!OPAQUE.test(q.get('state'))||q.get('redirect_uri')!==APP||!['yes','no'].includes(q.get('remember')))return appFailure();
  const state=oauth.generateRandomState(),existingBinding=readCookie(request,'__Host-otpanda_browser'),binding=/^otpda_[A-Za-z0-9_-]{55}$/.test(existingBinding??'')?existingBinding:generateAccessToken().token,verifier=oauth.generateRandomCodeVerifier(),nonce=oauth.generateRandomNonce(),now=clock(),id=await hashText(state);
  const envelope=await cipher.encrypt(JSON.stringify({verifier,nonce,appState:q.get('state'),challenge:q.get('challenge'),remember:q.get('remember')==='yes'}),context(id,now,now+TTL));
  await db.prepare('INSERT INTO oauth_transactions(state_digest,binding_digest,envelope,created_at,expires_at) VALUES(?1,?2,?3,?4,?5)').bind(id,await hashText(binding),JSON.stringify(envelope),now,now+TTL).run();
  const target=new URL(server.authorization_endpoint);target.search=new URLSearchParams({client_id:client.client_id,response_type:'code',redirect_uri:CALLBACK,scope:'openid email',state,nonce,code_challenge:await oauth.calculatePKCECodeChallenge(verifier),code_challenge_method:'S256'});
  const headers=new Headers({...securityHeaders,Location:target.href});headers.append('Set-Cookie',cookie(BIND,binding,TTL/1000));headers.append('Set-Cookie',cookie('__Host-otpanda_login',binding,TTL/1000));headers.append('Set-Cookie',cookie('__Host-otpanda_browser',binding,2147483647));headers.append('Set-Cookie',cookie(MARK,'',0));return new Response(null,{status:303,headers});},async startLink(request,{clientAddress}={}){
  // Signed-in link launch. Consumes the single-use ticket (bound to a live session and current generation) and
  // starts the same provider transaction. It never reads, sets or clears the device or recognition cookies.
  const u=new URL(request.url),q=u.searchParams,ticket=q.get('ticket');
  if(u.origin!==API||u.pathname!=='/auth/google/link/start'||request.method!=='GET'||[...q.keys()].join(',')!=='ticket'||!OPAQUE.test(ticket??''))return linkFailure('', 'restart',false);
  // Address limit fails closed and is checked BEFORE the ticket is spent. Generous enough for shared NAT addresses.
  if(typeof clientAddress!=='string'||!clientAddress||!(await takeRateLimit(db,'google-link-start:'+clientAddress,{now:clock(),limit:60,windowMs:3600000})).allowed)return linkFailure('', 'restart',false);
  const now=clock(),row=await db.prepare('DELETE FROM google_link_tickets WHERE ticket_digest=?1 AND expires_at>?2 AND EXISTS(SELECT 1 FROM device_sessions d JOIN account_security s ON s.owner_id=d.owner_id WHERE d.device_id=google_link_tickets.device_id AND d.owner_id=google_link_tickets.owner_id AND d.generation=google_link_tickets.generation AND s.generation=google_link_tickets.generation AND d.revoked_at IS NULL AND d.expires_at>?2) RETURNING owner_id,device_id,generation,app_state').bind(await hashText(ticket),now).first();
  if(!row)return linkFailure('', 'restart',false);
  const state=oauth.generateRandomState(),binding=generateAccessToken().token,verifier=oauth.generateRandomCodeVerifier(),nonce=oauth.generateRandomNonce(),id=await hashText(state);
  const envelope=await cipher.encrypt(JSON.stringify({verifier,nonce,appState:row.app_state,link:{ownerId:row.owner_id,deviceId:row.device_id,generation:row.generation}}),context(id,now,now+TTL));
  await db.prepare('INSERT INTO oauth_transactions(state_digest,binding_digest,envelope,created_at,expires_at) VALUES(?1,?2,?3,?4,?5)').bind(id,await hashText(binding),JSON.stringify(envelope),now,now+TTL).run();
  const target=new URL(server.authorization_endpoint);target.search=new URLSearchParams({client_id:client.client_id,response_type:'code',redirect_uri:CALLBACK,scope:'openid email',state,nonce,code_challenge:await oauth.calculatePKCECodeChallenge(verifier),code_challenge_method:'S256'});
  const headers=new Headers({...securityHeaders,Location:target.href,'Referrer-Policy':'no-referrer'});headers.append('Set-Cookie',cookie(BIND,binding,TTL/1000));headers.append('Set-Cookie',cookie(MARK,'1',1800));return new Response(null,{status:303,headers});
 },async callback(request){
  const u=new URL(request.url),states=u.searchParams.getAll('state'),binding=readCookie(request,BIND),clear={'Set-Cookie':cookie(BIND,'',0)};let appState='',isLink=false;const marked=readCookie(request,MARK)==='1';
  if(u.origin!==API||u.pathname!=='/auth/callback'||request.method!=='GET'||states.length!==1||states[0].length>256||typeof binding!=='string'||binding.length>128)return marked?linkFailure('', 'restart'):appFailure('', 'restart',clear);
  try{
   const id=await hashText(states[0]),now=clock(),row=await db.prepare('DELETE FROM oauth_transactions WHERE state_digest=?1 AND binding_digest=?2 AND created_at<=?3 AND expires_at>?3 RETURNING envelope,created_at,expires_at').bind(id,await hashText(binding),now).first();if(!row)return marked?linkFailure('', 'restart'):appFailure('', 'restart',clear);
   const p=JSON.parse(await cipher.decrypt(JSON.parse(row.envelope),context(id,row.created_at,row.expires_at)));appState=p.appState;isLink=!!p.link;
   if(p.link){if(!OPAQUE.test(appState)||typeof completeLink!=='function')throw Error();}else
   if(!OPAQUE.test(appState)||!OPAQUE.test(p.challenge)||typeof p.remember!=='boolean')throw Error();
   const params=oauth.validateAuthResponse(server,client,u,states[0]),response=await oauth.authorizationCodeGrantRequest(server,client,clientAuthentication,params,CALLBACK,p.verifier,oauthOptions);
   const result=await oauth.processAuthorizationCodeResponse(server,client,response,{expectedNonce:p.nonce,requireIdToken:true});await oauth.validateApplicationLevelSignature(server,response,oauthOptions);
   const claims=oauth.getValidatedIdTokenClaims(result),evidence=googleEmailEvidence(claims);if(clock()>=row.expires_at)throw Error();
   // No provider access/refresh token retained or passed to completion.
   if(p.link){const linked=await completeLink({identity:evidence,appState,link:p.link,request});if(!(linked instanceof Response))throw Error();linked.headers.append('Set-Cookie',cookie(BIND,'',0));linked.headers.append('Set-Cookie',cookie(MARK,'',0));return linked;}
   const completed=await complete({identity:evidence,appState,challenge:p.challenge,remember:p.remember,verifiedAt:clock(),request});
   if(!(completed instanceof Response))throw Error();completed.headers.append('Set-Cookie',cookie(BIND,'',0));if(marked)completed.headers.append('Set-Cookie',cookie(MARK,'',0));return completed;
  }catch{return isLink||(marked&&!appState)?linkFailure(appState,'restart'):appFailure(appState,'restart',clear);}
 }};
}
