// Provider verification only. Completion must enforce current account/session
// policy; this adapter never creates legacy sessions or links by email.
import * as oauth from 'oauth4webapi';
import {generateAccessToken} from './tokens.js';
import {hashText,readCookie,cookie,securityHeaders} from './sessions.js';
import {googleEmailEvidence} from './account-identity.js';
import {appFailure} from './silent-bridge.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io/app/',CALLBACK=API+'/auth/callback',BIND='__Host-otpanda_google',TTL=300000,OPAQUE=/^[A-Za-z0-9_-]{43}$/;
export function createGoogleBrowserFlow({db,cipher,server,client,clientAuthentication,complete,clock=Date.now,oauthOptions={}}={}){
 if(!db||!cipher||server?.issuer!=='https://accounts.google.com'||!client?.client_id||typeof complete!=='function')throw new TypeError('Google browser dependencies required');
 const context=(id,createdAt,expiresAt)=>({ownerId:'oauth-transaction',recordId:id,serviceId:server.issuer,receivedAt:createdAt,expiresAt});
 return {async start(request){
  const u=new URL(request.url),q=u.searchParams;
  if(u.origin!==API||u.pathname!=='/auth/google/start'||request.method!=='GET'||[...q.keys()].sort().join(',')!=='challenge,redirect_uri,remember,state'||!OPAQUE.test(q.get('challenge'))||!OPAQUE.test(q.get('state'))||q.get('redirect_uri')!==APP||!['yes','no'].includes(q.get('remember')))return appFailure();
  const state=oauth.generateRandomState(),existingBinding=readCookie(request,'__Host-otpanda_browser'),binding=/^otpda_[A-Za-z0-9_-]{55}$/.test(existingBinding??'')?existingBinding:generateAccessToken().token,verifier=oauth.generateRandomCodeVerifier(),nonce=oauth.generateRandomNonce(),now=clock(),id=await hashText(state);
  const envelope=await cipher.encrypt(JSON.stringify({verifier,nonce,appState:q.get('state'),challenge:q.get('challenge'),remember:q.get('remember')==='yes'}),context(id,now,now+TTL));
  await db.prepare('INSERT INTO oauth_transactions(state_digest,binding_digest,envelope,created_at,expires_at) VALUES(?1,?2,?3,?4,?5)').bind(id,await hashText(binding),JSON.stringify(envelope),now,now+TTL).run();
  const target=new URL(server.authorization_endpoint);target.search=new URLSearchParams({client_id:client.client_id,response_type:'code',redirect_uri:CALLBACK,scope:'openid email',state,nonce,code_challenge:await oauth.calculatePKCECodeChallenge(verifier),code_challenge_method:'S256'});
  const headers=new Headers({...securityHeaders,Location:target.href});headers.append('Set-Cookie',cookie(BIND,binding,TTL/1000));headers.append('Set-Cookie',cookie('__Host-otpanda_login',binding,TTL/1000));headers.append('Set-Cookie',cookie('__Host-otpanda_browser',binding,2147483647));return new Response(null,{status:303,headers});
 },async callback(request){
  const u=new URL(request.url),states=u.searchParams.getAll('state'),binding=readCookie(request,BIND),clear={'Set-Cookie':cookie(BIND,'',0)};let appState='';
  if(u.origin!==API||u.pathname!=='/auth/callback'||request.method!=='GET'||states.length!==1||states[0].length>256||typeof binding!=='string'||binding.length>128)return appFailure('', 'restart',clear);
  try{
   const id=await hashText(states[0]),now=clock(),row=await db.prepare('DELETE FROM oauth_transactions WHERE state_digest=?1 AND binding_digest=?2 AND created_at<=?3 AND expires_at>?3 RETURNING envelope,created_at,expires_at').bind(id,await hashText(binding),now).first();if(!row)return appFailure('', 'restart',clear);
   const p=JSON.parse(await cipher.decrypt(JSON.parse(row.envelope),context(id,row.created_at,row.expires_at)));appState=p.appState;
   if(!OPAQUE.test(appState)||!OPAQUE.test(p.challenge)||typeof p.remember!=='boolean')throw Error();
   const params=oauth.validateAuthResponse(server,client,u,states[0]),response=await oauth.authorizationCodeGrantRequest(server,client,clientAuthentication,params,CALLBACK,p.verifier,oauthOptions);
   const result=await oauth.processAuthorizationCodeResponse(server,client,response,{expectedNonce:p.nonce,requireIdToken:true});await oauth.validateApplicationLevelSignature(server,response,oauthOptions);
   const claims=oauth.getValidatedIdTokenClaims(result),evidence=googleEmailEvidence(claims);if(clock()>=row.expires_at)throw Error();
   // No provider access/refresh token retained or passed to completion.
   const completed=await complete({identity:evidence,appState,challenge:p.challenge,remember:p.remember,verifiedAt:clock(),request});
   if(!(completed instanceof Response))throw Error();completed.headers.append('Set-Cookie',cookie(BIND,'',0));return completed;
  }catch{return appFailure(appState,'restart',clear);}
 }};
}
