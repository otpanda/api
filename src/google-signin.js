import * as oauth from 'oauth4webapi';
import { createOidcSignIn } from './oidc.js';

export const GOOGLE_ISSUER='https://accounts.google.com';
// No provider token or mailbox scope is retained. Requires separately approved
// OAuth web-client registration and an exact HTTPS application origin.
export async function createGoogleSignIn({clientId,clientSecret,...dependencies}){
  if(typeof clientId!=='string'||!clientId.endsWith('.apps.googleusercontent.com')||typeof clientSecret!=='string'||!clientSecret)throw new TypeError('Registered Google web client required');
  const response=await oauth.discoveryRequest(new URL(GOOGLE_ISSUER),dependencies.oauthOptions);
  const server=await oauth.processDiscoveryResponse(new URL(GOOGLE_ISSUER),response);
  if(server.issuer!==GOOGLE_ISSUER||!server.code_challenge_methods_supported?.includes('S256')||!server.id_token_signing_alg_values_supported?.includes('RS256')||!server.token_endpoint_auth_methods_supported?.includes('client_secret_post'))throw new Error('Unexpected Google discovery metadata');
  return createOidcSignIn({...dependencies,server,client:{client_id:clientId,id_token_signed_response_alg:'RS256'},clientAuthentication:oauth.ClientSecretPost(clientSecret)});
}
