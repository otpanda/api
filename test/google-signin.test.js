import test from 'node:test';
import assert from 'node:assert/strict';
import * as oauth from 'oauth4webapi';
import {createGoogleSignIn,GOOGLE_ISSUER} from '../src/google-signin.js';
import {SessionService} from '../src/sessions.js';
import {database} from './sqlite-helper.js';
import {CodeCipher} from '../src/code-cipher.js';
const valid={issuer:GOOGLE_ISSUER,authorization_endpoint:'https://accounts.google.com/o/oauth2/v2/auth',token_endpoint:'https://oauth2.googleapis.com/token',jwks_uri:'https://www.googleapis.com/oauth2/v3/certs',code_challenge_methods_supported:['S256'],id_token_signing_alg_values_supported:['RS256'],token_endpoint_auth_methods_supported:['client_secret_post']};
async function deps(server=valid){const db=database(),sessions=new SessionService(db,{origin:'https://app.test'}),key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);return {db,sessions,cipher:new CodeCipher({keys:new Map([['test',key]]),activeKeyId:'test'}),clientId:'synthetic.apps.googleusercontent.com',clientSecret:'synthetic-not-real',oauthOptions:{[oauth.customFetch]:async(url)=>{assert.equal(String(url),'https://accounts.google.com/.well-known/openid-configuration');return Response.json(server);}}};}
test('Google adapter pins discovery and starts openid-only PKCE flow',async()=>{
 const d=await deps();const signIn=await createGoogleSignIn(d);const response=await signIn.start(new Request('https://app.test/auth/start',{method:'POST',headers:{origin:'https://app.test'}}));
 assert.equal(response.status,303);const target=new URL(response.headers.get('location'));assert.equal(target.origin,'https://accounts.google.com');assert.equal(target.searchParams.get('scope'),'openid');assert.equal(target.searchParams.get('code_challenge_method'),'S256');assert.equal(target.searchParams.has('access_type'),false);d.db.sqlite.close();
});
test('Google adapter rejects unexpected issuer or missing protocol capabilities',async()=>{
 for(const change of [{issuer:'https://other.test'},{code_challenge_methods_supported:['plain']},{id_token_signing_alg_values_supported:['none']},{token_endpoint_auth_methods_supported:['none']}]){const d=await deps({...valid,...change});await assert.rejects(createGoogleSignIn(d));d.db.sqlite.close();}
 const d=await deps();await assert.rejects(createGoogleSignIn({...d,clientId:'other'}));await assert.rejects(createGoogleSignIn({...d,clientSecret:''}));d.db.sqlite.close();
});
