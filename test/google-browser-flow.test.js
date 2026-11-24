import test from 'node:test';
import assert from 'node:assert/strict';
import * as oauth from 'oauth4webapi';
import { database } from './sqlite-helper.js';
import { SessionService, LOGIN_COOKIE, SESSION_COOKIE } from '../src/sessions.js';
import { createGoogleBrowserFlow } from '../src/google-browser-flow.js';
import { CodeCipher } from '../src/code-cipher.js';
import { base64urlEncode } from '../src/tokens.js';
const encoder = new TextEncoder();
async function setup({ wrongNonce = false, wrongAudience = false, tamperSignature = false, wrongIssuer = false, expiredToken = false, missingIdToken = false } = {}) {
  const db = database();
  const sessions = new SessionService(db, { origin: 'https://app.test' });
  const encryptionKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const cipher = new CodeCipher({ keys: new Map([['test', encryptionKey]]), activeKeyId: 'test' });
  const signing = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  const jwk = { ...await crypto.subtle.exportKey('jwk', signing.publicKey), kid: 'key-1', alg: 'RS256', use: 'sig' };
  const server = { issuer: 'https://accounts.google.com', authorization_endpoint: 'https://id.test/auth', token_endpoint: 'https://id.test/token', jwks_uri: 'https://id.test/jwks', id_token_signing_alg_values_supported: ['RS256'] };
  let nonce, tokenCalls = 0;
  const mockedFetch = async (url, options) => {
    if (String(url) === server.jwks_uri) return Response.json({ keys: [jwk] });
    assert.equal(String(url), server.token_endpoint);
    tokenCalls++;
    const body = new URLSearchParams(options.body);
    assert.ok(body.get('code_verifier'));
    assert.equal(body.get('redirect_uri'), 'https://otpanda-api.abrahammurciano.workers.dev/auth/callback');
    const now = Math.floor(Date.now() / 1000);
    const header = base64urlEncode(encoder.encode(JSON.stringify({ alg: 'RS256', kid: 'key-1' })));
    const payload = base64urlEncode(encoder.encode(JSON.stringify({ iss: wrongIssuer ? 'https://evil.test' : server.issuer, sub: 'person-1', aud: wrongAudience ? 'wrong' : 'client', iat: now, exp: expiredToken ? now - 600 : now + 300, email:'a@gmail.com',email_verified:true,nonce: wrongNonce ? 'wrong' : nonce })));
    const signature = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', signing.privateKey, encoder.encode(header + '.' + payload)));
    if (tamperSignature) signature[0] ^= 1;
    return Response.json({ access_token: 'synthetic-provider-token', token_type: 'Bearer', ...(missingIdToken ? {} : { id_token: header + '.' + payload + '.' + base64urlEncode(signature) }) });
  };
  let completed;
  const flow=createGoogleBrowserFlow({db,cipher,server,client:{client_id:'client',id_token_signed_response_alg:'RS256'},clientAuthentication:oauth.None(),oauthOptions:{[oauth.customFetch]:mockedFetch},complete:async value=>{completed=value;return new Response(null,{status:303,headers:{Location:'https://otpanda.github.io/app/'}});}});
  const start=await flow.start(new Request('https://otpanda-api.abrahammurciano.workers.dev/auth/google/start?'+new URLSearchParams({challenge:'c'.repeat(43),state:'s'.repeat(43),redirect_uri:'https://otpanda.github.io/app/',remember:'yes'})));
  const target=new URL(start.headers.get('location'));nonce=target.searchParams.get('nonce');const cookie=start.headers.get('set-cookie').split(';')[0];
  const callback=(binding=cookie,state=target.searchParams.get('state'))=>new Request('https://otpanda-api.abrahammurciano.workers.dev/auth/callback?'+new URLSearchParams({code:'synthetic-code',state}),{headers:{cookie:binding}});
  return{db,flow,target,cookie,callback,tokenCalls:()=>tokenCalls,completed:()=>completed};
}
test('Google verifies signature audience nonce state and PKCE before bounded completion',async()=>{const x=await setup();assert.equal(x.target.searchParams.get('scope'),'openid email');assert.equal(x.target.searchParams.get('code_challenge_method'),'S256');const wrong=await x.flow.callback(x.callback('__Host-otpanda_google=wrong'));assert.equal(wrong.status,303);assert.equal(x.tokenCalls(),0);const r=await x.flow.callback(x.callback());assert.equal(r.status,303);assert.equal(x.completed().identity.subject,'person-1');assert.equal(x.completed().identity.email,'a@gmail.com');assert.equal(x.completed().identity.authoritative,true);assert.equal(x.completed().remember,true);assert.equal(x.completed().appState,'s'.repeat(43));assert.equal(x.completed().access_token,undefined);assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM accounts').get().n,0);await x.flow.callback(x.callback());assert.equal(x.tokenCalls(),1);});
for(const flag of ['wrongNonce','wrongAudience','tamperSignature','wrongIssuer','expiredToken','missingIdToken'])test('Google rejects '+flag+' without completion',async()=>{const x=await setup({[flag]:true});const r=await x.flow.callback(x.callback());assert.equal(r.status,303);assert.equal(x.completed(),undefined);assert.ok(r.headers.get('location').startsWith('https://otpanda.github.io/app/'));});
// Ported from the retired legacy OIDC adapter tests: transaction, binding and
// replay rejection must hold in the current flow before any token exchange.
test('Google callback rejects duplicate state, foreign origin, wrong binding and expired transaction before the token call',async()=>{
 const x=await setup(),dup=x.callback(),u=new URL(dup.url);u.searchParams.append('state','extra');
 for(const req of [new Request(u,{headers:dup.headers}),new Request(x.callback().url.replace('https://otpanda-api.abrahammurciano.workers.dev','https://evil.test'),{headers:x.callback().headers}),x.callback('__Host-otpanda_google=wrong')]){const r=await x.flow.callback(req);assert.equal(r.status,303);assert.ok(r.headers.get('location').startsWith('https://otpanda.github.io/app/'));}
 assert.equal(x.tokenCalls(),0);assert.equal(x.completed(),undefined);
 x.db.sqlite.prepare('UPDATE oauth_transactions SET created_at=?,expires_at=?').run(Date.now()-2000,Date.now()-1000);
 assert.equal((await x.flow.callback(x.callback())).status,303);assert.equal(x.tokenCalls(),0);assert.equal(x.completed(),undefined);});
test('Google callback transaction is one-time: a replay never reaches the provider again',async()=>{
 const x=await setup();assert.ok(x.completed()===undefined);await x.flow.callback(x.callback());const calls=x.tokenCalls();assert.equal(calls,1);
 const r=await x.flow.callback(x.callback());assert.equal(r.status,303);assert.equal(x.tokenCalls(),1);});
