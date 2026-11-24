import test from 'node:test';
import assert from 'node:assert/strict';
import * as oauth from 'oauth4webapi';
import { database } from './sqlite-helper.js';
import { SessionService, LOGIN_COOKIE, SESSION_COOKIE } from '../src/sessions.js';
import { createGoogleBrowserRuntime } from '../src/google-browser-runtime.js';
import {BrowserExchangeService} from '../src/browser-exchanges.js';
import {FirstPasskeyEnrollment} from '../src/first-passkey-enrollment.js';
import {DeviceSessionService} from '../src/device-sessions.js';
import {ExtraVerification} from '../src/extra-verification.js';
import {GoogleAccountService} from '../src/google-account.js';
import {hashText} from '../src/sessions.js';
import {authenticator} from './passkey-fixture.js';
import { createGoogleBrowserFlow } from '../src/google-browser-flow.js';
import { CodeCipher } from '../src/code-cipher.js';
import { base64urlEncode } from '../src/tokens.js';
const encoder = new TextEncoder();
async function setup({ wrongNonce = false, wrongAudience = false, tamperSignature = false, wrongIssuer = false, expiredToken = false, missingIdToken = false, remember = true, email = 'a@gmail.com' } = {}) {
  const db = database();let clockNow=Date.now();
  const sessions = new SessionService(db, { origin: 'https://app.test' });
  const encryptionKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const cipher = new CodeCipher({ keys: new Map([['test', encryptionKey]]), activeKeyId: 'test' });
  const signing = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  const jwk = { ...await crypto.subtle.exportKey('jwk', signing.publicKey), kid: 'key-1', alg: 'RS256', use: 'sig' };
  const server = { issuer: 'https://accounts.google.com', authorization_endpoint: 'https://id.test/auth', token_endpoint: 'https://id.test/token', jwks_uri: 'https://id.test/jwks', id_token_signing_alg_values_supported: ['RS256'] };
  let nonce, tokenCalls = 0;
  const mockedFetch = async (url, options) => {
    if(String(url)==='https://accounts.google.com/.well-known/openid-configuration')return Response.json({...server,code_challenge_methods_supported:['S256'],token_endpoint_auth_methods_supported:['client_secret_post']});
    if (String(url) === server.jwks_uri) return Response.json({ keys: [jwk] });
    assert.equal(String(url), server.token_endpoint);
    tokenCalls++;
    const body = new URLSearchParams(options.body);
    assert.ok(body.get('code_verifier'));
    assert.equal(body.get('redirect_uri'), 'https://otpanda-api.abrahammurciano.workers.dev/auth/callback');
    const now = Math.floor(Date.now() / 1000);
    const header = base64urlEncode(encoder.encode(JSON.stringify({ alg: 'RS256', kid: 'key-1' })));
    const payload = base64urlEncode(encoder.encode(JSON.stringify({ iss: wrongIssuer ? 'https://evil.test' : server.issuer, sub: 'person-1', aud: wrongAudience ? 'wrong' : 'client.apps.googleusercontent.com', iat: now, exp: expiredToken ? now - 600 : now + 300, email,email_verified:true,nonce: wrongNonce ? 'wrong' : nonce })));
    const signature = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', signing.privateKey, encoder.encode(header + '.' + payload)));
    if (tamperSignature) signature[0] ^= 1;
    return Response.json({ access_token: 'synthetic-provider-token', token_type: 'Bearer', ...(missingIdToken ? {} : { id_token: header + '.' + payload + '.' + base64urlEncode(signature) }) });
  };
  const flow=await createGoogleBrowserRuntime({db,keys:new Map([['test',encryptionKey]]),activeKeyId:'test',clientId:'client.apps.googleusercontent.com',clientSecret:'synthetic-secret',clock:()=>clockNow,oauthOptions:{[oauth.customFetch]:mockedFetch}});
  const start=await flow.fetch(new Request('https://otpanda-api.abrahammurciano.workers.dev/auth/google/start?'+new URLSearchParams({challenge:await oauth.calculatePKCECodeChallenge('v'.repeat(43)),state:'s'.repeat(43),redirect_uri:'https://otpanda.github.io/app/',remember:remember?'yes':'no'})));
  const target=new URL(start.headers.get('location'));nonce=target.searchParams.get('nonce');const cookie=start.headers.get('set-cookie').split(';')[0];
  const callback=(binding=cookie,state=target.searchParams.get('state'))=>new Request('https://otpanda-api.abrahammurciano.workers.dev/auth/callback?'+new URLSearchParams({code:'synthetic-code',state}),{headers:{cookie:binding}});
  return{db,flow,target,cookie,callback,tokenCalls:()=>tokenCalls,now:()=>clockNow,setNow:v=>clockNow=v};
}

test('composed Google callback creates real provider session and PKCE exchange then optional passkey',async()=>{const x=await setup(),r=await x.flow.fetch(x.callback());assert.equal(r.status,303);const target=new URL(r.headers.get('location'));assert.equal(target.origin+target.pathname,'https://otpanda.github.io/app/');assert.equal(target.search,'');assert.equal(target.hash.includes('access'),false);const f=new URLSearchParams(target.hash.slice(1));assert.ok(f.get('code'));assert.ok(f.get('enrollment'));assert.equal(f.get('state'),'s'.repeat(43));const exchanges=new BrowserExchangeService(x.db,{redirectUri:'https://otpanda.github.io/app/'}),issued=await exchanges.exchange({code:f.get('code'),verifier:'v'.repeat(43),redirectUri:'https://otpanda.github.io/app/'});assert.ok(issued);const user=await new DeviceSessionService(x.db).authenticate(issued.access);assert.equal(user.authMethod,'google');assert.equal(x.db.sqlite.prepare('SELECT credential_id FROM device_sessions').get().credential_id,null);const enrollment=new FirstPasskeyEnrollment(x.db),c=await enrollment.begin({user,grant:f.get('enrollment')});assert.ok(c);assert.equal(await enrollment.finish({user,grant:f.get('enrollment'),token:c.token,response:authenticator().registration({expected:c.options.challenge})}),true);assert.ok(await new DeviceSessionService(x.db).authenticate(issued.access));assert.equal(await exchanges.exchange({code:f.get('code'),verifier:'v'.repeat(43),redirectUri:'https://otpanda.github.io/app/'}),undefined);assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM sessions').get().n,0);});
test('remember opt-out creates no recognition record after valid Google callback',async()=>{const x=await setup({remember:false});await x.flow.fetch(x.callback());assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM device_sessions').get().n,1);assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM recognized_browsers').get().n,0);});
test('enabled unrecognized Google creates zero-authority pending; explicit existing client approval survives original proof age',async()=>{
 const x=await setup(),now=x.now(),account=await new GoogleAccountService(x.db,{clock:x.now}).resolve({issuer:'https://accounts.google.com',subject:'person-1',email:'a@gmail.com',authoritative:true}),sessions=new DeviceSessionService(x.db,{clock:x.now});
 const old=await sessions.issue({proof:{authMethod:'google',issuer:'https://accounts.google.com',subject:'person-1',ownerId:account.ownerId,generation:0,purpose:'authenticate',verifiedAt:now},clientKind:'web',browserBindingDigest:'1'.repeat(64)});assert.ok(old);
 x.db.sqlite.prepare('INSERT INTO new_device_verification VALUES(?,?,0)').run(account.ownerId,now);x.setNow(now+1000);
 const response=await x.flow.fetch(x.callback()),params=new URLSearchParams(new URL(response.headers.get('Location')).hash.slice(1)),pending=JSON.parse(params.get('protection'));assert.ok(pending.token);assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM device_sessions').get().n,1);assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM browser_exchanges').get().n,0);
 const service=new ExtraVerification(x.db,{clock:x.now,localVerification:async()=>true});assert.equal(await service.approveWithClient({ownerId:account.ownerId,deviceId:old.deviceId,generation:0,pendingId:pending.pendingId}),true);
 x.setNow(now+181000);const start=await x.flow.fetch(new Request('https://otpanda-api.abrahammurciano.workers.dev/auth/google/protection/complete'),{clientAddress:'192.0.2.1'}),csrfCookie=start.headers.getSetCookie()[0].split(';')[0],bindingCookie=response.headers.getSetCookie().find(c=>c.startsWith('__Host-otpanda_google_pending=')).split(';')[0];
 const finish=await x.flow.fetch(new Request('https://otpanda-api.abrahammurciano.workers.dev/auth/google/protection/complete',{method:'POST',headers:{Origin:'https://otpanda-api.abrahammurciano.workers.dev','Content-Type':'application/x-www-form-urlencoded',Cookie:csrfCookie+'; '+bindingCookie},body:new URLSearchParams({token:pending.token,csrf:csrfCookie.split('=')[1]})}),{clientAddress:'192.0.2.1'});
 const final=new URLSearchParams(new URL(finish.headers.get('Location')).hash.slice(1));assert.ok(final.get('code'));assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM device_sessions').get().n,2);assert.equal(x.db.sqlite.prepare('SELECT consumed_at FROM pending_logins').get().consumed_at,x.now());
});

test('external-email Google callback directly creates provider account and session without email challenge',async()=>{const x=await setup({email:'external@example.test'}),r=await x.flow.fetch(x.callback()),f=new URLSearchParams(new URL(r.headers.get('location')).hash.slice(1));assert.equal(r.status,303);assert.ok(f.get('code'));assert.ok(f.get('enrollment'));assert.equal(f.has('google'),false);assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM accounts').get().n,1);assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM device_sessions').get().n,1);assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM auth_challenges').get().n,0);assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM google_continuations').get().n,0);});
