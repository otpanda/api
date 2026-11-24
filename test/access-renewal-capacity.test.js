import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { PasskeySignupService } from '../src/passkey-signup.js';
import { AccountIdentityService } from '../src/account-identity.js';
import { BrowserExchangeService,pkceChallenge } from '../src/browser-exchanges.js';
import { DeviceSessionService } from '../src/device-sessions.js';
import { authenticator } from './passkey-fixture.js';
const NOW=1_800_000_000_000,DAY=86400000;
async function setup(){const db=database();let now=NOW;const identity=new AccountIdentityService(db,{clock:()=>now}),signup=new PasskeySignupService(db,{clock:()=>now});const {token}=await identity.issueEmailChallenge({purpose:'signup-email',email:'a@example.com'});const c=await signup.begin({email:'a@example.com',emailToken:token,binding:'binding'}),a=authenticator();const account=await signup.finish({token:c.token,binding:'binding',response:a.registration({expected:c.options.challenge})});const proof={...account,verifiedAt:NOW,purpose:'authenticate'};const service=new DeviceSessionService(db,{clock:()=>now});return {db,service,proof,setNow:v=>now=v};}
import { AccessRenewal,renewalMessage,MAX_LINEAGES } from '../src/access-renewal.js';
import { base64urlEncode } from '../src/tokens.js';
import { createBrowserSessionHttp } from '../src/browser-session-http.js';
const redirectUri='https://otpanda.github.io/app/',verifier='a'.repeat(43),API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io';
const enc=u=>base64urlEncode(new Uint8Array(u));
async function newKey(){const k=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign']);return{priv:k.privateKey,pub:enc(await crypto.subtle.exportKey('raw',k.publicKey))};}
async function sign(k,{lineageId,handleId,expiresAt}){return enc(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},k.priv,renewalMessage({lineageId,handleId,expiresAt})));}
async function fixture(){const f=await setup();let now=NOW;const clock=()=>now;const service=new DeviceSessionService(f.db,{clock}),d=await service.issue({proof:f.proof,clientKind:'web'}),exchange=new BrowserExchangeService(f.db,{redirectUri,clock}),renewals=new AccessRenewal(f.db,{clock});
 const bind=async(key,v=verifier)=>{const x=await exchange.mint({deviceId:d.deviceId,challenge:await pkceChallenge(v),redirectUri});return exchange.exchange({code:x.code,verifier:v,redirectUri,...(key?{renewalKey:key.pub}:{})});};
 return{...f,service,d,exchange,renewals,clock,bind,setTime:v=>{now=v;f.setNow(v);}};}
const renewReq=async(f,k,e,over={})=>({token:e.access,lineageId:e.renewal.lineageId,expiresAt:f.clock()+30000,...over});
async function renew(f,k,e,over={}){const r=await renewReq(f,k,e,over);r.signature=over.signature??await sign(k,{lineageId:r.lineageId,handleId:over.handleId??e.renewal.handleId,expiresAt:r.expiresAt});return f.renewals.renew(r);}
const fill=(f,n)=>{for(let i=0;i<n;i++)f.db.sqlite.prepare('INSERT INTO device_access_handles(handle_id,secret_digest,device_id,created_at,expires_at) VALUES(?,?,?,?,?)').run('fill'+i+'x'.repeat(8),'a'.repeat(64),f.d.deviceId,f.clock(),f.clock()+300000);};
const spent=(f,id)=>f.db.sqlite.prepare('SELECT renewed_at,renew_receipt FROM device_access_handles WHERE handle_id=?').get(id);
test('capacity refusal gives the handle back: nothing spent, no successor, and renewal works once capacity frees',async()=>{
 const f=await fixture(),k=await newKey(),e=await f.bind(k);
 const live=()=>f.db.sqlite.prepare('SELECT count(*) n FROM device_access_handles WHERE expires_at>?').get(f.clock()).n;
 fill(f,64-live());assert.equal(live(),64);
 const r=await renew(f,k,e);assert.notEqual(r.status,'renewed');
 const s=spent(f,e.renewal.handleId);assert.equal(s.renewed_at,null,'handle must not stay spent');assert.equal(s.renew_receipt,null);assert.equal(live(),64);
 f.db.sqlite.prepare("DELETE FROM device_access_handles WHERE handle_id LIKE 'fill%'").run();
 const again=await renew(f,k,e);assert.equal(again.status,'renewed');f.db.sqlite.close();});
test('PROBE exchange at capacity: does the oldest lineage get evicted with no replacement',async()=>{
 const f=await fixture();const es=[];for(let i=0;i<MAX_LINEAGES;i++)es.push(await f.bind(await newKey(),'b'.repeat(42)+String.fromCharCode(97+i)));
 const lin=()=>f.db.sqlite.prepare('SELECT count(*) n FROM access_lineages').get().n;const live=()=>f.db.sqlite.prepare('SELECT count(*) n FROM device_access_handles WHERE expires_at>?').get(f.clock()).n;
 const before=lin();fill(f,64-live());
 const r=await f.bind(await newKey(),'c'.repeat(43));console.log('PROBE result',r===undefined?'refused':'ok','lineages before/after',before,lin());f.db.sqlite.close();});
