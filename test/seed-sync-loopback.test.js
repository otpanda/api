// Real TCP loopback to the real runtime host (tool/seed-sync-loopback/server.mjs). The client side here is a JS stand-in for the app's Dart adapters: it applies the SAME
// strict shape rules as lib/offline_totp/seed_enrollment_http.dart, seed_sync_http.dart and lib/native/native_passkey.dart (passkeyRequestJson, passkeyAssertionBody),
// so a server response that the Dart adapter would refuse fails here. It does NOT run Dart, Kotlin, Keystore or Credential Manager.
import test from 'node:test';import assert from 'node:assert/strict';
import {startLoopback,OWNER,RFC_SEED} from '../tool/seed-sync-loopback/server.mjs';
import {seedSyncProofMessage} from '../src/seed-sync-proof.js';import {entriesDigest} from '../src/seed-sync.js';
import {openSealed,sha256Hex} from '../src/seed-sync-seal.js';import {base64urlEncode,base64urlDecode} from '../src/tokens.js';import {hashText} from '../src/sessions.js';
const TOKEN=/^otpda_[A-Za-z0-9_-]{55}$/,NONCE=/^[A-Za-z0-9_-]{43}$/,HEX64=/^[0-9a-f]{64}$/,HEX32=/^[0-9a-f]{32}$/;
const kid=()=>[...crypto.getRandomValues(new Uint8Array(16))].map(b=>b.toString(16).padStart(2,'0')).join('');
const INSTALL=base64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
const keys=(o,k)=>o&&typeof o==='object'&&Object.keys(o).sort().join()===[...k].sort().join();
// Port of passkeyRequestJson (native_passkey.dart): throws on anything the app would refuse before the OS prompt.
function passkeyRequestJson(begin,nowMs,rpId='otpanda.github.io'){const o=begin.options;
 if(!TOKEN.test(begin.token??'')||!o||o.rpId!==rpId||o.userVerification!=='required'||!NONCE.test(o.challenge??'')||!Array.isArray(o.allowCredentials)||o.allowCredentials.length>50||!Number.isSafeInteger(begin.expiresAt)||begin.expiresAt<=nowMs)throw Error('app would refuse step-up options');
 return JSON.stringify({rpId,challenge:o.challenge,userVerification:'required',timeout:Math.min(Math.max(begin.expiresAt-nowMs,1),120000),allowCredentials:o.allowCredentials.map(v=>({type:'public-key',id:v.id}))});}
// Port of passkeyAssertionBody.
function passkeyAssertionBody(raw){const j=JSON.parse(raw),r=j.response;if(j.type!=='public-key'||typeof j.id!=='string'||typeof j.rawId!=='string'||typeof r?.clientDataJSON!=='string'||typeof r.authenticatorData!=='string'||typeof r.signature!=='string')throw Error('app would refuse assertion');
 return{id:j.id,rawId:j.rawId,type:'public-key',clientExtensionResults:{},response:{clientDataJSON:r.clientDataJSON,authenticatorData:r.authenticatorData,signature:r.signature,userHandle:typeof r.userHandle==='string'?r.userHandle:null}};}
async function world(opts){
 const lb=await startLoopback(opts),sess=await (await fetch(lb.url+'/__loopback/session',{method:'POST'})).json();
 const dk=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']),jx=await crypto.subtle.exportKey('jwk',dk.publicKey),jwk={kty:'EC',crv:'P-256',x:jx.x,y:jx.y};
 const sign=async(p,c)=>base64urlEncode(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},dk.privateKey,seedSyncProofMessage(p,c))));
 // No Origin header, bearer only, exact JSON body: the app's DevicePost contract.
 const post=async(op,body,auth=sess.access)=>{const r=await fetch(lb.url+'/v1/manage/seed-sync/'+op,{method:'POST',headers:{'Content-Type':'application/json',...(auth?{Authorization:'Bearer '+auth}:{})},body:JSON.stringify(body)});let b=null;try{b=await r.json();}catch{}return{status:r.status,body:b};};
 const state=async()=>(await fetch(lb.url+'/__loopback/state')).json();
 const fresh=async()=>{const k=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']),x=await crypto.subtle.exportKey('jwk',k.publicKey);return{jwk:{kty:'EC',crv:'P-256',x:x.x,y:x.y},sign:async(p,c)=>base64urlEncode(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},k.privateKey,seedSyncProofMessage(p,c))))};};
 const enroll=async(keyId=kid(),key={jwk,sign})=>{const publicJwk=key.jwk;
  const su=await post('stepup-begin',{installId:INSTALL,keyId,publicJwk});assert.equal(su.status,200);assert.ok(keys(su.body,['token','options','expiresAt']),'stepup shape');
  const req=passkeyRequestJson(su.body,Date.now());
  const ar=await fetch(lb.url+'/__loopback/assert',{method:'POST',body:req});assert.equal(ar.status,200);const assertion=passkeyAssertionBody(JSON.stringify(await ar.json()));
  const eb=await post('enroll-begin',{installId:INSTALL,keyId,publicJwk,response:assertion,token:su.body.token});
  return{su,eb,keyId,key};};
 return{lb,sess,jwk,sign,post,state,enroll,dk,fresh};
}
test('TCP loopback: session, context, step-up through the synthetic authenticator, enroll, snapshot, sealed batch opens to the RFC seed; shapes satisfy the Dart adapter rules',async()=>{
 const w=await world();try{
  const ctx=await w.post('context',{});assert.equal(ctx.status,200);assert.ok(keys(ctx.body,['generation']));assert.ok(Number.isSafeInteger(ctx.body.generation)&&ctx.body.generation>=0);
  const {eb,keyId}=await w.enroll();assert.equal(eb.status,200);assert.ok(keys(eb.body,['token','challenge']));assert.ok(TOKEN.test(eb.body.token));
  const c=eb.body.challenge;assert.ok(keys(c,['ownerId','keyId','installId','generation','challenge','actionDigest','expiresAt']),'enroll challenge shape');
  assert.ok(NONCE.test(c.challenge)&&HEX64.test(c.actionDigest)&&HEX32.test(c.keyId)&&c.keyId===keyId&&c.installId===INSTALL&&c.ownerId===OWNER,'echo and formats');
  const ef=await w.post('enroll-finish',{signature:await w.sign('seed-sync-enroll',c),token:eb.body.token});assert.equal(ef.status,200);assert.deepEqual(ef.body,{keyId});
  const st=await w.state();assert.equal(st.keys.length,1);assert.equal(st.keys[0].revoked,false);assert.equal(st.notices,1);assert.equal(st.assertionsSigned,1);
  const sb=await w.post('snapshot-begin',{epoch:0,keyId});assert.equal(sb.status,200);
  const sf=await w.post('snapshot-finish',{signature:await w.sign('seed-sync-snapshot',sb.body.challenge),token:sb.body.token});assert.equal(sf.status,200);
  assert.deepEqual(sf.body.entries.map(x=>[x.entryId,x.algorithm,x.digits,x.period]),[['sealed-entry','SHA-1',8,30]]);
  const eph=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']),raw=base64urlEncode(new Uint8Array(await crypto.subtle.exportKey('raw',eph.publicKey)));assert.equal(raw.length,87);
  const ents=sf.body.entries.map(x=>({entryId:x.entryId,seedVersion:x.seedVersion})),bb=await w.post('batch-begin',{entries:ents,ephemeralKey:raw,epoch:0,keyId});assert.equal(bb.status,200);
  assert.equal(bb.body.challenge.entriesDigest,await entriesDigest(ents));
  const bf=await w.post('batch-finish',{signature:await w.sign('seed-sync-batch',bb.body.challenge),token:bb.body.token});assert.equal(bf.status,200);
  const r=bf.body.results[0],challengeDigest=await hashText(bb.body.challenge.challenge),ephemeralDigest=await sha256Hex(base64urlDecode(raw,65));assert.equal(r.status,'sealed');
  const opened=await openSealed({clientPrivateKey:eph.privateKey,serverPublicKey:bf.body.serverPublicKey,challengeDigest,ephemeralDigest,aad:{ownerId:OWNER,deviceId:w.sess.deviceId,epoch:0,entryId:'sealed-entry',seedVersion:r.seedVersion,algorithm:r.algorithm,digits:r.digits,period:r.period},nonce:r.nonce,ciphertext:r.ciphertext});
  assert.deepEqual([...opened],[...RFC_SEED],'sealed download equals the RFC 6238 test seed');
  assert.equal(JSON.stringify(bf.body).includes(base64urlEncode(RFC_SEED)),false);
 }finally{await w.lb.close();}});
test('TCP loopback refusals: no bearer, an Origin header, wrong assertion rpId, a stale/unknown token, and a second enroll for another key id leaves exactly one active key',async()=>{
 const w=await world();try{
  assert.equal((await w.post('context',{},null)).status,401);
  const withOrigin=await fetch(w.lb.url+'/v1/manage/seed-sync/context',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+w.sess.access,Origin:'https://otpanda.github.io'},body:'{}'});assert.equal(withOrigin.status,403);
  const su=await w.post('stepup-begin',{installId:INSTALL,keyId:kid(),publicJwk:w.jwk});
  assert.throws(()=>passkeyRequestJson(su.body,Date.now(),'evil.example'),/refuse/,'the app refuses a different rpId');
  const bad=await fetch(w.lb.url+'/__loopback/assert',{method:'POST',body:JSON.stringify({rpId:'evil.example',challenge:su.body.options.challenge,userVerification:'required',allowCredentials:[]})});assert.equal(bad.status,400,'synthetic authenticator refuses other relying parties');
  assert.equal((await w.post('enroll-finish',{signature:'A'.repeat(86),token:'otpda_'+'A'.repeat(55)})).status,409,'unknown token is the opaque 409');
  const a=await w.enroll(),ac=a.eb.body;assert.equal(a.eb.status,200,JSON.stringify(a.eb));await w.post('enroll-finish',{signature:await a.key.sign('seed-sync-enroll',ac.challenge),token:ac.token});
  const reuse=await w.enroll(kid(),{jwk:w.jwk,sign:w.sign});assert.equal(reuse.eb.status,409,'a public key already enrolled is never reused');
  const b=await w.enroll(kid(),await w.fresh()),bc=b.eb.body;assert.equal(b.eb.status,200,JSON.stringify(b.eb));await w.post('enroll-finish',{signature:await b.key.sign('seed-sync-enroll',bc.challenge),token:bc.token});
  const st=await w.state();assert.equal(st.keys.filter(k=>!k.revoked).length,1);assert.equal(st.keys.length,2);assert.equal(st.keys.find(k=>k.revoked).reason,'superseded');
 }finally{await w.lb.close();}});
