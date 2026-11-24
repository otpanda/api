import assert from 'node:assert/strict';
import {DurableDeviceKeys,deviceEnrollmentAction} from '../src/durable-device-keys.js';
import {deviceProofMessage} from '../src/device-key-proof.js';
import {base64urlEncode} from '../src/tokens.js';
import {createRequire} from 'node:module';import{readdirSync,readFileSync}from'node:fs';
const require=createRequire(import.meta.url);const{Miniflare,convertV4MiniflareOptions}=require('miniflare');
const options=await convertV4MiniflareOptions({modules:true,script:'export default{fetch(){return new Response("ok")}}',compatibilityDate:'2026-11-23',d1Databases:['DB']});const mf=new Miniflare(options);
const NOW=1800000000000,BINDING='b'.repeat(43),ACTION='c'.repeat(64);
try {
const db=await mf.getD1Database('DB');
for(const f of readdirSync('migrations').sort())for(const sql of readFileSync('migrations/'+f,'utf8').replace(/^--.*$/gm,'').split(/;(?=\s*(?:CREATE|ALTER|PRAGMA|$))/).map(s=>s.trim()).filter(Boolean))await db.prepare(sql).run();
await db.prepare('INSERT INTO accounts(owner_id,created_at) VALUES(?1,?2)').bind('owner',NOW).run();
await db.prepare('INSERT INTO account_security(owner_id) VALUES(?1)').bind('owner').run();
await db.prepare('INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)').bind('credential','owner',new Uint8Array([1]),0,'[]','singleDevice',0,NOW).run();
let now=NOW;const service=new DurableDeviceKeys(db,{clock:()=>now});
const keys=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']),raw=await crypto.subtle.exportKey('jwk',keys.publicKey),jwk={kty:raw.kty,crv:raw.crv,x:raw.x,y:raw.y};
const sign=async c=>base64urlEncode(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},keys.privateKey,deviceProofMessage(c))));
const strongProof={ownerId:'owner',credentialId:'credential',generation:0,purpose:'step-up',actionDigest:await deviceEnrollmentAction(jwk),verifiedAt:NOW};
const enroll=async()=>{const c=await service.beginEnrollment({jwk,strongProof,browserBinding:BINDING});return service.finish({token:c.token,browserBinding:BINDING,signature:await sign(c.challenge)});};
const first=await enroll();assert.ok(first);assert.equal((await enroll()).keyId,first.keyId);
const work=()=>service.beginProof({keyId:first.keyId,purpose:'recover-access',actionDigest:ACTION,browserBinding:BINDING});
const c=await work(),signature=await sign(c.challenge);const race=await Promise.all([service.finish({token:c.token,browserBinding:BINDING,signature}),service.finish({token:c.token,browserBinding:BINDING,signature})]);assert.equal(race.filter(Boolean).length,1);
const expiry=await work();now+=120000;assert.equal(await service.finish({token:expiry.token,browserBinding:BINDING,signature:await sign(expiry.challenge)}),undefined);
const active=await work();await service.revoke({ownerId:'owner',keyId:first.keyId});assert.equal(await service.finish({token:active.token,browserBinding:BINDING,signature:await sign(active.challenge)}),undefined);
now=NOW;assert.equal(await service.beginEnrollment({jwk,strongProof,browserBinding:BINDING}),undefined);
console.log('PASS actual local workerd D1 migrations0021, cryptographic enrollment/reconciliation, parallel finish one winner, expiry and revocation tombstone');
} finally {await mf.dispose();}
