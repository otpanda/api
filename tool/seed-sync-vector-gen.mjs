// Regenerates test/seed-sync-vector.json: SYNTHETIC keys only, public for native interop (Kotlin and TS must agree byte for byte).
import {writeFileSync} from 'node:fs';
import {seedSyncProofMessage} from '../src/seed-sync-proof.js';
import {sealBatch,importClientEphemeral,sha256Hex,sealAad} from '../src/seed-sync-seal.js';
import {base64urlEncode} from '../src/tokens.js';
const ec=(n,u)=>crypto.subtle.generateKey({name:n,namedCurve:'P-256'},true,u),pub=async k=>{const j=await crypto.subtle.exportKey('jwk',k);return {kty:j.kty,crv:j.crv,x:j.x,y:j.y};};
const sig=await ec('ECDSA',['sign','verify']),sign=async m=>base64urlEncode(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},sig.privateKey,m)));
const N='A'.repeat(43),H='b'.repeat(64),E=1800000120000;
const challenges={
 'seed-sync-enroll':{ownerId:'owner',keyId:'key',installId:'I'.repeat(22),generation:1,challenge:N,actionDigest:H,expiresAt:E},
 'seed-sync-snapshot':{ownerId:'owner',keyId:'key',deviceId:'device',generation:1,epoch:7,challenge:N,expiresAt:E},
 'seed-sync-status':{keyId:'key',challenge:N,expiresAt:E},
 'seed-sync-revoke':{ownerId:'owner',keyId:'key',deviceId:'device',generation:1,challenge:N,expiresAt:E},
 'seed-sync-batch':{ownerId:'owner',keyId:'key',deviceId:'device',generation:1,epoch:7,challenge:N,ephemeralDigest:'c'.repeat(64),entriesDigest:'d'.repeat(64),expiresAt:E},
};
const proofs={};for(const [p,c] of Object.entries(challenges)){const m=seedSyncProofMessage(p,c);proofs[p]={challenge:c,message:Buffer.from(m).toString('base64'),signature:await sign(m)};}
const cli=await ec('ECDH',['deriveBits']),srv=await ec('ECDH',['deriveBits']);
const client=await importClientEphemeral(base64urlEncode(new Uint8Array(await crypto.subtle.exportKey('raw',cli.publicKey))));
const challengeDigest='e'.repeat(64),ephemeralDigest=await sha256Hex(client.raw),secret=Uint8Array.from({length:20},(_,i)=>i+1);
const aad={ownerId:'owner',deviceId:'device',epoch:7,entryId:'entry1',seedVersion:3,algorithm:'SHA-1',digits:6,period:30};
const nonce=Uint8Array.from({length:12},(_,i)=>i+1);
const sealed=await sealBatch({client,challengeDigest,ephemeralDigest,items:[{aad,secret}],serverKeyPair:srv,nonces:[nonce]});
const out={note:'synthetic test keys only',signing:{publicJwk:await pub(sig.publicKey)},proofs,
 seal:{clientPrivateJwk:await crypto.subtle.exportKey('jwk',cli.privateKey),clientPublicRaw:base64urlEncode(client.raw),serverPrivateJwk:await crypto.subtle.exportKey('jwk',srv.privateKey),challengeDigest,ephemeralDigest,secret:Buffer.from(secret).toString('base64'),aad,aadBytes:Buffer.from(sealAad({...aad,challengeDigest,ephemeralDigest})).toString('base64'),nonce:base64urlEncode(nonce),serverPublicKey:sealed.serverPublicKey,ciphertext:sealed.entries[0].ciphertext}};
out.algorithmAads=Object.fromEntries(['SHA-1','SHA-256','SHA-512'].map(a=>[a,Buffer.from(sealAad({...aad,algorithm:a,challengeDigest,ephemeralDigest})).toString('base64')]));
// Off-curve and malformed client ephemeral keys the server must refuse (and native must refuse for the server key).
const raw=new Uint8Array(client.raw);const offCurve=raw.slice();offCurve[64]^=1;
out.badPoints={offCurve:base64urlEncode(offCurve),compressedPrefix:base64urlEncode(Uint8Array.from([2,...raw.slice(1,33)])),wrongLength:base64urlEncode(raw.slice(0,64)),nonCanonicalBase64:base64urlEncode(raw)+'='};
writeFileSync(new URL('../test/seed-sync-vector.json',import.meta.url),JSON.stringify(out,null,1)+'\n');
