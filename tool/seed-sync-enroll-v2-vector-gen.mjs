// Regenerates test/seed-sync-enroll-v2-vector.json: the v2 enrollment action digest, SYNTHETIC fixed key points only, for native interop (Kotlin and JS must agree byte for byte).
import {writeFileSync} from 'node:fs';
import {seedSyncEnrollAction} from '../src/seed-sync.js';
const keys=[];for(const seed of [1,2]){const k=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']),j=await crypto.subtle.exportKey('jwk',k.publicKey);keys.push({kty:j.kty,crv:j.crv,x:j.x,y:j.y});}
const cases=[];
for(const [i,jwk] of keys.entries())for(const gen of [0,7]){
 const input={ownerId:'owner'+i,installId:'I'.repeat(22),keyId:'0123456789abcdef0123456789abcdef',publicJwk:jwk,generation:gen};
 const preimage=JSON.stringify(['seed-sync-enroll-v2',input.ownerId,input.installId,input.keyId,JSON.stringify({kty:jwk.kty,crv:jwk.crv,x:jwk.x,y:jwk.y}),gen]);
 cases.push({input,preimage,digest:await seedSyncEnrollAction(input)});
}
writeFileSync(new URL('../test/seed-sync-enroll-v2-vector.json',import.meta.url),JSON.stringify({note:'synthetic test keys only; digest = hex SHA-256 of the UTF-8 preimage',cases},null,1)+'\n');
