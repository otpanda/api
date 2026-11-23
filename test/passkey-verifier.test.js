import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import { PasskeyVerifier } from '../src/passkey-verifier.js';
const challenge=Buffer.alloc(32,7).toString('base64url');
const hash = value => createHash('sha256').update(value).digest();
function authenticator() {
 const {privateKey,publicKey}=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),jwk=publicKey.export({format:'jwk'});
 const cose=isoCBOR.encode(new Map([[1,2],[3,-7],[-1,1],[-2,Buffer.from(jwk.x,'base64url')],[-3,Buffer.from(jwk.y,'base64url')]]));
 const id=Buffer.alloc(32,3).toString('base64url');
 const credential={id,publicKey:cose,counter:0,transports:['internal']};
 function registration({origin='https://otpanda.github.io',expected=challenge,flags=0x45,rp='otpanda.github.io'}={}) {
  const client=Buffer.from(JSON.stringify({type:'webauthn.create',challenge:expected,origin,crossOrigin:false}));
  const idBytes=Buffer.from(id,'base64url'),len=Buffer.alloc(2);len.writeUInt16BE(idBytes.length);
  const auth=Buffer.concat([hash(rp),Buffer.from([flags]),Buffer.alloc(4),Buffer.alloc(16),len,idBytes,Buffer.from(cose)]);
  const att=isoCBOR.encode(new Map([['fmt','none'],['attStmt',new Map()],['authData',auth]]));
  return {id,rawId:id,type:'public-key',clientExtensionResults:{},response:{clientDataJSON:client.toString('base64url'),attestationObject:Buffer.from(att).toString('base64url'),transports:['internal']}};
 }
 function assertion({origin='https://otpanda.github.io',expected=challenge,flags=5,rp='otpanda.github.io',counter=1,invalidSignature=false}={}) {
  const client=Buffer.from(JSON.stringify({type:'webauthn.get',challenge:expected,origin,crossOrigin:false})),count=Buffer.alloc(4);count.writeUInt32BE(counter);
  const auth=Buffer.concat([hash(rp),Buffer.from([flags]),count]);
  const signature=sign('sha256',Buffer.concat([auth,hash(client)]),privateKey);
  if(invalidSignature)signature[signature.length-1]^=1;
  return {id,rawId:id,type:'public-key',clientExtensionResults:{},response:{clientDataJSON:client.toString('base64url'),authenticatorData:auth.toString('base64url'),signature:signature.toString('base64url')}};
 }
 return {registration,assertion,credential};
}
test('registration options require resident passkeys and UV, exact approved RP and stable opaque owner',async()=>{
 const v=new PasskeyVerifier(),o=await v.registrationOptions({ownerId:'owner-id',email:'a@example.com',challenge});
 assert.equal(o.challenge,challenge);assert.equal(o.rp.id,'otpanda.github.io');assert.equal(o.authenticatorSelection.userVerification,'required');assert.equal(o.authenticatorSelection.residentKey,'required');assert.equal(o.attestation,'none');assert.deepEqual(o.pubKeyCredParams.map(x=>x.alg),[-7,-257]);assert.equal(Buffer.from(o.user.id,'base64url').toString(),'owner-id');
 const a=await v.authenticationOptions({challenge});assert.equal(a.challenge,challenge);assert.equal(a.rpId,'otpanda.github.io');assert.equal(a.userVerification,'required');
});
test('real synthetic registration and signed assertion verify through actual library',async()=>{
 const a=authenticator(),v=new PasskeyVerifier();
 const registered=await v.verifyRegistration({response:a.registration(),expectedChallenge:challenge});assert.ok(registered.userVerified);assert.equal(registered.credential.id,a.credential.id);
 const verified=await v.verifyAuthentication({response:a.assertion(),expectedChallenge:challenge,credential:registered.credential});assert.equal(verified.newCounter,1);assert.equal(verified.userVerified,true);
});
test('registration rejects wrong RP/challenge/origin and absent user verification',async()=>{
 const a=authenticator(),v=new PasskeyVerifier();
 for(const change of [{origin:'https://evil.test'},{origin:'https://otpanda.github.io.evil.test'},{expected:Buffer.alloc(32,8).toString('base64url')},{rp:'evil.test'},{flags:0x41}])await assert.rejects(v.verifyRegistration({response:a.registration(change),expectedChallenge:challenge}));
});
test('authentication rejects wrong RP/challenge/origin, missing UV, forged signature and counter replay',async()=>{
 const a=authenticator(),v=new PasskeyVerifier();
 for(const change of [{origin:'https://evil.test'},{expected:Buffer.alloc(32,8).toString('base64url')},{rp:'evil.test'},{flags:1},{invalidSignature:true}]) {
  let result;try{result=await v.verifyAuthentication({response:a.assertion(change),expectedChallenge:challenge,credential:a.credential});}catch{continue;}assert.equal(result,undefined);
 }
 await assert.rejects(v.verifyAuthentication({response:a.assertion({counter:1}),expectedChallenge:challenge,credential:{...a.credential,counter:1}}));
});
test('Android origin is not allowed absent verified release fingerprint config',async()=>{
 const a=authenticator(),origin='android:apk-key-hash:'+Buffer.alloc(32,9).toString('base64url');
 await assert.rejects(new PasskeyVerifier().verifyRegistration({response:a.registration({origin}),expectedChallenge:challenge}));
 const registered=await new PasskeyVerifier({androidOrigins:[origin]}).verifyRegistration({response:a.registration({origin}),expectedChallenge:challenge});assert.ok(registered.userVerified);
 assert.throws(()=>new PasskeyVerifier({androidOrigins:['https://evil.test']}));
});

test('malformed expected challenge and response fail closed',async()=>{
 const v=new PasskeyVerifier();
 for(const c of [undefined,()=>true,'short','A'.repeat(44),'A'.repeat(42)+'B']){await assert.rejects(v.authenticationOptions({challenge:c}));await assert.rejects(v.verifyRegistration({response:{},expectedChallenge:c}));}
 for(const response of [null,{}, {id:'id',response:{}}, {id:'id',rawId:'id',type:'public-key',response:{clientDataJSON:'bad'}}])await assert.rejects(v.verifyRegistration({response,expectedChallenge:challenge}));
});
