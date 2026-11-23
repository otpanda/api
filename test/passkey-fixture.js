import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { isoCBOR } from '@simplewebauthn/server/helpers';
const challenge=Buffer.alloc(32,7).toString('base64url');
const hash = value => createHash('sha256').update(value).digest();
export function authenticator() {
 const {privateKey,publicKey}=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),jwk=publicKey.export({format:'jwk'});
 const cose=isoCBOR.encode(new Map([[1,2],[3,-7],[-1,1],[-2,Buffer.from(jwk.x,'base64url')],[-3,Buffer.from(jwk.y,'base64url')]]));
 const id=Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url');
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
