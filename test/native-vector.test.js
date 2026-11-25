import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {nativeMessage,NATIVE_DOMAIN} from '../src/native-sessions.js';
import {importRenewalKey} from '../src/access-renewal.js';
import {base64urlDecode} from '../src/tokens.js';
const v=JSON.parse(readFileSync(new URL('./native-vector.json',import.meta.url),'utf8'));
const hex=h=>Uint8Array.from(Buffer.from(h,'hex'));
function derToRaw(d){let i=2;const out=new Uint8Array(64);for(const o of [0,32]){if(d[i]!==2)throw Error('der');const n=d[i+1];let b=d.slice(i+2,i+2+n);i+=2+n;while(b.length>32&&b[0]===0)b=b.slice(1);if(b.length>32)throw Error('der');out.set(b,o+32-b.length);}return out;}
test('domain and endpoint strings are fixed',()=>{assert.equal(NATIVE_DOMAIN,'otpanda-native-v1');});
for(const purpose of ['renew','logout'])test(`vector ${purpose}: exact message bytes, server-format signature verifies, DER converts to the same raw signature, tampering fails`,async()=>{
 const c=v.cases[purpose],msg=nativeMessage({purpose,deviceId:c.device_id,nonce:c.nonce,expiresAt:c.expires_at});
 const literal=['otpanda-native-v1','POST /auth/native/'+purpose,c.device_id,c.nonce,String(c.expires_at)].join('\n');
 assert.equal(c.message_utf8,literal);assert.equal(Buffer.from(msg).toString('hex'),c.message_hex);assert.equal(literal.split('\n').length,5);assert.ok(!literal.endsWith('\n'));
 const key=await importRenewalKey(v.public_key);assert.ok(key);
 assert.ok(await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,base64urlDecode(c.signature_raw,64),msg));
 assert.deepEqual(derToRaw(hex(c.signature_der_hex)),base64urlDecode(c.signature_raw,64));
 const other=purpose==='renew'?'logout':'renew';
 assert.equal(await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,base64urlDecode(c.signature_raw,64),nativeMessage({purpose:other,deviceId:c.device_id,nonce:c.nonce,expiresAt:c.expires_at})),false);
 assert.equal(await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,base64urlDecode(c.signature_raw,64),new TextEncoder().encode(literal+'\n')),false,'trailing newline is not canonical');
 assert.equal(await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,base64urlDecode(c.signature_raw,64),new TextEncoder().encode(literal.replaceAll('\n','\r\n'))),false);
});
