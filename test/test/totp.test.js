import test from 'node:test';
import assert from 'node:assert/strict';
import { decodeBase32, hotp, totp } from '../src/totp.js';
const ascii = value => new TextEncoder().encode(value);
const secret = ascii('12345678901234567890');
test('RFC 4226 all ten HOTP vectors', async () => {
  const expected = ['755224','287082','359152','969429','338314','254676','287922','162583','399871','520489'];
  for (let i=0;i<expected.length;i++) assert.equal(await hotp(secret, BigInt(i)), expected[i]);
});
const times = [59,1111111109,1111111111,1234567890,2000000000,20000000000];
const vectors = [
  ['SHA-1','12345678901234567890',['94287082','07081804','14050471','89005924','69279037','65353130']],
  ['SHA-256','12345678901234567890123456789012',['46119246','68084774','67062674','91819424','90698825','77737706']],
  ['SHA-512','1234567890123456789012345678901234567890123456789012345678901234',['90693936','25091201','99943326','93441116','38618901','47863826']],
];
for (const [algorithm,key,expected] of vectors) test(`RFC 6238 ${algorithm} vectors`, async () => {
  for (let i=0;i<times.length;i++) assert.equal(await totp(ascii(key), { unixSeconds: times[i], algorithm, digits: 8 }),expected[i]);
});
test('Base32 canonical decoding, padding and lowercase', () => {
  for (const encoded of ['MZXW6===','MZXW6','mzxw6']) assert.equal(new TextDecoder().decode(decodeBase32(encoded)),'foo');
  for (const encoded of ['', 'A', 'MZ', 'MZ======', 'MY=', 'MY======X', 'MY ======', '12']) assert.throws(()=>decodeBase32(encoded));
});
test('reject invalid time, counter, algorithm, key and digits', async () => {
  for (const unixSeconds of [-1,NaN,Infinity,1.5,undefined]) await assert.rejects(totp(secret,{unixSeconds}));
  await assert.rejects(hotp(secret,-1n));
  await assert.rejects(hotp(secret,1));
  await assert.rejects(hotp(secret,2n**64n));
  await assert.rejects(hotp(secret,0n,{digits:5}));
  await assert.rejects(hotp(secret,0n,{algorithm:'MD5'}));
  await assert.rejects(hotp(new Uint8Array(0),0n));
});
test('period boundary changes only at next time step', async () => {
  assert.equal(await totp(secret,{unixSeconds:59}),await totp(secret,{unixSeconds:30}));
  assert.notEqual(await totp(secret,{unixSeconds:59}),await totp(secret,{unixSeconds:60}));
});
