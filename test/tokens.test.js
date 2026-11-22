import test from 'node:test';
import assert from 'node:assert/strict';
import {
  TOKEN_PREFIX,
  TOKEN_LENGTH,
  TOKEN_ID_BYTES,
  TOKEN_SECRET_BYTES,
  MAX_TOKEN_INPUT_LENGTH,
  base64urlEncode,
  base64urlDecode,
  generateAccessToken,
  parseAccessToken,
  digestSecret,
  digestToHex,
  timingSafeEqual,
} from '../src/tokens.js';

// The extension client's bearer acceptance rule (extension/src/client.js);
// the token format must stay inside it.
const CLIENT_ACCEPTANCE = /^[A-Za-z0-9_-]{32,512}$/;

test('generated tokens have the documented shape and embed the id as a prefix', () => {
  const { token, tokenId, secret } = generateAccessToken();
  assert.ok(token.startsWith(TOKEN_PREFIX));
  assert.equal(token.length, TOKEN_LENGTH);
  assert.ok(token.startsWith(TOKEN_PREFIX + tokenId));
  assert.equal(tokenId.length, Math.ceil((TOKEN_ID_BYTES * 8) / 6));
  assert.equal(secret.length, TOKEN_SECRET_BYTES);
  assert.match(token, CLIENT_ACCEPTANCE);
});

test('tokens are unique in practice', () => {
  const tokens = new Set();
  const ids = new Set();
  for (let i = 0; i < 1000; i++) {
    const { token, tokenId } = generateAccessToken();
    tokens.add(token);
    ids.add(tokenId);
  }
  assert.equal(tokens.size, 1000);
  assert.equal(ids.size, 1000);
});

test('parse round-trips a generated token exactly', () => {
  const { token, tokenId, secret } = generateAccessToken();
  const parsed = parseAccessToken(token);
  assert.equal(parsed.tokenId, tokenId);
  assert.deepEqual(parsed.secret, secret);
});

test('parse rejects malformed input without throwing', () => {
  const { token } = generateAccessToken();
  const cases = [
    undefined, null, 42, {}, '', 'otpda_', 'Bearer ' + token,
    token.replace(TOKEN_PREFIX, 'otpdb_'),
    token.slice(0, -1), token + 'A',
    TOKEN_PREFIX + base64urlEncode(new Uint8Array(40)),
    token.replace(/.$/, '.'), token.replace(/.$/, '='), token.replace(/.$/, '+'),
    'x'.repeat(MAX_TOKEN_INPUT_LENGTH + 1),
  ];
  for (const input of cases) assert.equal(parseAccessToken(input), null, String(input));
});

test('parse rejects non-canonical encodings (non-zero trailing bits)', () => {
  // 41 zero bytes encode to 55 'A's; the last sextet carries 4 real bits, so
  // 'B' decodes to the same bytes but is not the canonical spelling.
  const canonical = TOKEN_PREFIX + 'A'.repeat(55);
  const parsed = parseAccessToken(canonical);
  assert.equal(parsed.tokenId, 'AAAAAAAAAAAA');
  assert.equal(parseAccessToken(canonical.slice(0, -1) + 'B'), null);
});

test('base64url round-trips byte arrays of every length 0..64', () => {
  const bytes = new Uint8Array(64);
  crypto.getRandomValues(bytes);
  for (let n = 0; n <= 64; n++) {
    const slice = bytes.subarray(0, n);
    assert.deepEqual(base64urlDecode(base64urlEncode(slice), n), slice, `length ${n}`);
  }
});

test('base64urlDecode rejects wrong lengths, bad alphabets and non-strings', () => {
  assert.equal(base64urlDecode('AAA', 3), null);
  assert.equal(base64urlDecode('AAAAA', 3), null);
  assert.equal(base64urlDecode('AAA+', 3), null);
  assert.equal(base64urlDecode('AAA/', 3), null);
  assert.equal(base64urlDecode('AAA=', 3), null);
  assert.equal(base64urlDecode(42, 3), null);
  assert.equal(base64urlDecode('', 1), null);
  assert.deepEqual(base64urlDecode('', 0), new Uint8Array(0));
});

test('digestSecret is SHA-256 of the secret bytes', async () => {
  // Known answer: SHA-256 of 32 zero bytes.
  const digest = await digestSecret(new Uint8Array(32));
  assert.equal(digest.length, 32);
  assert.equal(digestToHex(digest), '66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925');
  await assert.rejects(() => digestSecret(new Uint8Array(31)), TypeError);
  await assert.rejects(() => digestSecret('not bytes'), TypeError);
});

test('timingSafeEqual compares equal-length byte strings only', () => {
  const a = crypto.getRandomValues(new Uint8Array(32));
  const b = Uint8Array.from(a);
  const c = Uint8Array.from(a);
  c[0] ^= 1;
  assert.equal(timingSafeEqual(a, b), true);
  assert.equal(timingSafeEqual(a, c), false);
  assert.equal(timingSafeEqual(a, new Uint8Array(31)), false);
  assert.equal(timingSafeEqual(a, 'not bytes'), false);
  assert.equal(timingSafeEqual(new Uint8Array(0), new Uint8Array(0)), false);
});

test('the random source is injectable for deterministic tests', () => {
  const fixed = (bytes) => bytes.fill(7);
  const first = generateAccessToken(fixed);
  const second = generateAccessToken(fixed);
  assert.equal(first.token, second.token);
  assert.equal(parseAccessToken(first.token).tokenId, first.tokenId);
});
