// RFC 4226 / RFC 6238 primitives. No storage, networking or logging.
const ALGORITHMS = new Set(['SHA-1', 'SHA-256', 'SHA-512']);

export function decodeBase32(encoded) {
  if (typeof encoded !== 'string' || !encoded.length) throw new TypeError('Base32 secret required');
  const value = encoded.toUpperCase();
  if (!/^[A-Z2-7]+={0,6}$/.test(value)) throw new TypeError('Invalid Base32');
  const raw = value.replace(/=+$/, '');
  const remainder = raw.length % 8;
  const padding = { 0: 0, 2: 6, 4: 4, 5: 3, 7: 1 }[remainder];
  if (padding === undefined || (value.includes('=') && value.length - raw.length !== padding)) {
    throw new TypeError('Invalid Base32 length');
  }
  let bits = 0, accumulator = 0;
  const bytes = [];
  for (const char of raw) {
    accumulator = (accumulator << 5) | 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(char);
    bits += 5;
    if (bits >= 8) { bits -= 8; bytes.push((accumulator >>> bits) & 255); }
  }
  if (bits && (accumulator & ((1 << bits) - 1))) throw new TypeError('Non-canonical Base32 tail');
  return new Uint8Array(bytes);
}

export async function hotp(secret, counter, { digits = 6, algorithm = 'SHA-1' } = {}) {
  if (!(secret instanceof Uint8Array) || secret.byteLength < 10) throw new TypeError('Secret must contain at least 80 bits');
  if (!Number.isInteger(digits) || digits < 6 || digits > 8) throw new RangeError('Digits must be 6 through 8');
  if (!ALGORITHMS.has(algorithm)) throw new RangeError('Unsupported HMAC algorithm');
  if (typeof counter !== 'bigint' || counter < 0n || counter > 0xffffffffffffffffn) throw new RangeError('Invalid counter');
  const message = new Uint8Array(8);
  new DataView(message.buffer).setBigUint64(0, counter);
  const key = await crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: algorithm }, false, ['sign']);
  const digest = new Uint8Array(await crypto.subtle.sign('HMAC', key, message));
  const offset = digest.at(-1) & 15;
  const number = new DataView(digest.buffer).getUint32(offset) & 0x7fffffff;
  return String(number % 10 ** digits).padStart(digits, '0');
}

export async function totp(secret, { unixSeconds, period = 30, digits = 6, algorithm = 'SHA-1' } = {}) {
  if (!Number.isSafeInteger(unixSeconds) || unixSeconds < 0) throw new RangeError('Explicit nonnegative integer Unix time required');
  if (!Number.isSafeInteger(period) || period <= 0) throw new RangeError('Invalid period');
  return hotp(secret, BigInt(Math.floor(unixSeconds / period)), { digits, algorithm });
}

// Codes for consecutive periods with a single HMAC key import. Equivalent to
// calling totp() for each period start; `count` is bounded by the caller.
export async function totpWindow(secret, { unixSeconds, period = 30, digits = 6, algorithm = 'SHA-1', count } = {}) {
  if (!(secret instanceof Uint8Array) || secret.byteLength < 10) throw new TypeError('Secret must contain at least 80 bits');
  if (!Number.isSafeInteger(unixSeconds) || unixSeconds < 0) throw new RangeError('Explicit nonnegative integer Unix time required');
  if (!Number.isSafeInteger(period) || period <= 0) throw new RangeError('Invalid period');
  if (!Number.isInteger(digits) || digits < 6 || digits > 8) throw new RangeError('Digits must be 6 through 8');
  if (!ALGORITHMS.has(algorithm)) throw new RangeError('Unsupported HMAC algorithm');
  if (!Number.isInteger(count) || count < 1 || count > 64) throw new RangeError('Invalid window count');
  const first = BigInt(Math.floor(unixSeconds / period));
  const key = await crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: algorithm }, false, ['sign']);
  const codes = [];
  for (let i = 0n; i < BigInt(count); i++) {
    const message = new Uint8Array(8);
    new DataView(message.buffer).setBigUint64(0, first + i);
    const digest = new Uint8Array(await crypto.subtle.sign('HMAC', key, message));
    const offset = digest.at(-1) & 15;
    codes.push(String((new DataView(digest.buffer).getUint32(offset) & 0x7fffffff) % 10 ** digits).padStart(digits, '0'));
  }
  return codes;
}
