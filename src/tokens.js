// Opaque access-token primitives. No storage, networking or logging.
//
// Token format: `otpda_` followed by base64url(id || secret), where the id is
// 9 random bytes (a public record identifier) and the secret is 32 random
// bytes (the credential). Only the SHA-256 digest of the secret may be stored.
// The charset and length intentionally satisfy the extension client's bearer
// acceptance rule (/^[A-Za-z0-9_-]{32,512}$/) so the two sides stay aligned.

export const TOKEN_PREFIX = 'otpda_';
export const TOKEN_ID_BYTES = 9;
export const TOKEN_SECRET_BYTES = 32;
const PAYLOAD_BYTES = TOKEN_ID_BYTES + TOKEN_SECRET_BYTES;
const PAYLOAD_CHARS = Math.ceil((PAYLOAD_BYTES * 8) / 6);
export const TOKEN_LENGTH = TOKEN_PREFIX.length + PAYLOAD_CHARS;
// Hard cap applied before any parsing work, so oversized inputs cost O(1).
export const MAX_TOKEN_INPUT_LENGTH = 1024;

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const VALUES = new Map([...ALPHABET].map((ch, i) => [ch, i]));

export function base64urlEncode(bytes) {
  let out = '';
  let acc = 0;
  let bits = 0;
  for (const byte of bytes) {
    acc = ((acc << 8) | byte) >>> 0;
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      out += ALPHABET[(acc >>> bits) & 63];
    }
    acc &= (1 << bits) - 1;
  }
  if (bits > 0) out += ALPHABET[(acc << (6 - bits)) & 63];
  return out;
}

// Strict decoder: exact length for the expected byte count, alphabet-only,
// and canonical (non-zero trailing bits are rejected). Returns null instead
// of throwing on any deviation so it is safe on untrusted input.
export function base64urlDecode(text, expectedBytes) {
  if (typeof text !== 'string' || !Number.isSafeInteger(expectedBytes) || expectedBytes < 0) return null;
  if (text.length !== Math.ceil((expectedBytes * 8) / 6)) return null;
  const out = [];
  let acc = 0;
  let bits = 0;
  for (const ch of text) {
    const value = VALUES.get(ch);
    if (value === undefined) return null;
    acc = ((acc << 6) | value) >>> 0;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >>> bits) & 255);
    }
    acc &= (1 << bits) - 1;
  }
  if (out.length !== expectedBytes) return null;
  const bytes = Uint8Array.from(out);
  return base64urlEncode(bytes) === text ? bytes : null;
}

export function generateAccessToken(randomFill = (bytes) => crypto.getRandomValues(bytes)) {
  if (typeof randomFill !== 'function') throw new TypeError('Random source required');
  const payload = new Uint8Array(PAYLOAD_BYTES);
  randomFill(payload);
  return {
    token: TOKEN_PREFIX + base64urlEncode(payload),
    tokenId: base64urlEncode(payload.subarray(0, TOKEN_ID_BYTES)),
    secret: payload.subarray(TOKEN_ID_BYTES),
  };
}

// Returns { tokenId, secret } or null. Never throws on untrusted input.
export function parseAccessToken(input) {
  if (typeof input !== 'string' || input.length > MAX_TOKEN_INPUT_LENGTH) return null;
  if (!input.startsWith(TOKEN_PREFIX)) return null;
  const payload = base64urlDecode(input.slice(TOKEN_PREFIX.length), PAYLOAD_BYTES);
  if (!payload) return null;
  return {
    tokenId: base64urlEncode(payload.subarray(0, TOKEN_ID_BYTES)),
    secret: payload.subarray(TOKEN_ID_BYTES),
  };
}

// Plain SHA-256 is sufficient here because the secret carries 256 bits of
// entropy; there is no password-guessing surface to slow down. If a future
// threat model adds server-side peppering, only this function changes.
export async function digestSecret(secretBytes) {
  if (!(secretBytes instanceof Uint8Array) || secretBytes.length !== TOKEN_SECRET_BYTES) {
    throw new TypeError(`Secret must be a ${TOKEN_SECRET_BYTES}-byte Uint8Array`);
  }
  return new Uint8Array(await crypto.subtle.digest('SHA-256', secretBytes));
}

export function digestToHex(digest) {
  if (!(digest instanceof Uint8Array)) throw new TypeError('Digest must be a Uint8Array');
  return [...digest].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Fixed-work comparison for equal-length byte strings. Different lengths
// return false immediately; digest lengths are fixed by construction, so this
// leaks nothing about content.
export function timingSafeEqual(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length || a.length === 0) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
