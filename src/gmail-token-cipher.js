// Purpose-bound AES-GCM envelopes for Gmail refresh tokens. The purpose and
// (owner, source) binding are authenticated, so a token envelope cannot be
// opened as a code or seed envelope, nor moved to another owner or source.
import { base64urlEncode, base64urlDecode } from './tokens.js';
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
function aad(c, keyId) {
  if (!c || ['ownerId', 'sourceId'].some(k => typeof c[k] !== 'string' || !c[k] || c[k].length > 256)) throw new TypeError('Complete token context required');
  return encoder.encode(JSON.stringify(['otpanda-gmail-refresh', 1, keyId, c.ownerId, c.sourceId]));
}
export class GmailTokenCipher {
  #keys; #active;
  constructor({ keys, activeKeyId }) {
    if (!(keys instanceof Map) || !keys.has(activeKeyId)) throw new TypeError('Active encryption key required');
    for (const [id, key] of keys) if (typeof id !== 'string' || !/^[a-zA-Z0-9_-]{1,64}$/.test(id) || key?.algorithm?.name !== 'AES-GCM' || key.algorithm.length !== 256 || key.extractable || !key.usages.includes('encrypt') || !key.usages.includes('decrypt')) throw new TypeError('Non-extractable AES-256-GCM keys required');
    this.#keys = new Map(keys); this.#active = activeKeyId;
  }
  async encrypt(plaintext, context) {
    if (typeof plaintext !== 'string' || !plaintext || encoder.encode(plaintext).length > 1024) throw new TypeError('Bounded plaintext required');
    const keyId = this.#active, iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad(context, keyId), tagLength: 128 }, this.#keys.get(keyId), encoder.encode(plaintext)));
    return { version: 1, keyId, iv: base64urlEncode(iv), ciphertext: base64urlEncode(ct), bytes: ct.length };
  }
  async decrypt(envelope, context) {
    if (!envelope || envelope.version !== 1 || !this.#keys.has(envelope.keyId) || !Number.isSafeInteger(envelope.bytes) || envelope.bytes < 17 || envelope.bytes > 1040) throw new Error('Invalid encrypted record');
    const iv = base64urlDecode(envelope.iv, 12), ct = base64urlDecode(envelope.ciphertext, envelope.bytes);
    if (!iv || !ct) throw new Error('Invalid encrypted record');
    return decoder.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad(context, envelope.keyId), tagLength: 128 }, this.#keys.get(envelope.keyId), ct));
  }
}
