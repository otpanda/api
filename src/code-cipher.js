// AES-GCM authenticated envelopes. Key material is injected, never generated,
// persisted or logged by this module. Production key provisioning is separate.
import { base64urlEncode, base64urlDecode } from './tokens.js';
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

function aad(context, keyId) {
  if (!context || ['ownerId', 'recordId', 'serviceId'].some(k => typeof context[k] !== 'string' || !context[k] || context[k].length > 256)) {
    throw new TypeError('Complete record context required');
  }
  if (!Number.isSafeInteger(context.receivedAt) || !Number.isSafeInteger(context.expiresAt) || context.receivedAt < 0 || context.expiresAt <= context.receivedAt) {
    throw new TypeError('Valid record lifetime required');
  }
  return encoder.encode(JSON.stringify(['otpanda-code', 1, keyId, context.ownerId, context.recordId, context.serviceId, context.receivedAt, context.expiresAt]));
}

export class CodeCipher {
  #keys;
  #active;
  constructor({ keys, activeKeyId }) {
    if (!(keys instanceof Map) || !keys.has(activeKeyId)) throw new TypeError('Active encryption key required');
    for (const [id, key] of keys) {
      if (typeof id !== 'string' || !/^[a-zA-Z0-9_-]{1,64}$/.test(id) || key?.algorithm?.name !== 'AES-GCM' || key.algorithm.length !== 256 || key.extractable || !key.usages.includes('encrypt') || !key.usages.includes('decrypt')) {
        throw new TypeError('Non-extractable AES-256-GCM keys required');
      }
    }
    this.#keys = new Map(keys);
    this.#active = activeKeyId;
  }
  async encrypt(plaintext, context) {
    if (typeof plaintext !== 'string' || !plaintext || encoder.encode(plaintext).length > 4096) throw new TypeError('Bounded plaintext required');
    const keyId = this.#active;
    const additionalData = aad(context, keyId);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData, tagLength: 128 }, this.#keys.get(keyId), encoder.encode(plaintext)));
    return { version: 1, keyId, iv: base64urlEncode(iv), ciphertext: base64urlEncode(ciphertext), bytes: ciphertext.length };
  }
  async decrypt(envelope, context) {
    if (!envelope || envelope.version !== 1 || !this.#keys.has(envelope.keyId) || !Number.isSafeInteger(envelope.bytes) || envelope.bytes < 17 || envelope.bytes > 4112) throw new Error('Invalid encrypted record');
    const iv = base64urlDecode(envelope.iv, 12);
    const ciphertext = base64urlDecode(envelope.ciphertext, envelope.bytes);
    if (!iv || !ciphertext) throw new Error('Invalid encrypted record');
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad(context, envelope.keyId), tagLength: 128 }, this.#keys.get(envelope.keyId), ciphertext);
    return decoder.decode(plaintext);
  }
}
