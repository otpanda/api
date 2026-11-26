// Turns one Gmail API `format=raw` response into a message for ingestEmail, or a verdict.
//
// What is and is not claimed: the message comes from Google's API with the connected owner's own
// token, so it belongs to that mailbox. Nothing here proves who SENT it. `from` is the From header
// as written and must not be shown or treated as a verified service identity. `to` is the mailbox
// of the stored connection, not a header. Only the extracted code, sender address and receiving
// address are kept by the ingest path.
import { extractMessage } from './mime-text.js';

export const GMAIL_POLICY = Object.freeze({
  maxBytes: 512 * 1024,   // raw message size; larger mail is skipped, counted and shown as skipped
  fetchTimeoutMs: 5000,   // the raw message request: headers and body together
});

const b64urlRe = /^[A-Za-z0-9_-]+$/;
function decodeB64url(s) {
  const std = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(std + '='.repeat((4 - (std.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

// Reads a Response body with a hard byte cap and a deadline, before anything is parsed. Returns
// undefined when the body is larger than the cap. A slow body is cancelled and the read throws
// (the push answers 503 or the message is deferred; this is not a verdict on the message).
export async function readBoundedText(res, maxBytes, { deadlineMs = 5000 } = {}) {
  const len = Number(res.headers?.get?.('content-length'));
  if (Number.isFinite(len) && len > maxBytes) { try { await res.body?.cancel(); } catch { /* ignore */ } return undefined; }
  if (!res.body?.getReader) { const t = await res.text(); return t.length > maxBytes ? undefined : t; }
  const reader = res.body.getReader(); const dec = new TextDecoder(); let total = 0; let out = '';
  let timer; const late = new Promise((_, rej) => { timer = setTimeout(() => { rej(new Error('message body timeout')); try { reader.cancel(); } catch { /* ignore */ } }, deadlineMs); });
  try {
    for (;;) {
      const { done, value } = await Promise.race([reader.read(), late]);
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) { try { await reader.cancel(); } catch { /* ignore */ } return undefined; }
      out += dec.decode(value, { stream: true });
    }
  } finally { clearTimeout(timer); late.catch(() => {}); }
  return out + dec.decode();
}
// base64url inflates 4/3, plus JSON framing
export const rawResponseCap = (policy) => Math.ceil(policy.maxBytes * 4 / 3) + 4096;

/**
 * @param {object} j parsed Gmail message JSON (format=raw)
 * @returns {{ok:true,message:object}|{ok:false,reason:'bad_response'|'too_large'|'from_invalid'}}
 */
export function parseGmailRaw(j, { id, mailbox, policy = GMAIL_POLICY } = {}) {
  const fail = (reason) => ({ ok: false, reason });
  if (!j || j.id !== id) return fail('bad_response');
  if (typeof j.internalDate !== 'string' || !/^\d{10,16}$/.test(j.internalDate)) return fail('bad_response');
  const receivedAt = Number(j.internalDate);
  if (typeof j.raw !== 'string' || !j.raw.length || !b64urlRe.test(j.raw.replace(/=+$/, ''))) return fail('bad_response');
  if (j.raw.length * 3 / 4 > policy.maxBytes + 4) return fail('too_large');
  let bytes;
  try { bytes = decodeB64url(j.raw); } catch { return fail('bad_response'); }
  const m = extractMessage(bytes);
  if (!m.from) return fail('from_invalid');
  return { ok: true, message: { id: 'gmail:' + id, provider: 'gmail', from: m.from, to: mailbox, subject: m.subject, text: m.text, receivedAt } };
}
