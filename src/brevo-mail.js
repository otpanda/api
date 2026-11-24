import {canonicalAccountEmail} from './account-identity.js';

const ENDPOINT = 'https://api.brevo.com/v3/smtp/email';
const MAX_RESPONSE = 8192;
export class MailSubmissionError extends Error {
  constructor(outcome = 'uncertain') {
    super('Email submission could not be confirmed.');
    this.name = 'MailSubmissionError';
    this.outcome = outcome;
  }
}
function boundedText(value, max, multiline = false) {
  if (typeof value !== 'string' || !value.trim() || value.length > max ||
      /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(value) ||
      (!multiline && /[\r\n]/.test(value))) throw new TypeError('Bounded email text required');
  return value;
}
async function readResponse(response) {
  const advertised = response.headers.get('content-length');
  if (advertised !== null && (!/^\d+$/.test(advertised) || Number(advertised) > MAX_RESPONSE)) {
    await response.body?.cancel(); throw new MailSubmissionError();
  }
  if (!response.body) throw new MailSubmissionError();
  const reader = response.body.getReader();
  let size = 0, done = false;
  const parts = [];
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) { done = true; break; }
      size += part.value.byteLength;
      if (size > MAX_RESPONSE) throw new MailSubmissionError();
      parts.push(part.value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const part of parts) { bytes.set(part, offset); offset += part.byteLength; }
    return JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes));
  } finally {
    if (!done) await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}
// Unmounted transport only. Callers own authorization, verification URL creation,
// one-use challenge issuance and abuse limits. Brevo may transform plain text
// into HTML and add tracking. Plain text input does not promise zero tracking.
export class BrevoMailTransport {
  #key; #sender; #replyTo; #fetch; #timeout;
  constructor({apiKey, senderEmail, replyToEmail, fetchImpl = (...args) => globalThis.fetch(...args), timeoutMs = 10000} = {}) {
    if (typeof apiKey !== 'string' || !apiKey || apiKey.length > 1024 || /\s/.test(apiKey)) throw new TypeError('Mail configuration required');
    if (typeof fetchImpl !== 'function' || !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 10000) throw new TypeError('Mail configuration required');
    this.#key = apiKey;
    this.#sender = canonicalAccountEmail(senderEmail);
    this.#replyTo = canonicalAccountEmail(replyToEmail);
    this.#fetch = fetchImpl;
    this.#timeout = timeoutMs;
  }
  toString() { return 'BrevoMailTransport(redacted)'; }
  toJSON() { return {transport: 'brevo', configuration: 'redacted'}; }
  async submit({to, subject, text, html} = {}) {
    const recipient = canonicalAccountEmail(to);
    subject = boundedText(subject, 160);
    text = boundedText(text, 16000, true);
    if (html !== undefined) html = boundedText(html, 20000, true);
    const payload = JSON.stringify({sender: {email: this.#sender, name: 'OTPanda'}, replyTo: {email: this.#replyTo}, to: [{email: recipient}], subject, textContent: text, ...(html === undefined ? {} : {htmlContent: html})});
    if (new TextEncoder().encode(payload).byteLength > 32768) throw new TypeError('Email payload too large');
    const controller = new AbortController();
    let timer;
    try {
      const timeout = new Promise((_, reject) => {
        timer = setTimeout(() => { controller.abort(); reject(new MailSubmissionError()); }, this.#timeout);
      });
      const attempt = (async () => {
        const response = await this.#fetch(ENDPOINT, {method: 'POST', redirect: 'manual', credentials: 'omit', cache: 'no-store', signal: controller.signal, headers: {'api-key': this.#key, accept: 'application/json', 'content-type': 'application/json'}, body: payload});
        if (response.status !== 201) {
          await response.body?.cancel();
          // Any request that reached the provider is not automatically retried.
          throw new MailSubmissionError('not-confirmed');
        }
        const result = await readResponse(response);
        if (!result || typeof result.messageId !== 'string' || !result.messageId || result.messageId.length > 512 || /[\r\n\x00]/.test(result.messageId)) throw new MailSubmissionError();
        return Object.freeze({status: 'accepted'});
      })();
      return await Promise.race([attempt, timeout]);
    } catch (error) {
      if (error instanceof MailSubmissionError) throw error;
      // Never leak provider errors, recipient, message, credentials or payload.
      throw new MailSubmissionError();
    } finally { clearTimeout(timer); }
  }
}
