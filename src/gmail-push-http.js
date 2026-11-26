// POST /sources/gmail/push. Not mounted by this module. Google's OIDC token is
// verified (signature, issuer, exact audience, exact service account) before the
// body is read, and the body is only a hint naming a mailbox and a history id.
import { json } from './sessions.js';
const MAX_BODY = 16384;
// Streaming bound: stop reading as soon as the cap is passed, never buffer more.
async function readBounded(request) {
  const declared = request.headers.get('content-length');
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > MAX_BODY)) return;
  if (!request.body) return '';
  const reader = request.body.getReader(), chunks = []; let n = 0;
  for (;;) {
    const { done, value } = await reader.read(); if (done) break;
    n += value.byteLength; if (n > MAX_BODY) { await reader.cancel().catch(() => {}); return; }
    chunks.push(value);
  }
  const all = new Uint8Array(n); let o = 0; for (const c of chunks) { all.set(c, o); o += c.byteLength; }
  try { return new TextDecoder('utf-8', { fatal: true }).decode(all); } catch { return; }
}
export function createGmailPushHttp({ verifier, sync, expectedSubscription, path = '/sources/gmail/push' } = {}) {
  if (typeof verifier !== 'function' || !sync || !expectedSubscription) throw new TypeError('Push dependencies required');
  return { path, async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname !== path) return json({ error: 'not_found' }, 404);
    if (request.method !== 'POST') return json({ error: 'method_not_allowed' }, 405, { Allow: 'POST' });
    const m = /^Bearer ([A-Za-z0-9._-]{1,4096})$/.exec(request.headers.get('authorization') ?? '');
    if (!m || !await verifier(m[1])) return json({ error: 'unauthorized' }, 401);
    if (!(request.headers.get('content-type') ?? '').toLowerCase().startsWith('application/json')) return json({ error: 'invalid_request' }, 400);
    const text = await readBounded(request);
    if (text === undefined) return json({ error: 'invalid_request' }, 413);
    let hint;
    try {
      const body = JSON.parse(text);
      if (body.subscription !== expectedSubscription || typeof body.message?.data !== 'string') return json({ error: 'invalid_request' }, 400);
      hint = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(atob(body.message.data.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))));
      if (typeof hint.emailAddress !== 'string' || !/^\d{1,20}$/.test(String(hint.historyId))) return json({ error: 'invalid_request' }, 400);
    } catch { return json({ error: 'invalid_request' }, 400); }
    let result;
    try { result = await sync.syncMailbox(hint.emailAddress, String(hint.historyId)); }
    catch { return json({ error: 'unavailable' }, 503); }
    // partial = bounded work done, more remains: ask Pub/Sub to redeliver.
    if (result === 'partial') return json({ error: 'continue' }, 503);
    // Unknown, stale and reauth-needed mailboxes are acknowledged so Pub/Sub does not retry forever.
    return new Response(null, { status: 204 });
  } };
}
