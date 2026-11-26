// Bounded extraction of the From, Subject and readable text from a raw RFC 5322 message.
// Pure and synchronous: no network, nothing persisted. The sender is whatever the From header says;
// nothing here authenticates it.
// Every loop and output is capped; hostile MIME (deep nesting, many parts, huge parts) ends in
// a truncated result, never in unbounded work.
export const MIME_LIMITS = Object.freeze({ maxDepth: 5, maxParts: 40, maxTextChars: 256 * 1024, maxHeaderBytes: 64 * 1024 });

const latin1 = (bytes) => { let s = ''; for (let i = 0; i < bytes.length; i += 16384) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 16384)); return s; };
const toBytes = (s) => { const b = new Uint8Array(s.length); for (let i = 0; i < s.length; i += 1) b[i] = s.charCodeAt(i) & 255; return b; };

function splitHead(s, maxHeaderBytes) {
  const m = /\r?\n\r?\n/.exec(s);
  let at = m ? m.index : s.length;
  let skip = m ? m[0].length : 0;
  if (at > maxHeaderBytes) { at = maxHeaderBytes; skip = 0; }
  return { head: s.slice(0, at), body: s.slice(at + skip) };
}
function parseHeaders(head) {
  const out = [];
  for (const line of head.split(/\r?\n/)) {
    if (/^[ \t]/.test(line) && out.length) { out[out.length - 1].value += ' ' + line.trim(); continue; }
    const i = line.indexOf(':');
    if (i > 0) out.push({ name: line.slice(0, i).trim().toLowerCase(), value: line.slice(i + 1).trim() });
  }
  return out;
}
const header = (hs, n) => hs.find((h) => h.name === n)?.value;
function params(v) {
  const out = {}; const parts = String(v ?? '').split(';');
  const main = parts.shift().trim().toLowerCase();
  for (const p of parts) { const m = /^\s*([\w-]+)\s*=\s*(?:"([^"]*)"|([^\s;]*))/.exec(p); if (m) out[m[1].toLowerCase()] = m[2] ?? m[3]; }
  return { main, params: out };
}
function decodeCharset(bytes, charset) {
  const label = String(charset || 'utf-8').toLowerCase();
  try { return new TextDecoder(label).decode(bytes); } catch { return new TextDecoder('utf-8').decode(bytes); }
}
function qpBytes(s, header = false) {
  if (header) s = s.replace(/_/g, ' ');
  s = s.replace(/=\r?\n/g, '');
  const out = [];
  for (let i = 0; i < s.length; i += 1) {
    const c = s[i];
    if (c === '=' && /^[0-9A-Fa-f]{2}$/.test(s.slice(i + 1, i + 3))) { out.push(parseInt(s.slice(i + 1, i + 3), 16)); i += 2; } else out.push(s.charCodeAt(i) & 255);
  }
  return Uint8Array.from(out);
}
function b64Bytes(s) {
  const clean = s.replace(/[^A-Za-z0-9+/]/g, '');
  try { return toBytes(atob(clean.slice(0, clean.length - (clean.length % 4 === 1 ? 1 : 0)))); } catch { return new Uint8Array(0); }
}
// RFC 2047 encoded words in header values.
export function decodeWords(v) {
  return String(v ?? '').replace(/=\?([^?\s]+)\?([bBqQ])\?([^?\s]*)\?=(\s+(?==\?))?/g, (_, cs, enc, txt) => {
    const bytes = enc.toLowerCase() === 'b' ? b64Bytes(txt) : qpBytes(txt, true);
    return decodeCharset(bytes, cs.split('*')[0]);
  });
}
const stripHtml = (h) => h.replace(/<(style|script)[\s\S]*?<\/\1>/gi, ' ').replace(/<[^>]+>/g, ' ').replace(/&nbsp;/gi, ' ').replace(/&amp;/gi, '&').replace(/\s+/g, ' ').trim();

export function bareAddress(v) {
  if (typeof v !== 'string') return undefined;
  const m = /<([^<>\s]+@[^<>\s]+)>/.exec(v);
  const a = (m ? m[1] : v.trim()).toLowerCase();
  return /^[^\s@<>"(),;:]+@[^\s@<>"(),;:]+\.[^\s@<>"(),;:]+$/.test(a) && a.length <= 254 ? a : undefined;
}

function decodeBody(body, cte, charset) {
  const e = String(cte || '7bit').trim().toLowerCase();
  const bytes = e === 'base64' ? b64Bytes(body) : e === 'quoted-printable' ? qpBytes(body) : toBytes(body);
  return decodeCharset(bytes, charset);
}

export function extractMessage(raw, limits = {}) {
  const L = { ...MIME_LIMITS, ...limits };
  const str = raw instanceof Uint8Array ? latin1(raw) : String(raw);
  const { head, body } = splitHead(str, L.maxHeaderBytes);
  const hs = parseHeaders(head);
  const froms = hs.filter((h) => h.name === 'from');
  const subjects = hs.filter((h) => h.name === 'subject');
  // A single From is guaranteed by the verifier. Exactly one Subject, or none is used: with a
  // duplicate, which one the signature covers is ambiguous, and the subject is only a hint.
  const from = froms.length === 1 ? bareAddress(decodeWords(froms[0].value)) : undefined;
  const subject = subjects.length === 1 ? decodeWords(subjects[0].value).slice(0, 998) : '';
  const acc = { plain: [], html: [], chars: 0, parts: 0 };
  walk(hs, body, 0, L, acc);
  const text = acc.plain.length ? acc.plain.join('\n') : stripHtml(acc.html.join('\n'));
  return { from, subject, text: text.slice(0, L.maxTextChars), truncated: acc.chars >= L.maxTextChars || acc.parts >= L.maxParts };
}

function walk(hs, body, depth, L, acc) {
  if (acc.parts >= L.maxParts || acc.chars >= L.maxTextChars) return;
  acc.parts += 1;
  const ct = params(header(hs, 'content-type') ?? 'text/plain');
  if (ct.main.startsWith('multipart/')) {
    if (depth >= L.maxDepth || !ct.params.boundary || ct.params.boundary.length > 200) return;
    const b = '--' + ct.params.boundary;
    let pos = body.indexOf(b);
    while (pos !== -1 && acc.parts < L.maxParts) {
      const lineEnd = body.indexOf('\n', pos);
      if (lineEnd === -1) break;
      if (body.slice(pos + b.length, pos + b.length + 2) === '--') break; // closing delimiter
      let next = body.indexOf('\n' + b, lineEnd);
      const partEnd = next === -1 ? body.length : next;
      const part = body.slice(lineEnd + 1, partEnd);
      const { head, body: pb } = splitHead(part, L.maxHeaderBytes);
      walk(parseHeaders(head), pb, depth + 1, L, acc);
      pos = next === -1 ? -1 : next + 1;
    }
    return;
  }
  const disp = params(header(hs, 'content-disposition') ?? '').main;
  if (disp === 'attachment') return;
  if (ct.main !== 'text/plain' && ct.main !== 'text/html') return;
  const room = L.maxTextChars - acc.chars;
  const text = decodeBody(body.slice(0, room * 4 + 1024), header(hs, 'content-transfer-encoding'), ct.params.charset).slice(0, room);
  acc.chars += text.length;
  (ct.main === 'text/plain' ? acc.plain : acc.html).push(text);
}
