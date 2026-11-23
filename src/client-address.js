// Canonical trusted-network identity for abuse limits. The input must come from
// the hosting provider's connection metadata, never from a request header a
// browser can influence (Forwarded, X-Forwarded-For and friends are unread).
// Malformed, zoned or oversized values are rejected so limits fail closed.

function ipv4(value) {
  const parts = value.split('.');
  if (parts.length !== 4) return undefined;
  const octets = [];
  for (const part of parts) {
    // Reject leading zeros: historically ambiguous with octal notation.
    if (!/^\d{1,3}$/.test(part) || (part.length > 1 && part.startsWith('0'))) return undefined;
    const n = Number(part);
    if (n > 255) return undefined;
    octets.push(n);
  }
  return octets.join('.');
}

// Expands a pure IPv6 address to eight lowercase hextets, or undefined.
function ipv6(value) {
  const halves = value.toLowerCase().split('::');
  if (halves.length > 2) return undefined;
  const group = g => (/^[0-9a-f]{1,4}$/.test(g) ? g : undefined);
  const left = halves[0] === '' ? [] : halves[0].split(':').map(group);
  const right = halves.length === 2 ? (halves[1] === '' ? [] : halves[1].split(':').map(group)) : null;
  if (left.includes(undefined) || right?.includes(undefined)) return undefined;
  if (right === null) return left.length === 8 ? left : undefined;
  if (left.length + right.length > 7) return undefined;
  return [...left, ...Array(8 - left.length - right.length).fill('0'), ...right];
}

// Returns the canonical quota identity: dotted IPv4 unchanged, IPv6 folded to
// its /64 prefix so address rotation inside one prefix cannot multiply quotas.
// IPv4-mapped IPv6 shares the native IPv4 bucket. Returns undefined on anything
// else; callers must treat that as unavailable, not as a shared bucket.
export function canonicalClientAddress(value) {
  if (typeof value !== 'string') return undefined;
  if (!value || value.length > 45 || value !== value.trim() || /[\s%]/.test(value)) return undefined;
  if (value.includes('.')) {
    const mapped = /^::ffff:([^:]+)$/.exec(value.toLowerCase());
    if (value.includes(':') && !mapped) return undefined;
    return ipv4(mapped ? mapped[1] : value);
  }
  if (!value.includes(':')) return undefined;
  const groups = ipv6(value);
  if (!groups) return undefined;
  if(groups.slice(0,5).every(g=>parseInt(g,16)===0)&&parseInt(groups[5],16)===65535){const hi=parseInt(groups[6],16),lo=parseInt(groups[7],16);return [hi>>8,hi&255,lo>>8,lo&255].join('.');}
  return groups.slice(0, 4).map(g => g.replace(/^0+(?=.)/, '')).join(':') + '::/64';
}
