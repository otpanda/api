import { createHandler } from './worker.js';
import { createManagementHandler } from './management.js';
import { json, takeRateLimit, hashText } from './sessions.js';

// Explicit composition only. No environment is auto-provisioned and no
// credentials or identity providers are silently selected.
export function createApplication({ db, tokenStore, codeStore, sessions, signIn, trustedRequestKey, clock = Date.now }) {
  if (!db || !tokenStore || !codeStore || !sessions || !signIn || typeof trustedRequestKey !== 'function') throw new TypeError('Complete application dependencies required');
  const api = createHandler({ tokenStore, codeStore, clock });
  const management = createManagementHandler({ db, sessions, tokenStore, clock });
  return {
    async fetch(request) {
      try {
        const url = new URL(request.url);
        if (url.origin !== sessions.origin) return json({ error: 'not_found' }, 404);
        // trustedRequestKey must be derived by the host adapter from authenticated
        // platform metadata, never a caller-supplied X-Forwarded-For value.
        const requestKey = trustedRequestKey(request);
        if (typeof requestKey !== 'string' || !requestKey || requestKey.length > 256) return json({ error: 'unavailable' }, 503);
        const bucket = 'request:' + await hashText(requestKey);
        const rate = await takeRateLimit(db, bucket, { now: clock(), limit: 60 });
        if (!rate.allowed) return json({ error: 'rate_limited' }, 429, { 'Retry-After': String(rate.retryAfter) });
        if (url.pathname === '/auth/start') return await signIn.start(request);
        if (url.pathname === '/auth/callback') return await signIn.callback(request);
        if (url.pathname.startsWith('/v1/manage/')) return await management.fetch(request);
        return await api.fetch(request);
      } catch {
        // No exception details or request content go to clients or logs.
        return json({ error: 'unavailable' }, 503);
      }
    },
    async cleanup() {
      const now = clock();
      await codeStore.purgeExpired(now, 100);
      for (const [table, column] of [['sessions', 'expires_at'], ['oauth_transactions', 'expires_at'], ['rate_buckets', 'resets_at']]) {
        // Table/column identifiers are constants, not external input.
        await db.prepare(`DELETE FROM ${table} WHERE rowid IN (SELECT rowid FROM ${table} WHERE ${column} <= ?1 LIMIT 100)`).bind(now).run();
      }
    },
  };
}
