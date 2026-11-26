// Dev-only scheduled maintenance for the one allowed mailbox. It is a function over already-built services so the mounted dev
// host decides where it runs; it does not mount anything and adds no cron by itself.
// - Delivery stays push-driven. This never lists or polls an inbox: it touches only rows that are DUE (a watch about to expire,
//   a message whose earlier fetch failed and whose retry time has passed), selected in SQL for this mailbox only.
// - Watch renewal goes through the same single-flight as connect/disconnect, so a blocked or indeterminate operation skips the
//   mailbox (counted in renewal.blocked) instead of bypassing the lock.
// - Idle cost is three D1 reads/writes and no Google call. Every task is isolated: one failing never skips the others, and the
//   result carries counts and booleans only (no ids, addresses or errors).
// Suggested split for the free-plan 50 subrequest allowance (each invocation has its own): every 5 minutes {retries, renew};
// every 15 minutes {prune}. Running all three in one invocation is also bounded by the shared budget.
import { canonicalMailbox } from './gmail-source-store.js';
const ALL = ['retries', 'renew', 'prune'];
export async function runGmailDevMaintenance({ sync, store, budget, clock = Date.now, mailbox, tasks = ALL } = {}) {
  if (!sync || !store || typeof budget?.remaining !== 'function') throw new TypeError('maintenance services required');
  if (typeof mailbox !== 'string' || !mailbox) throw new TypeError('dev mailbox required'); // never run unscoped
  const m = canonicalMailbox(mailbox);
  const want = new Set(tasks); const out = { mailbox: m, failed: [] };
  const step = async (name, fn) => { if (!want.has(name)) return; try { await fn(); } catch { out.failed.push(name); } };
  await step('retries', async () => { out.retries = await sync.drainDueAll(5, { mailbox: m }); });
  await step('renew', async () => { if (budget.remaining() < 3) { out.renewal = { renewed: 0, failed: 0, partial: true }; return; } await sync.renewWatches(undefined, { mailbox: m }); out.renewal = sync.lastRenewal; });
  await step('prune', async () => { if (budget.remaining() > 0) out.pruned = await store.pruneStates(clock(), 100); });
  return out;
}
