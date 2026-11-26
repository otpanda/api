// Per-invocation work accounting. Cloudflare counts fetch() calls AND every D1
// query (a db.batch counts once) against one subrequest limit per invocation
// (50 on Workers Free). Build one budget per request, wrap env.DB and fetch with
// it, and construct every store and verifier from the wrapped versions.
export class BudgetExceeded extends Error { constructor() { super('request budget exhausted'); } }
export function createRequestBudget(limit = 50) {
  let used = 0;
  return {
    limit,
    get used() { return used; },
    remaining: () => limit - used,
    spend(n = 1) { if (used + n > limit) throw new BudgetExceeded(); used += n; },
    reset() { used = 0; },
  };
}
// redirect:'error' is forced (and cannot be overridden): the runtime would otherwise follow
// redirects, and each hop counts as another subrequest that this budget never saw.
export function budgetedFetch(fetchImpl, budget) { return (url, init) => { budget.spend(); return fetchImpl(url, { ...init, redirect: 'error' }); }; }
export function budgetedDb(db, budget) {
  const wrap = st => ({ inner: st, bind: (...a) => wrap(st.bind(...a)), run: () => { budget.spend(); return st.run(); }, first: (...a) => { budget.spend(); return st.first(...a); }, all: () => { budget.spend(); return st.all(); } });
  return { prepare: sql => wrap(db.prepare(sql)), batch: stmts => { budget.spend(); return db.batch(stmts.map(s => s.inner ?? s)); } };
}
