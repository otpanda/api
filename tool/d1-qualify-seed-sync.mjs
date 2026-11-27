// Local-only run of qualification/seed-sync/checks.js on wrangler's local D1 simulation. Never contacts Cloudflare. Run: node tool/d1-qualify-seed-sync.mjs
import { getPlatformProxy } from 'wrangler';
import { readFileSync, readdirSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runChecks, GROUPS } from '../qualification/seed-sync/checks.js';
const dir = mkdtempSync(join(tmpdir(), 'd1-qualify-seed-sync-'));
const proxy = await getPlatformProxy({ configPath: 'qualification/seed-sync/wrangler.json', persist: { path: dir }, remoteBindings: false });
const db = proxy.env.DB, root = new URL('../migrations/', import.meta.url);
for (const f of readdirSync(root).sort()) {
  const sql = readFileSync(new URL(f, root), 'utf8'), statements = []; let cur = '', inTrigger = false;
  for (const line of sql.split('\n')) {
    if (/^\s*--/.test(line) && !cur.trim()) continue;
    cur += line + '\n';
    if (/^\s*CREATE TRIGGER/i.test(cur.trim().split('\n').find(l => !/^\s*--/.test(l)) ?? '')) inTrigger = true;
    if (inTrigger ? /^\s*END;\s*$/i.test(line) : /;\s*$/.test(line)) { statements.push(cur); cur = ''; inTrigger = false; }
  }
  if (cur.trim()) statements.push(cur);
  for (const st of statements) { if (st.trim()) await db.prepare(st).run(); }
}
let ok = true;
for (const g of (process.env.ONLY ? process.env.ONLY.split(',') : GROUPS)) {
  const out = await runChecks(db, g);
  for (const c of out.checks) console.log(c.pass ? 'PASS' : 'FAIL', g, c.name, 'queries=' + c.queries, c.error ?? '');
  console.log('group', g, 'totalQueries=' + out.totalQueries, JSON.stringify(out.info));
  ok = ok && out.pass;
}
await proxy.dispose();
process.exit(ok ? 0 : 1);
