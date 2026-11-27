// Local-only D1 qualification for the sharing/machine-access SQL, using wrangler's local D1 simulation
// (workerd + local SQLite, `getPlatformProxy` with a throwaway config and persist dir). It never contacts
// Cloudflare and never reads wrangler.jsonc's real database id. Run: node tool/d1-qualify-sharing.mjs
import { getPlatformProxy } from 'wrangler';
import { readFileSync, readdirSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runChecks } from '../qualification/transfer/checks.js';

const dir = mkdtempSync(join(tmpdir(), 'd1-qualify-'));
const proxy = await getPlatformProxy({ configPath: process.env.D1_HARNESS_CONFIG ?? 'qualification/transfer/wrangler.json', persist: { path: dir }, remoteBindings: false });
const db = proxy.env.DB;
const root = new URL('../migrations/', import.meta.url);
for (const f of readdirSync(root).sort()) {
  // D1 exec runs one statement per line; split on statement boundaries ourselves, triggers keep their BEGIN..END.
  const sql = readFileSync(new URL(f, root), 'utf8');
  const statements = []; let cur = '', inTrigger = false;
  for (const line of sql.split('\n')) {
    if (/^\s*--/.test(line) && !cur.trim()) continue;
    cur += line + '\n';
    if (/^\s*CREATE TRIGGER/i.test(cur.trim().split('\n').find(l => !/^\s*--/.test(l)) ?? '')) inTrigger = true;
    if (inTrigger ? /^\s*END;\s*$/i.test(line) : /;\s*$/.test(line)) { statements.push(cur); cur = ''; inTrigger = false; }
  }
  if (cur.trim()) statements.push(cur);
  for (const st of statements) { if (st.trim()) await db.prepare(st).run(); }
}
const out = await runChecks(db);
await proxy.dispose();
for (const c of out.checks) console.log(c.pass ? 'PASS' : 'FAIL', c.name, c.error ?? '');
process.exit(out.pass ? 0 : 1);
