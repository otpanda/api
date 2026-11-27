// POSTs once to the isolated Worker and fails unless every synthetic check passed. Usage: node driver.mjs <base-url-with-prefix>
import { writeFileSync } from 'node:fs';
import { CEILING, MIGRATION_ALLOWANCE, mayStartNext, IN_FLIGHT_OVERSHOOT } from './budget.mjs';
// Wait only on the read-only readiness endpoint. Never replay the mutating run.
let ready = false;
for (let n = 0; n < 30; n++) {
  try { const r = await fetch(process.argv[2] + '/ready'); ready = r.status === 200 && (await r.json()).ready === true; } catch {}
  if (ready) break;
  await new Promise(resolve => setTimeout(resolve, 2000));
}
if (!ready) throw Error('Synthetic Worker readiness timed out');
// One POST per group, sequential, each its own Worker request (own CPU and query budget). A group is never replayed.
const GROUPS = Array.from({ length: 14 }, (_, i) => 'c' + String(i + 1).padStart(2, '0')), all = { synthetic: true, pass: true, groups: {} };
let failed = false;
const cum = { writes: MIGRATION_ALLOWANCE.writes, reads: MIGRATION_ALLOWANCE.reads };
all.metering = { ceiling: CEILING, migrationAllowance: MIGRATION_ALLOWANCE, inFlightOvershootBound: IN_FLIGHT_OVERSHOOT, cumulative: cum };
for (const g of GROUPS) {
  // Stop BEFORE the next request when it could cross the ceiling. A request already in flight is bounded only by the Worker's per-request cap plus one statement.
  if (!mayStartNext(cum)) { all.groups[g] = { skipped: 'row ceiling', cumulative: { ...cum } }; failed = true; console.log('STOP before group ' + g + ': cumulative rows written ' + cum.writes + ', read ' + cum.reads + ' would risk the ceiling'); break; }
  const res = await fetch(process.argv[2] + '/run?group=' + g, { method: 'POST' });
  const text = await res.text(); let data;
  try { data = JSON.parse(text); } catch { all.groups[g] = { httpStatus: res.status, pass: false }; failed = true; console.log('FATAL group ' + g + ' HTTP ' + res.status); break; }
  all.groups[g] = { httpStatus: res.status, ...data };
  // Fail closed when a response does not report its rows: the budget cannot be enforced without it.
  if (!Number.isFinite(data.totalRowsWritten) || !Number.isFinite(data.totalRowsRead)) { failed = true; console.log('STOP: group ' + g + ' did not report row counts'); break; }
  cum.writes += data.totalRowsWritten; cum.reads += data.totalRowsRead;
  console.log('cumulative rows written ' + cum.writes + '/' + CEILING.writes + ', read ' + cum.reads + '/' + CEILING.reads);
  for (const c of data.checks ?? []) console.log(c.pass ? 'PASS' : 'FAIL', g, c.name, 'queries=' + c.queries, c.error ?? '');
  console.log('group ' + g + ': HTTP ' + res.status + ' totalQueries=' + data.totalQueries);
  if (data.fatal) console.log('FATAL', data.fatal);
  if (res.status !== 200 || data.pass !== true) { failed = true; break; }
}
all.pass = !failed;
writeFileSync('qualification/seed-sync/seed-sync-result.json', JSON.stringify(all, null, 2));
if (failed) { console.error('Seed-sync qualification failed'); process.exit(1); }
console.log('All seed-sync qualification groups passed on remote D1.');
