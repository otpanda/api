// POSTs once to the isolated Worker and fails unless every synthetic check passed. Usage: node driver.mjs <base-url-with-prefix>
import { writeFileSync } from 'node:fs';
// Wait only on the read-only readiness endpoint. Never replay the mutating run.
let ready = false;
for (let n = 0; n < 30; n++) {
  try { const r = await fetch(process.argv[2] + '/ready'); ready = r.status === 200 && (await r.json()).ready === true; } catch {}
  if (ready) break;
  await new Promise(resolve => setTimeout(resolve, 2000));
}
if (!ready) throw Error('Synthetic Worker readiness timed out');
const res = await fetch(process.argv[2] + '/run', { method: 'POST' });
const text = await res.text(); let data;
try { data = JSON.parse(text); } catch { throw Error('Non-JSON HTTP ' + res.status); }
writeFileSync('qualification/transfer/transfer-result.json', JSON.stringify(data, null, 2));
for (const c of data.checks ?? []) console.log(c.pass ? 'PASS' : 'FAIL', c.name, c.error ?? '');
if (data.fatal) console.log('FATAL', data.fatal);
if (res.status !== 200 || data.pass !== true) { console.error('Transfer qualification failed, HTTP ' + res.status); process.exit(1); }
console.log('All transfer qualification checks passed on remote D1.');
