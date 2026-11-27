// POSTs once to the isolated Worker and fails unless every synthetic check passed. Usage: node driver.mjs <base-url-with-prefix>
import { writeFileSync } from 'node:fs';
const res = await fetch(process.argv[2] + '/run', { method: 'POST' });
const text = await res.text(); let data;
try { data = JSON.parse(text); } catch { throw Error('Non-JSON HTTP ' + res.status); }
writeFileSync('qualification/sharing/sharing-result.json', JSON.stringify(data, null, 2));
for (const c of data.checks ?? []) console.log(c.pass ? 'PASS' : 'FAIL', c.name, c.error ?? '');
if (data.fatal) console.log('FATAL', data.fatal);
if (res.status !== 200 || data.pass !== true) { console.error('Sharing qualification failed, HTTP ' + res.status); process.exit(1); }
console.log('All sharing qualification checks passed on remote D1.');
