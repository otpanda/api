import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,readdirSync} from 'node:fs';
// D1 reports meta.changes as the total_changes delta, so rows written by a trigger count too. An exact
// `meta.changes===1` (or !==1) on a statement that writes a table with an AFTER/BEFORE row trigger breaks
// as soon as the trigger inserts a row. Use `>=1` / `<1` for single-key guarded writes, or RETURNING for a count.
// Heuristic guard: a write to a triggered table within the 12 lines above an exact check needs `// exact-count-ok: reason`.
const dir=new URL('../migrations/',import.meta.url),srcDir=new URL('../src/',import.meta.url);
const triggered=new Set();
// Only triggers whose body writes rows matter (RAISE-only guard triggers do not change counts).
for(const f of readdirSync(dir))for(const m of readFileSync(new URL(f,dir),'utf8').matchAll(/CREATE TRIGGER\s+\w+\s+(?:AFTER|BEFORE)\s+(?:INSERT|UPDATE|DELETE)(?:\s+OF\s+[\w,\s]+?)?\s+ON\s+(\w+)([\s\S]*?)\bEND\s*;/gi))if(/\b(?:INSERT\s+(?:OR\s+\w+\s+)?INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b/i.test(m[2]))triggered.add(m[1]);
test('the trigger table list is discovered from migrations',()=>{for(const t of ['incoming_codes','entries','entry_shares','sources','device_sessions','account_security','personal_organization','realtime_tickets'])assert.ok(triggered.has(t),t);});
test('no exact meta.changes check follows a write to a triggered table',()=>{
 const write=new RegExp(`(?:UPDATE|DELETE\\s+FROM|INSERT\\s+(?:OR\\s+\\w+\\s+)?INTO)\\s+(${[...triggered].join('|')})\\b`,'i');
 const bad=[];
 for(const f of readdirSync(srcDir)){if(!f.endsWith('.js'))continue;
  const lines=readFileSync(new URL(f,srcDir),'utf8').split('\n');
  lines.forEach((line,i)=>{
   if(!/changes\s*(===|!==)\s*1\b/.test(line)||/exact-count-ok/.test(line))return;
   const window=lines.slice(Math.max(0,i-12),i+1).join('\n'),m=window.match(write);
   if(m)bad.push(`${f}:${i+1} exact count after a write to ${m[1]}`);
  });}
 assert.deepEqual(bad,[],'use >=1 / <1 or RETURNING; D1 counts trigger rows');
});
