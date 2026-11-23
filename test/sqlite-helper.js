import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';

// Real SQLite semantics behind the small D1 prepared-statement interface.
// This is not a substitute for a pre-deployment D1 runtime smoke test.
export function database(path = ':memory:') {
  const sqlite = new DatabaseSync(path);
  sqlite.exec(readFileSync(new URL('../migrations/0001_storage.sql', import.meta.url), 'utf8'));
  return {
    sqlite,
    prepare(sql) {
      const statement = sqlite.prepare(sql);
      let params = [];
      const query = {
        bind(...values) { params = values.map(v => Array.isArray(v) ? new Uint8Array(v) : v); return query; },
        async first() { return statement.get(...params) ?? null; },
        async all() { return { results: statement.all(...params), success: true }; },
        async run() { const r = statement.run(...params); return { success: true, meta: { changes: Number(r.changes) } }; },
      };
      return query;
    },
  };
}
