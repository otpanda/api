import { DatabaseSync } from 'node:sqlite';
import { readFileSync, readdirSync } from 'node:fs';

// Real SQLite semantics behind the small D1 prepared-statement interface.
// This is not a substitute for a pre-deployment D1 runtime smoke test.
export function database(path = ':memory:') {
  const sqlite = new DatabaseSync(path);
  sqlite.exec('PRAGMA foreign_keys = ON');
  sqlite.exec('CREATE TABLE IF NOT EXISTS _test_migrations (name TEXT PRIMARY KEY)');
  for (const file of readdirSync(new URL('../migrations/', import.meta.url)).sort()) {
    if(sqlite.prepare('SELECT name FROM _test_migrations WHERE name = ?').get(file))continue;
    sqlite.exec('BEGIN');
    try { sqlite.exec(readFileSync(new URL('../migrations/' + file, import.meta.url), 'utf8')); sqlite.prepare('INSERT INTO _test_migrations VALUES (?)').run(file); sqlite.exec('COMMIT'); }
    catch(error){sqlite.exec('ROLLBACK');throw error;}
  }
  let inBatch=false;
  return {
    sqlite,
    async batch(statements) {
      if(process.env.FRESH_OUTBOX==='1'&&!inBatch)sqlite.exec('DELETE FROM realtime_outbox WHERE claimed_at IS NULL AND cursor IS NULL');
      sqlite.exec('BEGIN');inBatch=true;
      try { const results = []; for (const s of statements) results.push(await s.run()); sqlite.exec('COMMIT'); return results; }
      catch (error) { sqlite.exec('ROLLBACK'); throw error; }
      finally { inBatch=false; }
    },
    prepare(sql) {
      const statement = sqlite.prepare(sql);
      let params = [];
      const query = {
        bind(...values) { params = values.map(v => Array.isArray(v) ? new Uint8Array(v) : v); return query; },
        async first() { return statement.get(...params) ?? null; },
        async all() { return { results: statement.all(...params), success: true }; },
        // Real D1 (workerd) reports meta.changes as the connection's total_changes delta, so trigger writes are included.
        // FRESH_OUTBOX=1 clears hints before each independent write or atomic batch. Never inject a DELETE between batch statements: that overwrites SQLite changes() and fabricates failures in guarded SQL. A real outbox consumer cannot interleave inside an atomic D1 batch.
        async run() { if(process.env.FRESH_OUTBOX==='1'&&!inBatch)sqlite.exec('DELETE FROM realtime_outbox WHERE claimed_at IS NULL AND cursor IS NULL'); const before = Number(sqlite.prepare('SELECT total_changes() n').get().n); statement.run(...params); const after = Number(sqlite.prepare('SELECT total_changes() n').get().n); return { success: true, meta: { changes: after - before } }; },
      };
      return query;
    },
  };
}
