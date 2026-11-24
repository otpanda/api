PRAGMA foreign_keys = ON;
-- Nonsecret, permanent initial-provisioning reservation. Never delete to retry.
CREATE TABLE initial_key_provisioning (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  key_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('reserved','bindings_written')),
  created_at INTEGER NOT NULL
);
