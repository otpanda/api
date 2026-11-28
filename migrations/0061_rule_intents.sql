-- Signed rule actions that have no live code: (a) create a rule from an unassigned review row, (b) change a rule's phrase/template basis.
-- Additive table, so the existing assignment_intents/receipts are untouched. subject_json is server-held (never sent to a client): the exact row version the action was shown for.
CREATE TABLE IF NOT EXISTS rule_intents (
 intent_id TEXT PRIMARY KEY,
 owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
 device_id TEXT NOT NULL REFERENCES device_sessions(device_id) ON DELETE CASCADE,
 generation INTEGER NOT NULL,
 operation TEXT NOT NULL CHECK(operation IN ('review','edit','resume')),
 subject_id TEXT NOT NULL,
 source_id TEXT,
 entry_id TEXT NOT NULL,
 entry_revision INTEGER NOT NULL,
 subject_json TEXT NOT NULL CHECK(json_valid(subject_json)),
 action_digest TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 consumed_at INTEGER,
 retired_at INTEGER,
 result_expires_at INTEGER NOT NULL,
 rule_json TEXT,
 rule_result TEXT CHECK(rule_result IS NULL OR rule_result IN ('saved','exists','paused','updated','resumed','unavailable'))
);
CREATE INDEX IF NOT EXISTS rule_intents_owner ON rule_intents(owner_id,expires_at);
CREATE INDEX IF NOT EXISTS rule_intents_cleanup ON rule_intents(result_expires_at);
