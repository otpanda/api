-- Assignment-only action intents. No route is mounted by this migration.
ALTER TABLE entries ADD COLUMN mutation_revision INTEGER NOT NULL DEFAULT 0;
CREATE TRIGGER entries_assignment_revision AFTER UPDATE OF label,account_name,service_id ON entries BEGIN
 UPDATE entries SET mutation_revision=mutation_revision+1 WHERE entry_id=NEW.entry_id;
END;
CREATE TRIGGER share_assignment_insert AFTER INSERT ON entry_shares BEGIN
 UPDATE entries SET mutation_revision=mutation_revision+1 WHERE entry_id=NEW.entry_id;
END;
CREATE TRIGGER share_assignment_update AFTER UPDATE ON entry_shares BEGIN
 UPDATE entries SET mutation_revision=mutation_revision+1 WHERE entry_id=NEW.entry_id;
END;
CREATE TRIGGER share_assignment_delete AFTER DELETE ON entry_shares BEGIN
 UPDATE entries SET mutation_revision=mutation_revision+1 WHERE entry_id=OLD.entry_id;
END;
CREATE TABLE assignment_intents (
 intent_id TEXT PRIMARY KEY,
 owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
 device_id TEXT NOT NULL REFERENCES device_sessions(device_id) ON DELETE CASCADE,
 generation INTEGER NOT NULL,
 source_id TEXT NOT NULL,
 event_id TEXT NOT NULL,
 entry_id TEXT NOT NULL,
 entry_revision INTEGER NOT NULL,
 envelope TEXT NOT NULL CHECK(json_valid(envelope)),
 received_at INTEGER NOT NULL,
 code_expires_at INTEGER NOT NULL,
 action_digest TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 consumed_at INTEGER,
 result_expires_at INTEGER NOT NULL
);
CREATE INDEX assignment_intents_owner ON assignment_intents(owner_id,expires_at);
CREATE INDEX assignment_intents_cleanup ON assignment_intents(result_expires_at);
-- CHECK violation rolls back the entire batch if consumption somehow succeeds
-- but the paired assignment does not. No success receipt without one write.
CREATE TABLE assignment_receipts (
 intent_id TEXT PRIMARY KEY REFERENCES assignment_intents(intent_id) ON DELETE CASCADE,
 assignment_changes INTEGER NOT NULL CHECK(assignment_changes=1)
);
