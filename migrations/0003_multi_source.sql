-- Sources stay private to an account. Sharing entries never grants source access.
CREATE TABLE IF NOT EXISTS sources (
  source_id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('gmail', 'outlook', 'sms')),
  label TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  revoked_at INTEGER,
  UNIQUE(owner_id, source_id)
);
CREATE INDEX IF NOT EXISTS sources_owner ON sources(owner_id);
CREATE TABLE IF NOT EXISTS entries (
  entry_id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
  service_id TEXT NOT NULL,
  label TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(owner_id, entry_id)
);
CREATE INDEX IF NOT EXISTS entries_owner ON entries(owner_id, service_id);
-- An exact sender plus account discriminator is an explicit owner rule, not
-- proof that the sender is authentic. Provider validation remains separate.
CREATE TABLE IF NOT EXISTS assignment_rules (
  rule_id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  entry_id TEXT NOT NULL,
  sender TEXT NOT NULL,
  account_hint TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(owner_id, source_id) REFERENCES sources(owner_id, source_id) ON DELETE CASCADE,
  FOREIGN KEY(owner_id, entry_id) REFERENCES entries(owner_id, entry_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS rules_source ON assignment_rules(owner_id, source_id);
CREATE TABLE IF NOT EXISTS incoming_codes (
  owner_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  entry_id TEXT,
  envelope TEXT NOT NULL CHECK (json_valid(envelope)),
  received_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL CHECK (expires_at > received_at),
  assignment TEXT NOT NULL CHECK (assignment IN ('unassigned', 'rule', 'confirmed')),
  PRIMARY KEY(owner_id, source_id, event_id),
  FOREIGN KEY(owner_id, source_id) REFERENCES sources(owner_id, source_id) ON DELETE CASCADE,
  FOREIGN KEY(owner_id, entry_id) REFERENCES entries(owner_id, entry_id) ON DELETE CASCADE,
  CHECK ((entry_id IS NULL AND assignment = 'unassigned') OR (entry_id IS NOT NULL AND assignment != 'unassigned'))
);
CREATE INDEX IF NOT EXISTS incoming_entry ON incoming_codes(owner_id, entry_id, received_at DESC);
CREATE INDEX IF NOT EXISTS incoming_expiry ON incoming_codes(expires_at);
