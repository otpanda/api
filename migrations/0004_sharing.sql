CREATE TABLE IF NOT EXISTS entry_shares (
  entry_id TEXT NOT NULL REFERENCES entries(entry_id) ON DELETE CASCADE,
  recipient_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
  allow_automation INTEGER NOT NULL DEFAULT 0 CHECK (allow_automation IN (0,1)),
  created_at INTEGER NOT NULL,
  revoked_at INTEGER,
  PRIMARY KEY(entry_id, recipient_id)
);
