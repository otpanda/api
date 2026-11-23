CREATE TABLE IF NOT EXISTS entry_tokens (
  token_id TEXT PRIMARY KEY,
  token_digest BLOB NOT NULL CHECK (length(token_digest) = 32),
  actor_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
  entry_id TEXT NOT NULL REFERENCES entries(entry_id) ON DELETE CASCADE,
  client_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
  revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS entry_tokens_actor ON entry_tokens(actor_id, created_at);
