PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS accounts (
  owner_id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL CHECK (created_at >= 0)
);
CREATE TABLE IF NOT EXISTS access_tokens (
  token_id TEXT PRIMARY KEY,
  token_digest BLOB NOT NULL CHECK (length(token_digest) = 32),
  owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
  client_id TEXT NOT NULL,
  service_id TEXT NOT NULL,
  scopes TEXT NOT NULL CHECK (json_valid(scopes)),
  created_at INTEGER NOT NULL,
  not_before INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER,
  CHECK (expires_at > not_before)
);
CREATE INDEX IF NOT EXISTS tokens_owner ON access_tokens(owner_id, created_at);
CREATE TABLE IF NOT EXISTS code_records (
  owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
  record_id TEXT NOT NULL,
  service_id TEXT NOT NULL,
  envelope TEXT NOT NULL CHECK (json_valid(envelope)),
  received_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL CHECK (expires_at > received_at),
  PRIMARY KEY (owner_id, record_id)
);
CREATE INDEX IF NOT EXISTS codes_lookup ON code_records(owner_id, service_id, received_at DESC);
CREATE INDEX IF NOT EXISTS codes_expiry ON code_records(expires_at);
