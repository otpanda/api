CREATE TABLE IF NOT EXISTS identities (
  issuer TEXT NOT NULL,
  subject TEXT NOT NULL,
  owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
  PRIMARY KEY (issuer, subject)
);
CREATE TABLE IF NOT EXISTS sessions (
  session_id TEXT PRIMARY KEY,
  session_digest BLOB NOT NULL CHECK (length(session_digest) = 32),
  csrf_digest BLOB NOT NULL CHECK (length(csrf_digest) = 32),
  owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL CHECK (expires_at > created_at)
);
CREATE INDEX IF NOT EXISTS sessions_owner ON sessions(owner_id);
CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS oauth_transactions (
  state_digest TEXT PRIMARY KEY,
  binding_digest TEXT NOT NULL,
  envelope TEXT NOT NULL CHECK (json_valid(envelope)),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL CHECK (expires_at > created_at)
);
CREATE INDEX IF NOT EXISTS transactions_expiry ON oauth_transactions(expires_at);
CREATE TABLE IF NOT EXISTS rate_buckets (
  bucket_key TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  resets_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS buckets_expiry ON rate_buckets(resets_at);
