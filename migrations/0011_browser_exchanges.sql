-- Short-lived, one-use top-level browser restoration grants. No raw code/access.
CREATE TABLE IF NOT EXISTS browser_exchanges (
  exchange_id TEXT PRIMARY KEY,
  secret_digest TEXT NOT NULL CHECK(length(secret_digest)=64),
  device_id TEXT NOT NULL REFERENCES device_sessions(device_id) ON DELETE CASCADE,
  challenge TEXT NOT NULL CHECK(length(challenge)=43),
  redirect_uri TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS browser_exchanges_expiry ON browser_exchanges(expires_at);
