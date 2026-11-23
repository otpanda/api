-- Persistent first-party sessions. Raw handles are never stored.
CREATE TABLE IF NOT EXISTS device_sessions (
  device_id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
  credential_id TEXT NOT NULL REFERENCES passkey_credentials(credential_id) ON DELETE CASCADE,
  generation INTEGER NOT NULL,
  client_kind TEXT NOT NULL CHECK (client_kind IN ('web', 'android', 'extension')),
  created_at INTEGER NOT NULL,
  last_used_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS device_sessions_owner ON device_sessions(owner_id);
CREATE TABLE IF NOT EXISTS device_refresh_handles (
  handle_id TEXT PRIMARY KEY,
  secret_digest TEXT NOT NULL CHECK (length(secret_digest) = 64),
  device_id TEXT NOT NULL REFERENCES device_sessions(device_id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  used_at INTEGER
);
CREATE INDEX IF NOT EXISTS device_handles_device ON device_refresh_handles(device_id);
CREATE TABLE IF NOT EXISTS device_access_handles (
  handle_id TEXT PRIMARY KEY,
  secret_digest TEXT NOT NULL CHECK (length(secret_digest) = 64),
  device_id TEXT NOT NULL REFERENCES device_sessions(device_id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS device_access_expiry ON device_access_handles(expires_at);
