-- Public-key material only. No authenticator private key reaches the server.
CREATE TABLE IF NOT EXISTS passkey_credentials (
  credential_id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
  public_key BLOB NOT NULL,
  counter INTEGER NOT NULL CHECK (counter >= 0),
  revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
  transports TEXT NOT NULL CHECK (json_valid(transports)),
  device_type TEXT NOT NULL CHECK (device_type IN ('singleDevice', 'multiDevice')),
  backed_up INTEGER NOT NULL CHECK (backed_up IN (0, 1)),
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS passkeys_owner ON passkey_credentials(owner_id);
CREATE TABLE IF NOT EXISTS passkey_ceremonies (
  ceremony_id TEXT PRIMARY KEY,
  secret_digest TEXT NOT NULL CHECK (length(secret_digest) = 64),
  binding_digest TEXT NOT NULL CHECK (length(binding_digest) = 64),
  challenge TEXT NOT NULL CHECK (length(challenge) = 43),
  purpose TEXT NOT NULL CHECK (purpose IN ('register', 'authenticate', 'step-up')),
  owner_id TEXT REFERENCES accounts(owner_id) ON DELETE CASCADE,
  generation INTEGER,
  action_digest TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL CHECK (expires_at > created_at)
);
CREATE INDEX IF NOT EXISTS ceremonies_expiry ON passkey_ceremonies(expires_at);
