-- Pending signups do not reserve an account/email or create an account row.
CREATE TABLE IF NOT EXISTS passkey_signups (
  signup_id TEXT PRIMARY KEY,
  secret_digest TEXT NOT NULL CHECK (length(secret_digest) = 64),
  binding_digest TEXT NOT NULL CHECK (length(binding_digest) = 64),
  owner_id TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL,
  challenge TEXT NOT NULL CHECK (length(challenge) = 43),
  verified_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL CHECK (expires_at > verified_at)
);
CREATE INDEX IF NOT EXISTS signups_expiry ON passkey_signups(expires_at);
