-- New email-primary identity generation. Existing pre-release accounts are not
-- automatically verified or matched by historical provider claims.
CREATE TABLE IF NOT EXISTS account_emails (
  owner_id TEXT PRIMARY KEY REFERENCES accounts(owner_id) ON DELETE CASCADE,
  email TEXT NOT NULL UNIQUE COLLATE BINARY,
  verified_at INTEGER NOT NULL CHECK (verified_at >= 0),
  updated_at INTEGER NOT NULL CHECK (updated_at >= verified_at)
);
CREATE TABLE IF NOT EXISTS auth_challenges (
  challenge_id TEXT PRIMARY KEY,
  secret_digest TEXT NOT NULL CHECK (length(secret_digest) = 64),
  purpose TEXT NOT NULL,
  owner_id TEXT REFERENCES accounts(owner_id) ON DELETE CASCADE,
  target_digest TEXT NOT NULL CHECK (length(target_digest) = 64),
  created_at INTEGER NOT NULL CHECK (created_at >= 0),
  expires_at INTEGER NOT NULL CHECK (expires_at > created_at)
);
CREATE INDEX IF NOT EXISTS auth_challenges_expiry ON auth_challenges(expires_at);
CREATE TABLE IF NOT EXISTS account_security (
  owner_id TEXT PRIMARY KEY REFERENCES accounts(owner_id) ON DELETE CASCADE,
  generation INTEGER NOT NULL DEFAULT 0 CHECK (generation >= 0),
  recovery_hold_until INTEGER NOT NULL DEFAULT 0 CHECK (recovery_hold_until >= 0)
);
