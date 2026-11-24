-- Public keys only. No inactivity expiry. This schema does not certify Android
-- key provenance, hardware backing or OS authentication configuration.
CREATE TABLE durable_device_keys (
 key_id TEXT PRIMARY KEY,owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
 public_jwk TEXT NOT NULL CHECK(json_valid(public_jwk)),public_key_digest TEXT NOT NULL,generation INTEGER NOT NULL,
 created_at INTEGER NOT NULL,last_used_at INTEGER,revoked_at INTEGER
);
CREATE UNIQUE INDEX durable_keys_owner_key ON durable_device_keys(owner_id,public_key_digest);
CREATE INDEX durable_keys_owner ON durable_device_keys(owner_id);
CREATE TABLE durable_device_challenges (
 challenge_id TEXT PRIMARY KEY,secret_digest TEXT NOT NULL,binding_digest TEXT NOT NULL,
 key_id TEXT NOT NULL,owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
 generation INTEGER NOT NULL,purpose TEXT NOT NULL CHECK(purpose IN ('enroll','step-up','recover-access')),
 action_digest TEXT NOT NULL,public_jwk TEXT,credential_id TEXT,challenge TEXT NOT NULL,
 created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL
);
CREATE INDEX durable_challenges_key ON durable_device_challenges(key_id,expires_at);
CREATE INDEX durable_challenges_expiry ON durable_device_challenges(expires_at);
