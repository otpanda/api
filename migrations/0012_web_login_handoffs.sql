-- Verified browser login handoffs, never refresh/access credentials.
CREATE TABLE web_login_handoffs (
 handoff_id TEXT PRIMARY KEY,
 secret_digest TEXT NOT NULL,
 binding_digest TEXT NOT NULL,
 owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
 credential_id TEXT NOT NULL REFERENCES passkey_credentials(credential_id),
 generation INTEGER NOT NULL,
 verified_at INTEGER NOT NULL,
 challenge TEXT NOT NULL,
 state TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL
);
CREATE INDEX web_login_handoffs_expiry ON web_login_handoffs(expires_at);
CREATE TABLE web_login_starts (
 ceremony_id TEXT PRIMARY KEY,
 secret_digest TEXT NOT NULL,
 cookie_digest TEXT NOT NULL,
 challenge TEXT NOT NULL,
 state TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL
);
CREATE INDEX web_login_starts_expiry ON web_login_starts(expires_at);
