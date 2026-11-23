-- Short-lived server-held ceremony context. No raw token or cookie stored.
-- Mail receipts separately retain canonical email until bounded expiry cleanup.
CREATE TABLE web_signup_starts (
 signup_id TEXT PRIMARY KEY,
 secret_digest TEXT NOT NULL,
 cookie_digest TEXT NOT NULL,
 challenge TEXT NOT NULL,
 state TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL CHECK(expires_at>created_at)
);
CREATE INDEX web_signup_starts_expiry ON web_signup_starts(expires_at);
CREATE TABLE signup_mail_bindings (
 proof_id TEXT PRIMARY KEY,
 secret_digest TEXT NOT NULL,
 cookie_digest TEXT NOT NULL,
 email TEXT NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0 AND attempts<=5),
 verified_at INTEGER,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL CHECK(expires_at>created_at)
);
CREATE INDEX signup_mail_bindings_expiry ON signup_mail_bindings(expires_at);
