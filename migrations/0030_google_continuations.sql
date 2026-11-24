CREATE TABLE google_continuations(continuation_id TEXT PRIMARY KEY,secret_digest TEXT NOT NULL,binding_digest TEXT NOT NULL,envelope TEXT NOT NULL,created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL);
CREATE INDEX google_continuation_expiry ON google_continuations(expires_at);
