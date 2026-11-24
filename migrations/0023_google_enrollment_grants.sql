-- Short-lived first-passkey bootstrap from verified Google identity.
-- Not a general session, recovery grant, or existing-method mutation permit.
CREATE TABLE google_enrollment_grants (
 grant_id TEXT PRIMARY KEY, secret_digest TEXT NOT NULL,
 owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
 device_id TEXT NOT NULL REFERENCES device_sessions(device_id) ON DELETE CASCADE,
 generation INTEGER NOT NULL, issuer TEXT NOT NULL, subject TEXT NOT NULL,
 created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL
);
CREATE INDEX google_enrollment_expiry ON google_enrollment_grants(expires_at);
