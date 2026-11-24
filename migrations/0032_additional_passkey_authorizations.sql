-- Single-use authorization to register an ADDITIONAL passkey. Issued only after
-- a fresh passkey step-up bound to the exact action, device session and
-- generation. Hash-only secret, one live row per owner device, short expiry.
-- Not a session, recovery grant or first-passkey bootstrap.
CREATE TABLE passkey_add_authorizations (
 auth_id TEXT PRIMARY KEY,
 secret_digest TEXT NOT NULL CHECK(length(secret_digest)=64),
 owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
 device_id TEXT NOT NULL REFERENCES device_sessions(device_id) ON DELETE CASCADE,
 generation INTEGER NOT NULL,
 approver_credential_id TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL CHECK(expires_at>created_at AND expires_at-created_at<=120000)
);
CREATE UNIQUE INDEX passkey_add_authorizations_device ON passkey_add_authorizations(owner_id,device_id);
CREATE INDEX passkey_add_authorizations_expiry ON passkey_add_authorizations(expires_at);
