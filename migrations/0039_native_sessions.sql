-- Native Android sessions. A native device is created only inside the one-use PKCE exchange
-- claim, with a Keystore-held P-256 public key bound there. No bearer refresh secret exists:
-- killed-app renewal is a server nonce signed by that key. Nothing here touches web tables' shape.
CREATE TABLE native_exchanges (
 exchange_id TEXT PRIMARY KEY,
 secret_digest TEXT NOT NULL CHECK(length(secret_digest)=64),
 owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
 credential_id TEXT REFERENCES passkey_credentials(credential_id) ON DELETE CASCADE,
 provider_identity_id TEXT REFERENCES provider_identities(identity_id) ON DELETE CASCADE,
 generation INTEGER NOT NULL,
 challenge TEXT NOT NULL CHECK(length(challenge)=43),
 redirect_uri TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 CHECK((credential_id IS NULL)<>(provider_identity_id IS NULL))
);
CREATE INDEX native_exchanges_owner ON native_exchanges(owner_id,expires_at);
CREATE TABLE native_keys (
 device_id TEXT PRIMARY KEY REFERENCES device_sessions(device_id) ON DELETE CASCADE,
 public_key TEXT NOT NULL CHECK(length(public_key)=87),
 created_at INTEGER NOT NULL
);
CREATE TABLE native_challenges (
 challenge_id TEXT PRIMARY KEY,
 secret_digest TEXT NOT NULL CHECK(length(secret_digest)=64),
 device_id TEXT NOT NULL REFERENCES device_sessions(device_id) ON DELETE CASCADE,
 purpose TEXT NOT NULL CHECK(purpose IN ('renew','logout')),
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 used_at INTEGER,
 receipt TEXT
);
CREATE INDEX native_challenges_device ON native_challenges(device_id,expires_at);
-- One-use server nonce for native Google ID tokens (Credential Manager). Only its digest is stored.
CREATE TABLE native_google_nonces (
 nonce_id TEXT PRIMARY KEY,
 secret_digest TEXT NOT NULL CHECK(length(secret_digest)=64),
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL
);
CREATE INDEX native_google_nonces_expiry ON native_google_nonces(expires_at);
