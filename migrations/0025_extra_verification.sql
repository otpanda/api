-- Optional "extra verification on new devices" setting. Default off: a row in
-- new_device_verification means the owner opted in. Nothing here grants a
-- session, code access or enrollment by itself.
CREATE TABLE new_device_verification (
 owner_id TEXT PRIMARY KEY REFERENCES accounts(owner_id) ON DELETE CASCADE,
 enabled_at INTEGER NOT NULL,
 generation INTEGER NOT NULL
);
-- Opaque hash-only browser recognition, created only after an authorized
-- session issue. Bound to owner, generation and the exact provider link. No
-- invented expiry: it ends on revocation, generation change or link revocation.
CREATE TABLE recognized_browsers (
 recognition_id TEXT PRIMARY KEY,
 secret_digest TEXT NOT NULL CHECK(length(secret_digest)=64),
 owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
 provider_identity_id TEXT NOT NULL REFERENCES provider_identities(identity_id) ON DELETE CASCADE,
 generation INTEGER NOT NULL,
 created_at INTEGER NOT NULL,
 revoked_at INTEGER
);
CREATE INDEX recognized_browsers_owner ON recognized_browsers(owner_id);
-- A new-device Google login waiting for explicit approval. It carries no
-- session, access or code authority. context is an opaque caller envelope.
CREATE TABLE pending_logins (
 pending_id TEXT PRIMARY KEY,
 secret_digest TEXT NOT NULL CHECK(length(secret_digest)=64),
 owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
 provider_identity_id TEXT NOT NULL REFERENCES provider_identities(identity_id) ON DELETE CASCADE,
 generation INTEGER NOT NULL,
 challenge TEXT NOT NULL CHECK(length(challenge)=43),
 browser_binding_digest TEXT NOT NULL CHECK(length(browser_binding_digest)=64),
 remember INTEGER NOT NULL CHECK(remember IN (0,1)),
 context TEXT NOT NULL CHECK(length(context)<=4096),
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL CHECK(expires_at>created_at),
 approved_at INTEGER,
 approval_method TEXT CHECK(approval_method IN ('passkey','client')),
 approver_device_id TEXT,
 approver_credential_id TEXT,
 canceled_at INTEGER,
 consumed_at INTEGER,
 CHECK((approved_at IS NULL)=(approval_method IS NULL)),
 CHECK(approval_method IS NOT 'passkey' OR approver_credential_id IS NOT NULL),
 CHECK(approval_method IS NOT 'client' OR approver_device_id IS NOT NULL)
);
CREATE INDEX pending_logins_owner ON pending_logins(owner_id,expires_at);
CREATE INDEX pending_logins_expiry ON pending_logins(expires_at);
-- While the setting is on, the last active passkey cannot be revoked by any
-- path. Strict and clockless on purpose: turn the setting off first (with
-- passkey proof or an approving client), then remove the final passkey.
CREATE TRIGGER passkey_last_verifier_guard BEFORE UPDATE OF revoked_at ON passkey_credentials
WHEN NEW.revoked_at IS NOT NULL AND OLD.revoked_at IS NULL
 AND EXISTS(SELECT 1 FROM new_device_verification v WHERE v.owner_id=OLD.owner_id)
 AND NOT EXISTS(SELECT 1 FROM passkey_credentials o WHERE o.owner_id=OLD.owner_id AND o.credential_id<>OLD.credential_id AND o.revoked_at IS NULL)
BEGIN SELECT RAISE(ABORT,'last verifier'); END;
