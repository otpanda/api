-- NN assigned by primary. Enrolled-device contract v8 schema deltas.
ALTER TABLE durable_device_challenges ADD COLUMN consumed_at INTEGER;
ALTER TABLE google_enrollment_grants ADD COLUMN consumed_at INTEGER;
ALTER TABLE native_exchanges ADD COLUMN carried_web_grant_id TEXT;
CREATE TABLE device_key_receipts(
 challenge_id TEXT PRIMARY KEY,
 owner_id TEXT NOT NULL,
 session_device_id TEXT NOT NULL,
 key_id TEXT NOT NULL,
 purpose TEXT NOT NULL,
 action_digest TEXT NOT NULL CHECK(length(action_digest)=64),
 secret_digest TEXT NOT NULL CHECK(length(secret_digest)=64),
 binding_digest TEXT NOT NULL CHECK(length(binding_digest)=64),
 result_json TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL CHECK(expires_at>created_at AND expires_at-created_at<=600000)
);
CREATE INDEX device_key_receipts_expiry ON device_key_receipts(expires_at);
CREATE TABLE enrolled_approvals(
 change_id TEXT PRIMARY KEY,
 owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
 generation INTEGER NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN('passkey-add','device-key-add')),
 target TEXT,
 target_jwk TEXT,
 requester_device_id TEXT NOT NULL REFERENCES device_sessions(device_id) ON DELETE CASCADE,
 requester_label TEXT CHECK(requester_label IS NULL OR length(requester_label)<=64),
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL CHECK(expires_at>created_at AND expires_at-created_at<=600000),
 approved_at INTEGER,
 approver_device_id TEXT,
 approver_key_id TEXT,
 consumed_at INTEGER,
 consume_receipt TEXT,
 CHECK((approved_at IS NULL)=(approver_device_id IS NULL)),
 CHECK((approved_at IS NULL)=(approver_key_id IS NULL)),
 CHECK((consumed_at IS NULL)=(consume_receipt IS NULL)),
 CHECK((kind='device-key-add')=(target IS NOT NULL AND target_jwk IS NOT NULL))
);
CREATE UNIQUE INDEX enrolled_approvals_open ON enrolled_approvals(owner_id,requester_device_id,kind) WHERE consumed_at IS NULL;
CREATE INDEX enrolled_approvals_expiry ON enrolled_approvals(expires_at);
CREATE TABLE passkey_add_authorizations_new(
 auth_id TEXT PRIMARY KEY,
 secret_digest TEXT NOT NULL CHECK(length(secret_digest)=64),
 owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
 device_id TEXT NOT NULL REFERENCES device_sessions(device_id) ON DELETE CASCADE,
 generation INTEGER NOT NULL,
 approver_credential_id TEXT,
 approver_key_id TEXT,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL CHECK(expires_at>created_at AND expires_at-created_at<=120000),
 CHECK((approver_credential_id IS NULL)<>(approver_key_id IS NULL))
);
INSERT INTO passkey_add_authorizations_new(auth_id,secret_digest,owner_id,device_id,generation,approver_credential_id,created_at,expires_at)
 SELECT auth_id,secret_digest,owner_id,device_id,generation,approver_credential_id,created_at,expires_at FROM passkey_add_authorizations;
DROP TABLE passkey_add_authorizations;
ALTER TABLE passkey_add_authorizations_new RENAME TO passkey_add_authorizations;
CREATE UNIQUE INDEX passkey_add_authorizations_device ON passkey_add_authorizations(owner_id,device_id);
CREATE INDEX passkey_add_authorizations_expiry ON passkey_add_authorizations(expires_at);
