-- Protocol2 bounded, secret-free recovery slots. Never grants v1 authority.
CREATE TABLE totp_import_admissions (
 owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
 admission_id TEXT NOT NULL PRIMARY KEY,
 batch_nonce TEXT NOT NULL,
 device_id TEXT NOT NULL,
 generation INTEGER NOT NULL,
 digest TEXT NOT NULL,
 expires_at INTEGER NOT NULL,
 fenced INTEGER NOT NULL CHECK(fenced IN (0,1)),
 UNIQUE(owner_id,batch_nonce)
);
CREATE INDEX totp_import_admissions_owner ON totp_import_admissions(owner_id);
CREATE INDEX totp_import_admissions_expiry ON totp_import_admissions(expires_at);
ALTER TABLE totp_batch_imports ADD COLUMN import_admission_id TEXT;
ALTER TABLE totp_batch_imports ADD COLUMN import_device_id TEXT;
