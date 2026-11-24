-- Action-bound approval of a recovery control by a DIFFERENT enrolled client.
-- Requester and approver are different device sessions of one owner. The
-- approval is a verifier-produced DurableDeviceKeys step-up proof bound to the
-- exact change id, kind, target, owner and generation. Possession of the
-- enrolled device key is what is proved (platformVerified:false): it is not
-- proof of an OS PIN or biometric. A bare browser session is never approval.
CREATE TABLE recovery_changes (
 change_id TEXT PRIMARY KEY,
 owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
 generation INTEGER NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('email-escape-on','email-escape-off','passkey-revoke','session-revoke')),
 target TEXT,
 requester_device_id TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL CHECK(expires_at>created_at),
 approved_at INTEGER,
 approver_device_id TEXT,
 approver_key_id TEXT,
 consumed_at INTEGER,
 consume_receipt TEXT,
 CHECK((approved_at IS NULL)=(approver_device_id IS NULL) AND (approved_at IS NULL)=(approver_key_id IS NULL)),
 CHECK((consumed_at IS NULL)=(consume_receipt IS NULL)),
 CHECK((kind IN ('passkey-revoke','session-revoke'))=(target IS NOT NULL))
);
CREATE INDEX recovery_changes_owner ON recovery_changes(owner_id,expires_at);
-- Opt-in email-only recovery. A request alone grants nothing. Completion needs
-- the 7-day wait, a fresh mailbox code and a NEW passkey, and then retires every
-- old passkey, device key, session and automation token in one atomic write.
CREATE TABLE email_recovery_requests (
 request_id TEXT PRIMARY KEY,
 owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
 generation INTEGER NOT NULL,
 requested_at INTEGER NOT NULL,
 available_at INTEGER NOT NULL,
 canceled_at INTEGER,
 canceled_by TEXT CHECK(canceled_by IN ('client','setting-off','generation-changed')),
 completed_at INTEGER,
 completion_receipt TEXT,
 CHECK(available_at-requested_at=604800000),
 CHECK((canceled_at IS NULL)=(canceled_by IS NULL)),
 CHECK((completed_at IS NULL)=(completion_receipt IS NULL)),
 CHECK(completed_at IS NULL OR (canceled_at IS NULL AND completed_at>=available_at))
);
CREATE UNIQUE INDEX email_recovery_one_open ON email_recovery_requests(owner_id) WHERE canceled_at IS NULL AND completed_at IS NULL;
-- Turning the opt-in off cancels any waiting request.
CREATE TRIGGER email_recovery_optin_off AFTER DELETE ON email_recovery_optin
BEGIN UPDATE email_recovery_requests SET canceled_at=CAST(strftime('%s','now') AS INTEGER)*1000,canceled_by='setting-off' WHERE owner_id=OLD.owner_id AND canceled_at IS NULL AND completed_at IS NULL; END;
-- Single-use completion grant, issued only after a fresh mailbox code on an
-- available request. It authorizes registering ONE new passkey, nothing else.
CREATE TABLE email_recovery_grants (
 grant_id TEXT PRIMARY KEY,
 secret_digest TEXT NOT NULL,
 request_id TEXT NOT NULL REFERENCES email_recovery_requests(request_id) ON DELETE CASCADE,
 owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
 generation INTEGER NOT NULL,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL CHECK(expires_at>created_at)
);
CREATE INDEX email_recovery_grants_expiry ON email_recovery_grants(expires_at);
-- Outbox for the mail path. Rows are facts to deliver; delivery is not done here.
CREATE TABLE recovery_notifications (
 notification_id TEXT PRIMARY KEY,
 owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
 request_id TEXT NOT NULL REFERENCES email_recovery_requests(request_id) ON DELETE CASCADE,
 kind TEXT NOT NULL CHECK(kind IN ('requested','canceled','completed')),
 created_at INTEGER NOT NULL,
 delivered_at INTEGER,
 attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 5),
 next_attempt_at INTEGER NOT NULL DEFAULT 0,
 claimed_until INTEGER NOT NULL DEFAULT 0,
 failed_at INTEGER,
 CHECK(failed_at IS NULL OR delivered_at IS NULL)
);
CREATE INDEX recovery_notifications_pending ON recovery_notifications(next_attempt_at) WHERE delivered_at IS NULL AND attempts<5;
-- Durable mailbox-code delivery jobs. The code is stored only as an AES-GCM
-- envelope (never plaintext, never logged) and wiped on delivery. A job lives
-- until its code expires, so a failed or skipped send is retried, not lost.
-- kind 'decoy' rows are written for non-qualifying requests so writes match;
-- they are born delivered and are never sent.
CREATE TABLE recovery_code_jobs (
 job_id TEXT PRIMARY KEY,
 owner_id TEXT,
 kind TEXT NOT NULL CHECK(kind IN ('recovery-request','recovery-complete','decoy')),
 binding_digest TEXT NOT NULL,
 envelope TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL CHECK(expires_at>created_at),
 attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 6),
 next_attempt_at INTEGER NOT NULL DEFAULT 0,
 claimed_until INTEGER NOT NULL DEFAULT 0,
 delivered_at INTEGER,
 failed_at INTEGER,
 failure TEXT CHECK(failure IS NULL OR failure IN ('expired','attempts','stale')),
 generation INTEGER,
 superseded_at INTEGER,
 code_id TEXT,
 CHECK(failed_at IS NULL OR delivered_at IS NULL),
 CHECK((failed_at IS NULL)=(failure IS NULL)),
 CHECK((kind='decoy')=(owner_id IS NULL)),
 CHECK(kind='decoy' OR code_id IS NOT NULL)
);
CREATE INDEX recovery_code_jobs_pending ON recovery_code_jobs(next_attempt_at) WHERE delivered_at IS NULL;
CREATE INDEX recovery_code_jobs_expiry ON recovery_code_jobs(expires_at);
-- Atomic proof that a credential was inserted BY a recovery completion batch.
-- NULL on every pre-existing credential, so an existing credential can never
-- satisfy the "new passkey" requirement, whatever its timestamps.
ALTER TABLE passkey_credentials ADD COLUMN recovery_receipt TEXT;
CREATE UNIQUE INDEX passkey_recovery_receipt ON passkey_credentials(recovery_receipt) WHERE recovery_receipt IS NOT NULL;
