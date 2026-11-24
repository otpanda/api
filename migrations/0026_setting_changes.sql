-- Action-bound approval of a security-setting change by a different signed-in
-- client. Requester and approver are existing device sessions of one owner.
CREATE TABLE setting_changes (
 change_id TEXT PRIMARY KEY,
 owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
 generation INTEGER NOT NULL,
 action TEXT NOT NULL CHECK(action IN ('enable-extra-verification','disable-extra-verification')),
 requester_device_id TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL CHECK(expires_at>created_at),
 approved_at INTEGER,
 approver_device_id TEXT,
 consumed_at INTEGER,
 consume_receipt TEXT,
 CHECK((approved_at IS NULL)=(approver_device_id IS NULL)),
 CHECK((consumed_at IS NULL)=(consume_receipt IS NULL))
);
CREATE INDEX setting_changes_owner ON setting_changes(owner_id,expires_at);
