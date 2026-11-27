-- Seed-sync new-device notice outbox (security notice to the account's stored mailbox). Additive, no triggers, own table.
-- Written in the same D1 batch as the key insert at enroll finish; delivered at-least-once by deliverSeedSyncNotices (not wired to any worker yet).
CREATE TABLE IF NOT EXISTS seed_sync_notices (
  notice_id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
  key_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('enrolled')),
  created_at INTEGER NOT NULL,
  delivered_at INTEGER,
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
  next_attempt_at INTEGER NOT NULL DEFAULT 0,
  claimed_until INTEGER NOT NULL DEFAULT 0,
  failed_at INTEGER,
  CHECK (failed_at IS NULL OR delivered_at IS NULL)
);
CREATE INDEX IF NOT EXISTS seed_sync_notices_pending ON seed_sync_notices(next_attempt_at) WHERE delivered_at IS NULL AND failed_at IS NULL;
