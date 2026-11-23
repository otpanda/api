-- Per-viewer state. Shared-entry owners never gain access to recipient state.
-- Count/ranking policy is separate from this tags/pins document.
CREATE TABLE IF NOT EXISTS personal_organization (
  viewer_id TEXT PRIMARY KEY REFERENCES accounts(owner_id) ON DELETE CASCADE,
  revision INTEGER NOT NULL DEFAULT 0 CHECK(revision >= 0),
  document TEXT NOT NULL CHECK(json_valid(document)),
  updated_at INTEGER NOT NULL CHECK(updated_at >= 0)
);
CREATE TABLE IF NOT EXISTS personal_copy_days (
 viewer_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
 entry_id TEXT NOT NULL REFERENCES entries(entry_id) ON DELETE CASCADE,
 day INTEGER NOT NULL CHECK(day>=0),
 copies INTEGER NOT NULL CHECK(copies BETWEEN 1 AND 1000),
 PRIMARY KEY(viewer_id,entry_id,day)
);
CREATE TABLE IF NOT EXISTS personal_copy_receipts (
 viewer_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
 receipt_id TEXT NOT NULL,
 accepted_at INTEGER NOT NULL CHECK(accepted_at>=0),
 PRIMARY KEY(viewer_id,receipt_id)
);
CREATE INDEX IF NOT EXISTS personal_copy_receipts_age ON personal_copy_receipts(viewer_id,accepted_at);

CREATE INDEX IF NOT EXISTS personal_copy_days_age ON personal_copy_days(day);
