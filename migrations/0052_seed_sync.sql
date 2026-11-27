-- Inactive native seed-sync server state (flag default off, nothing mounted). Additive.
-- Rollout order: deploy the count-compatible code (>=1 checks on totp_seeds writes) BEFORE this migration, because the triggers below
-- add rows to a table that older code counted exactly (D1 meta.changes includes trigger rows).
ALTER TABLE totp_seeds ADD COLUMN seed_version INTEGER NOT NULL DEFAULT 1 CHECK (seed_version >= 1);
-- Non-secret parameters, so a snapshot never decrypts envelopes. NULL until written or backfilled: such rows are reported unsupported (metadata_pending).
ALTER TABLE totp_seeds ADD COLUMN algorithm TEXT;
ALTER TABLE totp_seeds ADD COLUMN digits INTEGER;
ALTER TABLE totp_seeds ADD COLUMN period INTEGER;
ALTER TABLE totp_seeds ADD COLUMN seed_bytes INTEGER;

CREATE TABLE IF NOT EXISTS seed_sync_owner (
  owner_id TEXT PRIMARY KEY REFERENCES accounts(owner_id) ON DELETE CASCADE,
  revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0)
);
CREATE TABLE IF NOT EXISTS seed_sync_tombstones (
  owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
  entry_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (owner_id, entry_id)
);
-- Owners that already hold seeds start at revision 1 and their rows at seed_version 1, so every later change gets a strictly larger version.
INSERT OR IGNORE INTO seed_sync_owner(owner_id, revision) SELECT DISTINCT owner_id, 1 FROM totp_seeds;
-- Every route that changes a secret (create, replace, delete, entry cascade) bumps seed_version and the owner revision in the same
-- statement, because the triggers run inside the writing statement. WHEN EXISTS(accounts) skips account-deletion cascades.
CREATE TRIGGER seed_sync_seed_insert AFTER INSERT ON totp_seeds
WHEN EXISTS (SELECT 1 FROM accounts WHERE owner_id = NEW.owner_id)
BEGIN
  INSERT INTO seed_sync_owner(owner_id, revision) VALUES (NEW.owner_id, 1) ON CONFLICT(owner_id) DO UPDATE SET revision = revision + 1;
  DELETE FROM seed_sync_tombstones WHERE owner_id = NEW.owner_id AND entry_id = NEW.entry_id;
  -- seed_version is the owner revision after the bump: strictly increasing per owner, so delete then re-create of the same entry id
  -- always yields a version larger than any version a device may hold.
  UPDATE totp_seeds SET seed_version = (SELECT revision FROM seed_sync_owner WHERE owner_id = NEW.owner_id) WHERE entry_id = NEW.entry_id;
END;
CREATE TRIGGER seed_sync_seed_update AFTER UPDATE OF envelope ON totp_seeds
WHEN OLD.envelope <> NEW.envelope AND EXISTS (SELECT 1 FROM accounts WHERE owner_id = NEW.owner_id)
BEGIN
  INSERT INTO seed_sync_owner(owner_id, revision) VALUES (NEW.owner_id, 2) ON CONFLICT(owner_id) DO UPDATE SET revision = revision + 1;
  UPDATE totp_seeds SET seed_version = (SELECT revision FROM seed_sync_owner WHERE owner_id = NEW.owner_id) WHERE entry_id = NEW.entry_id;
END;
-- Backfilling non-secret metadata can flip an entry from unsupported (metadata_pending) to representable, so the revision must move.
CREATE TRIGGER seed_sync_seed_metadata AFTER UPDATE OF algorithm, digits, period, seed_bytes ON totp_seeds
WHEN OLD.envelope = NEW.envelope AND (OLD.algorithm IS NULL OR OLD.digits IS NULL OR OLD.period IS NULL OR OLD.seed_bytes IS NULL) AND EXISTS (SELECT 1 FROM accounts WHERE owner_id = NEW.owner_id)
BEGIN
  INSERT INTO seed_sync_owner(owner_id, revision) VALUES (NEW.owner_id, 2) ON CONFLICT(owner_id) DO UPDATE SET revision = revision + 1;
END;
CREATE TRIGGER seed_sync_seed_delete AFTER DELETE ON totp_seeds
WHEN EXISTS (SELECT 1 FROM accounts WHERE owner_id = OLD.owner_id)
BEGIN
  INSERT INTO seed_sync_owner(owner_id, revision) VALUES (OLD.owner_id, 1) ON CONFLICT(owner_id) DO UPDATE SET revision = revision + 1;
  INSERT OR REPLACE INTO seed_sync_tombstones(owner_id, entry_id, revision, created_at)
    VALUES (OLD.owner_id, OLD.entry_id, (SELECT revision FROM seed_sync_owner WHERE owner_id = OLD.owner_id), CAST(strftime('%s','now') AS INTEGER) * 1000);
END;

-- One row is one enrollment (the grant). Its own P-256 key, separate from durable_device_keys, so sign-out or disable can destroy it
-- without touching sign-in, recovery or approvals. install_id is a stable per-install random id (device_sessions ids change per sign-in).
CREATE TABLE IF NOT EXISTS seed_sync_keys (
  key_id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
  install_id TEXT NOT NULL,
  public_jwk TEXT NOT NULL CHECK (json_valid(public_jwk)),
  public_key_digest TEXT NOT NULL,
  generation INTEGER NOT NULL CHECK (generation >= 0),
  credential_id TEXT,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  last_device_id TEXT,
  revoked_at INTEGER,
  revoked_reason TEXT CHECK (revoked_reason IS NULL OR revoked_reason IN ('superseded','remote','disabled','generation'))
);
CREATE UNIQUE INDEX IF NOT EXISTS seed_sync_keys_one_active_install ON seed_sync_keys(owner_id, install_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS seed_sync_keys_install ON seed_sync_keys(owner_id, install_id);
CREATE UNIQUE INDEX IF NOT EXISTS seed_sync_keys_digest ON seed_sync_keys(owner_id, public_key_digest);

CREATE TABLE IF NOT EXISTS seed_sync_challenges (
  challenge_id TEXT PRIMARY KEY,
  secret_digest TEXT NOT NULL,
  owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
  key_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  install_id TEXT,
  generation INTEGER NOT NULL,
  purpose TEXT NOT NULL CHECK (purpose IN ('seed-sync-enroll','seed-sync-snapshot','seed-sync-batch','seed-sync-revoke','seed-sync-status')),
  epoch INTEGER,
  nonce TEXT NOT NULL,
  action_digest TEXT,
  public_jwk TEXT,
  credential_id TEXT,
  ephemeral_key TEXT,
  entries TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER,
  -- Install-state fence for enroll challenges (see SeedSync.enrollFinish): rows and active key of this (owner, install) when the challenge was issued.
  install_key_count INTEGER,
  predecessor_key_id TEXT
);
CREATE INDEX IF NOT EXISTS seed_sync_challenges_key ON seed_sync_challenges(key_id, expires_at);
CREATE INDEX IF NOT EXISTS seed_sync_challenges_expiry ON seed_sync_challenges(expires_at);

CREATE TABLE IF NOT EXISTS seed_sync_events (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
  key_id TEXT,
  kind TEXT NOT NULL CHECK (kind IN ('enrolled','revoked','denied')),
  reason TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS seed_sync_events_owner ON seed_sync_events(owner_id, created_at);
