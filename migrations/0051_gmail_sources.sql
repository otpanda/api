-- Gmail source connections. A mailbox maps to exactly one owner/source. The
-- refresh token is an AES-GCM envelope bound to owner and source, never plain.
CREATE TABLE IF NOT EXISTS gmail_oauth_states (
  state_hash TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
  verifier TEXT NOT NULL,
  device_id TEXT NOT NULL,
  generation TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
  used_at INTEGER
);
CREATE INDEX IF NOT EXISTS gmail_oauth_states_expiry ON gmail_oauth_states(expires_at);
CREATE TABLE IF NOT EXISTS gmail_connections (
  source_id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  mailbox TEXT NOT NULL UNIQUE,
  refresh_envelope TEXT NOT NULL,
  history_id TEXT NOT NULL CHECK (history_id GLOB '[1-9]*' AND history_id NOT GLOB '*[^0-9]*'),
  watch_expires_at INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active','reauth_required','disconnected')) DEFAULT 'active',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  recovery_hid TEXT CHECK (recovery_hid IS NULL OR (recovery_hid GLOB '[1-9]*' AND recovery_hid NOT GLOB '*[^0-9]*')),
  recovery_page TEXT,
  recovery_count INTEGER NOT NULL DEFAULT 0,
  -- Label mode only (both NULL = INBOX watch, nothing created in the mailbox). Provider ids of the one
  -- label and one filter THIS app created, kept so disconnect removes only those. Not secrets.
  -- Lifecycle generation: bumped by every connect and by the revoke trigger (any code path). A connect writes only if it still
  -- holds the generation it read, so a revoke that lands while it prepares its write is never undone.
  gen INTEGER NOT NULL DEFAULT 0,
  label_id TEXT CHECK (label_id IS NULL OR length(label_id) BETWEEN 1 AND 64),
  filter_id TEXT CHECK (filter_id IS NULL OR length(filter_id) BETWEEN 1 AND 64),
  FOREIGN KEY(owner_id, source_id) REFERENCES sources(owner_id, source_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS gmail_connections_owner ON gmail_connections(owner_id);
CREATE INDEX IF NOT EXISTS gmail_connections_watch ON gmail_connections(watch_expires_at);
-- Single-flight for anything that WRITES to a mailbox at Google (connect, disconnect, watch renewal), keyed by the canonical
-- mailbox. The row is inserted before the first Google call and deleted only after every mutating call returned a definite
-- answer. There is no expiry and no takeover: a timeout, transport error, 5xx/429 on a mutating call, or a crash leaves the row
-- ('indeterminate', or 'running' after a crash) and every later lifecycle operation for that mailbox fails closed until an
-- operator has a definite answer about the earlier request. Not used for reads.
CREATE TABLE IF NOT EXISTS gmail_op (
  mailbox TEXT PRIMARY KEY CHECK (length(mailbox) BETWEEN 3 AND 320),
  owner_id TEXT NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 128), -- who started it; the only owner whose status shows it (no FK: an account delete must not erase a block)
  op_id TEXT NOT NULL CHECK (length(op_id) BETWEEN 8 AND 64),
  kind TEXT NOT NULL CHECK (kind IN ('connect','disconnect','renew')),
  state TEXT NOT NULL CHECK (state IN ('running','indeterminate')) DEFAULT 'running',
  started_at INTEGER NOT NULL
) WITHOUT ROWID;
-- Messages already ingested per connection, so a resumed window never refetches them.
CREATE TABLE IF NOT EXISTS gmail_handled (
  source_id TEXT NOT NULL REFERENCES gmail_connections(source_id) ON DELETE CASCADE,
  message_id TEXT NOT NULL,
  handled_at INTEGER NOT NULL,
  skip_reason TEXT CHECK (skip_reason IN ('too_large','invalid_message')),
  PRIMARY KEY (source_id, message_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS gmail_handled_age ON gmail_handled(source_id, handled_at);
-- Messages whose fetch from Gmail failed transiently (timeout, 5xx or 429). Nothing about the
-- message is stored except its id and when we first and last tried; the reason is a fixed enum.
-- The row is retried with exponential backoff (1 min doubling to 1 h) until the message is fetched
-- (collected, skipped, or gone), and is deleted in the same batch that marks it handled. Never pruned by age.
-- At most 1000 rows per source (enforced by the single insert statement); when full the history
-- cursor is held instead of evicting a row.
CREATE TABLE IF NOT EXISTS gmail_deferred (
  source_id TEXT NOT NULL REFERENCES gmail_connections(source_id) ON DELETE CASCADE,
  message_id TEXT NOT NULL,
  first_seen_at INTEGER NOT NULL,
  next_attempt_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL CHECK (attempts >= 1),
  last_reason TEXT NOT NULL CHECK (last_reason IN ('fetch_timeout', 'fetch_error')),
  PRIMARY KEY (source_id, message_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS gmail_deferred_due ON gmail_deferred(source_id, next_attempt_at);
-- Revoking the source (by any code path) disconnects the mailbox in the same statement:
-- the stored refresh token is wiped and sync/renewal stop selecting it.
CREATE TRIGGER IF NOT EXISTS gmail_source_revoked AFTER UPDATE OF revoked_at ON sources
WHEN NEW.kind = 'gmail' AND NEW.revoked_at IS NOT NULL
BEGIN
  UPDATE gmail_connections SET status='disconnected', refresh_envelope='', recovery_hid=NULL, recovery_page=NULL, recovery_count=0, gen=gen+1, updated_at=NEW.revoked_at
  WHERE source_id=NEW.source_id AND owner_id=NEW.owner_id;
  DELETE FROM gmail_deferred WHERE source_id=NEW.source_id;
END;
