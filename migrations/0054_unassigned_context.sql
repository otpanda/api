-- Latest redacted message/subject per (owner, source, sender), kept only while retention is enabled in code (inactive by default).
-- Never holds a usable code: the text is redacted before it is encrypted, and active-code ciphertext stays in incoming_codes with its own expiry.
-- Sender and text are encrypted separately (the cipher caps one plaintext at 4096 bytes). sender_digest is a server-keyed HMAC scoped to owner+source (uniqueness key only), no plaintext sender is stored.
-- Rows go away with their source (cascade), on explicit dismiss/assign, on retention expiry (bounded cleanup), and when a rule starts assigning the sender.
CREATE TABLE IF NOT EXISTS unassigned_context (
  context_id TEXT NOT NULL,
  owner_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  sender_digest TEXT NOT NULL CHECK (length(sender_digest) BETWEEN 16 AND 128),
  kind TEXT NOT NULL CHECK (kind IN ('sms','email')),
  latest_event_id TEXT NOT NULL,
  received_at INTEGER NOT NULL, -- provider date, display only, clamped to the arrival time
  arrived_at INTEGER NOT NULL, -- server clock at ingest: drives retention and 'latest' ordering
  key_fingerprint TEXT NOT NULL CHECK (length(key_fingerprint) = 16), -- identifies the digest secret the row was written under; rows under another secret are purged
  retain_until INTEGER NOT NULL CHECK (retain_until > arrived_at),
  sender_envelope TEXT NOT NULL CHECK (json_valid(sender_envelope)),
  text_envelope TEXT CHECK (text_envelope IS NULL OR json_valid(text_envelope)),
  truncated INTEGER NOT NULL DEFAULT 0 CHECK (truncated IN (0,1)),
  size_bytes INTEGER NOT NULL CHECK (size_bytes BETWEEN 1 AND 65536),
  PRIMARY KEY(owner_id, source_id, sender_digest),
  FOREIGN KEY(owner_id, source_id) REFERENCES sources(owner_id, source_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS unassigned_context_id ON unassigned_context(context_id);
CREATE INDEX IF NOT EXISTS unassigned_context_owner_recent ON unassigned_context(owner_id, arrived_at DESC);
CREATE INDEX IF NOT EXISTS unassigned_context_expiry ON unassigned_context(retain_until);
-- Rotation purge and the readiness probe find rows under another digest secret by range probe, never a scan.
CREATE INDEX IF NOT EXISTS unassigned_context_fingerprint ON unassigned_context(key_fingerprint, retain_until);
