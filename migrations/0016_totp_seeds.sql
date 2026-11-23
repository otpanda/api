-- Durable TOTP seeds, one per entry, always encrypted with a seed-dedicated
-- envelope ('otpanda-seed'), never with the delivered-code envelope. Generated
-- codes are computed on demand and never stored. Sharing an entry exposes only
-- generated codes, never seed material.
CREATE TABLE IF NOT EXISTS totp_seeds (
  owner_id TEXT NOT NULL,
  entry_id TEXT NOT NULL,
  envelope TEXT NOT NULL CHECK (json_valid(envelope)),
  created_at INTEGER NOT NULL CHECK (created_at >= 0),
  updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
  PRIMARY KEY (entry_id),
  FOREIGN KEY (owner_id, entry_id) REFERENCES entries(owner_id, entry_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS totp_seeds_owner ON totp_seeds(owner_id);
