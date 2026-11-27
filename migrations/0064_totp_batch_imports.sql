-- Durable outcome record for owner TOTP batch imports (additive, no route is
-- activated by this file). One row per committed batch, written in the same
-- transaction as the entries and seeds, so a row exists if and only if the whole
-- batch committed. The (owner, nonce) key makes a repeated finish idempotent and
-- lets the client read back an unknown outcome. Rows hold no secret and no label:
-- only the action digest, the entry ids in request order and the time.
-- Permanent replay tombstones until account deletion. Never prune by age.
CREATE TABLE IF NOT EXISTS totp_batch_imports (
  owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
  batch_nonce TEXT NOT NULL CHECK (length(batch_nonce) BETWEEN 22 AND 64),
  action_digest TEXT NOT NULL CHECK (length(action_digest) = 64),
  entry_ids TEXT NOT NULL CHECK (json_valid(entry_ids)),
  created_at INTEGER NOT NULL CHECK (created_at >= 0),
  PRIMARY KEY (owner_id, batch_nonce)
);
CREATE INDEX IF NOT EXISTS totp_batch_imports_created ON totp_batch_imports(created_at);
