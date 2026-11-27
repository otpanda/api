-- Account-level sharing grants and limited machine profiles. Additive: the
-- per-entry entry_shares/entry_tokens tables stay as they are until the
-- application is moved over. Selectors are evaluated live on every read, so
-- full and deny-list grants automatically cover entries created later and a
-- narrowed grant takes effect for already-issued machine tokens at once.
CREATE TABLE IF NOT EXISTS access_grants (
  grant_id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
  grantee_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
  mode TEXT NOT NULL CHECK (mode IN ('all','allow','deny')),
  can_delegate INTEGER NOT NULL DEFAULT 0 CHECK (can_delegate IN (0,1)),
  created_at INTEGER NOT NULL,
  -- Start of the current continuous delegating grant. Moves on (re)activation or when delegation is switched on, never on narrowing.
  granted_at INTEGER NOT NULL,
  revoked_at INTEGER,
  CHECK (owner_id <> grantee_id),
  UNIQUE(owner_id, grantee_id)
);
CREATE INDEX IF NOT EXISTS access_grants_grantee ON access_grants(grantee_id);
CREATE TABLE IF NOT EXISTS access_grant_entries (
  grant_id TEXT NOT NULL REFERENCES access_grants(grant_id) ON DELETE CASCADE,
  entry_id TEXT NOT NULL REFERENCES entries(entry_id) ON DELETE CASCADE,
  PRIMARY KEY(grant_id, entry_id)
);
-- A profile ranges over everything its creator can currently reach (own entries plus every live delegating
-- path from any owner), narrowed by the profile's own selector. No parent is stored: paths are resolved live.
CREATE TABLE IF NOT EXISTS machine_profiles (
  profile_id TEXT PRIMARY KEY,
  creator_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
  name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
  mode TEXT NOT NULL CHECK (mode IN ('all','allow','deny')),
  created_at INTEGER NOT NULL,
  revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS machine_profiles_creator ON machine_profiles(creator_id, created_at);
CREATE TABLE IF NOT EXISTS machine_profile_entries (
  profile_id TEXT NOT NULL REFERENCES machine_profiles(profile_id) ON DELETE CASCADE,
  entry_id TEXT NOT NULL REFERENCES entries(entry_id) ON DELETE CASCADE,
  PRIMARY KEY(profile_id, entry_id)
);
CREATE TABLE IF NOT EXISTS machine_tokens (
  token_id TEXT PRIMARY KEY,
  token_digest BLOB NOT NULL CHECK (length(token_digest) = 32),
  profile_id TEXT NOT NULL REFERENCES machine_profiles(profile_id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  -- NULL means the owner chose "never expires" (revocation still works).
  expires_at INTEGER CHECK (expires_at IS NULL OR expires_at > created_at),
  revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS machine_tokens_profile ON machine_tokens(profile_id);
-- Canonical read policy. Every read-only sharing predicate selects from this view instead of entry_shares.
-- One row per live path: a per-entry legacy share, or a grant expanded over the owner's current entries
-- (so all/deny grants cover entries created later). Paths overlap freely; revoking one leaves the others.
-- since = when that path's current continuous authority began (used to void older machine tokens).
CREATE VIEW IF NOT EXISTS entry_readers AS
  SELECT s.entry_id AS entry_id, s.recipient_id AS recipient_id, s.allow_automation AS allow_automation, s.created_at AS created_at, NULL AS revoked_at
    FROM entry_shares s WHERE s.revoked_at IS NULL
  UNION ALL
  SELECT e.entry_id, g.grantee_id, g.can_delegate, g.granted_at, NULL
    FROM access_grants g JOIN entries e ON e.owner_id = g.owner_id
   WHERE g.revoked_at IS NULL AND (g.mode = 'all'
     OR (g.mode = 'allow' AND EXISTS (SELECT 1 FROM access_grant_entries l WHERE l.grant_id = g.grant_id AND l.entry_id = e.entry_id))
     OR (g.mode = 'deny' AND NOT EXISTS (SELECT 1 FROM access_grant_entries l WHERE l.grant_id = g.grant_id AND l.entry_id = e.entry_id)));
-- Grant consistency hooks, mirroring the entry_shares triggers. Grant changes notify exactly the grantee and the
-- owner (content-free hint, deduplicated against unclaimed rows) and bump mutation_revision on the owner's entries
-- so a pending assignment cannot finish after its privacy assumption (no recipients) stopped holding.
CREATE TRIGGER realtime_grant_insert AFTER INSERT ON access_grants BEGIN
  INSERT INTO realtime_outbox(kind,account_id,created_at)
  SELECT 'account', a, CAST(strftime('%s','now') AS INTEGER)*1000 FROM (SELECT NEW.grantee_id AS a UNION SELECT NEW.owner_id) t
  WHERE NOT EXISTS (SELECT 1 FROM realtime_outbox o WHERE o.claimed_at IS NULL AND o.cursor IS NULL AND o.kind='account' AND o.account_id=t.a);
END;
CREATE TRIGGER realtime_grant_update AFTER UPDATE ON access_grants BEGIN
  INSERT INTO realtime_outbox(kind,account_id,created_at)
  SELECT 'account', a, CAST(strftime('%s','now') AS INTEGER)*1000 FROM (SELECT NEW.grantee_id AS a UNION SELECT NEW.owner_id) t
  WHERE NOT EXISTS (SELECT 1 FROM realtime_outbox o WHERE o.claimed_at IS NULL AND o.cursor IS NULL AND o.kind='account' AND o.account_id=t.a);
END;
CREATE TRIGGER realtime_grant_entry_insert AFTER INSERT ON access_grant_entries BEGIN
  INSERT INTO realtime_outbox(kind,account_id,created_at)
  SELECT 'account', a, CAST(strftime('%s','now') AS INTEGER)*1000 FROM (SELECT grantee_id AS a FROM access_grants WHERE grant_id=NEW.grant_id UNION SELECT owner_id FROM access_grants WHERE grant_id=NEW.grant_id) t
  WHERE NOT EXISTS (SELECT 1 FROM realtime_outbox o WHERE o.claimed_at IS NULL AND o.cursor IS NULL AND o.kind='account' AND o.account_id=t.a);
END;
CREATE TRIGGER realtime_grant_entry_delete AFTER DELETE ON access_grant_entries BEGIN
  INSERT INTO realtime_outbox(kind,account_id,created_at)
  SELECT 'account', a, CAST(strftime('%s','now') AS INTEGER)*1000 FROM (SELECT grantee_id AS a FROM access_grants WHERE grant_id=OLD.grant_id UNION SELECT owner_id FROM access_grants WHERE grant_id=OLD.grant_id) t
  WHERE NOT EXISTS (SELECT 1 FROM realtime_outbox o WHERE o.claimed_at IS NULL AND o.cursor IS NULL AND o.kind='account' AND o.account_id=t.a);
END;
-- A new entry under an all/deny grant becomes visible to that grantee: notify live grantees.
CREATE TRIGGER realtime_entry_grantees AFTER INSERT ON entries BEGIN
  INSERT INTO realtime_outbox(kind,account_id,created_at)
  SELECT 'account', g.grantee_id, CAST(strftime('%s','now') AS INTEGER)*1000 FROM access_grants g
  WHERE g.owner_id=NEW.owner_id AND g.revoked_at IS NULL AND g.mode<>'allow'
  AND NOT EXISTS (SELECT 1 FROM realtime_outbox o WHERE o.claimed_at IS NULL AND o.cursor IS NULL AND o.kind='account' AND o.account_id=g.grantee_id);
END;
CREATE TRIGGER grant_assignment_insert AFTER INSERT ON access_grants BEGIN
  UPDATE entries SET mutation_revision=mutation_revision+1 WHERE owner_id=NEW.owner_id;
END;
CREATE TRIGGER grant_assignment_update AFTER UPDATE ON access_grants BEGIN
  UPDATE entries SET mutation_revision=mutation_revision+1 WHERE owner_id=NEW.owner_id;
END;
CREATE TRIGGER grant_assignment_entries_insert AFTER INSERT ON access_grant_entries BEGIN
  UPDATE entries SET mutation_revision=mutation_revision+1 WHERE owner_id=(SELECT owner_id FROM access_grants WHERE grant_id=NEW.grant_id);
END;
CREATE TRIGGER grant_assignment_entries_delete AFTER DELETE ON access_grant_entries BEGIN
  UPDATE entries SET mutation_revision=mutation_revision+1 WHERE owner_id=(SELECT owner_id FROM access_grants WHERE grant_id=OLD.grant_id);
END;
-- Owner-generated invitation links. The owner fixes the terms (mode, list, delegation); a signed-in recipient
-- accepts and the grant is created from the stored terms in one atomic batch. Single use, bounded lifetime,
-- digest only. Nothing is granted by creating an invite.
CREATE TABLE IF NOT EXISTS access_invites (
  invite_id TEXT PRIMARY KEY,
  token_digest BLOB NOT NULL CHECK (length(token_digest) = 32),
  owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
  mode TEXT NOT NULL CHECK (mode IN ('all','allow','deny')),
  can_delegate INTEGER NOT NULL DEFAULT 0 CHECK (can_delegate IN (0,1)),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
  revoked_at INTEGER,
  accepted_by TEXT REFERENCES accounts(owner_id) ON DELETE CASCADE,
  accepted_at INTEGER,
  accept_nonce TEXT
);
CREATE INDEX IF NOT EXISTS access_invites_owner ON access_invites(owner_id, created_at);
CREATE TABLE IF NOT EXISTS access_invite_entries (
  invite_id TEXT NOT NULL REFERENCES access_invites(invite_id) ON DELETE CASCADE,
  entry_id TEXT NOT NULL REFERENCES entries(entry_id) ON DELETE CASCADE,
  PRIMARY KEY(invite_id, entry_id)
);
-- All-or-nothing guard for multi-statement batches. A batch inserts a row computed as 1 or 0; 0 violates the
-- CHECK, the whole batch rolls back (grant, list, triggers' outbox rows and revision bumps included). The
-- trigger clears the row so nothing accumulates when the assertion holds.
CREATE TABLE IF NOT EXISTS tx_assert (ok INTEGER NOT NULL CHECK (ok = 1));
CREATE TRIGGER IF NOT EXISTS tx_assert_clear AFTER INSERT ON tx_assert BEGIN DELETE FROM tx_assert; END;

-- Owner-private remembered recipients: written in the same batch that consumes an invite, so a completed
-- invite is the only way an account becomes a contact. Removing a contact never changes existing grants.
CREATE TABLE IF NOT EXISTS sharing_contacts (
  owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
  contact_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
  -- Opaque handle the owner's clients use. The recipient's internal account id is never sent to the owner.
  contact_ref TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL CHECK (created_at >= 0),
  -- Hidden from suggestions and from new shares. The row stays while a grant is live so it can still be revoked.
  removed_at INTEGER,
  PRIMARY KEY (owner_id, contact_id),
  CHECK (owner_id <> contact_id)
);
-- Cosmetic Google display name (bounded plain text, validated on write). Shown only to an owner who shared with
-- this account, never used for authority or matching. Refreshed on each Google sign-in like the picture.
ALTER TABLE provider_identities ADD COLUMN display_name TEXT;
-- Per-call causal marker for grant writes: the final assertion requires that THIS batch wrote the row.
ALTER TABLE access_grants ADD COLUMN write_nonce TEXT;
