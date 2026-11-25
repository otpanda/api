-- Content-free real-time invalidation. The outbox holds no code, entry label, sender or recipient list:
-- only who to notify (or which scope to resolve recipients for at delivery time) and when.
-- Rows are written by triggers inside the same transaction as the change they describe, so a row
-- exists if and only if the change committed (including FK cascades and batch rollbacks).
CREATE TABLE realtime_outbox (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL CHECK (kind IN ('account','entry','accounts','device','revoke')),
  account_id TEXT NOT NULL,
  scope_id TEXT,
  device_id TEXT,
  payload TEXT,
  cursor TEXT,
  claimed_at INTEGER,
  claim_id TEXT,
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_attempt_at INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  CHECK (kind <> 'entry' OR scope_id IS NOT NULL),
  CHECK (kind <> 'device' OR device_id IS NOT NULL),
  -- A snapshot is a packed list of at most 100 former recipients: no LIMIT, no truncation, N/100 rows.
  CHECK (kind <> 'accounts' OR (payload IS NOT NULL AND json_valid(payload) AND json_type(payload)='array' AND json_array_length(payload) BETWEEN 1 AND 100)),
  CHECK ((claimed_at IS NULL) = (claim_id IS NULL))
);
CREATE INDEX realtime_outbox_created ON realtime_outbox(created_at);
-- Eligibility and fairness: due rows first, oldest due first; a failing row moves behind everything else by its backoff.
CREATE INDEX realtime_outbox_due ON realtime_outbox(next_attempt_at, seq);
CREATE INDEX realtime_outbox_pending ON realtime_outbox(kind, account_id, scope_id) WHERE claimed_at IS NULL;

-- One-use WebSocket tickets. The raw secret is never stored. A ticket is bound to one device and
-- security generation and cannot outlive the access handle it was minted from (close_at).
CREATE TABLE realtime_tickets (
  ticket_id TEXT PRIMARY KEY,
  secret_digest TEXT NOT NULL CHECK (length(secret_digest) = 64),
  owner_id TEXT NOT NULL,
  device_id TEXT NOT NULL REFERENCES device_sessions(device_id) ON DELETE CASCADE,
  generation INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
  close_at INTEGER NOT NULL CHECK (close_at > created_at)
);
CREATE INDEX realtime_tickets_device ON realtime_tickets(device_id, expires_at);
CREATE INDEX realtime_tickets_expiry ON realtime_tickets(expires_at);

-- Which accounts could hold an open socket: a ticket is minted before every socket, and a socket never outlives
-- its access handle (5 min). Hints for an account with no ticket in the last 6 min cannot reach a socket, so
-- delivery skips the DO call. Safe against the connect race: a client always refetches a snapshot AFTER connecting.
CREATE TABLE realtime_activity (
  account_id TEXT PRIMARY KEY,
  last_ticket_at INTEGER NOT NULL
);
CREATE INDEX realtime_activity_seen ON realtime_activity(last_ticket_at);
CREATE TRIGGER realtime_ticket_activity AFTER INSERT ON realtime_tickets BEGIN
  INSERT INTO realtime_activity(account_id,last_ticket_at) VALUES (NEW.owner_id,NEW.created_at)
  ON CONFLICT(account_id) DO UPDATE SET last_ticket_at=max(last_ticket_at,excluded.last_ticket_at);
END;

-- Coalescing: a new identical hint joins a pending row only while that row is unclaimed and unstarted (no cursor). Delivery
-- claims a row BEFORE resolving recipients, so a write that commits after the claim gets its own row.
CREATE TRIGGER realtime_codes_insert AFTER INSERT ON incoming_codes BEGIN
  INSERT INTO realtime_outbox(kind,account_id,scope_id,created_at)
  SELECT CASE WHEN NEW.entry_id IS NULL THEN 'account' ELSE 'entry' END, NEW.owner_id, NEW.entry_id, CAST(strftime('%s','now') AS INTEGER)*1000
  WHERE NOT EXISTS (SELECT 1 FROM realtime_outbox WHERE claimed_at IS NULL AND cursor IS NULL AND kind=CASE WHEN NEW.entry_id IS NULL THEN 'account' ELSE 'entry' END AND account_id=NEW.owner_id AND scope_id IS NEW.entry_id);
END;
CREATE TRIGGER realtime_codes_assign AFTER UPDATE OF entry_id ON incoming_codes WHEN OLD.entry_id IS NOT NEW.entry_id BEGIN
  INSERT INTO realtime_outbox(kind,account_id,scope_id,created_at)
  SELECT CASE WHEN NEW.entry_id IS NULL THEN 'account' ELSE 'entry' END, NEW.owner_id, NEW.entry_id, CAST(strftime('%s','now') AS INTEGER)*1000
  WHERE NOT EXISTS (SELECT 1 FROM realtime_outbox WHERE claimed_at IS NULL AND cursor IS NULL AND kind=CASE WHEN NEW.entry_id IS NULL THEN 'account' ELSE 'entry' END AND account_id=NEW.owner_id AND scope_id IS NEW.entry_id);
  INSERT INTO realtime_outbox(kind,account_id,scope_id,created_at)
  SELECT 'entry', OLD.owner_id, OLD.entry_id, CAST(strftime('%s','now') AS INTEGER)*1000
  WHERE OLD.entry_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM realtime_outbox WHERE claimed_at IS NULL AND cursor IS NULL AND kind='entry' AND account_id=OLD.owner_id AND scope_id=OLD.entry_id);
END;
-- Deleting a code that was still live (expiry cleanup is not a visible change) hides it for its viewers.
CREATE TRIGGER realtime_codes_delete AFTER DELETE ON incoming_codes WHEN OLD.expires_at > CAST(strftime('%s','now') AS INTEGER)*1000 BEGIN
  INSERT INTO realtime_outbox(kind,account_id,scope_id,created_at)
  SELECT CASE WHEN OLD.entry_id IS NULL THEN 'account' ELSE 'entry' END, OLD.owner_id, OLD.entry_id, CAST(strftime('%s','now') AS INTEGER)*1000
  WHERE NOT EXISTS (SELECT 1 FROM realtime_outbox WHERE claimed_at IS NULL AND cursor IS NULL AND kind=CASE WHEN OLD.entry_id IS NULL THEN 'account' ELSE 'entry' END AND account_id=OLD.owner_id AND scope_id IS OLD.entry_id);
END;
-- Share changes notify exactly the affected recipient (including one just revoked, so its view drops the entry) and the owner.
CREATE TRIGGER realtime_share_insert AFTER INSERT ON entry_shares BEGIN
  INSERT INTO realtime_outbox(kind,account_id,created_at)
  SELECT 'account', a, CAST(strftime('%s','now') AS INTEGER)*1000 FROM (SELECT NEW.recipient_id AS a UNION SELECT owner_id FROM entries WHERE entry_id=NEW.entry_id) t
  WHERE NOT EXISTS (SELECT 1 FROM realtime_outbox o WHERE o.claimed_at IS NULL AND o.cursor IS NULL AND o.kind='account' AND o.account_id=t.a);
END;
CREATE TRIGGER realtime_share_update AFTER UPDATE OF revoked_at, allow_automation ON entry_shares BEGIN
  INSERT INTO realtime_outbox(kind,account_id,created_at)
  SELECT 'account', a, CAST(strftime('%s','now') AS INTEGER)*1000 FROM (SELECT NEW.recipient_id AS a UNION SELECT owner_id FROM entries WHERE entry_id=NEW.entry_id) t
  WHERE NOT EXISTS (SELECT 1 FROM realtime_outbox o WHERE o.claimed_at IS NULL AND o.cursor IS NULL AND o.kind='account' AND o.account_id=t.a);
END;
CREATE TRIGGER realtime_entry_insert AFTER INSERT ON entries BEGIN
  INSERT INTO realtime_outbox(kind,account_id,created_at)
  SELECT 'account', NEW.owner_id, CAST(strftime('%s','now') AS INTEGER)*1000 
  WHERE NOT EXISTS (SELECT 1 FROM realtime_outbox WHERE claimed_at IS NULL AND cursor IS NULL AND kind='account' AND account_id=NEW.owner_id);
END;
CREATE TRIGGER realtime_entry_update AFTER UPDATE OF label, account_name, service_id ON entries BEGIN
  INSERT INTO realtime_outbox(kind,account_id,scope_id,created_at)
  SELECT 'entry', NEW.owner_id, NEW.entry_id, CAST(strftime('%s','now') AS INTEGER)*1000
  WHERE NOT EXISTS (SELECT 1 FROM realtime_outbox WHERE claimed_at IS NULL AND cursor IS NULL AND kind='entry' AND account_id=NEW.owner_id AND scope_id IS NEW.entry_id);
END;
-- The cascade removes entry_shares, so former recipients are captured BEFORE the delete: packed 100 per row
-- (one INSERT...SELECT, no LIMIT, nothing dropped). Cost is still O(recipients) inside the delete statement.
CREATE TRIGGER realtime_entry_delete BEFORE DELETE ON entries BEGIN
  INSERT INTO realtime_outbox(kind,account_id,created_at)
  SELECT 'account', OLD.owner_id, CAST(strftime('%s','now') AS INTEGER)*1000 
  WHERE NOT EXISTS (SELECT 1 FROM realtime_outbox WHERE claimed_at IS NULL AND cursor IS NULL AND kind='account' AND account_id=OLD.owner_id);
  INSERT INTO realtime_outbox(kind,account_id,payload,created_at)
  SELECT 'accounts', OLD.owner_id, json_group_array(r), CAST(strftime('%s','now') AS INTEGER)*1000
  FROM (SELECT r, (row_number() OVER (ORDER BY r)-1)/100 AS g FROM (SELECT DISTINCT recipient_id AS r FROM entry_shares WHERE entry_id=OLD.entry_id AND revoked_at IS NULL AND recipient_id<>OLD.owner_id)) GROUP BY g;
END;
CREATE TRIGGER realtime_source_insert AFTER INSERT ON sources BEGIN
  INSERT INTO realtime_outbox(kind,account_id,created_at)
  SELECT 'account', NEW.owner_id, CAST(strftime('%s','now') AS INTEGER)*1000 
  WHERE NOT EXISTS (SELECT 1 FROM realtime_outbox WHERE claimed_at IS NULL AND cursor IS NULL AND kind='account' AND account_id=NEW.owner_id);
END;
-- Revoking a source hides its codes from every recipient of an entry those codes were assigned to. Their ids are captured
-- now, so the hint never depends on incoming_codes still existing at delivery time.
CREATE TRIGGER realtime_source_revoke AFTER UPDATE OF revoked_at ON sources WHEN OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL BEGIN
  INSERT INTO realtime_outbox(kind,account_id,created_at)
  SELECT 'account', NEW.owner_id, CAST(strftime('%s','now') AS INTEGER)*1000 
  WHERE NOT EXISTS (SELECT 1 FROM realtime_outbox WHERE claimed_at IS NULL AND cursor IS NULL AND kind='account' AND account_id=NEW.owner_id);
  INSERT INTO realtime_outbox(kind,account_id,payload,created_at)
  SELECT 'accounts', NEW.owner_id, json_group_array(r), CAST(strftime('%s','now') AS INTEGER)*1000
  FROM (SELECT r, (row_number() OVER (ORDER BY r)-1)/100 AS g FROM (SELECT DISTINCT m.recipient_id AS r FROM incoming_codes c JOIN entry_shares m ON m.entry_id=c.entry_id AND m.revoked_at IS NULL WHERE c.owner_id=NEW.owner_id AND c.source_id=NEW.source_id AND c.entry_id IS NOT NULL AND m.recipient_id<>NEW.owner_id)) GROUP BY g;
END;
CREATE TRIGGER realtime_device_revoke AFTER UPDATE OF revoked_at ON device_sessions WHEN OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL BEGIN
  INSERT INTO realtime_outbox(kind,account_id,device_id,created_at)
  SELECT 'device', NEW.owner_id, NEW.device_id, CAST(strftime('%s','now') AS INTEGER)*1000
  WHERE NOT EXISTS (SELECT 1 FROM realtime_outbox WHERE claimed_at IS NULL AND cursor IS NULL AND kind='device' AND account_id=NEW.owner_id AND device_id=NEW.device_id);
END;
-- A security generation bump (recovery) invalidates every device of the account at once: close all its sockets.
CREATE TRIGGER realtime_generation_bump AFTER UPDATE OF generation ON account_security WHEN NEW.generation<>OLD.generation BEGIN
  INSERT INTO realtime_outbox(kind,account_id,created_at)
  SELECT 'revoke', NEW.owner_id, CAST(strftime('%s','now') AS INTEGER)*1000
  WHERE NOT EXISTS (SELECT 1 FROM realtime_outbox WHERE claimed_at IS NULL AND cursor IS NULL AND kind='revoke' AND account_id=NEW.owner_id);
END;
CREATE TRIGGER realtime_org_insert AFTER INSERT ON personal_organization BEGIN
  INSERT INTO realtime_outbox(kind,account_id,created_at)
  SELECT 'account', NEW.viewer_id, CAST(strftime('%s','now') AS INTEGER)*1000 
  WHERE NOT EXISTS (SELECT 1 FROM realtime_outbox WHERE claimed_at IS NULL AND cursor IS NULL AND kind='account' AND account_id=NEW.viewer_id);
END;
CREATE TRIGGER realtime_org_update AFTER UPDATE OF document ON personal_organization BEGIN
  INSERT INTO realtime_outbox(kind,account_id,created_at)
  SELECT 'account', NEW.viewer_id, CAST(strftime('%s','now') AS INTEGER)*1000 
  WHERE NOT EXISTS (SELECT 1 FROM realtime_outbox WHERE claimed_at IS NULL AND cursor IS NULL AND kind='account' AND account_id=NEW.viewer_id);
END;
