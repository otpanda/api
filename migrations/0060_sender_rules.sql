-- Durable exact-sender assignment rules created by a signed Assign. NUMBERING: 0060 is deliberately clear of the offline v4.11 candidate (0052-0054); renumber at integration.
-- phrase: optional case-insensitive "contains" over the SMS text or email subject+body, stored lowercase, evaluated at ingest, message text is never stored.
ALTER TABLE service_routes ADD COLUMN phrase TEXT CHECK (phrase IS NULL OR length(phrase) BETWEEN 1 AND 120);
ALTER TABLE service_routes ADD COLUMN created_at INTEGER;
-- template_fp: versioned keyed digest ('v1:'+64 hex) of the code-redacted, digit-free message template. Never the text. Exclusive with phrase in rules created by Assign.
ALTER TABLE service_routes ADD COLUMN template_fp TEXT CHECK (template_fp IS NULL OR (length(template_fp)=67 AND template_fp LIKE 'v1:%'));
-- saved_template_fp: when the owner switches a template rule to a phrase, the original digest is kept privately here so switching back restores it (never matched, never listed).
ALTER TABLE service_routes ADD COLUMN saved_template_fp TEXT CHECK (saved_template_fp IS NULL OR (length(saved_template_fp)=67 AND saved_template_fp LIKE 'v1:%'));
-- NULL-safe uniqueness enforced by the database. Existing duplicates are removed first (the oldest row of each group stays).
DELETE FROM service_routes WHERE rowid NOT IN (SELECT min(rowid) FROM service_routes GROUP BY owner_id,service_id,source_id,origin_kind,origin_value,COALESCE(entry_id,''),COALESCE(account_hint,''),COALESCE(phrase,''),COALESCE(template_fp,''));
CREATE UNIQUE INDEX service_routes_unique ON service_routes(owner_id,service_id,source_id,origin_kind,origin_value,COALESCE(entry_id,''),COALESCE(account_hint,''),COALESCE(phrase,''),COALESCE(template_fp,''));
-- Sender and mailbox hint of an incoming code, encrypted with the code cipher, kept only with the code row (24h max).
ALTER TABLE incoming_codes ADD COLUMN sender_envelope TEXT CHECK (sender_envelope IS NULL OR json_valid(sender_envelope));
-- Outcome of the rule that was part of the signed Assign, written in the same batch so status and replay can report it.
-- Same keyed digest of the arriving message's template, kept with the code row only (24h max).
ALTER TABLE incoming_codes ADD COLUMN template_fp TEXT CHECK (template_fp IS NULL OR (length(template_fp)=67 AND template_fp LIKE 'v1:%'));
ALTER TABLE assignment_intents ADD COLUMN rule_json TEXT;
ALTER TABLE assignment_intents ADD COLUMN rule_result TEXT CHECK (rule_result IS NULL OR rule_result IN ('saved','exists','paused','unavailable'));
-- Content-free invalidation for rule changes (same dedupe as the other account triggers).
CREATE TRIGGER realtime_routes_insert AFTER INSERT ON service_routes BEGIN
  INSERT INTO realtime_outbox(kind,account_id,created_at)
  SELECT 'account', NEW.owner_id, CAST(strftime('%s','now') AS INTEGER)*1000
  WHERE NOT EXISTS (SELECT 1 FROM realtime_outbox WHERE claimed_at IS NULL AND cursor IS NULL AND kind='account' AND account_id=NEW.owner_id);
END;
CREATE TRIGGER realtime_routes_update AFTER UPDATE OF phrase,template_fp ON service_routes BEGIN
  INSERT INTO realtime_outbox(kind,account_id,created_at)
  SELECT 'account', NEW.owner_id, CAST(strftime('%s','now') AS INTEGER)*1000
  WHERE NOT EXISTS (SELECT 1 FROM realtime_outbox WHERE claimed_at IS NULL AND cursor IS NULL AND kind='account' AND account_id=NEW.owner_id);
END;
CREATE TRIGGER realtime_routes_delete AFTER DELETE ON service_routes BEGIN
  INSERT INTO realtime_outbox(kind,account_id,created_at)
  SELECT 'account', OLD.owner_id, CAST(strftime('%s','now') AS INTEGER)*1000
  WHERE NOT EXISTS (SELECT 1 FROM realtime_outbox WHERE claimed_at IS NULL AND cursor IS NULL AND kind='account' AND account_id=OLD.owner_id);
END;

-- Review row remembers the keyed template digest of its latest message, so a rule for one template never removes the review of a different template from the same sender.
ALTER TABLE unassigned_context ADD COLUMN template_fp TEXT CHECK (template_fp IS NULL OR (length(template_fp)=67 AND template_fp LIKE 'v1:%'));
-- Encrypted receiving-address hint of the latest message (same envelope rules as sender_envelope), so a rule created from a review row keeps the same hint scope as a rule created by Assign.
ALTER TABLE unassigned_context ADD COLUMN hint_envelope TEXT CHECK (hint_envelope IS NULL OR json_valid(hint_envelope));
