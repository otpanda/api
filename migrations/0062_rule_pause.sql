-- Entryless legacy routes are ambiguity fences, not user-managed rules. Preserve them across reconnect.
-- Rule lifecycle on disconnect/reconnect. paused_at non-NULL = the rule is kept but never matches, never lists as active and cannot be edited until the owner signs an explicit resume.
ALTER TABLE service_routes ADD COLUMN paused_at INTEGER;
-- Invariant in the database, so EVERY path that revokes or un-revokes a source (Gmail connect/disconnect, generic revoke, account wipe, operator) pauses its rules and drops its latest-message previews.
-- Previews are never resurrected: a stale preview is deleted when the source goes away and again when it comes back.
CREATE TRIGGER sources_pause_rules_on_revoke AFTER UPDATE OF revoked_at ON sources WHEN OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL BEGIN
  UPDATE service_routes SET paused_at=COALESCE(paused_at,NEW.revoked_at) WHERE owner_id=NEW.owner_id AND source_id=NEW.source_id AND entry_id IS NOT NULL;
  DELETE FROM unassigned_context WHERE owner_id=NEW.owner_id AND source_id=NEW.source_id;
END;
CREATE TRIGGER sources_pause_rules_on_unrevoke AFTER UPDATE OF revoked_at ON sources WHEN OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NULL BEGIN
  UPDATE service_routes SET paused_at=COALESCE(paused_at,OLD.revoked_at) WHERE owner_id=NEW.owner_id AND source_id=NEW.source_id AND entry_id IS NOT NULL;
  DELETE FROM unassigned_context WHERE owner_id=NEW.owner_id AND source_id=NEW.source_id;
END;
-- Rules of sources that are already revoked when this migration runs stay paused after a later reconnect.
UPDATE service_routes SET paused_at=(SELECT s.revoked_at FROM sources s WHERE s.owner_id=service_routes.owner_id AND s.source_id=service_routes.source_id) WHERE entry_id IS NOT NULL AND paused_at IS NULL AND EXISTS (SELECT 1 FROM sources s WHERE s.owner_id=service_routes.owner_id AND s.source_id=service_routes.source_id AND s.revoked_at IS NOT NULL);
DELETE FROM unassigned_context WHERE EXISTS (SELECT 1 FROM sources s WHERE s.owner_id=unassigned_context.owner_id AND s.source_id=unassigned_context.source_id AND s.revoked_at IS NOT NULL);
