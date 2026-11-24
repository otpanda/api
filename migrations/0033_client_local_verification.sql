-- Existing browser-session-only approvals are not fresh local proof.
-- Default NULL invalidates old approvals without changing sign-in credentials.
ALTER TABLE pending_logins ADD COLUMN local_verified_at INTEGER;
ALTER TABLE setting_changes ADD COLUMN local_verified_at INTEGER;
