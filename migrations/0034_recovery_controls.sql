-- Opt-in delayed email-only escape hatch. Absent row means off (the default).
-- This table is only the setting. It grants no session, recovery or code
-- authority by itself, and nothing here starts or completes a recovery.
CREATE TABLE email_recovery_optin (
 owner_id TEXT PRIMARY KEY REFERENCES accounts(owner_id) ON DELETE CASCADE,
 enabled_at INTEGER NOT NULL,
 generation INTEGER NOT NULL,
 delay_ms INTEGER NOT NULL CHECK(delay_ms=604800000)
);
-- User-approved: this opt-in and "Require extra verification for Google on new
-- devices" never coexist. Neither setting changes the other silently; the
-- second one is refused until the first is turned off.
CREATE TRIGGER email_recovery_optin_exclusive BEFORE INSERT ON email_recovery_optin
WHEN EXISTS(SELECT 1 FROM new_device_verification v WHERE v.owner_id=NEW.owner_id)
BEGIN SELECT RAISE(ABORT,'exclusive settings'); END;
CREATE TRIGGER new_device_verification_exclusive BEFORE INSERT ON new_device_verification
WHEN EXISTS(SELECT 1 FROM email_recovery_optin o WHERE o.owner_id=NEW.owner_id)
BEGIN SELECT RAISE(ABORT,'exclusive settings'); END;
