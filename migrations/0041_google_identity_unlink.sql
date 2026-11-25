-- Google sign-in unlink keeps the revoked identity row for audit. The subject uniqueness must
-- therefore apply to ACTIVE links only, or the same Google account could never be linked again.
DROP INDEX provider_identities_subject;
CREATE UNIQUE INDEX provider_identities_subject ON provider_identities(issuer,subject) WHERE revoked_at IS NULL;
