-- Cosmetic Google profile picture URL (https googleusercontent.com only, validated on write and read). Never used for authority.
ALTER TABLE provider_identities ADD COLUMN picture TEXT;
