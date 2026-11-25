-- Passkey identification metadata in a side table (no change to passkey_credentials, so positional inserts elsewhere keep working).
-- aaguid: the authenticator's self-reported AAGUID at registration (lowercase uuid; all-zero is never stored). Display hint only, never attestation,
-- never used for authority. label: optional user-chosen name. Existing passkeys simply have no row.
CREATE TABLE passkey_metadata (
 credential_id TEXT PRIMARY KEY REFERENCES passkey_credentials(credential_id) ON DELETE CASCADE,
 owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
 aaguid TEXT CHECK (aaguid IS NULL OR (length(aaguid)=36 AND aaguid=lower(aaguid) AND aaguid<>'00000000-0000-0000-0000-000000000000')),
 label TEXT CHECK (label IS NULL OR length(label) BETWEEN 1 AND 40)
) WITHOUT ROWID;
CREATE INDEX passkey_metadata_owner ON passkey_metadata(owner_id);
