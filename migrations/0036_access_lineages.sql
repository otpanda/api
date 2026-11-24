-- Silent access renewal. A lineage is one in-memory P-256 public key, bound ONLY
-- inside the one-use PKCE exchange claim. It is not a refresh credential, never
-- replaces another tab's key and holds no secret. Access handles carry the lineage
-- they were issued under; a renewal spends exactly one handle.
CREATE TABLE access_lineages (
 lineage_id TEXT PRIMARY KEY,
 device_id TEXT NOT NULL REFERENCES device_sessions(device_id) ON DELETE CASCADE,
 public_key TEXT NOT NULL CHECK(length(public_key)=87),
 created_at INTEGER NOT NULL
);
CREATE INDEX access_lineages_device ON access_lineages(device_id,created_at);
ALTER TABLE device_access_handles ADD COLUMN lineage_id TEXT REFERENCES access_lineages(lineage_id) ON DELETE CASCADE;
ALTER TABLE device_access_handles ADD COLUMN renewed_at INTEGER;
ALTER TABLE device_access_handles ADD COLUMN renew_receipt TEXT;
CREATE INDEX device_access_lineage ON device_access_handles(lineage_id) WHERE lineage_id IS NOT NULL;
