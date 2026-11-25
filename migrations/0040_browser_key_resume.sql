-- Resume renewal without an expired bearer. The lineage records its newest (head) access handle id and
-- when it last renewed. A tab that was away past the 5-minute access life proves itself with a fresh
-- signature from its memory-only key over the head id; the head moves once (compare-and-set), so a
-- bearer renewal and a resume renewal cannot both win. Nothing about an expired access handle is accepted
-- or retained longer. A lineage ends with its device session (cascade) or 30 days after its last renewal.
ALTER TABLE access_lineages ADD COLUMN head_handle_id TEXT;
ALTER TABLE access_lineages ADD COLUMN last_renewed_at INTEGER;
UPDATE access_lineages SET head_handle_id=(SELECT a.handle_id FROM device_access_handles a WHERE a.lineage_id=access_lineages.lineage_id AND a.renewed_at IS NULL ORDER BY a.created_at DESC LIMIT 1);
