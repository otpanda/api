-- Each viewer's extra website associations stay private, even on shared entries.
CREATE TABLE entry_domain_associations (
 viewer_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
 entry_id TEXT NOT NULL,
 domains_json TEXT NOT NULL,
 PRIMARY KEY(viewer_id,entry_id)
);
CREATE TRIGGER entry_domains_delete AFTER DELETE ON entries BEGIN
 DELETE FROM entry_domain_associations WHERE entry_id=OLD.entry_id;
END;
