-- Historical owners are preserved, even if aliases already collide. Only new
-- inserts/changes are blocked; no owner is merged and no email is rewritten.
CREATE TABLE account_mailbox_keys(owner_id TEXT PRIMARY KEY REFERENCES accounts(owner_id) ON DELETE CASCADE,mailbox_key TEXT NOT NULL);
CREATE INDEX account_mailbox_lookup ON account_mailbox_keys(mailbox_key);
INSERT INTO account_mailbox_keys SELECT owner_id,CASE WHEN substr(email,instr(email,'@')+1) IN ('gmail.com','googlemail.com') THEN replace(CASE WHEN instr(substr(email,1,instr(email,'@')-1),'+')>0 THEN substr(email,1,instr(email,'+')-1) ELSE substr(email,1,instr(email,'@')-1) END,'.','')||'@gmail.com' ELSE email END FROM account_emails;
CREATE TRIGGER account_mailbox_insert AFTER INSERT ON account_emails BEGIN
 INSERT INTO account_mailbox_keys SELECT NEW.owner_id,CASE WHEN substr(NEW.email,instr(NEW.email,'@')+1) IN ('gmail.com','googlemail.com') THEN replace(CASE WHEN instr(substr(NEW.email,1,instr(NEW.email,'@')-1),'+')>0 THEN substr(NEW.email,1,instr(NEW.email,'+')-1) ELSE substr(NEW.email,1,instr(NEW.email,'@')-1) END,'.','')||'@gmail.com' ELSE NEW.email END;
 SELECT RAISE(ABORT,'mailbox already assigned') WHERE EXISTS(SELECT 1 FROM account_mailbox_keys a JOIN account_mailbox_keys b ON a.mailbox_key=b.mailbox_key WHERE a.owner_id=NEW.owner_id AND b.owner_id<>NEW.owner_id);
END;
CREATE TRIGGER account_mailbox_update AFTER UPDATE OF email ON account_emails BEGIN
 UPDATE account_mailbox_keys SET mailbox_key=CASE WHEN substr(NEW.email,instr(NEW.email,'@')+1) IN ('gmail.com','googlemail.com') THEN replace(CASE WHEN instr(substr(NEW.email,1,instr(NEW.email,'@')-1),'+')>0 THEN substr(NEW.email,1,instr(NEW.email,'+')-1) ELSE substr(NEW.email,1,instr(NEW.email,'@')-1) END,'.','')||'@gmail.com' ELSE NEW.email END WHERE owner_id=NEW.owner_id;
 SELECT RAISE(ABORT,'mailbox already assigned') WHERE EXISTS(SELECT 1 FROM account_mailbox_keys a JOIN account_mailbox_keys b ON a.mailbox_key=b.mailbox_key WHERE a.owner_id=NEW.owner_id AND b.owner_id<>NEW.owner_id);
END;
CREATE TRIGGER account_mailbox_delete AFTER DELETE ON account_emails BEGIN DELETE FROM account_mailbox_keys WHERE owner_id=OLD.owner_id; END;
