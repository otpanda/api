CREATE TABLE human_email_codes(code_id TEXT PRIMARY KEY,purpose TEXT NOT NULL,binding_digest TEXT NOT NULL,code_digest TEXT NOT NULL,proof_id TEXT,created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,attempts INTEGER NOT NULL DEFAULT 0);
CREATE UNIQUE INDEX human_email_lookup ON human_email_codes(purpose,binding_digest);
