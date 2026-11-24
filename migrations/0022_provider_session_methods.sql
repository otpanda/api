-- Session authentication methods: a device session now proves either a passkey
-- credential or a linked provider identity (Google). Populated databases keep
-- every session, handle, PKCE exchange, assignment intent and receipt.
-- SQLite cannot relax NOT NULL in place, and dropping device_sessions while
-- children exist would cascade-delete them. So children are copied aside,
-- dropped child-first, the parent is rebuilt, and everything is restored.
CREATE TABLE provider_identities (
 identity_id TEXT PRIMARY KEY,
 owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
 provider TEXT NOT NULL CHECK(provider IN ('google')),
 issuer TEXT NOT NULL,
 subject TEXT NOT NULL,
 email TEXT NOT NULL COLLATE BINARY,
 created_at INTEGER NOT NULL,
 revoked_at INTEGER
);
CREATE UNIQUE INDEX provider_identities_subject ON provider_identities(issuer,subject);
CREATE INDEX provider_identities_owner ON provider_identities(owner_id);

CREATE TABLE _bak_device_sessions AS SELECT * FROM device_sessions;
CREATE TABLE _bak_device_refresh_handles AS SELECT * FROM device_refresh_handles;
CREATE TABLE _bak_device_access_handles AS SELECT * FROM device_access_handles;
CREATE TABLE _bak_browser_exchanges AS SELECT * FROM browser_exchanges;
CREATE TABLE _bak_assignment_intents AS SELECT * FROM assignment_intents;
CREATE TABLE _bak_assignment_receipts AS SELECT * FROM assignment_receipts;

DROP TABLE assignment_receipts;
DROP TABLE assignment_intents;
DROP TABLE browser_exchanges;
DROP TABLE device_access_handles;
DROP TABLE device_refresh_handles;
DROP TABLE device_sessions;

CREATE TABLE device_sessions (
  device_id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
  credential_id TEXT REFERENCES passkey_credentials(credential_id) ON DELETE CASCADE,
  provider_identity_id TEXT REFERENCES provider_identities(identity_id) ON DELETE CASCADE,
  generation INTEGER NOT NULL,
  client_kind TEXT NOT NULL CHECK (client_kind IN ('web', 'android', 'extension')),
  created_at INTEGER NOT NULL,
  last_used_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER,
  browser_binding_digest TEXT,
  CHECK ((credential_id IS NULL) <> (provider_identity_id IS NULL))
);
CREATE INDEX device_sessions_owner ON device_sessions(owner_id);
CREATE INDEX device_sessions_binding ON device_sessions(browser_binding_digest);
CREATE TABLE device_refresh_handles (
  handle_id TEXT PRIMARY KEY,
  secret_digest TEXT NOT NULL CHECK (length(secret_digest) = 64),
  device_id TEXT NOT NULL REFERENCES device_sessions(device_id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  used_at INTEGER
);
CREATE INDEX device_handles_device ON device_refresh_handles(device_id);
CREATE TABLE device_access_handles (
  handle_id TEXT PRIMARY KEY,
  secret_digest TEXT NOT NULL CHECK (length(secret_digest) = 64),
  device_id TEXT NOT NULL REFERENCES device_sessions(device_id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX device_access_expiry ON device_access_handles(expires_at);
CREATE INDEX device_access_device_expiry ON device_access_handles(device_id,expires_at);
CREATE TABLE browser_exchanges (
  exchange_id TEXT PRIMARY KEY,
  secret_digest TEXT NOT NULL CHECK(length(secret_digest)=64),
  device_id TEXT NOT NULL REFERENCES device_sessions(device_id) ON DELETE CASCADE,
  challenge TEXT NOT NULL CHECK(length(challenge)=43),
  redirect_uri TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX browser_exchanges_expiry ON browser_exchanges(expires_at);
CREATE INDEX browser_exchanges_device_expiry ON browser_exchanges(device_id,expires_at);
CREATE TABLE assignment_intents (
 intent_id TEXT PRIMARY KEY,
 owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
 device_id TEXT NOT NULL REFERENCES device_sessions(device_id) ON DELETE CASCADE,
 generation INTEGER NOT NULL,
 source_id TEXT NOT NULL,
 event_id TEXT NOT NULL,
 entry_id TEXT NOT NULL,
 entry_revision INTEGER NOT NULL,
 envelope TEXT NOT NULL CHECK(json_valid(envelope)),
 received_at INTEGER NOT NULL,
 code_expires_at INTEGER NOT NULL,
 action_digest TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 consumed_at INTEGER,
 result_expires_at INTEGER NOT NULL,
 retired_at INTEGER
);
CREATE INDEX assignment_intents_owner ON assignment_intents(owner_id,expires_at);
CREATE INDEX assignment_intents_cleanup ON assignment_intents(result_expires_at);
CREATE TABLE assignment_receipts (
 intent_id TEXT PRIMARY KEY REFERENCES assignment_intents(intent_id) ON DELETE CASCADE,
 assignment_changes INTEGER NOT NULL CHECK(assignment_changes=1)
);

INSERT INTO device_sessions(device_id,owner_id,credential_id,provider_identity_id,generation,client_kind,created_at,last_used_at,expires_at,revoked_at,browser_binding_digest)
 SELECT device_id,owner_id,credential_id,NULL,generation,client_kind,created_at,last_used_at,expires_at,revoked_at,browser_binding_digest FROM _bak_device_sessions;
INSERT INTO device_refresh_handles(handle_id,secret_digest,device_id,created_at,used_at) SELECT handle_id,secret_digest,device_id,created_at,used_at FROM _bak_device_refresh_handles;
INSERT INTO device_access_handles(handle_id,secret_digest,device_id,created_at,expires_at) SELECT handle_id,secret_digest,device_id,created_at,expires_at FROM _bak_device_access_handles;
INSERT INTO browser_exchanges(exchange_id,secret_digest,device_id,challenge,redirect_uri,created_at,expires_at) SELECT exchange_id,secret_digest,device_id,challenge,redirect_uri,created_at,expires_at FROM _bak_browser_exchanges;
INSERT INTO assignment_intents(intent_id,owner_id,device_id,generation,source_id,event_id,entry_id,entry_revision,envelope,received_at,code_expires_at,action_digest,created_at,expires_at,consumed_at,result_expires_at,retired_at)
 SELECT intent_id,owner_id,device_id,generation,source_id,event_id,entry_id,entry_revision,envelope,received_at,code_expires_at,action_digest,created_at,expires_at,consumed_at,result_expires_at,retired_at FROM _bak_assignment_intents;
INSERT INTO assignment_receipts(intent_id,assignment_changes) SELECT intent_id,assignment_changes FROM _bak_assignment_receipts;

DROP TABLE _bak_assignment_receipts;
DROP TABLE _bak_assignment_intents;
DROP TABLE _bak_browser_exchanges;
DROP TABLE _bak_device_access_handles;
DROP TABLE _bak_device_refresh_handles;
DROP TABLE _bak_device_sessions;
