-- Temporary browser-login cancellation, no raw browser binding stored.
ALTER TABLE device_sessions ADD COLUMN browser_binding_digest TEXT;
CREATE INDEX device_sessions_binding ON device_sessions(browser_binding_digest);
CREATE TABLE browser_logout_bindings (
 binding_digest TEXT PRIMARY KEY,
 expires_at INTEGER NOT NULL
);
CREATE INDEX browser_logout_bindings_expiry ON browser_logout_bindings(expires_at);
