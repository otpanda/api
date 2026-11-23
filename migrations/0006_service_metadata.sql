CREATE TABLE IF NOT EXISTS services (
  service_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  website_host TEXT,
  icon_key TEXT
);
ALTER TABLE entries ADD COLUMN account_name TEXT;
ALTER TABLE sources ADD COLUMN receiver TEXT;
-- A service route names the receiving source and the code's origin. Account
-- hints are optional, but a route may only auto-assign if exactly one entry is
-- selected and no other service/entry matches the event.
CREATE TABLE IF NOT EXISTS service_routes (
  route_id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  service_id TEXT NOT NULL REFERENCES services(service_id),
  source_id TEXT NOT NULL,
  origin_kind TEXT NOT NULL CHECK (origin_kind IN ('email_address','email_domain','sms_number')),
  origin_value TEXT NOT NULL,
  entry_id TEXT,
  account_hint TEXT,
  FOREIGN KEY(owner_id,source_id) REFERENCES sources(owner_id,source_id) ON DELETE CASCADE,
  FOREIGN KEY(owner_id,entry_id) REFERENCES entries(owner_id,entry_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS routes_source ON service_routes(owner_id,source_id);
