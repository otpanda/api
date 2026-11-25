-- Single-use launch ticket for linking Google to an already signed-in account. Only a digest is stored.
-- Bound to the owner, device session and security generation that asked; consumed by one top-level GET.
CREATE TABLE google_link_tickets(ticket_digest TEXT PRIMARY KEY,owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,device_id TEXT NOT NULL,generation INTEGER NOT NULL,app_state TEXT NOT NULL,created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL);
CREATE INDEX google_link_ticket_expiry ON google_link_tickets(expires_at);
