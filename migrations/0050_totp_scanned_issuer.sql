-- Scanned issuer: the issuer parsed by the server from a validated otpauth:// URI at creation, kept separate from the editable label
-- (display name). Create-only (no UPDATE path), nullable; legacy rows and manually typed keys stay NULL, never backfilled or guessed.
-- Display data only: never joined to services, service_routes, website_host, icon_key, sender recognition or any trust decision.
ALTER TABLE entries ADD COLUMN issuer TEXT CHECK(issuer IS NULL OR (length(issuer) BETWEEN 1 AND 254 AND issuer=trim(issuer)));
