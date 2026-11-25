-- Owner-asserted client-catalogue identity for an entry (the public catalogue's domain ID). It is create-only, untrusted display/eligibility metadata:
-- never joined to services, service_routes, website_host or icon_key, never used for sender recognition or code routing. Migration number 0049 is
-- reserved by primary.
ALTER TABLE entries ADD COLUMN catalog_id TEXT CHECK(catalog_id IS NULL OR (length(catalog_id) BETWEEN 1 AND 128 AND catalog_id GLOB '[a-z0-9]*' AND catalog_id NOT GLOB '*[^a-z0-9._-]*'));
