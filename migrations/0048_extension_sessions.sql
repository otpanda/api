-- Extension sessions reuse the native exchange/key/challenge tables. A one-use code records which client kind it was minted for, so a code
-- minted for one kind can never be redeemed as another. Existing rows are native (android). Migration number is assigned by the integrator.
ALTER TABLE native_exchanges ADD COLUMN client_kind TEXT NOT NULL DEFAULT 'android' CHECK(client_kind IN ('android','extension'));
-- The web device that minted an extension code. The exchange re-checks it (active, same generation) in the same write that creates the device.
ALTER TABLE native_exchanges ADD COLUMN source_device_id TEXT;
