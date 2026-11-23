-- Composite indexes keep per-device safety checks bounded by one device.
CREATE INDEX IF NOT EXISTS device_access_device_expiry ON device_access_handles(device_id,expires_at);
CREATE INDEX IF NOT EXISTS browser_exchanges_device_expiry ON browser_exchanges(device_id,expires_at);
