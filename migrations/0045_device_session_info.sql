-- Display-only description of a signed-in device, declared by the client itself (closed browser/OS families, optional native device name).
-- Never used for authority. Side table: device_sessions is untouched. A session without a row simply has no description.
CREATE TABLE device_session_info (
 device_id TEXT PRIMARY KEY REFERENCES device_sessions(device_id) ON DELETE CASCADE,
 owner_id TEXT NOT NULL REFERENCES accounts(owner_id) ON DELETE CASCADE,
 browser TEXT CHECK (browser IS NULL OR browser IN ('chrome','edge','firefox','safari','opera','samsung','other')),
 os TEXT CHECK (os IS NULL OR os IN ('android','windows','mac','ios','linux','chromeos','other')),
 name TEXT CHECK (name IS NULL OR length(name) BETWEEN 1 AND 60)
) WITHOUT ROWID;
CREATE INDEX device_session_info_owner ON device_session_info(owner_id);
