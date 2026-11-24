-- A retained negative receipt, never inferred from a missing/expired read.
ALTER TABLE assignment_intents ADD COLUMN retired_at INTEGER;
