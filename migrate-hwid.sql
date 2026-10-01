-- One-time: device binding for license sharing prevention.
ALTER TABLE keys ADD COLUMN IF NOT EXISTS bound_hwid TEXT;
