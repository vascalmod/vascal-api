-- Reseller system migration. Idempotent: safe to re-run.
CREATE TABLE IF NOT EXISTS resellers (
    id                  BIGSERIAL PRIMARY KEY,
    username            TEXT NOT NULL UNIQUE,
    password_hash       TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
    plan                TEXT NOT NULL DEFAULT 'standard',
    max_keys            INT NOT NULL DEFAULT 100,
    max_devices_per_key INT NOT NULL DEFAULT 5,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at       TIMESTAMPTZ
);
ALTER TABLE keys ADD COLUMN IF NOT EXISTS reseller_id BIGINT REFERENCES resellers(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS keys_reseller_idx ON keys (reseller_id);
CREATE TABLE IF NOT EXISTS reseller_sales (
    id           BIGSERIAL PRIMARY KEY,
    reseller_id  BIGINT NOT NULL REFERENCES resellers(id) ON DELETE CASCADE,
    key_id       BIGINT NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
    sale_amount  NUMERIC,
    plan         TEXT NOT NULL DEFAULT '',
    duration     INT NOT NULL DEFAULT 0,
    customer_ref TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sales_reseller_idx ON reseller_sales (reseller_id);
CREATE TABLE IF NOT EXISTS reseller_sessions (
    jti         TEXT PRIMARY KEY,
    reseller_id BIGINT NOT NULL REFERENCES resellers(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS rsessions_reseller_idx ON reseller_sessions (reseller_id);
