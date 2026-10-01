-- VascalMod auth backend — Postgres schema (Neon / Supabase free tier)
-- Run once: psql $DATABASE_URL -f schema.sql

-- License keys. Only SHA-256 hashes stored, never plaintext.
-- id is a random 8-digit integer (non-sequential: deletions leave no order gaps).
CREATE TABLE IF NOT EXISTS keys (
    id              BIGINT PRIMARY KEY,
    license_key_hash CHAR(64) NOT NULL UNIQUE,
    key_prefix      CHAR(8) NOT NULL DEFAULT '',
    key_suffix      CHAR(4) NOT NULL DEFAULT '',
    key_enc         TEXT NOT NULL DEFAULT '',
    plan            TEXT NOT NULL DEFAULT 'monthly',
    expires_at      TIMESTAMPTZ NOT NULL,
    bound_uid       BIGINT,
    bound_hwid      TEXT,
    max_devices     INT NOT NULL DEFAULT 1,
    duration_days   INT NOT NULL DEFAULT 3,
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked','suspended')),
    note            TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seats: one row per device. Independent expiry from first activation.
CREATE TABLE IF NOT EXISTS key_devices (
    key_id      BIGINT NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
    hwid        TEXT NOT NULL,
    uid         BIGINT,
    activated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (key_id, hwid)
);

-- UID history per key. Feeds anomaly detection (UID hopping = shared key).
CREATE TABLE IF NOT EXISTS devices (
    id          BIGSERIAL PRIMARY KEY,
    key_id      BIGINT NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
    uid         BIGINT NOT NULL,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (key_id, uid)
);

-- Short-lived sessions (one row per minted token, keyed by JTI).
CREATE TABLE IF NOT EXISTS sessions (
    jti         TEXT PRIMARY KEY,                 -- token id, 128-bit hex
    key_id      BIGINT NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
    uid         BIGINT NOT NULL,
    build_tag   TEXT NOT NULL DEFAULT '',
    issued_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked     BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS sessions_key_idx ON sessions (key_id);

-- Versioned server-side offset tables.
CREATE TABLE IF NOT EXISTS offsets (
    game_version TEXT PRIMARY KEY,                -- e.g. '2.2.16.12322'
    table_json   JSONB NOT NULL,                  -- { classes: {...}, fields: {...}, globals: {...} }
    min_build    TEXT NOT NULL DEFAULT '',        -- oldest client build_tag allowed
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Audit trail: logins, heartbeats (sampled), anomalies, admin ops.
CREATE TABLE IF NOT EXISTS events (
    id          BIGSERIAL PRIMARY KEY,
    key_id      BIGINT REFERENCES keys(id) ON DELETE SET NULL,
    type        TEXT NOT NULL,                    -- login_ok, login_fail, heartbeat_ok, anomaly, revoke, ...
    ip          TEXT NOT NULL DEFAULT '',
    meta        JSONB NOT NULL DEFAULT '{}',
    at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS events_key_idx ON events (key_id);
CREATE INDEX IF NOT EXISTS events_at_idx ON events (at);

-- Published binaries for auto-update. url = public object URL (Supabase Storage).
CREATE TABLE IF NOT EXISTS releases (
    id          BIGSERIAL PRIMARY KEY,
    tag         TEXT NOT NULL,                    -- cheat build tag, e.g. '1.0.0'
    url         TEXT NOT NULL,
    sha256      CHAR(64) NOT NULL,                -- hex of the exact binary
    notes       TEXT NOT NULL DEFAULT '',
    seals       JSONB NOT NULL DEFAULT '{}',      -- e.g. {"trust":"<hex sha256 of trust anchors>"}
    at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
