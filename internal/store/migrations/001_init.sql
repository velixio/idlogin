-- One-time codes (sign-in, sign-up, password reset, email verification).
-- Only an HMAC of the code is stored.
CREATE TABLE IF NOT EXISTS login_codes (
    id          text PRIMARY KEY,
    brand       text NOT NULL,
    purpose     text NOT NULL,
    email       text NOT NULL,
    user_id     text NOT NULL DEFAULT '',
    code_hash   bytea NOT NULL,
    attempts    integer NOT NULL DEFAULT 0,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    consumed_at timestamptz
);
CREATE INDEX IF NOT EXISTS login_codes_live ON login_codes (brand, purpose, email) WHERE consumed_at IS NULL;
CREATE INDEX IF NOT EXISTS login_codes_expires ON login_codes (expires_at);

-- Rate-limit events: one row per counted event (code send, password attempt...).
CREATE TABLE IF NOT EXISTS login_rate_events (
    key        text NOT NULL,
    at         timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS login_rate_events_key_at ON login_rate_events (key, at);
CREATE INDEX IF NOT EXISTS login_rate_events_expires ON login_rate_events (expires_at);
