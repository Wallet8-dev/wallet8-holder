-- Wallet8 Holder - the credential vault schema (DESIGN.md §3).
--
-- RLS is mandatory on every tenant table (architecture-principles §4.3):
-- ENABLE + FORCE, the standard env_id policy. Credential material is
-- stored ENCRYPTED (AES-256-GCM envelope via sentin8-crypto); the API
-- surface exposes secret references only.

-- The credential vault rows.
CREATE TABLE IF NOT EXISTS credentials (
    id            UUID PRIMARY KEY,
    env_id        UUID NOT NULL,
    user_id       UUID NOT NULL,
    format        TEXT NOT NULL CHECK (format IN ('mso_mdoc', 'dc+sd-jwt')),
    doctype       TEXT,
    vct           TEXT,
    display_name  TEXT NOT NULL DEFAULT '',
    issuer        TEXT NOT NULL,
    -- The credential material (the mdoc IssuerSigned base64url / the
    -- compact sd-jwt) - encrypted at rest by the service layer.
    credential_ct TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active', 'revoked', 'expired')),
    issued_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE credentials FORCE ROW LEVEL SECURITY;

CREATE POLICY credentials_env_policy ON credentials
    USING (env_id = current_setting('app.env_id', true)::uuid);

-- The registered device keys (the wallet's P-256 pairs).
CREATE TABLE IF NOT EXISTS device_keys (
    id             UUID PRIMARY KEY,
    env_id         UUID NOT NULL,
    user_id        UUID NOT NULL,
    thumbprint     TEXT NOT NULL,
    jwk            JSONB NOT NULL,
    registered_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE device_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_keys FORCE ROW LEVEL SECURITY;

CREATE POLICY device_keys_env_policy ON device_keys
    USING (env_id = current_setting('app.env_id', true)::uuid);

-- The presentation history (who verified what, when).
CREATE TABLE IF NOT EXISTS presentations (
    id                 UUID PRIMARY KEY,
    env_id             UUID NOT NULL,
    user_id            UUID NOT NULL,
    verifier_client_id TEXT NOT NULL,
    verifier_host      TEXT NOT NULL,
    disclosed_claims   TEXT[] NOT NULL DEFAULT '{}',
    formats            TEXT[] NOT NULL DEFAULT '{}',
    presented_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE presentations ENABLE ROW LEVEL SECURITY;
ALTER TABLE presentations FORCE ROW LEVEL SECURITY;

CREATE POLICY presentations_env_policy ON presentations
    USING (env_id = current_setting('app.env_id', true)::uuid);

CREATE UNIQUE INDEX IF NOT EXISTS credentials_env_user_idx
    ON credentials (env_id, user_id);
CREATE UNIQUE INDEX IF NOT EXISTS device_keys_env_thumb_idx
    ON device_keys (env_id, thumbprint);
