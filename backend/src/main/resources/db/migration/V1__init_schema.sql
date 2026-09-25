-- =====================================================================
-- V1__init_schema.sql
-- Core schema for the passwordless authentication service.
-- =====================================================================

CREATE TABLE users (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                   VARCHAR(255) NOT NULL,
    email                  VARCHAR(255) NOT NULL,
    password_hash          VARCHAR(255),              -- Argon2id hash; NULL if passkey-only
    webauthn_user_handle   VARCHAR(128) NOT NULL,      -- opaque, unrelated to email
    status                 VARCHAR(20)  NOT NULL DEFAULT 'ACTIVE',
    failed_login_attempts  INT          NOT NULL DEFAULT 0,
    locked_until           TIMESTAMPTZ,
    created_at             TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT uq_users_email UNIQUE (email),
    CONSTRAINT uq_users_webauthn_handle UNIQUE (webauthn_user_handle)
);

CREATE INDEX idx_users_email ON users (lower(email));

COMMENT ON TABLE users IS 'Registered accounts.';
COMMENT ON COLUMN users.webauthn_user_handle IS
    'Random opaque ID used only as the WebAuthn user.id — deliberately not the email, so credential metadata that syncs to the OS/cloud never carries PII.';
COMMENT ON COLUMN users.password_hash IS
    'Argon2id hash of the fallback password. NULL for accounts that only ever used a passkey.';


CREATE TABLE webauthn_credentials (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    credential_id     VARCHAR(512) NOT NULL,   -- Base64URL credential ID from the authenticator
    public_key        BYTEA NOT NULL,          -- COSE public key; private key never leaves the device
    sign_count        BIGINT NOT NULL DEFAULT 0,
    aaguid            VARCHAR(64),             -- authenticator MODEL identifier, not per-device
    transports        VARCHAR(128),            -- e.g. "internal", "usb,nfc"
    device_name       VARCHAR(100),            -- user-editable label shown in /settings/security
    credential_type   VARCHAR(20) NOT NULL,    -- PLATFORM | CROSS_PLATFORM
    backup_eligible   BOOLEAN NOT NULL DEFAULT FALSE,
    backup_state      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at      TIMESTAMPTZ,

    CONSTRAINT uq_webauthn_credential_id UNIQUE (credential_id)
);

CREATE INDEX idx_webauthn_credentials_user_id ON webauthn_credentials (user_id);

COMMENT ON TABLE webauthn_credentials IS
    'One row per registered authenticator (passkey or security key). A user can have many.';
COMMENT ON COLUMN webauthn_credentials.sign_count IS
    'Authenticator signature counter at last successful use. Must not go backwards or stay flat on hardware that supports counters — used to detect cloned authenticators.';


CREATE TABLE webauthn_challenges (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID REFERENCES users (id) ON DELETE CASCADE, -- NULL for usernameless login
    challenge      VARCHAR(255) NOT NULL,
    ceremony_type  VARCHAR(20)  NOT NULL,  -- REGISTRATION | AUTHENTICATION
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at     TIMESTAMPTZ  NOT NULL,
    consumed       BOOLEAN      NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_webauthn_challenges_expiry ON webauthn_challenges (expires_at);

COMMENT ON TABLE webauthn_challenges IS
    'Short-lived, single-use challenges issued for registration/login ceremonies. Rows are deleted or marked consumed after use or expiry — required for WebAuthn replay protection.';


CREATE TABLE sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    session_token   VARCHAR(255) NOT NULL,   -- opaque value; the raw value set in the cookie is never stored, only its hash
    ip_address      VARCHAR(64),
    user_agent      VARCHAR(512),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_active_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked         BOOLEAN     NOT NULL DEFAULT FALSE,

    CONSTRAINT uq_sessions_token UNIQUE (session_token)
);

CREATE INDEX idx_sessions_user_id ON sessions (user_id);
CREATE INDEX idx_sessions_expiry ON sessions (expires_at);

COMMENT ON TABLE sessions IS
    'Server-side session records enabling central revocation ("log out this device") independent of cookie expiry. session_token stores a SHA-256 hash of the cookie value, never the raw value.';


CREATE TABLE audit_logs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID REFERENCES users (id) ON DELETE SET NULL,
    event_type  VARCHAR(50) NOT NULL,
    ip_address  VARCHAR(64),
    user_agent  VARCHAR(512),
    metadata    TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_logs_user_id ON audit_logs (user_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs (created_at);

COMMENT ON TABLE audit_logs IS
    'Append-only security event trail. Never contains passwords, challenges, or key material.';
