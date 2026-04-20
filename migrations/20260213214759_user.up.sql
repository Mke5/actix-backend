-- Creates all the core tables for the authentication service

-- Enable the uuid-ossp extension so we can generate UUIDs in SQL
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TYPE user_role AS ENUM ('user', 'admin', 'superadmin');

CREATE TABLE users (
    id                              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email                           VARCHAR(255) NOT NULL UNIQUE,
    username                        VARCHAR(50) UNIQUE,
    display_name                    VARCHAR(100),
    avatar_url                      TEXT,

    -- The Argon2id password hash. NULL means the user only uses OAuth login.
    password_hash                   TEXT,

    -- Role-based access control
    role                            user_role NOT NULL DEFAULT 'user',

    -- Account status
    is_active                       BOOLEAN NOT NULL DEFAULT true,
    is_email_verified               BOOLEAN NOT NULL DEFAULT false,

    -- Email verification tokens
    -- The token is a random string sent to the user's email.
    -- expires_at ensures old tokens can't be used forever.
    email_verification_token        VARCHAR(128) UNIQUE,
    email_verification_expires_at   TIMESTAMPTZ,

    -- Password reset tokens
    password_reset_token            VARCHAR(128) UNIQUE,
    password_reset_expires_at       TIMESTAMPTZ,

    -- Brute-force protection
    -- We count failed logins and lock the account temporarily
    -- to stop attackers from trying millions of passwords.
    failed_login_attempts           INTEGER NOT NULL DEFAULT 0,
    locked_until                    TIMESTAMPTZ,

    -- Multi-factor authentication (authenticator app)
    totp_enabled                    BOOLEAN NOT NULL DEFAULT false,
    totp_secret                     VARCHAR(64),  -- The base32 secret shared with the authenticator app
    totp_backup_codes               JSONB,        -- Array of one-time recovery codes

    -- Audit fields
    created_at                      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at                   TIMESTAMPTZ,
    last_login_ip                   VARCHAR(45)  -- IPv4 (15 chars) or IPv6 (45 chars)
);

-- Indexes speed up queries we run frequently
-- Without indexes, PostgreSQL has to scan every row to find matches
CREATE INDEX idx_users_email         ON users(email);
CREATE INDEX idx_users_username      ON users(username) WHERE username IS NOT NULL;
CREATE INDEX idx_users_role          ON users(role);
CREATE INDEX idx_users_is_active     ON users(is_active);
CREATE INDEX idx_users_created_at    ON users(created_at DESC);

-- ============================================================
-- SESSIONS TABLE
-- Each time a user logs in, a new session is created.
-- This lets users see and manage all their active logins
-- (like how Google lets you see all logged-in devices).
-- ============================================================
CREATE TABLE sessions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- We store a HASH of the refresh token, not the token itself.
    -- If someone steals our database, they can't use the hashes to log in.
    token_hash      VARCHAR(255) NOT NULL UNIQUE,

    -- Device/browser information for the "active sessions" display
    user_agent      TEXT,
    ip_address      VARCHAR(45),

    -- Was this session created by OAuth (social login)?
    is_oauth        BOOLEAN NOT NULL DEFAULT false,
    oauth_provider  VARCHAR(50),

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    last_used_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Revoked sessions are like "logged out" sessions.
    -- We keep them in the DB for audit purposes.
    is_revoked      BOOLEAN NOT NULL DEFAULT false
);

CREATE INDEX idx_sessions_user_id    ON sessions(user_id);
CREATE INDEX idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_sessions_active     ON sessions(user_id, is_revoked, expires_at)
    WHERE is_revoked = false;

-- ============================================================
-- OAUTH PROVIDERS TABLE
-- Links a user account to one or more social login providers.
-- One user can have GitHub AND Google linked to the same account.
-- ============================================================
CREATE TABLE oauth_providers (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Which provider: "github", "google", "discord", etc.
    provider            VARCHAR(50) NOT NULL,

    -- The user's ID in the provider's system
    -- (e.g., GitHub user ID: "12345678")
    provider_user_id    VARCHAR(255) NOT NULL,

    -- OAuth tokens to make API calls on the user's behalf
    access_token        TEXT,
    refresh_token       TEXT,
    token_expires_at    TIMESTAMPTZ,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- A user can only link one account per provider
    UNIQUE(provider, provider_user_id),
    UNIQUE(user_id, provider)
);

CREATE INDEX idx_oauth_user_id           ON oauth_providers(user_id);
CREATE INDEX idx_oauth_provider_user     ON oauth_providers(provider, provider_user_id);

-- ============================================================
-- AUTO-UPDATE updated_at TRIGGER
-- PostgreSQL doesn't auto-update updated_at like some ORMs do.
-- This trigger fires whenever a row is updated to keep it current.
-- ============================================================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_oauth_providers_updated_at
    BEFORE UPDATE ON oauth_providers
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
