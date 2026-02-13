-- Add up migration script here
CREATE TABLE otp_codes (
    email VARCHAR(100) PRIMARY KEY,
    code VARCHAR(6) NOT NULL,
    attempts INT DEFAULT 0,
    request_count INT DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL,
    last_request_at TIMESTAMPTZ DEFAULT NOW(),
    spam_locked_until TIMESTAMPTZ
);

-- Index for the background cleanup
CREATE INDEX idx_otp_expiry ON otp_codes(expires_at);
