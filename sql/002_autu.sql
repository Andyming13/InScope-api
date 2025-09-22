-- 需要 pgcrypto 用于 gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 1) 存验证码
CREATE TABLE IF NOT EXISTS verification_codes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  purpose TEXT NOT NULL CHECK (purpose IN ('verify_email', 'reset_password')),
  expires_at TIMESTAMPTZ NOT NULL,
  attempts_remaining INT NOT NULL DEFAULT 5,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_verification_codes_email ON verification_codes (LOWER(email));
CREATE INDEX IF NOT EXISTS idx_verification_codes_purpose ON verification_codes (purpose);
CREATE INDEX IF NOT EXISTS idx_verification_codes_expires ON verification_codes (expires_at);

-- 2) 刷新令牌
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL,
  user_agent TEXT,
  ip_hash TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens (user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_refresh_tokens_token_hash ON refresh_tokens (token_hash);