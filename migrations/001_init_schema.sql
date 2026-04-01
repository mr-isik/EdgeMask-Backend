-- EdgeMask Database Schema
-- Run this against your Supabase PostgreSQL instance

-- ─── Users ──────────────────────────────────────────────────────────────────
-- Synced with Supabase Auth. The ID references auth.users(id).
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY REFERENCES auth.users(id),
    email TEXT UNIQUE NOT NULL,
    plan TEXT DEFAULT 'growth',  -- 'growth' or 'enterprise'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ─── EdgeMask API Keys ──────────────────────────────────────────────────────
-- These are OUR keys (edgemask_live_...) that customers use to authenticate.
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    key_hash TEXT UNIQUE NOT NULL,     -- SHA-256 hash of the full key
    key_prefix TEXT NOT NULL,           -- First 8 chars for display
    name TEXT,                          -- Human label: "Production Key", etc.
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash) WHERE is_active = TRUE;

-- ─── Customer Provider Keys (BYOK) ─────────────────────────────────────────
-- Customers' own LLM provider API keys, encrypted with AES-256-GCM.
CREATE TABLE IF NOT EXISTS customer_provider_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,             -- 'openai', 'anthropic', 'gemini'
    encrypted_key TEXT NOT NULL,        -- AES-256-GCM encrypted, base64-encoded
    key_hint TEXT,                      -- 'sk-p...4k2f' for dashboard display
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, provider)
);

-- ─── Usage Logs (Analytics) ─────────────────────────────────────────────────
-- Records every proxy request for dashboard analytics.
CREATE TABLE IF NOT EXISTS usage_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    pii_redacted INT DEFAULT 0,
    tokens_used INT DEFAULT 0,
    status_code INT NOT NULL,
    latency_ms INT DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Index for fast per-user analytics queries
CREATE INDEX IF NOT EXISTS idx_usage_logs_user_time ON usage_logs(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_logs_user_provider ON usage_logs(user_id, provider);
