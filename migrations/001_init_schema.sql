-- EdgeMask Database Schema
-- Compatible with Supabase PostgreSQL (auth.users is managed by Supabase Auth)

-- ─── Users ──────────────────────────────────────────────────────────────────
-- Synced with Supabase Auth. The ID references auth.users(id).
-- This table is automatically populated via a Supabase trigger or webhook
-- when a user signs up through Supabase Auth.
CREATE TABLE IF NOT EXISTS public.users (
    id UUID PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    plan TEXT DEFAULT 'growth',  -- 'growth' or 'enterprise'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Optional: If running on Supabase with auth.users available,
-- add the foreign key constraint. This is safe to run on Supabase.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'auth' AND table_name = 'users'
    ) THEN
        ALTER TABLE public.users
            ADD CONSTRAINT fk_users_auth
            FOREIGN KEY (id) REFERENCES auth.users(id)
            ON DELETE CASCADE;
    END IF;
EXCEPTION
    WHEN duplicate_object THEN NULL; -- constraint already exists, skip
END $$;

-- ─── EdgeMask API Keys ──────────────────────────────────────────────────────
-- These are OUR keys (edgemask_live_...) that customers use to authenticate.
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    key_hash TEXT UNIQUE NOT NULL,     -- SHA-256 hash of the full key
    key_prefix TEXT NOT NULL,           -- First 8 chars for display
    name TEXT,                          -- Human label: "Production Key", etc.
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash) WHERE is_active = TRUE;

-- ─── Customer Provider Keys ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS customer_provider_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
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
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
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

-- ─── Row Level Security (Supabase) ──────────────────────────────────────────
-- Enable RLS on all tables to leverage Supabase's security model.
-- The EdgeMask API connects with service_role key, bypassing RLS.
-- These policies are for direct Supabase client access (if ever needed).

ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE customer_provider_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_logs ENABLE ROW LEVEL SECURITY;

-- Users can only read their own row
DO $$ BEGIN
    CREATE POLICY "users_select_own" ON public.users
        FOR SELECT USING (auth.uid() = id);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- Users can only access their own API keys
DO $$ BEGIN
    CREATE POLICY "api_keys_select_own" ON api_keys
        FOR SELECT USING (auth.uid() = user_id);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE POLICY "api_keys_insert_own" ON api_keys
        FOR INSERT WITH CHECK (auth.uid() = user_id);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- Users can only access their own provider keys
DO $$ BEGIN
    CREATE POLICY "provider_keys_select_own" ON customer_provider_keys
        FOR SELECT USING (auth.uid() = user_id);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE POLICY "provider_keys_upsert_own" ON customer_provider_keys
        FOR INSERT WITH CHECK (auth.uid() = user_id);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE POLICY "provider_keys_update_own" ON customer_provider_keys
        FOR UPDATE USING (auth.uid() = user_id);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- Users can only access their own usage logs
DO $$ BEGIN
    CREATE POLICY "usage_logs_select_own" ON usage_logs
        FOR SELECT USING (auth.uid() = user_id);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
