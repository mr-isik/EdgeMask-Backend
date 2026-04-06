-- Request Logs — stores metadata about filtered proxy requests.
-- Raw prompts are NEVER stored. Only PII category names and request metadata.

CREATE TABLE IF NOT EXISTS request_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
    api_key_prefix TEXT NOT NULL DEFAULT '',
    model_used TEXT NOT NULL DEFAULT '',
    provider TEXT NOT NULL,
    tokens_processed INT DEFAULT 0,
    pii_detected BOOLEAN DEFAULT FALSE,
    scrubbed_items TEXT[] DEFAULT '{}',
    latency_ms INT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_request_logs_user_time
    ON request_logs(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_request_logs_pii
    ON request_logs(user_id, pii_detected) WHERE pii_detected = TRUE;

-- RLS policy
ALTER TABLE request_logs ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    CREATE POLICY "request_logs_select_own" ON request_logs
        FOR SELECT USING (auth.uid() = user_id);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
