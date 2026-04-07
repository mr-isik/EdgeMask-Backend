ALTER TABLE request_logs
    ADD COLUMN IF NOT EXISTS semantic_cache_hit BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_request_logs_semantic_cache_hit
    ON request_logs(user_id, semantic_cache_hit, created_at DESC);
