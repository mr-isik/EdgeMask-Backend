CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS semantic_cache_entries (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    prompt_hash TEXT NOT NULL,
    prompt_text TEXT NOT NULL,
    embedding vector(1536) NOT NULL,
    response_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS semantic_cache_entries_unique_prompt
    ON semantic_cache_entries (user_id, provider, model, prompt_hash);

CREATE INDEX IF NOT EXISTS semantic_cache_entries_expires_idx
    ON semantic_cache_entries (expires_at);

CREATE INDEX IF NOT EXISTS semantic_cache_entries_embedding_idx
    ON semantic_cache_entries
    USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 100);
