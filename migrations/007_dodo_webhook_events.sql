-- Stores processed Dodo webhook IDs for idempotency.
CREATE TABLE IF NOT EXISTS dodo_webhook_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    received_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dodo_webhook_events_received_at
ON dodo_webhook_events(received_at DESC);
