package domain

import "time"

// UsageLog records each proxy request for analytics.
type UsageLog struct {
	ID           string    `json:"id" db:"id"`
	UserID       string    `json:"user_id" db:"user_id"`
	Provider     string    `json:"provider" db:"provider"`
	PIIRedacted  int       `json:"pii_redacted" db:"pii_redacted"`
	TokensUsed   int       `json:"tokens_used" db:"tokens_used"`
	StatusCode   int       `json:"status_code" db:"status_code"`
	LatencyMs    int       `json:"latency_ms" db:"latency_ms"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
}

// AggregateStats holds high-level dashboard statistics.
type AggregateStats struct {
	TotalRequests            int64   `json:"total_requests" db:"total_requests"`
	TotalPIIRedacted         int64   `json:"total_pii_redacted" db:"total_pii_redacted"`
	TotalTokensUsed          int64   `json:"total_tokens_used" db:"total_tokens_used"`
	TotalSemanticCacheHits   int64   `json:"total_semantic_cache_hits" db:"total_semantic_cache_hits"`
	TotalSemanticCacheMisses int64   `json:"total_semantic_cache_misses" db:"total_semantic_cache_misses"`
	SemanticCacheHitRate     float64 `json:"semantic_cache_hit_rate" db:"semantic_cache_hit_rate"`
}

// UsageDataPoint holds a single time-series data point for charts.
type UsageDataPoint struct {
	Period               string `json:"period" db:"period"` // e.g., "2026-04-01" or "2026-04-01T14:00"
	Requests             int64  `json:"requests" db:"requests"`
	PIIRedacted          int64  `json:"pii_redacted" db:"pii_redacted"`
	TokensUsed           int64  `json:"tokens_used" db:"tokens_used"`
	SemanticCacheHits    int64  `json:"semantic_cache_hits" db:"semantic_cache_hits"`
	SemanticCacheMisses  int64  `json:"semantic_cache_misses" db:"semantic_cache_misses"`
}
