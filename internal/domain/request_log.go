package domain

import "time"

// RequestLog records metadata about a proxy request where PII was filtered.
// Raw prompts are NEVER stored — only PII category names and request metadata.
type RequestLog struct {
	ID              string    `json:"log_id" db:"id"`
	UserID          string    `json:"-" db:"user_id"`
	APIKeyPrefix    string    `json:"api_key_prefix" db:"api_key_prefix"`
	ModelUsed       string    `json:"model_used" db:"model_used"`
	Provider        string    `json:"provider" db:"provider"`
	TokensProcessed int       `json:"tokens_processed" db:"tokens_processed"`
	PIIDetected     bool      `json:"pii_detected" db:"pii_detected"`
	SemanticCacheHit bool     `json:"semantic_cache_hit" db:"semantic_cache_hit"`
	ScrubbedItems   []string  `json:"scrubbed_items" db:"scrubbed_items"`
	LatencyMs       int       `json:"latency_ms" db:"latency_ms"`
	CreatedAt       time.Time `json:"timestamp" db:"created_at"`
}

// RequestLogFilter holds pagination and optional filter parameters.
type RequestLogFilter struct {
	Page    int    // 1-based page number
	PerPage int    // Items per page (max 100)
	PIIOnly bool   // If true, only return logs where PII was detected
}

// RequestLogPage is the paginated response envelope.
type RequestLogPage struct {
	TotalRecords int64        `json:"total_records"`
	Page         int          `json:"page"`
	Logs         []RequestLog `json:"logs"`
}

// ForwardResult wraps the proxy response along with scrub metadata
// needed for logging. This replaces the previous multi-return approach.
type ForwardResult struct {
	StatusCode    int
	PIIDetected   bool
	ScrubbedItems []string
	RedactCount   int
	SemanticCacheHit bool
}
