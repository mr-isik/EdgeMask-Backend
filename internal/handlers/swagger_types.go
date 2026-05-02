package handlers

// ──────────────────────────────────────────────────────────────────────────────
// Swagger documentation types — used ONLY for annotations, not in business logic
// ──────────────────────────────────────────────────────────────────────────────

// ErrorResponse is the standard error response.
type ErrorResponse struct {
	Error string `json:"error" example:"something went wrong"`
}

// HealthResponse is the health check response.
type HealthResponse struct {
	Status  string `json:"status" example:"ok"`
	Service string `json:"service" example:"edgemask"`
}

// ListKeysResponse is the response for GET /api/keys.
type ListKeysResponse struct {
	Keys []APIKeyDoc `json:"keys"`
}

// APIKeyDoc represents a single key in list responses.
type APIKeyDoc struct {
	ID        string `json:"id" example:"550e8400-e29b-41d4-a716-446655440000"`
	UserID    string `json:"user_id" example:"a1b2c3d4-e5f6-7890-abcd-ef1234567890"`
	KeyPrefix string `json:"key_prefix" example:"edgemask_live_a1b2c3d4"`
	Name      string `json:"name" example:"Production Key"`
	IsActive  bool   `json:"is_active" example:"true"`
	CreatedAt string `json:"created_at" example:"2026-04-01T12:00:00Z"`
}

// CreateKeyReq is the swagger request body for POST /api/keys.
type CreateKeyReq struct {
	Name string `json:"name" example:"Production Key"`
}

// CreateKeyResp is the swagger response for POST /api/keys.
type CreateKeyResp struct {
	Key     string `json:"key" example:"edgemask_live_a1b2c3d4e5f6..."`
	Message string `json:"message" example:"Save this key securely. It will NOT be shown again."`
}

// AggregateStatsResp is the swagger response for GET /api/stats.
type AggregateStatsResp struct {
	TotalRequests            int64   `json:"total_requests" example:"12450"`
	TotalPIIRedacted         int64   `json:"total_pii_redacted" example:"3420"`
	TotalTokensUsed          int64   `json:"total_tokens_used" example:"1250000"`
	TotalSemanticCacheHits   int64   `json:"total_semantic_cache_hits" example:"8200"`
	TotalSemanticCacheMisses int64   `json:"total_semantic_cache_misses" example:"4250"`
	SemanticCacheHitRate     float64 `json:"semantic_cache_hit_rate" example:"0.66"`
}

// UsageChartResp is the swagger response for GET /api/usage-chart.
type UsageChartResp struct {
	Interval string          `json:"interval" example:"day"`
	Days     int             `json:"days" example:"7"`
	Data     []UsagePointDoc `json:"data"`
}

// UsagePointDoc represents a single chart data point.
type UsagePointDoc struct {
	Period              string `json:"period" example:"2026-04-01T00:00"`
	Requests            int64  `json:"requests" example:"150"`
	PIIRedacted         int64  `json:"pii_redacted" example:"42"`
	TokensUsed          int64  `json:"tokens_used" example:"25000"`
	SemanticCacheHits   int64  `json:"semantic_cache_hits" example:"98"`
	SemanticCacheMisses int64  `json:"semantic_cache_misses" example:"52"`
}

// ProxyReq represents the OpenAI-format request body for proxy.
type ProxyReq struct {
	Model    string      `json:"model" example:"gpt-4o"`
	Messages []MsgDoc    `json:"messages"`
	Stream   bool        `json:"stream" example:"true"`
}

// MsgDoc represents a chat message.
type MsgDoc struct {
	Role    string `json:"role" example:"user"`
	Content string `json:"content" example:"Hello, how are you?"`
}

// LogListResponse is the swagger response for GET /api/logs.
type LogListResponse struct {
	TotalRecords int64         `json:"total_records" example:"10450"`
	Page         int           `json:"page" example:"1"`
	Logs         []LogEntryDoc `json:"logs"`
}

// LogEntryDoc represents a single request log entry.
type LogEntryDoc struct {
	LogID           string   `json:"log_id" example:"req_8f7d6a..."`
	Timestamp       string   `json:"timestamp" example:"2024-05-20T14:32:01Z"`
	APIKeyPrefix    string   `json:"api_key_prefix" example:"edgemask_live_f4a2"`
	ModelUsed       string   `json:"model_used" example:"gpt-4-turbo"`
	TokensProcessed int      `json:"tokens_processed" example:"450"`
	PIIDetected     bool     `json:"pii_detected" example:"true"`
	SemanticCacheHit bool    `json:"semantic_cache_hit" example:"false"`
	ScrubbedItems   []string `json:"scrubbed_items" example:"CREDIT_CARD,EMAIL"`
	LatencyMs       int      `json:"latency_ms" example:"8"`
}

