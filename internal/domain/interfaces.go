package domain

import (
	"context"
	"io"
	"net/http"
	"time"
)

// ---------------------------------------------------------------------------
// Repository Interfaces
// ---------------------------------------------------------------------------

// KeyRepository handles persistent storage for EdgeMask API keys (PostgreSQL).
type KeyRepository interface {
	GetKeyByHash(ctx context.Context, keyHash string) (*KeyLookupResult, error)
	CreateKey(ctx context.Context, userID string, name string) (rawKey string, err error)
	ListKeysByUserID(ctx context.Context, userID string) ([]APIKey, error)
	RevokeKey(ctx context.Context, userID string, keyID string) error
}



// AnalyticsRepository handles usage logging and aggregation.
type AnalyticsRepository interface {
	// LogUsage records a proxy request asynchronously (called via goroutine).
	LogUsage(ctx context.Context, log *UsageLog) error

	// GetAggregateStats returns total stats for a user.
	GetAggregateStats(ctx context.Context, userID string) (*AggregateStats, error)

	// GetUsageChart returns time-series data grouped by the given interval.
	// interval: "hour" or "day". days: how many days back to look.
	GetUsageChart(ctx context.Context, userID string, interval string, days int) ([]UsageDataPoint, error)
}

// RequestLogRepository handles storage and retrieval of filtered request logs.
type RequestLogRepository interface {
	InsertLog(ctx context.Context, log *RequestLog) error
	GetLogs(ctx context.Context, userID string, filter RequestLogFilter) (*RequestLogPage, error)
}

// RedisKeyCache handles fast key-to-user lookups in Redis.
type RedisKeyCache interface {
	GetCachedKey(ctx context.Context, keyHash string) (*KeyLookupResult, error)
	SetCachedKey(ctx context.Context, keyHash string, result *KeyLookupResult, ttl time.Duration) error
	InvalidateKey(ctx context.Context, keyHash string) error
}

// SemanticResponseCache stores serialized model responses in Redis.
type SemanticResponseCache interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
}

// SemanticCacheRepository stores and queries semantic cache vectors in PostgreSQL.
type SemanticCacheRepository interface {
	FindNearest(ctx context.Context, req SemanticLookupRequest) (*SemanticCacheHit, error)
	UpsertEntry(ctx context.Context, entry SemanticCacheEntry) error
}

// ---------------------------------------------------------------------------
// Service Interfaces
// ---------------------------------------------------------------------------

type AuthService interface {
	ValidateKey(ctx context.Context, rawKey string) (*KeyLookupResult, error)
}



type ScrubbingService interface {
	Redact(text string) ScrubbingResult
}

type ProxyService interface {
	Forward(ctx context.Context, userID string, providerID ProviderID, rawBody []byte, headers http.Header) (body io.ReadCloser, respHeaders http.Header, result ForwardResult, err error)
}

// EmbeddingService converts a text prompt into a float embedding vector.
// Zero-trust: the API key is passed per-request from the caller's Authorization header.
type EmbeddingService interface {
	Embed(ctx context.Context, text string, apiKey string) ([]float32, error)
}
