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

// ProviderKeyRepository handles storage/retrieval of customer-owned LLM provider keys.
type ProviderKeyRepository interface {
	GetProviderKey(ctx context.Context, userID string, provider ProviderID) (*CustomerProviderKey, error)
	ListProviderKeys(ctx context.Context, userID string) ([]CustomerProviderKey, error)
	SaveProviderKey(ctx context.Context, userID string, provider ProviderID, encryptedKey string, keyHint string) error
	DeleteProviderKey(ctx context.Context, userID string, provider ProviderID) error
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

// ---------------------------------------------------------------------------
// Service Interfaces
// ---------------------------------------------------------------------------

type AuthService interface {
	ValidateKey(ctx context.Context, rawKey string) (*KeyLookupResult, error)
}

type EncryptionService interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(ciphertext string) (string, error)
}

type ScrubbingService interface {
	Redact(text string) ScrubbingResult
}

type ProxyService interface {
	Forward(ctx context.Context, userID string, providerID ProviderID, rawBody []byte, headers http.Header) (body io.ReadCloser, respHeaders http.Header, result ForwardResult, err error)
}
