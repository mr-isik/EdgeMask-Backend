package domain

import "time"

const (
	// APIKeyPrefix is the required prefix for all EdgeMask API keys.
	APIKeyPrefix = "edgemask_live_"
)

// APIKey represents an authentication key issued to a B2B customer.
// Keys are stored as SHA-256 hashes; the raw key is only shown once at creation.
type APIKey struct {
	ID        string    `json:"id" db:"id"`
	UserID    string    `json:"user_id" db:"user_id"`
	KeyHash   string    `json:"-" db:"key_hash"`       // SHA-256 hash, never serialized
	KeyPrefix string    `json:"key_prefix" db:"key_prefix"` // First 8 chars for display
	Name      string    `json:"name" db:"name"`         // Human label: "Production Key", etc.
	IsActive  bool      `json:"is_active" db:"is_active"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// KeyLookupResult is the fast-path return value when validating an API key.
// Contains just enough data for the auth middleware to proceed.
type KeyLookupResult struct {
	UserID string `json:"user_id" db:"user_id"`
	Plan   string `json:"plan" db:"plan"`
}
