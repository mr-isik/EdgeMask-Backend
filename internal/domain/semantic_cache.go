package domain

import "time"

type SemanticLookupRequest struct {
	UserID      string
	ProviderID  ProviderID
	Model       string
	Embedding   []float32
	MaxDistance float64
	Now         time.Time
}

type SemanticCacheHit struct {
	ResponseKey string
	Distance    float64
}

type SemanticCacheEntry struct {
	UserID      string
	ProviderID  ProviderID
	Model       string
	PromptHash  string
	PromptText  string
	Embedding   []float32
	ResponseKey string
	ExpiresAt   time.Time
}
