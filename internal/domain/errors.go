package domain

import "errors"

// Sentinel errors for the EdgeMask domain.
var (
	ErrUnauthorized           = errors.New("unauthorized: invalid or missing API key")
	ErrKeyNotFound            = errors.New("api key not found")
	ErrKeyInactive            = errors.New("api key is inactive")
	ErrInvalidRequest         = errors.New("invalid request payload")
	ErrUpstreamFailure        = errors.New("upstream API request failed")
	ErrProviderUnknown        = errors.New("unknown LLM provider")
	ErrProviderKeyMissing     = errors.New("provider key not configured: please add your API key in the EdgeMask Dashboard")
	ErrEncryption             = errors.New("encryption error")
	ErrDecryption             = errors.New("decryption error")
	ErrBillingMappingNotFound = errors.New("billing customer mapping not found")
)
