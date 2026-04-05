package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/mr-isik/edgemask-backend/internal/domain"
)

const keyCacheTTL = 5 * time.Minute

// authService implements domain.AuthService.
// Uses Redis for fast key lookups with DB fallback.
type authService struct {
	keyRepo  domain.KeyRepository
	keyCache domain.RedisKeyCache
}

// NewAuthService creates a new AuthService.
func NewAuthService(keyRepo domain.KeyRepository, keyCache domain.RedisKeyCache) domain.AuthService {
	return &authService{
		keyRepo:  keyRepo,
		keyCache: keyCache,
	}
}

// ValidateKey validates an edgemask_live_ API key.
// Fast path: check Redis cache. Slow path: query PostgreSQL + cache result.
func (s *authService) ValidateKey(ctx context.Context, rawKey string) (*domain.KeyLookupResult, error) {
	// 1. Hash the raw key
	hash := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(hash[:])

	// 2. Fast path: check Redis cache
	if s.keyCache != nil {
		cached, err := s.keyCache.GetCachedKey(ctx, keyHash)
		if err == nil && cached != nil {
			return cached, nil
		}
	}

	// 3. Slow path: query PostgreSQL
	result, err := s.keyRepo.GetKeyByHash(ctx, keyHash)
	if err != nil {
		return nil, err
	}

	// 4. Cache the result in Redis for next time
	if s.keyCache != nil {
		_ = s.keyCache.SetCachedKey(ctx, keyHash, result, keyCacheTTL)
	}

	return result, nil
}
