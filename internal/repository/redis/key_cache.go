package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/mr-isik/edgemask-backend/internal/domain"
	goredis "github.com/redis/go-redis/v9"
)

const keyPrefix = "edgemask:key:" // Redis key namespace

// keyCache implements domain.RedisKeyCache backed by Redis.
type keyCache struct {
	client *goredis.Client
}

// NewKeyCache creates a new Redis-backed key cache.
func NewKeyCache(client *goredis.Client) domain.RedisKeyCache {
	return &keyCache{client: client}
}

// GetCachedKey returns the cached KeyLookupResult for an API key hash.
// Returns nil, nil on cache miss (not an error).
func (c *keyCache) GetCachedKey(ctx context.Context, keyHash string) (*domain.KeyLookupResult, error) {
	data, err := c.client.Get(ctx, keyPrefix+keyHash).Bytes()
	if err != nil {
		if errors.Is(err, goredis.Nil) {
			return nil, nil // Cache miss — not an error
		}
		return nil, fmt.Errorf("redis get failed: %w", err)
	}

	var result domain.KeyLookupResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("redis unmarshal failed: %w", err)
	}

	return &result, nil
}

// SetCachedKey stores a KeyLookupResult in Redis with a TTL.
func (c *keyCache) SetCachedKey(ctx context.Context, keyHash string, result *domain.KeyLookupResult, ttl time.Duration) error {
	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("redis marshal failed: %w", err)
	}

	if err := c.client.Set(ctx, keyPrefix+keyHash, data, ttl).Err(); err != nil {
		return fmt.Errorf("redis set failed: %w", err)
	}

	return nil
}

// InvalidateKey removes a cached key entry from Redis.
func (c *keyCache) InvalidateKey(ctx context.Context, keyHash string) error {
	if err := c.client.Del(ctx, keyPrefix+keyHash).Err(); err != nil {
		return fmt.Errorf("redis del failed: %w", err)
	}
	return nil
}
