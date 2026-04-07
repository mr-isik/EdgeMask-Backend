package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/mr-isik/edgemask-backend/internal/domain"
	goredis "github.com/redis/go-redis/v9"
)

const semanticPrefix = "edgemask:semantic:resp:"

type semanticResponseCache struct {
	client *goredis.Client
}

func NewSemanticResponseCache(client *goredis.Client) domain.SemanticResponseCache {
	return &semanticResponseCache{client: client}
}

func (c *semanticResponseCache) Get(ctx context.Context, key string) ([]byte, error) {
	data, err := c.client.Get(ctx, semanticPrefix+key).Bytes()
	if err != nil {
		if errors.Is(err, goredis.Nil) {
			return nil, nil
		}
		return nil, fmt.Errorf("redis get failed: %w", err)
	}
	return data, nil
}

func (c *semanticResponseCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if err := c.client.Set(ctx, semanticPrefix+key, value, ttl).Err(); err != nil {
		return fmt.Errorf("redis set failed: %w", err)
	}
	return nil
}
