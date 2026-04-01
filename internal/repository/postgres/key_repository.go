package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/mr-isik/edgemask-backend/internal/domain"
)

// keyRepository implements domain.KeyRepository backed by PostgreSQL.
type keyRepository struct {
	db *sqlx.DB
}

// NewKeyRepository creates a new PostgreSQL-backed KeyRepository.
func NewKeyRepository(db *sqlx.DB) domain.KeyRepository {
	return &keyRepository{db: db}
}

// GetKeyByHash looks up an active API key by its SHA-256 hash and joins with
// the users table to return UserID + Plan in a single query.
func (r *keyRepository) GetKeyByHash(ctx context.Context, keyHash string) (*domain.KeyLookupResult, error) {
	const query = `
		SELECT ak.user_id, u.plan
		FROM api_keys ak
		JOIN users u ON u.id = ak.user_id
		WHERE ak.key_hash = $1 AND ak.is_active = TRUE
	`

	var result domain.KeyLookupResult
	if err := r.db.GetContext(ctx, &result, query, keyHash); err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrKeyNotFound
		}
		return nil, fmt.Errorf("key lookup failed: %w", err)
	}

	return &result, nil
}

// CreateKey generates a new edgemask_live_ key, hashes it with SHA-256,
// and stores the hash + 8-char prefix in the database.
// Returns the full raw key — this is the ONLY time it's ever available.
func (r *keyRepository) CreateKey(ctx context.Context, userID string, name string) (string, error) {
	// 1. Generate 32 random bytes → 64 hex chars
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random key: %w", err)
	}

	rawKey := domain.APIKeyPrefix + hex.EncodeToString(randomBytes) // edgemask_live_<64 hex chars>

	// 2. SHA-256 hash the full key for storage
	hash := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(hash[:])

	// 3. Extract prefix for display (first 8 chars of the random part)
	keyPrefix := rawKey[:len(domain.APIKeyPrefix)+8] // edgemask_live_XXXXXXXX

	// 4. Insert into database
	const query = `
		INSERT INTO api_keys (user_id, key_hash, key_prefix, name)
		VALUES ($1, $2, $3, $4)
	`

	if _, err := r.db.ExecContext(ctx, query, userID, keyHash, keyPrefix, name); err != nil {
		return "", fmt.Errorf("failed to store api key: %w", err)
	}

	return rawKey, nil
}

// ListKeysByUserID retrieves all API keys for a given user.
// Only returns safe fields — KeyHash is excluded via json:"-" on the struct.
func (r *keyRepository) ListKeysByUserID(ctx context.Context, userID string) ([]domain.APIKey, error) {
	const query = `
		SELECT id, user_id, key_hash, key_prefix, name, is_active, created_at
		FROM api_keys
		WHERE user_id = $1
		ORDER BY created_at DESC
	`

	var keys []domain.APIKey
	if err := r.db.SelectContext(ctx, &keys, query, userID); err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	if keys == nil {
		keys = []domain.APIKey{}
	}

	return keys, nil
}
