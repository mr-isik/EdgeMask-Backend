package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/mr-isik/edgemask-backend/internal/domain"
)

// providerKeyRepository implements domain.ProviderKeyRepository backed by PostgreSQL.
type providerKeyRepository struct {
	db *sqlx.DB
}

// NewProviderKeyRepository creates a new PostgreSQL-backed ProviderKeyRepository.
func NewProviderKeyRepository(db *sqlx.DB) domain.ProviderKeyRepository {
	return &providerKeyRepository{db: db}
}

// GetProviderKey retrieves the encrypted provider key for a user + provider combo.
func (r *providerKeyRepository) GetProviderKey(ctx context.Context, userID string, provider domain.ProviderID) (*domain.CustomerProviderKey, error) {
	const query = `
		SELECT id, user_id, provider, encrypted_key, key_hint, updated_at
		FROM customer_provider_keys
		WHERE user_id = $1 AND provider = $2
	`

	var key domain.CustomerProviderKey
	if err := r.db.GetContext(ctx, &key, query, userID, string(provider)); err != nil {
		if err == sql.ErrNoRows {
			return nil, domain.ErrProviderKeyMissing
		}
		return nil, fmt.Errorf("failed to get provider key: %w", err)
	}

	return &key, nil
}

// SaveProviderKey upserts a customer's encrypted provider key.
// Uses ON CONFLICT on (user_id, provider) to update if already exists.
func (r *providerKeyRepository) SaveProviderKey(ctx context.Context, userID string, provider domain.ProviderID, encryptedKey string, keyHint string) error {
	const query = `
		INSERT INTO customer_provider_keys (user_id, provider, encrypted_key, key_hint)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id, provider)
		DO UPDATE SET encrypted_key = EXCLUDED.encrypted_key,
		              key_hint = EXCLUDED.key_hint,
		              updated_at = NOW()
	`

	if _, err := r.db.ExecContext(ctx, query, userID, string(provider), encryptedKey, keyHint); err != nil {
		return fmt.Errorf("failed to save provider key: %w", err)
	}

	return nil
}

// DeleteProviderKey hard deletes a customer's provider key.
func (r *providerKeyRepository) DeleteProviderKey(ctx context.Context, userID string, provider domain.ProviderID) error {
	const query = `
		DELETE FROM customer_provider_keys
		WHERE user_id = $1 AND provider = $2
	`

	res, err := r.db.ExecContext(ctx, query, userID, string(provider))
	if err != nil {
		return fmt.Errorf("failed to delete provider key: %w", err)
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return domain.ErrProviderKeyMissing
	}

	return nil
}
