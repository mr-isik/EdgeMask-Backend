package postgres

import (
	"context"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/mr-isik/edgemask-backend/internal/domain"
)

type webhookEventRepository struct {
	db *sqlx.DB
}

func NewWebhookEventRepository(db *sqlx.DB) domain.WebhookEventRepository {
	return &webhookEventRepository{db: db}
}

func (r *webhookEventRepository) MarkProcessed(ctx context.Context, webhookID string, eventType string, payload []byte) (bool, error) {
	const query = `
		INSERT INTO dodo_webhook_events (webhook_id, event_type, payload)
		VALUES ($1, $2, $3)
		ON CONFLICT (webhook_id) DO NOTHING
	`

	result, err := r.db.ExecContext(ctx, query, webhookID, eventType, payload)
	if err != nil {
		return false, fmt.Errorf("failed to persist webhook idempotency record: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to inspect webhook insert result: %w", err)
	}
	return affected == 0, nil
}
