package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/mr-isik/edgemask-backend/internal/domain"
)

type semanticCacheRepository struct {
	db *sqlx.DB
}

func NewSemanticCacheRepository(db *sqlx.DB) domain.SemanticCacheRepository {
	return &semanticCacheRepository{db: db}
}

type semanticCacheHitRow struct {
	ResponseKey string  `db:"response_key"`
	Distance    float64 `db:"distance"`
}

func (r *semanticCacheRepository) FindNearest(ctx context.Context, req domain.SemanticLookupRequest) (*domain.SemanticCacheHit, error) {
	if len(req.Embedding) == 0 {
		return nil, nil
	}

	const query = `
		SELECT response_key, (embedding <=> $4::vector) AS distance
		FROM semantic_cache_entries
		WHERE user_id = $1
		  AND provider = $2
		  AND model = $3
		  AND expires_at > $5
		  AND (embedding <=> $4::vector) <= $6
		ORDER BY embedding <=> $4::vector
		LIMIT 1
	`

	var row semanticCacheHitRow
	err := r.db.GetContext(ctx, &row, query, req.UserID, string(req.ProviderID), req.Model, vectorLiteral(req.Embedding), req.Now, req.MaxDistance)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed semantic lookup: %w", err)
	}

	return &domain.SemanticCacheHit{
		ResponseKey: row.ResponseKey,
		Distance:    row.Distance,
	}, nil
}

func (r *semanticCacheRepository) UpsertEntry(ctx context.Context, entry domain.SemanticCacheEntry) error {
	const query = `
		INSERT INTO semantic_cache_entries (
			user_id, provider, model, prompt_hash, prompt_text, embedding, response_key, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6::vector, $7, $8)
		ON CONFLICT (user_id, provider, model, prompt_hash)
		DO UPDATE SET
			prompt_text = EXCLUDED.prompt_text,
			embedding = EXCLUDED.embedding,
			response_key = EXCLUDED.response_key,
			expires_at = EXCLUDED.expires_at,
			created_at = NOW()
	`

	_, err := r.db.ExecContext(
		ctx,
		query,
		entry.UserID,
		string(entry.ProviderID),
		entry.Model,
		entry.PromptHash,
		entry.PromptText,
		vectorLiteral(entry.Embedding),
		entry.ResponseKey,
		entry.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("failed semantic cache upsert: %w", err)
	}
	return nil
}

func vectorLiteral(v []float32) string {
	if len(v) == 0 {
		return "[]"
	}
	out := make([]byte, 0, len(v)*8)
	out = append(out, '[')
	for i, f := range v {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, []byte(fmt.Sprintf("%f", f))...)
	}
	out = append(out, ']')
	return string(out)
}
