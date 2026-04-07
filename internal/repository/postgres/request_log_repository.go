package postgres

import (
	"context"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/mr-isik/edgemask-backend/internal/domain"
)

// requestLogRepository implements domain.RequestLogRepository backed by PostgreSQL.
type requestLogRepository struct {
	db *sqlx.DB
}

// NewRequestLogRepository creates a new PostgreSQL-backed RequestLogRepository.
func NewRequestLogRepository(db *sqlx.DB) domain.RequestLogRepository {
	return &requestLogRepository{db: db}
}

// InsertLog inserts a new request log record.
// Designed to be called from a goroutine for non-blocking operation.
func (r *requestLogRepository) InsertLog(ctx context.Context, log *domain.RequestLog) error {
	const query = `
		INSERT INTO request_logs (user_id, api_key_prefix, model_used, provider, tokens_processed, pii_detected, semantic_cache_hit, scrubbed_items, latency_ms)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	if _, err := r.db.ExecContext(ctx, query,
		log.UserID,
		log.APIKeyPrefix,
		log.ModelUsed,
		log.Provider,
		log.TokensProcessed,
		log.PIIDetected,
		log.SemanticCacheHit,
		pq.Array(log.ScrubbedItems),
		log.LatencyMs,
	); err != nil {
		return fmt.Errorf("failed to insert request log: %w", err)
	}

	return nil
}

// GetLogs returns paginated request logs for a given user.
func (r *requestLogRepository) GetLogs(ctx context.Context, userID string, filter domain.RequestLogFilter) (*domain.RequestLogPage, error) {
	// Normalize pagination defaults.
	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.PerPage < 1 {
		filter.PerPage = 20
	}
	if filter.PerPage > 100 {
		filter.PerPage = 100
	}
	offset := (filter.Page - 1) * filter.PerPage

	// ── Count query ────────────────────────────────────────────────────
	countQuery := `SELECT COUNT(*) FROM request_logs WHERE user_id = $1`
	countArgs := []interface{}{userID}
	argIdx := 2

	if filter.PIIOnly {
		countQuery += fmt.Sprintf(` AND pii_detected = $%d`, argIdx)
		countArgs = append(countArgs, true)
		argIdx++
	}

	var total int64
	if err := r.db.GetContext(ctx, &total, countQuery, countArgs...); err != nil {
		return nil, fmt.Errorf("failed to count request logs: %w", err)
	}

	// ── Data query ─────────────────────────────────────────────────────
	dataQuery := `
		SELECT id, user_id, api_key_prefix, model_used, provider,
		       tokens_processed, pii_detected, semantic_cache_hit, scrubbed_items, latency_ms, created_at
		FROM request_logs
		WHERE user_id = $1
	`
	dataArgs := []interface{}{userID}
	dataArgIdx := 2

	if filter.PIIOnly {
		dataQuery += fmt.Sprintf(` AND pii_detected = $%d`, dataArgIdx)
		dataArgs = append(dataArgs, true)
		dataArgIdx++
	}

	dataQuery += fmt.Sprintf(` ORDER BY created_at DESC LIMIT $%d OFFSET $%d`, dataArgIdx, dataArgIdx+1)
	dataArgs = append(dataArgs, filter.PerPage, offset)

	rows, err := r.db.QueryxContext(ctx, dataQuery, dataArgs...)
	if err != nil {
		return nil, fmt.Errorf("failed to query request logs: %w", err)
	}
	defer rows.Close()

	var logs []domain.RequestLog
	for rows.Next() {
		var log domain.RequestLog
		if err := rows.Scan(
			&log.ID,
			&log.UserID,
			&log.APIKeyPrefix,
			&log.ModelUsed,
			&log.Provider,
			&log.TokensProcessed,
			&log.PIIDetected,
			&log.SemanticCacheHit,
			pq.Array(&log.ScrubbedItems),
			&log.LatencyMs,
			&log.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan request log: %w", err)
		}
		logs = append(logs, log)
	}

	if logs == nil {
		logs = []domain.RequestLog{}
	}

	return &domain.RequestLogPage{
		TotalRecords: total,
		Page:         filter.Page,
		Logs:         logs,
	}, nil
}
