package postgres

import (
	"context"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/mr-isik/edgemask-backend/internal/domain"
)

// analyticsRepository implements domain.AnalyticsRepository backed by PostgreSQL.
type analyticsRepository struct {
	db *sqlx.DB
}

// NewAnalyticsRepository creates a new PostgreSQL-backed AnalyticsRepository.
func NewAnalyticsRepository(db *sqlx.DB) domain.AnalyticsRepository {
	return &analyticsRepository{db: db}
}

// LogUsage inserts a new usage log record.
// This is designed to be called from a goroutine for non-blocking operation.
func (r *analyticsRepository) LogUsage(ctx context.Context, log *domain.UsageLog) error {
	const query = `
		INSERT INTO usage_logs (user_id, provider, pii_redacted, tokens_used, status_code, latency_ms)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	if _, err := r.db.ExecContext(ctx, query,
		log.UserID, log.Provider, log.PIIRedacted,
		log.TokensUsed, log.StatusCode, log.LatencyMs,
	); err != nil {
		return fmt.Errorf("failed to log usage: %w", err)
	}

	return nil
}

// GetAggregateStats returns total statistics for a given user.
func (r *analyticsRepository) GetAggregateStats(ctx context.Context, userID string) (*domain.AggregateStats, error) {
	const query = `
		SELECT
			COALESCE(COUNT(*), 0) AS total_requests,
			COALESCE(SUM(cardinality(scrubbed_items)), 0) AS total_pii_redacted,
			COALESCE(SUM(tokens_processed), 0) AS total_tokens_used,
			COALESCE(SUM(CASE WHEN semantic_cache_hit THEN 1 ELSE 0 END), 0) AS total_semantic_cache_hits,
			COALESCE(SUM(CASE WHEN semantic_cache_hit THEN 0 ELSE 1 END), 0) AS total_semantic_cache_misses,
			COALESCE(AVG(CASE WHEN semantic_cache_hit THEN 1.0 ELSE 0.0 END), 0)::float8 AS semantic_cache_hit_rate
		FROM request_logs
		WHERE user_id = $1
	`

	var stats domain.AggregateStats
	if err := r.db.GetContext(ctx, &stats, query, userID); err != nil {
		return nil, fmt.Errorf("failed to get aggregate stats: %w", err)
	}

	return &stats, nil
}

// GetUsageChart returns time-series data grouped by the given interval.
func (r *analyticsRepository) GetUsageChart(ctx context.Context, userID string, interval string, days int) ([]domain.UsageDataPoint, error) {
	// PostgreSQL date_trunc supports 'hour' and 'day'
	const query = `
		SELECT
			TO_CHAR(date_trunc($1, created_at), 'YYYY-MM-DD"T"HH24:MI') AS period,
			COUNT(*) AS requests,
			COALESCE(SUM(cardinality(scrubbed_items)), 0) AS pii_redacted,
			COALESCE(SUM(tokens_processed), 0) AS tokens_used,
			COALESCE(SUM(CASE WHEN semantic_cache_hit THEN 1 ELSE 0 END), 0) AS semantic_cache_hits,
			COALESCE(SUM(CASE WHEN semantic_cache_hit THEN 0 ELSE 1 END), 0) AS semantic_cache_misses
		FROM request_logs
		WHERE user_id = $2
		  AND created_at >= NOW() - ($3 || ' days')::INTERVAL
		GROUP BY date_trunc($1, created_at)
		ORDER BY period ASC
	`

	var dataPoints []domain.UsageDataPoint
	if err := r.db.SelectContext(ctx, &dataPoints, query, interval, userID, fmt.Sprintf("%d", days)); err != nil {
		return nil, fmt.Errorf("failed to get usage chart: %w", err)
	}

	if dataPoints == nil {
		dataPoints = []domain.UsageDataPoint{}
	}

	return dataPoints, nil
}
