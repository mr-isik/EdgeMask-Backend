package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
	"github.com/mr-isik/edgemask-backend/internal/domain"
)

type userBillingRepository struct {
	db *sqlx.DB
}

func NewUserBillingRepository(db *sqlx.DB) domain.UserBillingRepository {
	return &userBillingRepository{db: db}
}

func (r *userBillingRepository) GetDodoCustomerID(ctx context.Context, userID string) (string, error) {
	const query = `SELECT dodo_customer_id FROM public.users WHERE id = $1`

	var customerID sql.NullString
	if err := r.db.GetContext(ctx, &customerID, query, userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", domain.ErrBillingMappingNotFound
		}
		return "", fmt.Errorf("failed to read dodo customer mapping: %w", err)
	}
	if !customerID.Valid || strings.TrimSpace(customerID.String) == "" {
		return "", domain.ErrBillingMappingNotFound
	}
	return customerID.String, nil
}
