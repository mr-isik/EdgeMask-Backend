package domain

import "context"

// UsageEvent is normalized billable usage emitted by EdgeMask.
type UsageEvent struct {
	UserID           string
	Provider         string
	Model            string
	TokensProcessed  int
	StatusCode       int
	LatencyMs        int
	SemanticCacheHit bool
}

// UserBillingRepository resolves billing mappings for a user.
type UserBillingRepository interface {
	GetDodoCustomerID(ctx context.Context, userID string) (string, error)
}

// BillingService emits usage events to external billing systems.
type BillingService interface {
	RecordUsage(ctx context.Context, event UsageEvent) error
}

type CheckoutSessionRequest struct {
	UserID        string
	ProductID     string
	Quantity      int
	ReturnURL     string
	CancelURL     string
	CustomerEmail string
	CustomerName  string
}

type CheckoutSessionResponse struct {
	SessionID   string
	CheckoutURL string
}

type CheckoutService interface {
	CreateSession(ctx context.Context, req CheckoutSessionRequest) (*CheckoutSessionResponse, error)
	CreateCustomerPortalSession(ctx context.Context, req CustomerPortalSessionRequest) (*CustomerPortalSessionResponse, error)
}

type CustomerPortalSessionRequest struct {
	UserID    string
	ReturnURL string
	SendEmail bool
}

type CustomerPortalSessionResponse struct {
	Link string
}
