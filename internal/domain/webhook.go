package domain

import "context"

// WebhookEventRepository provides idempotency storage for webhook deliveries.
type WebhookEventRepository interface {
	MarkProcessed(ctx context.Context, webhookID string, eventType string, payload []byte) (alreadyProcessed bool, err error)
}
