package handlers

import (
	"context"
	"encoding/json"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/mr-isik/edgemask-backend/internal/domain"
	"github.com/mr-isik/edgemask-backend/internal/services"
	"github.com/mr-isik/edgemask-backend/pkg/logger"
)

type DodoWebhookHandler struct {
	secret      string
	tolerance   time.Duration
	webhookRepo domain.WebhookEventRepository
}

func NewDodoWebhookHandler(
	app fiber.Router,
	secret string,
	tolerance time.Duration,
	webhookRepo domain.WebhookEventRepository,
) {
	h := &DodoWebhookHandler{
		secret:      secret,
		tolerance:   tolerance,
		webhookRepo: webhookRepo,
	}
	app.Post("/webhooks/dodo", h.HandleWebhook)
}

type dodoWebhookEnvelope struct {
	Type      string          `json:"type"`
	Timestamp string          `json:"timestamp"`
	Data      json.RawMessage `json:"data"`
}

// HandleWebhook godoc
// @Summary      Dodo Payments webhook receiver
// @Description  Verifies Svix signature headers and accepts Dodo webhook events.
// @Tags         Billing
// @Accept       json
// @Produce      json
// @Param        webhook-id         header    string          true   "Unique webhook delivery ID"
// @Param        webhook-signature  header    string          true   "Svix signature header"
// @Param        webhook-timestamp  header    string          true   "Webhook timestamp (unix seconds or RFC3339)"
// @Param        body               body      DodoWebhookReq  true   "Webhook payload"
// @Success      200                {object}  DodoWebhookResp
// @Failure      400                {object}  ErrorResponse
// @Failure      401                {object}  ErrorResponse
// @Failure      500                {object}  ErrorResponse
// @Router       /webhooks/dodo [post]
func (h *DodoWebhookHandler) HandleWebhook(c *fiber.Ctx) error {
	rawBody := c.Body()
	webhookID := c.Get("webhook-id")
	webhookSig := c.Get("webhook-signature")
	webhookTs := c.Get("webhook-timestamp")

	if err := services.VerifyDodoWebhook(h.secret, webhookID, webhookTs, webhookSig, rawBody, h.tolerance); err != nil {
		logger.Error("Dodo webhook verification failed: ", err)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid webhook signature"})
	}

	var payload dodoWebhookEnvelope
	if err := json.Unmarshal(rawBody, &payload); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid webhook payload"})
	}

	alreadyProcessed, err := h.webhookRepo.MarkProcessed(context.Background(), webhookID, payload.Type, rawBody)
	if err != nil {
		logger.Error("Failed to persist webhook event id: ", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to persist webhook"})
	}
	if alreadyProcessed {
		return c.JSON(fiber.Map{"received": true, "duplicate": true})
	}

	// Business-specific webhook actions can be extended here per event type.
	switch payload.Type {
	case "payment.succeeded",
		"payment.failed",
		"subscription.active",
		"subscription.updated",
		"subscription.cancelled",
		"subscription.expired",
		"subscription.renewed":
		logger.Info("Dodo webhook received: ", payload.Type)
	default:
		logger.Info("Dodo webhook received (unhandled type): ", payload.Type)
	}

	return c.JSON(fiber.Map{"received": true})
}
