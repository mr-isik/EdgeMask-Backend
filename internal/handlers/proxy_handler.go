package handlers

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/mr-isik/edgemask-backend/internal/domain"
	"github.com/mr-isik/edgemask-backend/pkg/logger"
)

// ProxyHandler handles proxying requests to LLM providers.
type ProxyHandler struct {
	proxyService   domain.ProxyService
	requestLogRepo domain.RequestLogRepository
}

// NewProxyHandler creates a new ProxyHandler and registers routes.
func NewProxyHandler(app fiber.Router, proxyService domain.ProxyService, requestLogRepo domain.RequestLogRepository) {
	h := &ProxyHandler{
		proxyService:   proxyService,
		requestLogRepo: requestLogRepo,
	}

	app.Post("/proxy/:provider", h.HandleProxy)
	app.Post("/proxy/:provider/*", h.HandleProxy)
}

// HandleProxy godoc
// @Summary      Proxy request to LLM provider
// @Description  Scrubs PII from the request body, then forwards it to the selected LLM provider (openai, anthropic, gemini) using the customer's own API key. Supports streaming (SSE) responses.
// @Tags         Proxy
// @Accept       json
// @Produce      json
// @Produce      text/event-stream
// @Param        provider  path      string            true   "LLM provider"  Enums(openai, anthropic, gemini)
// @Param        body      body      ProxyReq     true   "OpenAI-compatible chat completion request"
// @Success      200       {string}  string       "Proxied response (may be SSE stream)"
// @Failure      400       {object}  ErrorResponse
// @Failure      401       {object}  ErrorResponse
// @Failure      502       {object}  ErrorResponse
// @Security     EdgeMaskAPIKey
// @Router       /v1/proxy/{provider} [post]
func (h *ProxyHandler) HandleProxy(c *fiber.Ctx) error {
	start := time.Now()

	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "authentication required",
		})
	}

	providerStr := c.Params("provider")
	if providerStr == "" {
		providerStr = c.Get("X-EdgeMask-Provider")
	}
	if providerStr == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "provider is required: use URL path (/v1/proxy/:provider) or X-EdgeMask-Provider header",
		})
	}
	providerID := domain.ProviderID(providerStr)

	rawBody := c.Body()
	if len(rawBody) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "request body is required",
		})
	}

	// Extract model name from request body for logging (best-effort).
	modelUsed := extractModel(rawBody)

	headers := c.GetReqHeaders()
	reqHeaders := make(map[string][]string)
	for k, v := range headers {
		reqHeaders[k] = v
	}

	body, respHeaders, fwdResult, err := h.proxyService.Forward(
		c.Context(),
		userID,
		providerID,
		rawBody,
		reqHeaders,
	)
	if err != nil {
		logger.Error("Proxy error: ", err)
		return c.Status(fwdResult.StatusCode).JSON(fiber.Map{
			"error": err.Error(),
		})
	}
	// ── Async request log (only metadata, NEVER raw prompts) ───────────
	latencyMs := int(time.Since(start).Milliseconds())
	apiKeyPrefix, _ := c.Locals("api_key_prefix").(string)

	go func() {
		logEntry := &domain.RequestLog{
			UserID:          userID,
			APIKeyPrefix:    apiKeyPrefix,
			ModelUsed:       modelUsed,
			Provider:        providerStr,
			TokensProcessed: 0, // can be enriched later from response
			PIIDetected:     fwdResult.PIIDetected,
			ScrubbedItems:   fwdResult.ScrubbedItems,
			LatencyMs:       latencyMs,
		}
		if logEntry.ScrubbedItems == nil {
			logEntry.ScrubbedItems = []string{}
		}
		if insertErr := h.requestLogRepo.InsertLog(context.Background(), logEntry); insertErr != nil {
			logger.Error("Failed to insert request log: ", insertErr)
		}
	}()

	if ct := respHeaders.Get("Content-Type"); ct != "" {
		c.Set("Content-Type", ct)
	}
	c.Set("Cache-Control", "no-cache")
	c.Set("X-EdgeMask-Provider", providerStr)

	c.Status(fwdResult.StatusCode)
	c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
		defer body.Close() // Ensure body is closed when stream writer finishes
		buf := make([]byte, 4096)
		for {
			n, readErr := body.Read(buf)
			if n > 0 {
				if _, writeErr := w.Write(buf[:n]); writeErr != nil {
					logger.Error("Stream write error: ", writeErr)
					return
				}
				if flushErr := w.Flush(); flushErr != nil {
					logger.Error("Stream flush error: ", flushErr)
					return
				}
			}
			if readErr != nil {
				if readErr != io.EOF {
					logger.Error("Stream read error: ", readErr)
				}
				return
			}
		}
	})

	return nil
}

// extractModel tries to read the "model" field from the JSON body.
// Returns an empty string if parsing fails — this is best-effort.
func extractModel(body []byte) string {
	var partial struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &partial); err != nil {
		return ""
	}
	return partial.Model
}

