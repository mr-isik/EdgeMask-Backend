package handlers

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"strings"
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
func NewProxyHandler(
	app fiber.Router,
	proxyService domain.ProxyService,
	requestLogRepo domain.RequestLogRepository,
) {
	h := &ProxyHandler{
		proxyService:   proxyService,
		requestLogRepo: requestLogRepo,
	}

	app.Post("/proxy/:provider", h.HandleProxy)
	app.Post("/proxy/:provider/*", h.HandleProxy)
}

// HandleProxy godoc
// @Summary      Proxy request to LLM provider
// @Description  Scrubs PII from the request body and forwards the request to the selected LLM provider. Zero-trust bypass: all headers (Authorization, custom headers, etc.) are forwarded as-is — pass your provider API key in Authorization. Only X-EdgeMask-Key is stripped before forwarding.
// @Tags         Proxy
// @Accept       json
// @Produce      json
// @Produce      text/event-stream
// @Param        provider        path      string    true   "LLM provider"  Enums(openai, anthropic, gemini)
// @Param        X-EdgeMask-Key  header    string    true   "EdgeMask API key (edgemask_live_...)"
// @Param        Authorization   header    string    false  "Provider API key forwarded directly to upstream (e.g. Bearer sk-...)"
// @Param        body            body      ProxyReq  true   "OpenAI-compatible chat completion request"
// @Success      200             {string}  string    "Proxied response (may be SSE stream)"
// @Failure      400             {object}  ErrorResponse
// @Failure      401             {object}  ErrorResponse
// @Failure      502             {object}  ErrorResponse
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

	modelUsed := extractModel(rawBody)

	// Build forwarded headers: copy all incoming headers, strip only X-EdgeMask-Key
	// so it does not leak to the upstream provider.
	reqHeaders := make(map[string][]string)
	for k, v := range c.GetReqHeaders() {
		if strings.EqualFold(k, "X-EdgeMask-Key") {
			continue
		}
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
	latencyMs := int(time.Since(start).Milliseconds())
	apiKeyPrefix, _ := c.Locals("api_key_prefix").(string)

	go func() {
		logEntry := &domain.RequestLog{
			UserID:           userID,
			APIKeyPrefix:     apiKeyPrefix,
			ModelUsed:        modelUsed,
			Provider:         providerStr,
			TokensProcessed:  fwdResult.TokensProcessed,
			PIIDetected:      fwdResult.PIIDetected,
			SemanticCacheHit: fwdResult.SemanticCacheHit,
			ScrubbedItems:    fwdResult.ScrubbedItems,
			LatencyMs:        latencyMs,
		}
		if logEntry.ScrubbedItems == nil {
			logEntry.ScrubbedItems = []string{}
		}
		if insertErr := h.requestLogRepo.InsertLog(context.Background(), logEntry); insertErr != nil {
			logger.Error("Failed to insert request log: ", insertErr)
		}
	}()

	for k, vals := range respHeaders {
		kLower := strings.ToLower(k)
		if kLower == "connection" || kLower == "transfer-encoding" || kLower == "content-length" || kLower == "keep-alive" {
			continue
		}
		if len(vals) > 0 {
			c.Set(k, strings.Join(vals, ", "))
		}
	}
	c.Set("Cache-Control", "no-cache")
	c.Set("X-EdgeMask-Provider", providerStr)

	c.Status(fwdResult.StatusCode)
	c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
		defer body.Close()
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

func extractModel(body []byte) string {
	var partial struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &partial); err != nil {
		return ""
	}
	return partial.Model
}
