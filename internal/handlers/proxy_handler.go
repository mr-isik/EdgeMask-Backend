package handlers

import (
	"bufio"
	"io"

	"github.com/gofiber/fiber/v2"
	"github.com/mr-isik/edgemask-backend/internal/domain"
	"github.com/mr-isik/edgemask-backend/pkg/logger"
)

// ProxyHandler handles proxying requests to LLM providers.
type ProxyHandler struct {
	proxyService domain.ProxyService
}

// NewProxyHandler creates a new ProxyHandler and registers routes.
func NewProxyHandler(app fiber.Router, proxyService domain.ProxyService) {
	h := &ProxyHandler{proxyService: proxyService}

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

	headers := c.GetReqHeaders()
	reqHeaders := make(map[string][]string)
	for k, v := range headers {
		reqHeaders[k] = v
	}

	body, respHeaders, statusCode, err := h.proxyService.Forward(
		c.Context(),
		userID,
		providerID,
		rawBody,
		reqHeaders,
	)
	if err != nil {
		logger.Error("Proxy error: ", err)
		if statusCode == 0 {
			statusCode = fiber.StatusBadGateway
		}
		return c.Status(statusCode).JSON(fiber.Map{
			"error": err.Error(),
		})
	}
	defer body.Close()

	if ct := respHeaders.Get("Content-Type"); ct != "" {
		c.Set("Content-Type", ct)
	}
	c.Set("Cache-Control", "no-cache")
	c.Set("X-EdgeMask-Provider", providerStr)

	c.Status(statusCode)
	c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
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
