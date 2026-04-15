package providers

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mr-isik/edgemask-backend/internal/domain"
)

// openAIAdapter implements domain.LLMProvider for the OpenAI API.
// Zero-trust bypass: headers are forwarded as-is. No key injection.
type openAIAdapter struct {
	baseURL string
	client  *http.Client
}

// NewOpenAIAdapter creates a new OpenAI provider adapter.
func NewOpenAIAdapter(baseURL string) domain.LLMProvider {
	return &openAIAdapter{
		baseURL: baseURL,
		client: &http.Client{
			Timeout: 5 * time.Minute,
		},
	}
}

func (a *openAIAdapter) Name() domain.ProviderID {
	return domain.ProviderOpenAI
}

// Forward sends the scrubbed body to OpenAI, forwarding all headers as-is.
// The caller's Authorization header (Bearer <openai-key>) is passed through directly.
// Only X-EdgeMask-Key is stripped upstream (by proxy handler before this call).
func (a *openAIAdapter) Forward(ctx context.Context, scrubbedBody []byte, headers http.Header) (io.ReadCloser, http.Header, int, error) {
	url := fmt.Sprintf("%s/v1/chat/completions", a.baseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(scrubbedBody))
	if err != nil {
		return nil, nil, 0, fmt.Errorf("openai: failed to create request: %w", err)
	}

	// Copy all incoming headers — pure bypass
	for key, values := range headers {
		// Skip hop-by-hop and internal EdgeMask headers
		lower := strings.ToLower(key)
		if lower == "x-edgemask-key" || lower == "host" || lower == "content-length" {
			continue
		}
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}
	// Ensure correct content type for the translated body
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, nil, http.StatusBadGateway, fmt.Errorf("openai: upstream request failed: %w", err)
	}

	return resp.Body, resp.Header, resp.StatusCode, nil
}
