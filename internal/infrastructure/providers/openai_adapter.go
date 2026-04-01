package providers

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/mr-isik/edgemask-backend/internal/domain"
)

// openAIAdapter implements domain.LLMProvider for the OpenAI API.
// Stateless — does NOT hold any API key. Key is injected per-request (BYOK).
type openAIAdapter struct {
	baseURL string
	client  *http.Client
}

// NewOpenAIAdapter creates a new OpenAI provider adapter.
func NewOpenAIAdapter(baseURL string) domain.LLMProvider {
	return &openAIAdapter{
		baseURL: baseURL,
		client: &http.Client{
			Timeout: 5 * time.Minute, // Long timeout for streaming responses
		},
	}
}

func (a *openAIAdapter) Name() domain.ProviderID {
	return domain.ProviderOpenAI
}

// Forward sends the scrubbed body to OpenAI's /v1/chat/completions endpoint.
// apiKey is the customer's own OpenAI key, decrypted at request time.
func (a *openAIAdapter) Forward(ctx context.Context, scrubbedBody []byte, apiKey string, headers http.Header) (io.ReadCloser, http.Header, int, error) {
	url := fmt.Sprintf("%s/v1/chat/completions", a.baseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(scrubbedBody))
	if err != nil {
		return nil, nil, 0, fmt.Errorf("openai: failed to create request: %w", err)
	}

	// Inject customer's API key
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))

	if accept := headers.Get("Accept"); accept != "" {
		req.Header.Set("Accept", accept)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, nil, http.StatusBadGateway, fmt.Errorf("openai: upstream request failed: %w", err)
	}

	return resp.Body, resp.Header, resp.StatusCode, nil
}
