package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/mr-isik/edgemask-backend/internal/domain"
)

// anthropicAdapter implements domain.LLMProvider for the Anthropic API.
// Stateless — does NOT hold any API key. Key is injected per-request (BYOK).
type anthropicAdapter struct {
	baseURL string
	client  *http.Client
}

// NewAnthropicAdapter creates a new Anthropic provider adapter.
func NewAnthropicAdapter(baseURL string) domain.LLMProvider {
	return &anthropicAdapter{
		baseURL: baseURL,
		client: &http.Client{
			Timeout: 5 * time.Minute,
		},
	}
}

func (a *anthropicAdapter) Name() domain.ProviderID {
	return domain.ProviderAnthropic
}

// ──────────────────────────────────────────────────────────────────────────────
// OpenAI → Anthropic JSON Translation
// ──────────────────────────────────────────────────────────────────────────────

// openAIRequest is the subset of OpenAI's chat completion request we need to translate.
type openAIRequest struct {
	Model       string          `json:"model"`
	Messages    []openAIMessage `json:"messages"`
	MaxTokens   int             `json:"max_tokens,omitempty"`
	Temperature float64         `json:"temperature,omitempty"`
	Stream      bool            `json:"stream,omitempty"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// anthropicRequest is Anthropic's expected message format.
type anthropicRequest struct {
	Model       string             `json:"model"`
	Messages    []anthropicMessage `json:"messages"`
	System      string             `json:"system,omitempty"`
	MaxTokens   int                `json:"max_tokens"`
	Temperature float64            `json:"temperature,omitempty"`
	Stream      bool               `json:"stream,omitempty"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// translateOpenAIToAnthropic converts an OpenAI-format request body to Anthropic format.
func translateOpenAIToAnthropic(body []byte) ([]byte, error) {
	var oReq openAIRequest
	if err := json.Unmarshal(body, &oReq); err != nil {
		return nil, fmt.Errorf("anthropic: failed to parse openai request: %w", err)
	}

	aReq := anthropicRequest{
		Model:       oReq.Model,
		MaxTokens:   oReq.MaxTokens,
		Temperature: oReq.Temperature,
		Stream:      oReq.Stream,
	}

	if aReq.MaxTokens == 0 {
		aReq.MaxTokens = 4096
	}

	for _, msg := range oReq.Messages {
		if msg.Role == "system" {
			if aReq.System != "" {
				aReq.System += "\n"
			}
			aReq.System += msg.Content
		} else {
			aReq.Messages = append(aReq.Messages, anthropicMessage{
				Role:    msg.Role,
				Content: msg.Content,
			})
		}
	}

	return json.Marshal(aReq)
}

// Forward sends the scrubbed body to Anthropic's /v1/messages endpoint.
// apiKey is the customer's own Anthropic key, decrypted at request time.
func (a *anthropicAdapter) Forward(ctx context.Context, scrubbedBody []byte, apiKey string, headers http.Header) (io.ReadCloser, http.Header, int, error) {
	translatedBody, err := translateOpenAIToAnthropic(scrubbedBody)
	if err != nil {
		return nil, nil, http.StatusBadRequest, err
	}

	url := fmt.Sprintf("%s/v1/messages", a.baseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(translatedBody))
	if err != nil {
		return nil, nil, 0, fmt.Errorf("anthropic: failed to create request: %w", err)
	}

	// Inject customer's API key via Anthropic's header convention
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	if accept := headers.Get("Accept"); accept != "" {
		req.Header.Set("Accept", accept)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, nil, http.StatusBadGateway, fmt.Errorf("anthropic: upstream request failed: %w", err)
	}

	return resp.Body, resp.Header, resp.StatusCode, nil
}
