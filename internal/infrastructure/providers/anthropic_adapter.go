package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mr-isik/edgemask-backend/internal/domain"
)

// anthropicAdapter implements domain.LLMProvider for the Anthropic API.
// Zero-trust bypass: headers are forwarded as-is. No key injection.
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
// All incoming headers are forwarded as-is (user sends x-api-key themselves).
// anthropic-version is set as a default if not already present.
func (a *anthropicAdapter) Forward(ctx context.Context, scrubbedBody []byte, headers http.Header) (io.ReadCloser, http.Header, int, error) {
	translatedBody, err := translateOpenAIToAnthropic(scrubbedBody)
	if err != nil {
		return nil, nil, http.StatusBadRequest, err
	}

	url := fmt.Sprintf("%s/v1/messages", a.baseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(translatedBody))
	if err != nil {
		return nil, nil, 0, fmt.Errorf("anthropic: failed to create request: %w", err)
	}

	// Copy all incoming headers — pure bypass
	for key, values := range headers {
		lower := strings.ToLower(key)
		if lower == "x-edgemask-key" || lower == "host" || lower == "content-length" {
			continue
		}
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}
	req.Header.Set("Content-Type", "application/json")
	// Set the required Anthropic version header if not already provided by the caller
	if req.Header.Get("anthropic-version") == "" {
		req.Header.Set("anthropic-version", "2023-06-01")
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, nil, http.StatusBadGateway, fmt.Errorf("anthropic: upstream request failed: %w", err)
	}

	return resp.Body, resp.Header, resp.StatusCode, nil
}
