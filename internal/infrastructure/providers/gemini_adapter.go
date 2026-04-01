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

// geminiAdapter implements domain.LLMProvider for Google's Gemini API.
// Stateless — does NOT hold any API key. Key is injected per-request (BYOK).
type geminiAdapter struct {
	baseURL string
	client  *http.Client
}

// NewGeminiAdapter creates a new Gemini provider adapter.
func NewGeminiAdapter(baseURL string) domain.LLMProvider {
	return &geminiAdapter{
		baseURL: baseURL,
		client: &http.Client{
			Timeout: 5 * time.Minute,
		},
	}
}

func (a *geminiAdapter) Name() domain.ProviderID {
	return domain.ProviderGemini
}

// ──────────────────────────────────────────────────────────────────────────────
// OpenAI → Gemini JSON Translation
// ──────────────────────────────────────────────────────────────────────────────

type geminiRequest struct {
	Contents          []geminiContent        `json:"contents"`
	SystemInstruction *geminiContent         `json:"systemInstruction,omitempty"`
	GenerationConfig  *geminiGenerationConfig `json:"generationConfig,omitempty"`
}

type geminiContent struct {
	Role  string       `json:"role"`
	Parts []geminiPart `json:"parts"`
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiGenerationConfig struct {
	Temperature     float64 `json:"temperature,omitempty"`
	MaxOutputTokens int     `json:"maxOutputTokens,omitempty"`
}

func translateOpenAIToGemini(body []byte) ([]byte, string, bool, error) {
	var oReq openAIRequest
	if err := json.Unmarshal(body, &oReq); err != nil {
		return nil, "", false, fmt.Errorf("gemini: failed to parse openai request: %w", err)
	}

	gReq := geminiRequest{
		GenerationConfig: &geminiGenerationConfig{
			Temperature:     oReq.Temperature,
			MaxOutputTokens: oReq.MaxTokens,
		},
	}

	for _, msg := range oReq.Messages {
		switch msg.Role {
		case "system":
			gReq.SystemInstruction = &geminiContent{
				Role:  "user",
				Parts: []geminiPart{{Text: msg.Content}},
			}
		case "assistant":
			gReq.Contents = append(gReq.Contents, geminiContent{
				Role:  "model",
				Parts: []geminiPart{{Text: msg.Content}},
			})
		default:
			gReq.Contents = append(gReq.Contents, geminiContent{
				Role:  msg.Role,
				Parts: []geminiPart{{Text: msg.Content}},
			})
		}
	}

	data, err := json.Marshal(gReq)
	return data, oReq.Model, oReq.Stream, err
}

// Forward sends the scrubbed body to Google's Gemini generateContent endpoint.
// apiKey is the customer's own Gemini key, decrypted at request time.
func (a *geminiAdapter) Forward(ctx context.Context, scrubbedBody []byte, apiKey string, headers http.Header) (io.ReadCloser, http.Header, int, error) {
	translatedBody, model, stream, err := translateOpenAIToGemini(scrubbedBody)
	if err != nil {
		return nil, nil, http.StatusBadRequest, err
	}

	if model == "" {
		model = "gemini-2.0-flash"
	}

	action := "generateContent"
	if stream {
		action = "streamGenerateContent"
	}

	// Inject customer's API key as query param (Google's convention)
	url := fmt.Sprintf("%s/v1beta/models/%s:%s?key=%s", a.baseURL, model, action, apiKey)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(translatedBody))
	if err != nil {
		return nil, nil, 0, fmt.Errorf("gemini: failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	if accept := headers.Get("Accept"); accept != "" {
		req.Header.Set("Accept", accept)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, nil, http.StatusBadGateway, fmt.Errorf("gemini: upstream request failed: %w", err)
	}

	return resp.Body, resp.Header, resp.StatusCode, nil
}
