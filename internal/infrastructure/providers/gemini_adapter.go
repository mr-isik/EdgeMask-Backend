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

// geminiAdapter implements domain.LLMProvider for Google's Gemini API.
// Zero-trust bypass: headers are forwarded as-is.
// Gemini uses ?key= query param — extracted from the Authorization header.
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

// extractBearerToken extracts the raw token from an "Authorization: Bearer <token>" header value.
func extractBearerToken(authHeader string) string {
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
		return strings.TrimSpace(parts[1])
	}
	return strings.TrimSpace(authHeader)
}

// Forward sends the scrubbed body to Google's Gemini generateContent endpoint.
// Gemini requires the API key as a ?key= query param; it is extracted from the
// caller's Authorization header (Bearer <gemini-key>) — never stored by EdgeMask.
func (a *geminiAdapter) Forward(ctx context.Context, scrubbedBody []byte, headers http.Header) (io.ReadCloser, http.Header, int, error) {
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

	// Gemini auth: extract key from Authorization header (Bearer <key>)
	apiKey := extractBearerToken(headers.Get("Authorization"))
	url := fmt.Sprintf("%s/v1beta/models/%s:%s", a.baseURL, model, action)
	if apiKey != "" {
		url += "?key=" + apiKey
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(translatedBody))
	if err != nil {
		return nil, nil, 0, fmt.Errorf("gemini: failed to create request: %w", err)
	}

	// Copy all incoming headers — pure bypass (Authorization itself is harmless for Gemini)
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

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, nil, http.StatusBadGateway, fmt.Errorf("gemini: upstream request failed: %w", err)
	}

	return resp.Body, resp.Header, resp.StatusCode, nil
}
