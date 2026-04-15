package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/mr-isik/edgemask-backend/internal/domain"
)

// embeddingService calls the OpenAI embeddings API.
// Zero-trust: no API key is stored — the caller provides the key per request.
type embeddingService struct {
	client   *http.Client
	baseURL  string
	model    string
	endpoint string
}

// NewEmbeddingService creates an EmbeddingService. No API key is stored.
func NewEmbeddingService(baseURL string, model string) domain.EmbeddingService {
	trimmed := strings.TrimRight(baseURL, "/")
	return &embeddingService{
		client:   &http.Client{},
		baseURL:  trimmed,
		model:    model,
		endpoint: trimmed + "/v1/embeddings",
	}
}

type embeddingRequest struct {
	Model string `json:"model"`
	Input string `json:"input"`
}

type embeddingResponse struct {
	Data []struct {
		Embedding []float32 `json:"embedding"`
	} `json:"data"`
}

// Embed generates an embedding vector for the given text.
// The apiKey is the caller's provider key, forwarded directly — never stored.
func (s *embeddingService) Embed(ctx context.Context, text string, apiKey string) ([]float32, error) {
	body, err := json.Marshal(embeddingRequest{
		Model: s.model,
		Input: text,
	})
	if err != nil {
		return nil, fmt.Errorf("failed embedding request encode: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed embedding request build: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed embedding request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("embedding upstream error: status=%d body=%s", resp.StatusCode, string(respBody))
	}

	var out embeddingResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("failed embedding response decode: %w", err)
	}
	if len(out.Data) == 0 || len(out.Data[0].Embedding) == 0 {
		return nil, fmt.Errorf("embedding upstream returned empty vector")
	}
	return out.Data[0].Embedding, nil
}
