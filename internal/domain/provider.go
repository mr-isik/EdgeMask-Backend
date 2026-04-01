package domain

import (
	"context"
	"io"
	"net/http"
)

type ProviderID string

const (
	ProviderOpenAI    ProviderID = "openai"
	ProviderAnthropic ProviderID = "anthropic"
	ProviderGemini    ProviderID = "gemini"
)

type LLMProvider interface {
	Forward(ctx context.Context, scrubbedBody []byte, apiKey string, headers http.Header) (body io.ReadCloser, respHeaders http.Header, statusCode int, err error)

	Name() ProviderID
}
