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

// LLMProvider forwards a scrubbed request to a specific upstream LLM API.
// Zero-trust bypass: all headers (auth, custom) are passed through as-is.
// No API keys are extracted or injected by EdgeMask.
type LLMProvider interface {
	Forward(ctx context.Context, scrubbedBody []byte, headers http.Header) (body io.ReadCloser, respHeaders http.Header, statusCode int, err error)
	Name() ProviderID
}
