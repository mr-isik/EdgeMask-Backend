package services

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mr-isik/edgemask-backend/internal/domain"
	"github.com/mr-isik/edgemask-backend/pkg/logger"
)

// chatMessage is the minimal struct needed to extract user-facing text fields
// from an OpenAI-compatible messages array.
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// scrubResult is the internal return type for scrubMessages.
type scrubResult struct {
	body          []byte
	totalRedacted int
	scrubbedTypes []string
}

// proxyService implements domain.ProxyService.
// Zero-trust bypass: no API keys stored or fetched. All headers flow through as-is.
// Only X-EdgeMask-Key is stripped by the handler before arriving here.
type proxyService struct {
	scrubber           domain.ScrubbingService
	providers          map[domain.ProviderID]domain.LLMProvider
	semanticEnabled    bool
	semanticTTL        time.Duration
	semanticSimilarity float64
	semanticRepo       domain.SemanticCacheRepository
	semanticRespCache  domain.SemanticResponseCache
	embeddingSvc       domain.EmbeddingService
}

// NewProxyService creates a new ProxyService.
func NewProxyService(
	scrubber domain.ScrubbingService,
	semanticEnabled bool,
	semanticTTL time.Duration,
	semanticSimilarity float64,
	semanticRepo domain.SemanticCacheRepository,
	semanticRespCache domain.SemanticResponseCache,
	embeddingSvc domain.EmbeddingService,
	providers ...domain.LLMProvider,
) domain.ProxyService {
	pm := make(map[domain.ProviderID]domain.LLMProvider, len(providers))
	for _, p := range providers {
		pm[p.Name()] = p
		logger.Info("Registered LLM provider: ", string(p.Name()))
	}

	return &proxyService{
		scrubber:           scrubber,
		providers:          pm,
		semanticEnabled:    semanticEnabled,
		semanticTTL:        semanticTTL,
		semanticSimilarity: semanticSimilarity,
		semanticRepo:       semanticRepo,
		semanticRespCache:  semanticRespCache,
		embeddingSvc:       embeddingSvc,
	}
}

type requestMetadata struct {
	Model      string        `json:"model"`
	Messages   []chatMessage `json:"messages"`
	Stream     bool          `json:"stream"`
	PromptText string
}

func extractRequestMetadata(rawBody []byte) (*requestMetadata, error) {
	var meta requestMetadata
	if err := json.Unmarshal(rawBody, &meta); err != nil {
		return nil, err
	}

	var b strings.Builder
	for _, msg := range meta.Messages {
		if strings.TrimSpace(msg.Content) == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString(msg.Role)
		b.WriteString(": ")
		b.WriteString(msg.Content)
	}
	meta.PromptText = b.String()
	return &meta, nil
}

// scrubMessages performs surgical PII redaction on ONLY the messages[].content
// fields of the raw JSON body. All other fields are preserved byte-for-byte.
func (s *proxyService) scrubMessages(rawBody []byte) (*scrubResult, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(rawBody, &top); err != nil {
		return nil, fmt.Errorf("failed to parse request JSON: %w", err)
	}

	msgsRaw, ok := top["messages"]
	if !ok {
		return &scrubResult{body: rawBody}, nil
	}

	var msgs []chatMessage
	if err := json.Unmarshal(msgsRaw, &msgs); err != nil {
		return nil, fmt.Errorf("failed to parse messages array: %w", err)
	}

	totalRedacted := 0
	seen := make(map[string]struct{})
	var allTypes []string

	for i := range msgs {
		result := s.scrubber.Redact(msgs[i].Content)
		if result.Count > 0 {
			msgs[i].Content = result.RedactedText
			totalRedacted += result.Count
			for _, t := range result.ScrubbedTypes {
				if _, exists := seen[t]; !exists {
					seen[t] = struct{}{}
					allTypes = append(allTypes, t)
				}
			}
		}
	}

	if totalRedacted == 0 {
		return &scrubResult{body: rawBody}, nil
	}

	scrubbedMsgs, err := json.Marshal(msgs)
	if err != nil {
		return nil, fmt.Errorf("failed to re-marshal scrubbed messages: %w", err)
	}
	top["messages"] = scrubbedMsgs

	result, err := json.Marshal(top)
	if err != nil {
		return nil, fmt.Errorf("failed to re-marshal request body: %w", err)
	}

	return &scrubResult{
		body:          result,
		totalRedacted: totalRedacted,
		scrubbedTypes: allTypes,
	}, nil
}

// extractBearerKey extracts the raw token from an Authorization: Bearer <token> header.
func extractBearerKey(headers http.Header) string {
	auth := headers.Get("Authorization")
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
		return strings.TrimSpace(parts[1])
	}
	return strings.TrimSpace(auth)
}

// Forward scrubs PII from the request body, runs semantic cache lookup,
// and forwards the request to the provider using the caller's own headers.
// Zero-trust bypass: all headers (minus X-EdgeMask-Key) flow through unmodified.
func (s *proxyService) Forward(
	ctx context.Context,
	userID string,
	providerID domain.ProviderID,
	rawBody []byte,
	headers http.Header,
) (io.ReadCloser, http.Header, domain.ForwardResult, error) {

	empty := domain.ForwardResult{}

	// 1. Select provider adapter
	provider, ok := s.providers[providerID]
	if !ok {
		return nil, nil, domain.ForwardResult{StatusCode: http.StatusBadRequest}, fmt.Errorf("%w: %s", domain.ErrProviderUnknown, providerID)
	}

	// 2. Scrub PII from ONLY the messages[].content fields
	sr, scrubErr := s.scrubMessages(rawBody)
	if scrubErr != nil {
		logger.Error("Failed to scrub request body: ", scrubErr)
		return nil, nil, domain.ForwardResult{StatusCode: http.StatusBadRequest}, fmt.Errorf("failed to scrub request body: %w", scrubErr)
	}

	// 3. Semantic cache lookup — uses the caller's Authorization key for embedding
	// The key is extracted from headers at runtime; never stored.
	var promptHash string
	apiKey := extractBearerKey(headers)
	meta, metaErr := extractRequestMetadata(sr.body)
	if metaErr == nil && s.semanticEnabled && !meta.Stream && meta.Model != "" && meta.PromptText != "" &&
		s.semanticRepo != nil && s.semanticRespCache != nil && s.embeddingSvc != nil && apiKey != "" {
		embedding, embErr := s.embeddingSvc.Embed(ctx, meta.PromptText, apiKey)
		if embErr == nil && len(embedding) > 0 {
			maxDistance := 1.0 - s.semanticSimilarity
			if maxDistance < 0 {
				maxDistance = 0
			}
			hit, hitErr := s.semanticRepo.FindNearest(ctx, domain.SemanticLookupRequest{
				UserID:      userID,
				ProviderID:  providerID,
				Model:       meta.Model,
				Embedding:   embedding,
				MaxDistance: maxDistance,
				Now:         time.Now(),
			})
			if hitErr == nil && hit != nil {
				cached, cacheErr := s.semanticRespCache.Get(ctx, hit.ResponseKey)
				if cacheErr == nil && len(cached) > 0 {
					respHeaders := make(http.Header)
					respHeaders.Set("Content-Type", "application/json")
					result := domain.ForwardResult{
						StatusCode:       http.StatusOK,
						PIIDetected:      sr.totalRedacted > 0,
						ScrubbedItems:    sr.scrubbedTypes,
						RedactCount:      sr.totalRedacted,
						TokensProcessed:  extractTokensFromResponse(providerID, cached),
						SemanticCacheHit: true,
					}
					return io.NopCloser(bytes.NewReader(cached)), respHeaders, result, nil
				}
			}
			promptHash = shaHex(meta.PromptText)
		}
	}

	// 4. Forward to provider — all headers passed through, provider handles auth
	body, respHeaders, statusCode, err := provider.Forward(ctx, sr.body, headers)
	if err != nil {
		logger.Error("Provider error [", string(providerID), "]: ", err)
		if statusCode == 0 {
			statusCode = http.StatusBadGateway
		}
		empty.StatusCode = statusCode
		return nil, nil, empty, fmt.Errorf("%w: %s", domain.ErrUpstreamFailure, err.Error())
	}

	fwdResult := domain.ForwardResult{
		StatusCode:       statusCode,
		PIIDetected:      sr.totalRedacted > 0,
		ScrubbedItems:    sr.scrubbedTypes,
		RedactCount:      sr.totalRedacted,
		TokensProcessed:  0,
		SemanticCacheHit: false,
	}

	if metaErr == nil && !meta.Stream {
		responseBytes, readErr := io.ReadAll(body)
		if readErr != nil {
			return nil, nil, domain.ForwardResult{StatusCode: http.StatusBadGateway}, fmt.Errorf("failed to read upstream body: %w", readErr)
		}
		_ = body.Close()
		fwdResult.TokensProcessed = extractTokensFromResponse(providerID, responseBytes)

		// 5. Store in semantic cache after a successful non-streaming response
		if s.semanticEnabled && promptHash != "" &&
			statusCode >= 200 && statusCode < 300 && s.semanticRepo != nil &&
			s.semanticRespCache != nil && s.embeddingSvc != nil && apiKey != "" {
			responseKey := shaHex(meta.PromptText + ":" + string(providerID) + ":" + meta.Model + ":" + string(responseBytes))
			if err := s.semanticRespCache.Set(ctx, responseKey, responseBytes, s.semanticTTL); err != nil {
				logger.Error("semantic redis set failed: ", err)
			} else {
				embedding, embErr := s.embeddingSvc.Embed(ctx, meta.PromptText, apiKey)
				if embErr == nil {
					repoErr := s.semanticRepo.UpsertEntry(ctx, domain.SemanticCacheEntry{
						UserID:      userID,
						ProviderID:  providerID,
						Model:       meta.Model,
						PromptHash:  promptHash,
						PromptText:  meta.PromptText,
						Embedding:   embedding,
						ResponseKey: responseKey,
						ExpiresAt:   time.Now().Add(s.semanticTTL),
					})
					if repoErr != nil {
						logger.Error("semantic postgres upsert failed: ", repoErr)
					}
				}
			}
		}

		return io.NopCloser(bytes.NewReader(responseBytes)), respHeaders, fwdResult, nil
	}

	return body, respHeaders, fwdResult, nil
}

func shaHex(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

func extractTokensFromResponse(providerID domain.ProviderID, responseBody []byte) int {
	switch providerID {
	case domain.ProviderOpenAI:
		return extractOpenAITokens(responseBody)
	case domain.ProviderAnthropic:
		return extractAnthropicTokens(responseBody)
	case domain.ProviderGemini:
		return extractGeminiTokens(responseBody)
	default:
		return 0
	}
}

func extractOpenAITokens(responseBody []byte) int {
	var resp struct {
		Usage struct {
			TotalTokens int `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(responseBody, &resp); err != nil {
		return 0
	}
	return resp.Usage.TotalTokens
}

func extractAnthropicTokens(responseBody []byte) int {
	var resp struct {
		Usage map[string]int `json:"usage"`
	}
	if err := json.Unmarshal(responseBody, &resp); err != nil {
		return 0
	}
	total := 0
	for _, v := range resp.Usage {
		if v > 0 {
			total += v
		}
	}
	return total
}

func extractGeminiTokens(responseBody []byte) int {
	var resp struct {
		UsageMetadata struct {
			TotalTokenCount int `json:"totalTokenCount"`
		} `json:"usageMetadata"`
	}
	if err := json.Unmarshal(responseBody, &resp); err != nil {
		return 0
	}
	return resp.UsageMetadata.TotalTokenCount
}
