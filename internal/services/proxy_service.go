package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

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
// Orchestrates: fetch customer key → scrub PII → select provider → forward.
type proxyService struct {
	scrubber     domain.ScrubbingService
	encryption   domain.EncryptionService
	providerKeys domain.ProviderKeyRepository
	providers    map[domain.ProviderID]domain.LLMProvider
}

// NewProxyService creates a new ProxyService with the given dependencies.
func NewProxyService(
	scrubber domain.ScrubbingService,
	encryption domain.EncryptionService,
	providerKeys domain.ProviderKeyRepository,
	providers ...domain.LLMProvider,
) domain.ProxyService {
	pm := make(map[domain.ProviderID]domain.LLMProvider, len(providers))
	for _, p := range providers {
		pm[p.Name()] = p
		logger.Info("Registered LLM provider: ", string(p.Name()))
	}

	return &proxyService{
		scrubber:     scrubber,
		encryption:   encryption,
		providerKeys: providerKeys,
		providers:    pm,
	}
}

// scrubMessages performs surgical PII redaction on ONLY the messages[].content
// fields of the raw JSON body. All other fields (model, temperature, etc.) are
// preserved byte-for-byte via json.RawMessage.
func (s *proxyService) scrubMessages(rawBody []byte) (*scrubResult, error) {
	// Pass 1: Unmarshal top-level keys into a map to preserve unknown fields.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(rawBody, &top); err != nil {
		return nil, fmt.Errorf("failed to parse request JSON: %w", err)
	}

	msgsRaw, ok := top["messages"]
	if !ok {
		// No messages array — nothing to scrub (e.g. embeddings request).
		return &scrubResult{body: rawBody}, nil
	}

	// Pass 2: Unmarshal only the messages array.
	var msgs []chatMessage
	if err := json.Unmarshal(msgsRaw, &msgs); err != nil {
		return nil, fmt.Errorf("failed to parse messages array: %w", err)
	}

	// Scrub only the content field of each message, collecting PII types.
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
		// Nothing was redacted — return the original body untouched.
		return &scrubResult{body: rawBody}, nil
	}

	// Re-marshal the scrubbed messages and put them back.
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

// Forward fetches the customer's decrypted provider key, scrubs PII from the
// request body, selects the correct LLM provider, and forwards the request.
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

	// 2. Fetch the customer's encrypted provider key from DB
	keyRecord, err := s.providerKeys.GetProviderKey(ctx, userID, providerID)
	if err != nil {
		return nil, nil, domain.ForwardResult{StatusCode: http.StatusBadRequest}, fmt.Errorf("%w", domain.ErrProviderKeyMissing)
	}

	// 3. Decrypt the key (only at the moment of use)
	decryptedKey, err := s.encryption.Decrypt(keyRecord.EncryptedKey)
	if err != nil {
		logger.Error("Failed to decrypt provider key for user ", userID, ": ", err)
		return nil, nil, domain.ForwardResult{StatusCode: http.StatusInternalServerError}, fmt.Errorf("failed to decrypt provider key")
	}

	// 4. Scrub PII from ONLY the messages[].content fields (surgical mutation)
	sr, scrubErr := s.scrubMessages(rawBody)
	if scrubErr != nil {
		logger.Error("Failed to scrub request body: ", scrubErr)
		return nil, nil, domain.ForwardResult{StatusCode: http.StatusBadRequest}, fmt.Errorf("failed to scrub request body: %w", scrubErr)
	}

	// 5. Forward to provider with the customer's key
	body, respHeaders, statusCode, err := provider.Forward(ctx, sr.body, decryptedKey, headers)
	if err != nil {
		logger.Error("Provider error [", string(providerID), "]: ", err)
		if statusCode == 0 {
			statusCode = http.StatusBadGateway
		}
		empty.StatusCode = statusCode
		return nil, nil, empty, fmt.Errorf("%w: %s", domain.ErrUpstreamFailure, err.Error())
	}

	fwdResult := domain.ForwardResult{
		StatusCode:    statusCode,
		PIIDetected:   sr.totalRedacted > 0,
		ScrubbedItems: sr.scrubbedTypes,
		RedactCount:   sr.totalRedacted,
	}

	return body, respHeaders, fwdResult, nil
}

