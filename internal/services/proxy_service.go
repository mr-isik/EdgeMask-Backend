package services

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/mr-isik/edgemask-backend/internal/domain"
	"github.com/mr-isik/edgemask-backend/pkg/logger"
)

// proxyService implements domain.ProxyService.
// Orchestrates: fetch customer key → scrub PII → select provider → forward.
type proxyService struct {
	scrubber      domain.ScrubbingService
	encryption    domain.EncryptionService
	providerKeys  domain.ProviderKeyRepository
	providers     map[domain.ProviderID]domain.LLMProvider
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

// Forward fetches the customer's decrypted provider key, scrubs PII from the
// request body, selects the correct LLM provider, and forwards the request.
func (s *proxyService) Forward(
	ctx context.Context,
	userID string,
	providerID domain.ProviderID,
	rawBody []byte,
	headers http.Header,
) (io.ReadCloser, http.Header, int, error) {

	// 1. Select provider adapter
	provider, ok := s.providers[providerID]
	if !ok {
		return nil, nil, http.StatusBadRequest, fmt.Errorf("%w: %s", domain.ErrProviderUnknown, providerID)
	}

	// 2. Fetch the customer's encrypted provider key from DB
	keyRecord, err := s.providerKeys.GetProviderKey(ctx, userID, providerID)
	if err != nil {
		return nil, nil, http.StatusBadRequest, fmt.Errorf("%w", domain.ErrProviderKeyMissing)
	}

	// 3. Decrypt the key (only at the moment of use)
	decryptedKey, err := s.encryption.Decrypt(keyRecord.EncryptedKey)
	if err != nil {
		logger.Error("Failed to decrypt provider key for user ", userID, ": ", err)
		return nil, nil, http.StatusInternalServerError, fmt.Errorf("failed to decrypt provider key")
	}

	// 4. Scrub PII from the request body
	scrubbedText, count := s.scrubber.Redact(string(rawBody))
	if count > 0 {
		logger.Info(fmt.Sprintf("Redacted %d PII item(s) before forwarding to %s", count, providerID))
	}

	// 5. Forward to provider with the customer's key
	body, respHeaders, statusCode, err := provider.Forward(ctx, []byte(scrubbedText), decryptedKey, headers)
	if err != nil {
		logger.Error("Provider error [", string(providerID), "]: ", err)
		if statusCode == 0 {
			statusCode = http.StatusBadGateway
		}
		return nil, nil, statusCode, fmt.Errorf("%w: %s", domain.ErrUpstreamFailure, err.Error())
	}

	return body, respHeaders, statusCode, nil
}
